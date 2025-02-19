import os
import sys
import time
import json
import re
import socket
import datetime
import platform
import psutil
import GPUtil
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# ----- Logging Setup -----
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Create a logger with rotating file handler (max 10MB per file, 14 backups)
log_filename = os.path.join(LOG_DIR, f"server-{datetime.date.today().isoformat()}.log")
logger = logging.getLogger('SERVER')
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO').upper())

formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] [%(context)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = RotatingFileHandler(log_filename, maxBytes=10 * 1024 * 1024, backupCount=14)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Helper functions for logging with a context field
def log_info(message, context='SERVER', details=None):
    if details:
        message += " " + json.dumps(details, indent=2)
    logger.info(message, extra={'context': context})

def log_warn(message, context='SERVER', details=None):
    if details:
        message += " " + json.dumps(details, indent=2)
    logger.warning(message, extra={'context': context})

def log_error(message, context='SERVER', details=None):
    if details:
        message += " " + json.dumps(details, indent=2)
    logger.error(message, extra={'context': context})

def log_debug(message, context='SERVER', details=None):
    if details:
        message += " " + json.dumps(details, indent=2)
    logger.debug(message, extra={'context': context})

# ----- Flask & Socket.IO Setup -----
app = Flask(__name__)
CORS(app)  # Allow all origins; adjust as needed
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# ----- Helper Functions -----
def format_uptime(seconds):
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    if days > 0:
        return f"{days}d {hours}h {minutes}m {secs}s"
    elif hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"

def get_metrics():
    try:
        # For CPU usage, take snapshots without blocking
        per_core_usage = psutil.cpu_percent(interval=0, percpu=True)
        overall_cpu = sum(per_core_usage) / len(per_core_usage) if per_core_usage else 0
        
        # Check if sensors_temperatures is available; otherwise, use "N/A"
        temps = psutil.sensors_temperatures() if hasattr(psutil, 'sensors_temperatures') else {}
        main_temp = (
            temps.get('coretemp', [{}])[0].current
            if temps.get('coretemp') and 'current' in temps.get('coretemp', [{}])[0]
            else 'N/A'
        )
        
        # Memory metrics
        mem = psutil.virtual_memory()
        
        # Disk metrics (using the root partition)
        disk = psutil.disk_usage('/')
        
        # CPU info using platform.uname() for a potentially more descriptive model
        uname = platform.uname()
        cpu_info = {
            'model': uname.processor or 'Unknown',
            'speed': psutil.cpu_freq().current if psutil.cpu_freq() else None,
            'cores': {
                'physical': psutil.cpu_count(logical=False),
                'logical': psutil.cpu_count(logical=True)
            }
        }
        
        # Network stats - using global monitoring state
        network_info = get_network_stats()
        
        # GPU details 
        gpu_info = get_gpu_details()
        
        # Uptime
        uptime_seconds = int(time.time() - psutil.boot_time())
        
        # System info with python version info
        system_info = {
            'hostname': platform.node(),
            'platform': platform.system(),
            'arch': platform.machine(),
            'release': platform.release(),
            'pythonVersion': sys.version
        }
        
        # Compile complete metrics
        result = {
            'cpu': {
                'usage': float(f"{overall_cpu:.2f}"),
                'temperature': main_temp,
                'cores': cpu_info['cores'],
                'model': cpu_info['model'],
                'per_core': [float(f"{c:.2f}") for c in per_core_usage],
                'frequency': {
                    'current': cpu_info['speed']
                }
            },
            'memory': {
                'total': mem.total,
                'used': mem.used,
                'free': mem.free,
                'available': mem.available,
                'usedPercent': float(f"{mem.percent:.2f}"),
                'buffers': getattr(mem, 'buffers', 0),
                'cached': getattr(mem, 'cached', 0)
            },
            'swap': {
                'total': psutil.swap_memory().total,
                'used': psutil.swap_memory().used,
                'free': psutil.swap_memory().free,
                'usedPercent': float(f"{psutil.swap_memory().percent:.2f}")
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'usedPercent': float(f"{disk.percent:.2f}")
            },
            'gpu': gpu_info,
            'network': network_info,
            'uptime': {
                'seconds': uptime_seconds,
                'formatted': format_uptime(uptime_seconds)
            },
            'system': system_info,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        log_debug("Collected system metrics", "METRICS", result)
        return result
    except Exception as e:
        log_error(f"Error getting metrics: {str(e)}", "METRICS", {'stack': str(e)})
        return None

# Global variables to track network usage between calls
last_net_io = None
last_net_time = None

# Corrected network stats function - uses global state to track between calls
def get_network_stats():
    global last_net_io, last_net_time
    
    try:
        current_time = time.time()
        current_net_io = psutil.net_io_counters(pernic=True)
        
        network_stats = []
        
        # If we have previous measurements, calculate the rates
        if last_net_io is not None and last_net_time is not None:
            time_delta = current_time - last_net_time
            
            for iface, current in current_net_io.items():
                if iface in last_net_io:
                    prev = last_net_io[iface]
                    
                    # Calculate bytes per second
                    rx_sec = (current.bytes_recv - prev.bytes_recv) / time_delta
                    tx_sec = (current.bytes_sent - prev.bytes_sent) / time_delta
                    
                    network_stats.append({
                        'interface': iface,
                        'rx_bytes': current.bytes_recv,
                        'tx_bytes': current.bytes_sent,
                        'rx_sec': round(rx_sec, 2),
                        'tx_sec': round(tx_sec, 2),
                        'rx_packets': current.packets_recv,
                        'tx_packets': current.packets_sent,
                        'rx_errors': current.errin,
                        'tx_errors': current.errout
                    })
        else:
            # First run, just record interfaces with zero rates
            for iface, current in current_net_io.items():
                network_stats.append({
                    'interface': iface,
                    'rx_bytes': current.bytes_recv,
                    'tx_bytes': current.bytes_sent,
                    'rx_sec': 0,
                    'tx_sec': 0,
                    'rx_packets': current.packets_recv,
                    'tx_packets': current.packets_sent,
                    'rx_errors': current.errin,
                    'tx_errors': current.errout
                })
        
        # Update the global state for next call
        last_net_io = current_net_io
        last_net_time = current_time
        
        return network_stats
    except Exception as e:
        log_error(f"Error getting network stats: {str(e)}", 'NETWORK', {'stack': str(e)})
        return []

def get_gpu_details():
    try:
        # Try using GPUtil first
        gpus = GPUtil.getGPUs()
        gpu_details = []
        
        if gpus:
            for gpu in gpus:
                # Calculate VRAM utilization safely with proper error handling
                vram_utilization = None
                if gpu.memoryTotal and gpu.memoryTotal > 0:
                    vram_utilization = float(f"{(gpu.memoryUsed / gpu.memoryTotal * 100):.2f}")
                
                gpu_details.append({
                    'index': gpu.id,
                    'model': gpu.name if gpu.name else 'Unknown',
                    'vendor': 'NVIDIA' if 'nvidia' in gpu.name.lower() else 'Unknown',
                    'bus': 'N/A',
                    'vram': {
                        'total': gpu.memoryTotal,
                        'used': gpu.memoryUsed,
                        'free': gpu.memoryFree if hasattr(gpu, 'memoryFree') else (gpu.memoryTotal - gpu.memoryUsed),
                        'utilizationPercent': vram_utilization
                    },
                    'utilization': float(f"{gpu.load * 100:.2f}") if gpu.load is not None else 0.0,
                    'memory_utilization': vram_utilization,
                    'temperature': gpu.temperature if hasattr(gpu, 'temperature') and gpu.temperature is not None else 'N/A',
                    'power': {
                        'draw': 'N/A',
                        'limit': 'N/A'
                    },
                    'clocks': {
                        'graphics': 'N/A',
                        'memory': 'N/A'
                    },
                    'driver_version': 'N/A'
                })
            
            log_debug("Collected GPU details using GPUtil", "GPU", gpu_details)
            return gpu_details
        
        # If GPUtil failed, try multiple fallbacks
        
        # Fallback 1: Try using subprocess to call lspci (Linux)
        if platform.system() == 'Linux':
            try:
                import subprocess
                import re
                
                # Get GPU info using lspci
                lspci_output = subprocess.check_output('lspci | grep -E "VGA|3D|Display"', shell=True).decode('utf-8')
                
                if lspci_output:
                    gpus_found = []
                    for i, line in enumerate(lspci_output.strip().split('\n')):
                        # Extract GPU model name from lspci output
                        match = re.search(r'(?:VGA|3D|Display).*: (.*)', line)
                        if match:
                            gpu_model = match.group(1).strip()
                            vendor = "Unknown"
                            
                            # Try to identify vendor
                            if "nvidia" in gpu_model.lower():
                                vendor = "NVIDIA"
                            elif "amd" in gpu_model.lower() or "radeon" in gpu_model.lower():
                                vendor = "AMD"
                            elif "intel" in gpu_model.lower():
                                vendor = "Intel"
                            
                            gpus_found.append({
                                'index': i,
                                'model': gpu_model,
                                'vendor': vendor,
                                'bus': line.split()[0],
                                'vram': {
                                    'total': 'N/A',
                                    'used': 'N/A',
                                    'free': 'N/A',
                                    'utilizationPercent': None
                                },
                                'utilization': 'N/A',
                                'memory_utilization': 'N/A',
                                'temperature': 'N/A',
                                'power': {
                                    'draw': 'N/A',
                                    'limit': 'N/A'
                                },
                                'clocks': {
                                    'graphics': 'N/A',
                                    'memory': 'N/A'
                                },
                                'driver_version': 'N/A'
                            })
                    
                    if gpus_found:
                        log_info(f"Detected {len(gpus_found)} GPUs via lspci", "GPU")
                        return gpus_found
            except Exception as e:
                log_error(f"Failed to get Linux GPU info via lspci: {str(e)}", "GPU")
        
        # Fallback 2: Try using DirectX/WMI for Windows systems
        elif platform.system() == 'Windows':
            try:
                import subprocess
                result = subprocess.check_output(['wmic', 'path', 'win32_VideoController', 'get', 
                                                'name,AdapterRAM,DriverVersion,VideoProcessor'], text=True)
                
                lines = [line.strip() for line in result.split('\n') if line.strip()]
                if len(lines) > 1:  # First line is header
                    headers = lines[0].lower()
                    gpu_list = []
                    
                    for i, line in enumerate(lines[1:]):
                        if not line.strip():
                            continue
                            
                        # Extract any useful data
                        name_match = re.search(r'([A-Za-z0-9].*?)\s+\d', line)
                        ram_match = re.search(r'(\d+)', line)
                        
                        gpu_name = name_match.group(1).strip() if name_match else "Unknown GPU"
                        
                        # Determine vendor from GPU name
                        vendor = "Unknown"
                        if "nvidia" in gpu_name.lower():
                            vendor = "NVIDIA"
                        elif "amd" in gpu_name.lower() or "radeon" in gpu_name.lower():
                            vendor = "AMD"
                        elif "intel" in gpu_name.lower():
                            vendor = "Intel"
                        
                        gpu_list.append({
                            'index': i,
                            'model': gpu_name,
                            'vendor': vendor,
                            'bus': 'N/A',
                            'vram': {
                                'total': int(ram_match.group(1)) if ram_match else 'N/A',
                                'used': 'N/A',
                                'free': 'N/A',
                                'utilizationPercent': None
                            },
                            'utilization': 'N/A',
                            'memory_utilization': 'N/A',
                            'temperature': 'N/A',
                            'power': {
                                'draw': 'N/A',
                                'limit': 'N/A'
                            },
                            'clocks': {
                                'graphics': 'N/A',
                                'memory': 'N/A'
                            },
                            'driver_version': 'N/A'
                        })
                    
                    if gpu_list:
                        log_info(f"Detected {len(gpu_list)} GPUs via wmic", "GPU")
                        return gpu_list
            except Exception as e:
                log_error(f"Failed to get Windows GPU info: {str(e)}", "GPU")
        
        # Fallback 3: Try using system_profiler for macOS
        elif platform.system() == 'Darwin':
            try:
                import subprocess
                result = subprocess.check_output(['system_profiler', 'SPDisplaysDataType'], text=True)
                
                # Extract GPU info from system_profiler output
                gpu_sections = re.findall(r'Chipset Model: (.*?)(?:Vendor|Memory|Bus|.*\n\s*$)', result, re.DOTALL)
                
                if gpu_sections:
                    mac_gpus = []
                    for i, section in enumerate(gpu_sections):
                        lines = [line.strip() for line in section.split('\n')]
                        model = lines[0].strip()
                        
                        # Try to extract VRAM if available
                        vram_match = re.search(r'VRAM \(.*\): (\d+) ?(?:MB|GB)', result)
                        vram = int(vram_match.group(1)) if vram_match else 'N/A'
                        
                        # Try to determine vendor from model name
                        vendor = "Apple"
                        if "amd" in model.lower() or "radeon" in model.lower():
                            vendor = "AMD"
                        elif "nvidia" in model.lower():
                            vendor = "NVIDIA"
                        elif "intel" in model.lower():
                            vendor = "Intel"
                        
                        mac_gpus.append({
                            'index': i,
                            'model': model,
                            'vendor': vendor,
                            'bus': 'N/A',
                            'vram': {
                                'total': vram,
                                'used': 'N/A',
                                'free': 'N/A',
                                'utilizationPercent': None
                            },
                            'utilization': 'N/A',
                            'memory_utilization': 'N/A',
                            'temperature': 'N/A',
                            'power': {
                                'draw': 'N/A',
                                'limit': 'N/A'
                            },
                            'clocks': {
                                'graphics': 'N/A',
                                'memory': 'N/A'
                            },
                            'driver_version': 'N/A'
                        })
                    
                    if mac_gpus:
                        log_info(f"Detected {len(mac_gpus)} GPUs via system_profiler", "GPU")
                        return mac_gpus
            except Exception as e:
                log_error(f"Failed to get macOS GPU info: {str(e)}", "GPU")
        
        # Fallback 4: Try using the py3nvml library for NVIDIA GPUs
        try:
            import py3nvml.py3nvml as nvml
            nvml.nvmlInit()
            device_count = nvml.nvmlDeviceGetCount()
            
            if device_count > 0:
                nvidia_gpus = []
                for i in range(device_count):
                    handle = nvml.nvmlDeviceGetHandleByIndex(i)
                    info = nvml.nvmlDeviceGetMemoryInfo(handle)
                    name = nvml.nvmlDeviceGetName(handle)
                    temp = nvml.nvmlDeviceGetTemperature(handle, nvml.NVML_TEMPERATURE_GPU)
                    util = nvml.nvmlDeviceGetUtilizationRates(handle)
                    
                    if isinstance(name, bytes):
                        name = name.decode('utf-8')
                    
                    nvidia_gpus.append({
                        'index': i,
                        'model': name,
                        'vendor': 'NVIDIA',
                        'bus': 'N/A',
                        'vram': {
                            'total': info.total,
                            'used': info.used,
                            'free': info.free,
                            'utilizationPercent': float(f"{(info.used / info.total * 100):.2f}") if info.total > 0 else None
                        },
                        'utilization': float(f"{util.gpu:.2f}") if hasattr(util, 'gpu') else 'N/A',
                        'memory_utilization': float(f"{util.memory:.2f}") if hasattr(util, 'memory') else 'N/A',
                        'temperature': temp,
                        'power': {
                            'draw': 'N/A',
                            'limit': 'N/A'
                        },
                        'clocks': {
                            'graphics': 'N/A',
                            'memory': 'N/A'
                        },
                        'driver_version': nvml.nvmlSystemGetDriverVersion().decode('utf-8') if hasattr(nvml, 'nvmlSystemGetDriverVersion') else 'N/A'
                    })
                
                nvml.nvmlShutdown()
                log_info(f"Detected {len(nvidia_gpus)} NVIDIA GPUs via py3nvml", "GPU")
                return nvidia_gpus
            nvml.nvmlShutdown()
        except:
            # py3nvml might not be installed or failed, continue with other fallbacks
            pass
        
        # Final fallback: Try using subprocess to directly mimic what the JavaScript version does
        try:
            import subprocess
            import json
            
            # Create a temporary script to use systeminformation-like approach
            temp_script = """
            const si = require('systeminformation');
            si.graphics().then(data => {
                console.log(JSON.stringify(data));
            });
            """
            
            # Write the script to a temp file
            with open('temp_gpu_check.js', 'w') as f:
                f.write(temp_script)
            
            # Execute with Node.js if available
            try:
                result = subprocess.check_output(['node', 'temp_gpu_check.js'], text=True)
                os.remove('temp_gpu_check.js')  # Clean up
                
                data = json.loads(result)
                if data and 'controllers' in data and len(data['controllers']) > 0:
                    node_gpus = []
                    for i, gpu in enumerate(data['controllers']):
                        vram_utilization = None
                        if gpu.get('memoryTotal') and gpu.get('memoryUsed'):
                            vram_utilization = float(f"{(gpu['memoryUsed'] / gpu['memoryTotal'] * 100):.2f}")
                        
                        node_gpus.append({
                            'index': i,
                            'model': gpu.get('model', 'Unknown'),
                            'vendor': gpu.get('vendor', 'Unknown'),
                            'bus': gpu.get('bus', 'N/A'),
                            'vram': {
                                'total': gpu.get('memoryTotal', 'N/A'),
                                'used': gpu.get('memoryUsed', 'N/A'),
                                'free': gpu.get('memoryFree', 'N/A'),
                                'utilizationPercent': vram_utilization
                            },
                            'utilization': gpu.get('utilizationGpu', 'N/A'),
                            'memory_utilization': gpu.get('utilizationMemory', 'N/A'),
                            'temperature': gpu.get('temperatureGpu', 'N/A'),
                            'power': {
                                'draw': gpu.get('powerDraw', 'N/A'),
                                'limit': gpu.get('powerLimit', 'N/A')
                            },
                            'clocks': {
                                'graphics': gpu.get('clockCore', 'N/A'),
                                'memory': gpu.get('clockMemory', 'N/A')
                            },
                            'driver_version': gpu.get('driverVersion', 'N/A')
                        })
                    
                    log_info(f"Detected {len(node_gpus)} GPUs via Node.js systeminformation", "GPU")
                    return node_gpus
            except Exception as node_err:
                log_error(f"Failed to get GPU info via Node.js: {str(node_err)}", "GPU")
                # Clean up temp file if it exists
                if os.path.exists('temp_gpu_check.js'):
                    os.remove('temp_gpu_check.js')
        except Exception as e:
            log_error(f"Final fallback failed: {str(e)}", "GPU")
        
        log_info("No GPU detected after trying all fallback methods", "GPU")
        return []
    except Exception as e:
        log_error(f"Error in GPU detection: {str(e)}", "GPU", {'stack': str(e)})
        return []
        
def get_processes():
    try:
        processes = []
        for proc in psutil.process_iter([
            'pid', 'name', 'username', 'cmdline',
            'create_time', 'cpu_percent', 'memory_percent',
            'memory_info', 'status', 'num_threads'
        ]):
            try:
                info = proc.info
                uptime_val = None
                if info.get('create_time'):
                    uptime_val = format_uptime(int(time.time() - info['create_time']))
                
                processes.append({
                    'pid': info['pid'],
                    'name': info.get('name'),
                    'command': ' '.join(info.get('cmdline', [])) if info.get('cmdline') else '',
                    'user': info.get('username'),
                    'started': datetime.datetime.fromtimestamp(info['create_time']).isoformat() if info.get('create_time') else None,
                    'uptime': uptime_val,
                    'cpu': round(info.get('cpu_percent') or 0, 2),
                    'memory': round(info.get('memory_percent') or 0, 2),
                    'memory_bytes': info.get('memory_info').rss if info.get('memory_info') else 0,
                    'status': info.get('status'),
                    'threads': info.get('num_threads', 0)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        processes.sort(key=lambda x: x['cpu'], reverse=True)
        result = processes[:10]
        log_debug(f"Retrieved top {len(result)} processes by CPU usage", "PROCESSES")
        return result
    except Exception as e:
        log_error(f"Error getting processes: {str(e)}", "PROCESSES", {'stack': str(e)})
        return []

def parse_log_entry(line):
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) \[(INFO|ERROR|WARN|DEBUG)\] (?:\[([^\]]+)\] )?(.+)$', line)
        if match:
            return {
                'timestamp': match.group(1),
                'level': match.group(2),
                'context': match.group(3) if match.group(3) else 'SERVER',
                'message': match.group(4),
                'details': None
            }
        return {'raw': line}

def get_logs(max_logs=100):
    try:
        log_files = [os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR)
                     if f.startswith("server-") and f.endswith(".log")]
        log_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        if not log_files:
            return []
        logs = []
        file_index = 0
        while len(logs) < max_logs and file_index < len(log_files):
            with open(log_files[file_index], 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip()]
                parsed_lines = [parse_log_entry(line) for line in lines]
                logs = parsed_lines + logs
            file_index += 1
        return logs[-max_logs:]
    except Exception as e:
        log_error(f"Error reading logs: {str(e)}", "LOGS", {'stack': str(e)})
        return []

# ----- API Endpoints -----
@app.route('/api/health', methods=['GET'])
def health():
    request_id = request.headers.get('x-request-id', f"req-{int(time.time()*1000)}")
    log_info("Health check endpoint called", "API", {'request_id': request_id})
    return jsonify({
        'status': 'online',
        'serverTime': datetime.datetime.now().isoformat(),
        'request_id': request_id
    })

@app.route('/api/metrics', methods=['GET'])
def metrics():
    request_id = request.headers.get('x-request-id', f"req-{int(time.time()*1000)}")
    log_info("Metrics endpoint called", "API", {'request_id': request_id})
    data = get_metrics()
    if data:
        return jsonify(data)
    else:
        return jsonify({'error': 'Failed to get metrics', 'request_id': request_id}), 500

@app.route('/api/gpu', methods=['GET'])
def gpu():
    request_id = request.headers.get('x-request-id', f"req-{int(time.time()*1000)}")
    log_info("GPU details endpoint called", "API", {'request_id': request_id})
    data = get_gpu_details()
    return jsonify(data)

@app.route('/api/processes', methods=['GET'])
def processes():
    request_id = request.headers.get('x-request-id', f"req-{int(time.time()*1000)}")
    log_info("Processes endpoint called", "API", {'request_id': request_id})
    data = get_processes()
    return jsonify(data)

@app.route('/api/logs', methods=['GET'])
def logs():
    request_id = request.headers.get('x-request-id', f"req-{int(time.time()*1000)}")
    limit = int(request.args.get('limit', 100))
    log_info(f"Logs endpoint called, requesting {limit} entries", "API", {'request_id': request_id})
    data = get_logs(limit)
    return jsonify(data)

# ----- Socket.IO Event Handlers -----
@socketio.on('connect')
def handle_connect():
    client_ip = request.remote_addr
    client_id = request.sid
    log_info(f"Client connected from {client_ip} with session ID {client_id}", "SOCKET")
    emit('connection_status', {'status': 'connected', 'serverTime': datetime.datetime.now().isoformat()})

@socketio.on('disconnect')
def handle_disconnect():
    client_id = request.sid
    log_info(f"Client disconnected: {client_id}", "SOCKET")

@socketio.on('requestData')
def handle_request_data(data):
    client_id = request.sid
    server_id = data.get('serverId') if data and isinstance(data, dict) else 'unknown'
    log_info(f"Data requested for server {server_id} from client {client_id}", "SOCKET")
    try:
        metrics_data = get_metrics()
        processes_data = get_processes()
        gpu_data = get_gpu_details()
        logs_data = get_logs()
        emit('metrics', metrics_data)
        emit('processes', processes_data)
        emit('gpu', gpu_data)
        emit('logs', logs_data)
    except Exception as e:
        log_error(f"Error handling data request: {str(e)}", "SOCKET", {'stack': str(e)})
        emit('error', {'message': 'Failed to fetch data', 'error': str(e)})

@socketio.on('requestGpuDetails')
def handle_request_gpu_details():
    client_id = request.sid
    log_info(f"GPU details requested by client {client_id}", "SOCKET")
    try:
        gpu_details = get_gpu_details()
        emit('gpuDetails', gpu_details)
    except Exception as e:
        log_error(f"Error handling GPU details request: {str(e)}", "SOCKET", {'stack': str(e)})
        emit('error', {'message': 'Failed to fetch GPU details', 'error': str(e)})

@socketio.on('requestLogs')
def handle_request_logs(options):
    client_id = request.sid
    limit = options.get('limit', 100) if options and isinstance(options, dict) else 100
    log_info(f"Logs requested by client {client_id}, limit: {limit}", "SOCKET")
    try:
        logs_data = get_logs(limit)
        emit('logs', logs_data)
    except Exception as e:
        log_error(f"Error handling logs request: {str(e)}", "SOCKET", {'stack': str(e)})
        emit('error', {'message': 'Failed to fetch logs', 'error': str(e)})

# ----- Server Startup -----
if __name__ == '__main__':
    PORT = int(os.getenv('PORT', 5000))
    system_info = {
        'pythonVersion': sys.version,
        'platform': platform.system(),
        'arch': platform.machine(),
        'hostname': platform.node(),
        'cpus': psutil.cpu_count(logical=True),
        'memory': f"{round(psutil.virtual_memory().total / (1024**3))} GB",
        'ip': socket.gethostbyname(socket.gethostname())
    }
    log_info(f"Server started on port {PORT}", "STARTUP", system_info)
    socketio.run(app, host='0.0.0.0', port=PORT)
