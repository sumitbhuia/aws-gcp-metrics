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

def get_network_stats():
    try:
        # Take the first snapshot
        initial_stats = psutil.net_io_counters(pernic=True)
        # Wait for 1 second
        time.sleep(1)
        # Take the second snapshot
        later_stats = psutil.net_io_counters(pernic=True)
        
        network_stats = []
        for iface, later in later_stats.items():
            if iface in initial_stats:
                initial = initial_stats[iface]
                # Calculate difference (bytes per second)
                rx_sec = later.bytes_recv - initial.bytes_recv
                tx_sec = later.bytes_sent - initial.bytes_sent
                network_stats.append({
                    'interface': iface,
                    'rx_bytes': later.bytes_recv,
                    'tx_bytes': later.bytes_sent,
                    'rx_sec': rx_sec,
                    'tx_sec': tx_sec,
                    'rx_packets': later.packets_recv,
                    'tx_packets': later.packets_sent,
                    'rx_errors': later.errin,
                    'tx_errors': later.errout
                })
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
                vram_utilization = None
                if gpu.memoryTotal and gpu.memoryUsed:
                    vram_utilization = float(f"{(gpu.memoryUsed / gpu.memoryTotal * 100):.2f}")
                gpu_details.append({
                    'index': gpu.id,
                    'model': gpu.name,
                    'vendor': 'N/A',  # GPUtil may not provide vendor info
                    'bus': 'N/A',
                    'vram': {
                        'total': gpu.memoryTotal,
                        'used': gpu.memoryUsed,
                        'free': gpu.memoryFree,
                        'utilizationPercent': vram_utilization
                    },
                    'utilization': float(f"{gpu.load * 100:.2f}"),
                    'memory_utilization': float(f"{(gpu.memoryUsed / gpu.memoryTotal * 100):.2f}") if gpu.memoryTotal else 'N/A',
                    'temperature': gpu.temperature,
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
            log_debug("Collected GPU details", "GPU", gpu_details)
            return gpu_details
        else:
            log_info("No GPU detected via GPUtil.", "GPU")
            return []  # Return an empty list if no GPU is detected
    except Exception as e:
        log_error(f"Error getting GPU details: {str(e)}", "GPU", {'stack': str(e)})
        return []

def get_metrics():
    try:
        # Measure overall and per-core CPU usage in one go
        overall_cpu = psutil.cpu_percent(interval=1)
        per_core_usage = psutil.cpu_percent(interval=0, percpu=True)  # immediate reading after overall
        
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
        
        # GPU details and network stats
        gpu_info = get_gpu_details()
        network_info = get_network_stats()
        
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
                'buffers': 0,   # Not exposed by psutil on all systems
                'cached': 0
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
