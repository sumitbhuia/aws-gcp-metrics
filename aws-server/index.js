// const express = require('express');
// const http = require('http');
// const socketIo = require('socket.io');
// const cors = require('cors');
// const helmet = require('helmet');
// const rateLimit = require('express-rate-limit');
// const os = require('os');
// const fs = require('fs');
// const path = require('path');
// const winston = require('winston');
// const moment = require('moment');
// const si = require('systeminformation');
// const pidusage = require('pidusage');
// require('dotenv').config();

// // Initialize Express app
// const app = express();

// // Security middlewares
// app.use(helmet());
// app.use(cors({
//   // For production, consider restricting the origin:
//   // origin: process.env.CLIENT_ORIGIN || "http://yourdomain.com",
//   origin: "*"
// }));

// // Rate limiter to mitigate abuse (adjust as needed)
// const limiter = rateLimit({
//   windowMs: 1 * 60 * 1000, // 1 minute
//   max: 100, // limit each IP to 100 requests per windowMs
// });
// app.use(limiter);

// // Parse JSON bodies
// app.use(express.json());

// // Create HTTP server
// const server = http.createServer(app);

// // Initialize Socket.io with CORS settings
// const io = socketIo(server, {
//   cors: {
//     origin: "*", // adjust this for production
//     methods: ["GET", "POST"]
//   }
// });

// // Configure logging
// const logDir = 'logs';
// if (!fs.existsSync(logDir)) {
//   fs.mkdirSync(logDir);
// }

// // Custom log format
// const logFormat = winston.format.printf(({ level, message, timestamp, context, details }) => {
//   const baseLog = `${timestamp} [${level.toUpperCase()}] ${context ? `[${context}]` : ''} ${message}`;
//   if (details) {
//     return `${baseLog}\n${typeof details === 'string' ? details : JSON.stringify(details, null, 2)}`;
//   }
//   return baseLog;
// });

// // Create logger
// const logger = winston.createLogger({
//   level: process.env.LOG_LEVEL || 'info',
//   format: winston.format.combine(
//     winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
//     winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp', 'context', 'details'] }),
//     logFormat
//   ),
//   transports: [
//     new winston.transports.Console({
//       format: winston.format.combine(
//         winston.format.colorize(),
//         logFormat
//       )
//     }),
//     new winston.transports.File({
//       filename: path.join(logDir, `server-${moment().format('YYYY-MM-DD')}.log`),
//       maxsize: 10 * 1024 * 1024, // 10MB
//       maxFiles: 14, // Keep logs for 14 days
//     })
//   ]
// });

// // Logger wrapper functions
// const log = {
//   info: (message, context = 'SERVER', details = null) => logger.info(message, { context, details }),
//   warn: (message, context = 'SERVER', details = null) => logger.warn(message, { context, details }),
//   error: (message, context = 'SERVER', details = null) => logger.error(message, { context, details }),
//   debug: (message, context = 'SERVER', details = null) => logger.debug(message, { context, details })
// };

// // Helper function to format uptime
// function formatUptime(seconds) {
//   const days = Math.floor(seconds / 86400);
//   const hours = Math.floor((seconds % 86400) / 3600);
//   const minutes = Math.floor((seconds % 3600) / 60);
//   const secs = Math.floor(seconds % 60);
  
//   if (days > 0) {
//     return `${days}d ${hours}h ${minutes}m ${secs}s`;
//   } else if (hours > 0) {
//     return `${hours}h ${minutes}m ${secs}s`;
//   } else if (minutes > 0) {
//     return `${minutes}m ${secs}s`;
//   } else {
//     return `${secs}s`;
//   }
// }

// // Get network statistics
// async function getNetworkStats() {
//   try {
//     const networkStats = await si.networkStats();
//     return networkStats.map(adapter => ({
//       interface: adapter.iface,
//       rx_bytes: adapter.rx_bytes,
//       tx_bytes: adapter.tx_bytes,
//       rx_sec: adapter.rx_sec,
//       tx_sec: adapter.tx_sec,
//       rx_packets: adapter.rx_packets || 0,
//       tx_packets: adapter.tx_packets || 0,
//       rx_errors: adapter.rx_errors || 0,
//       tx_errors: adapter.tx_errors || 0
//     }));
//   } catch (err) {
//     log.error(`Error getting network stats: ${err.message}`, 'NETWORK', { stack: err.stack });
//     return [];
//   }
// }

// // Helper function to get system metrics including GPU
// async function getMetrics() {
//   try {
//     // CPU load information
//     const loadData = await si.currentLoad();
//     const overallCpuUsage = loadData.currentLoad; // percentage
//     const perCoreUsage = loadData.cpus ? loadData.cpus.map(cpu => parseFloat(cpu.load.toFixed(2))) : [];

//     // CPU temperature
//     const cpuTemperature = await si.cpuTemperature();

//     // Memory metrics
//     const mem = await si.mem();
//     const actualUsedMemory = mem.total - mem.available;
//     const usedPercent = parseFloat(((actualUsedMemory / mem.total) * 100).toFixed(2));

//     // Disk info; check if available before accessing disk[0]
//     const disk = await si.fsSize();
//     let diskMetrics = {};
//     if (disk && disk.length > 0) {
//       diskMetrics = {
//         total: disk[0].size,
//         used: disk[0].used,
//         free: disk[0].available,
//         usedPercent: parseFloat((disk[0].use).toFixed(2))
//       };
//     } else {
//       diskMetrics = { total: 0, used: 0, free: 0, usedPercent: 0 };
//     }

//     // GPU and network stats
//     const gpuInfo = await getGpuDetails();
//     const networkInfo = await getNetworkStats();

//     // CPU info from os module
//     const cpuInfo = os.cpus();
//     const cpuModel = cpuInfo.length > 0 ? cpuInfo[0].model : 'Unknown';

//     // Uptime
//     const uptimeSeconds = os.uptime();

//     // Basic system info
//     const systemInfo = {
//       hostname: os.hostname(),
//       platform: process.platform,
//       arch: os.arch(),
//       release: os.release(),
//       nodeVersion: process.version
//     };

//     // Compile metrics
//     const result = {
//       cpu: {
//         usage: parseFloat(overallCpuUsage.toFixed(2)),
//         temperature: cpuTemperature.main || 'N/A',
//         cores: {
//           physical: cpuInfo.length,
//           logical: cpuInfo.length
//         },
//         model: cpuModel,
//         per_core: perCoreUsage,
//         frequency: {
//           current: cpuInfo.length > 0 ? cpuInfo[0].speed : null
//         }
//       },
//       memory: {
//         total: mem.total,
//         used: actualUsedMemory,
//         free: mem.free,
//         available: mem.available,
//         usedPercent: usedPercent,
//         buffers: mem.buffers || 0,
//         cached: mem.cached || 0
//       },
//       swap: {
//         total: mem.swaptotal || 0,
//         used: mem.swapused || 0,
//         free: (mem.swaptotal || 0) - (mem.swapused || 0),
//         usedPercent: mem.swaptotal ? parseFloat(((mem.swapused / mem.swaptotal) * 100).toFixed(2)) : 0
//       },
//       disk: diskMetrics,
//       gpu: gpuInfo,
//       network: networkInfo,
//       uptime: {
//         seconds: uptimeSeconds,
//         formatted: formatUptime(uptimeSeconds)
//       },
//       system: systemInfo,
//       timestamp: moment().toISOString()
//     };

//     log.debug('Collected system metrics', 'METRICS', result);
//     return result;
//   } catch (err) {
//     log.error(`Error getting metrics: ${err.message}`, 'METRICS', { stack: err.stack });
//     return null;
//   }
// }

// // Get detailed GPU information
// async function getGpuDetails() {
//   try {
//     const graphics = await si.graphics();
    
//     const gpuDetails = graphics.controllers.map(gpu => {
//       const vramUtilization = gpu.memoryTotal && gpu.memoryUsed
//         ? parseFloat(((gpu.memoryUsed / gpu.memoryTotal) * 100).toFixed(2))
//         : null;
        
//       return {
//         index: gpu.deviceId || 0,
//         model: gpu.model,
//         vendor: gpu.vendor,
//         bus: gpu.bus || 'N/A',
//         vram: {
//           total: gpu.memoryTotal || 'N/A',
//           used: gpu.memoryUsed || 'N/A',
//           free: gpu.memoryFree || 'N/A',
//           utilizationPercent: vramUtilization
//         },
//         utilization: gpu.utilizationGpu || 'N/A',
//         memory_utilization: gpu.utilizationMemory || 'N/A',
//         temperature: gpu.temperatureGpu || 'N/A',
//         power: {
//           draw: gpu.powerDraw || 'N/A',
//           limit: gpu.powerLimit || 'N/A'
//         },
//         clocks: {
//           graphics: gpu.clockCore || 'N/A',
//           memory: gpu.clockMemory || 'N/A'
//         },
//         driver_version: gpu.driverVersion || 'N/A'
//       };
//     });
    
//     log.debug('Collected GPU details', 'GPU', gpuDetails);
//     return gpuDetails;
//   } catch (err) {
//     log.error(`Error getting GPU details: ${err.message}`, 'GPU', { stack: err.stack });
//     return [];
//   }
// }

// // Get process information
// async function getProcesses() {
//   try {
//     const processes = await si.processes();
//     const pids = processes.list.map(p => p.pid);
//     const stats = await pidusage(pids);
    
//     const result = processes.list
//       .map(proc => {
//         const usage = stats[proc.pid] || {};
//         const totalMemory = os.totalmem();
//         const cpuValue = usage.cpu || 0;
//         const memValue = (usage.memory || 0) / totalMemory * 100;
        
//         let uptime = null;
//         if (proc.started) {
//           const uptimeSeconds = Date.now() - new Date(proc.started).getTime();
//           uptime = formatUptime(Math.floor(uptimeSeconds / 1000));
//         }
        
//         return {
//           pid: proc.pid,
//           name: proc.name,
//           command: proc.command,
//           user: proc.user,
//           started: proc.started,
//           uptime: uptime,
//           cpu: parseFloat(cpuValue.toFixed(2)),
//           memory: parseFloat(memValue.toFixed(2)),
//           memory_bytes: usage.memory || 0,
//           status: proc.state,
//           threads: proc.threads || 0
//         };
//       })
//       .sort((a, b) => b.cpu - a.cpu)
//       .slice(0, 10);
    
//     log.debug(`Retrieved top ${result.length} processes by CPU usage`, 'PROCESSES');
//     return result;
//   } catch (err) {
//     log.error(`Error getting processes: ${err.message}`, 'PROCESSES', { stack: err.stack });
//     return [];
//   }
// }

// // Helper function to parse log entries
// function parseLogEntry(line) {
//   try {
//     return JSON.parse(line);
//   } catch (e) {
//     const match = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3}) \[(INFO|ERROR|WARN|DEBUG)\] (?:\[([^\]]+)\] )?(.+)$/);
//     if (match) {
//       return {
//         timestamp: match[1],
//         level: match[2],
//         context: match[3] || 'SERVER',
//         message: match[4],
//         details: null
//       };
//     }
//     return { raw: line };
//   }
// }

// // Helper function to get logs
// function getLogs(maxLogs = 100) {
//   try {
//     const logFiles = fs.readdirSync(logDir)
//       .filter(file => file.startsWith('server-') && file.endsWith('.log'))
//       .map(file => path.join(logDir, file))
//       .sort((a, b) => fs.statSync(b).mtime.getTime() - fs.statSync(a).mtime.getTime());
    
//     if (logFiles.length === 0) {
//       return [];
//     }
    
//     let logs = [];
//     let fileIndex = 0;
    
//     while (logs.length < maxLogs && fileIndex < logFiles.length) {
//       const fileData = fs.readFileSync(logFiles[fileIndex], 'utf8');
//       const fileLines = fileData.split('\n')
//         .filter(line => line.trim() !== '')
//         .map(line => parseLogEntry(line.trim()));
      
//       logs = [...fileLines, ...logs];
//       fileIndex++;
//     }
    
//     return logs.slice(-maxLogs);
//   } catch (err) {
//     log.error(`Error reading logs: ${err.message}`, 'LOGS', { stack: err.stack });
//     return [];
//   }
// }

// // API Routes
// app.get('/api/health', (req, res) => {
//   const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
//   log.info('Health check endpoint called', 'API', { request_id: requestId });
//   res.json({ 
//     status: 'online', 
//     serverTime: new Date().toISOString(),
//     request_id: requestId
//   });
// });

// app.get('/api/metrics', async (req, res) => {
//   const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
//   log.info('Metrics endpoint called', 'API', { request_id: requestId });
//   const data = await getMetrics();
//   if (data) {
//     res.json(data);
//   } else {
//     res.status(500).json({ error: 'Failed to get metrics', request_id: requestId });
//   }
// });

// app.get('/api/gpu', async (req, res) => {
//   const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
//   log.info('GPU details endpoint called', 'API', { request_id: requestId });
//   const data = await getGpuDetails();
//   res.json(data);
// });

// app.get('/api/processes', async (req, res) => {
//   const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
//   log.info('Processes endpoint called', 'API', { request_id: requestId });
//   const data = await getProcesses();
//   res.json(data);
// });

// app.get('/api/logs', (req, res) => {
//   const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
//   const limit = parseInt(req.query.limit) || 100;
//   log.info(`Logs endpoint called, requesting ${limit} entries`, 'API', { request_id: requestId });
//   const data = getLogs(limit);
//   res.json(data);
// });

// // Socket.io event handlers
// io.on('connection', (socket) => {
//   const clientIp = socket.handshake.address;
//   const clientId = socket.id;
//   log.info(`Client connected from ${clientIp} with session ID ${clientId}`, 'SOCKET');
//   socket.emit('connection_status', { 
//     status: 'connected', 
//     serverTime: new Date().toISOString() 
//   });

//   socket.on('disconnect', () => {
//     log.info(`Client disconnected: ${clientId}`, 'SOCKET');
//   });

//   socket.on('requestData', async (data) => {
//     try {
//       const serverId = data?.serverId;
//       log.info(`Data requested for server ${serverId || 'unknown'} from client ${clientId}`, 'SOCKET');
      
//       // Collect all data in parallel
//       const [metrics, processes, gpu, logs] = await Promise.all([
//         getMetrics(),
//         getProcesses(),
//         getGpuDetails(),
//         getLogs()
//       ]);
      
//       socket.emit('metrics', metrics);
//       socket.emit('processes', processes);
//       socket.emit('gpu', gpu);
//       socket.emit('logs', logs);
//     } catch (err) {
//       log.error(`Error handling data request: ${err.message}`, 'SOCKET', { stack: err.stack });
//       socket.emit('error', { message: 'Failed to fetch data', error: err.message });
//     }
//   });

//   socket.on('requestGpuDetails', async () => {
//     try {
//       log.info(`GPU details requested by client ${clientId}`, 'SOCKET');
//       const gpuDetails = await getGpuDetails();
//       socket.emit('gpuDetails', gpuDetails);
//     } catch (err) {
//       log.error(`Error handling GPU details request: ${err.message}`, 'SOCKET', { stack: err.stack });
//       socket.emit('error', { message: 'Failed to fetch GPU details', error: err.message });
//     }
//   });

//   socket.on('requestLogs', async (options = {}) => {
//     try {
//       const limit = options.limit || 100;
//       log.info(`Logs requested by client ${clientId}, limit: ${limit}`, 'SOCKET');
//       const logs = getLogs(limit);
//       socket.emit('logs', logs);
//     } catch (err) {
//       log.error(`Error handling logs request: ${err.message}`, 'SOCKET', { stack: err.stack });
//       socket.emit('error', { message: 'Failed to fetch logs', error: err.message });
//     }
//   });
// });

// // Express error-handling middleware
// app.use((err, req, res, next) => {
//   log.error(err.message, 'API', { stack: err.stack });
//   res.status(500).json({ error: 'Internal Server Error' });
// });

// // Start the server
// const PORT = process.env.PORT || 3000;
// server.listen(PORT, () => {
//   const systemInfo = {
//     nodeVersion: process.version,
//     platform: process.platform,
//     arch: process.arch,
//     hostname: os.hostname(),
//     cpus: os.cpus().length,
//     memory: `${Math.round(os.totalmem() / (1024 * 1024 * 1024))} GB`,
//     ip: Object.values(os.networkInterfaces())
//       .flat()
//       .filter(details => details.family === 'IPv4' && !details.internal)
//       .map(details => details.address)[0] || 'localhost'
//   };
  
//   log.info(`Server started on port ${PORT}`, 'STARTUP', systemInfo);
// });

// // Process-level error handling
// process.on('uncaughtException', (err) => {
//   log.error(`Uncaught Exception: ${err.message}`, 'SYSTEM', { stack: err.stack });
//   process.exit(1);
// });

// process.on('unhandledRejection', (reason, promise) => {
//   log.error('Unhandled Rejection at:', 'SYSTEM', { reason, promise });
// });

// // Graceful shutdown
// const shutdown = () => {
//   log.info('Received shutdown signal, closing server gracefully...', 'SHUTDOWN');
//   server.close(() => {
//     log.info('Closed remaining connections', 'SHUTDOWN');
//     process.exit(0);
//   });

//   // Force shutdown after 10 seconds if necessary
//   setTimeout(() => {
//     log.error('Forcefully shutting down after timeout', 'SHUTDOWN');
//     process.exit(1);
//   }, 10000);
// };

// process.on('SIGTERM', shutdown);
// process.on('SIGINT', shutdown);

// // Export for testing
// module.exports = { app, server };

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const os = require('os');
const fs = require('fs');
const path = require('path');
const winston = require('winston');
const moment = require('moment');
const si = require('systeminformation');
const pidusage = require('pidusage');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
require('dotenv').config();

// Initialize Express app
const app = express();

// Security middlewares
app.use(helmet());
app.use(cors({
  origin: "*"
}));

// Rate limiter
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Parse JSON bodies
app.use(express.json());

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.io
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Configure logging
const logDir = 'logs';
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

// Custom log format
const logFormat = winston.format.printf(({ level, message, timestamp, context, details }) => {
  const baseLog = `${timestamp} [${level.toUpperCase()}] ${context ? `[${context}]` : ''} ${message}`;
  if (details) {
    return `${baseLog}\n${typeof details === 'string' ? details : JSON.stringify(details, null, 2)}`;
  }
  return baseLog;
});

// Create logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp', 'context', 'details'] }),
    logFormat
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        logFormat
      )
    }),
    new winston.transports.File({
      filename: path.join(logDir, `server-${moment().format('YYYY-MM-DD')}.log`),
      maxsize: 10 * 1024 * 1024,
      maxFiles: 14
    })
  ]
});

// Logger wrapper
const log = {
  info: (message, context = 'SERVER', details = null) => logger.info(message, { context, details }),
  warn: (message, context = 'SERVER', details = null) => logger.warn(message, { context, details }),
  error: (message, context = 'SERVER', details = null) => logger.error(message, { context, details }),
  debug: (message, context = 'SERVER', details = null) => logger.debug(message, { context, details })
};

// Helper function to format uptime
function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  if (days > 0) return `${days}d ${hours}h ${minutes}m ${secs}s`;
  if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

// Get CPU temperature
async function getCpuTemperature() {
  try {
    // Try sensors command first
    try {
      const { stdout: sensorsOutput } = await execPromise('sensors');
      const tempMatch = sensorsOutput.match(/Package id 0:\s+\+(\d+\.\d+)°C/);
      if (tempMatch) {
        return parseFloat(tempMatch[1]);
      }
    } catch (err) {
      log.debug('sensors command failed, trying thermal zone', 'CPU');
    }

    // Try reading from thermal zone
    const thermalZones = fs.readdirSync('/sys/class/thermal/').filter(zone => zone.startsWith('thermal_zone'));
    for (const zone of thermalZones) {
      try {
        const type = fs.readFileSync(`/sys/class/thermal/${zone}/type`, 'utf8').trim();
        if (type.includes('x86_pkg_temp') || type.includes('cpu')) {
          const temp = parseInt(fs.readFileSync(`/sys/class/thermal/${zone}/temp`, 'utf8')) / 1000;
          return temp;
        }
      } catch (err) {
        continue;
      }
    }
  } catch (err) {
    log.warn('Could not read CPU temperature', 'CPU', { error: err.message });
  }
  return null;
}

// Get GPU details using nvidia-smi
async function getGpuDetails() {
  try {
    // Check if nvidia-smi exists
    try {
      await execPromise('which nvidia-smi');
    } catch (err) {
      log.warn('nvidia-smi not found, falling back to systeminformation', 'GPU');
      return fallbackGpuDetails();
    }

    // Get detailed GPU information
    const { stdout } = await execPromise(
      'nvidia-smi --query-gpu=index,name,temperature.gpu,memory.total,memory.used,memory.free,' +
      'utilization.gpu,utilization.memory,power.draw,power.limit,clocks.current.graphics,' +
      'clocks.current.memory,driver_version,pci.bus_id --format=csv,noheader,nounits'
    );
    
    const gpuDetails = stdout.trim().split('\n').map(line => {
      const [
        index, name, temperature, memoryTotal, memoryUsed, memoryFree,
        gpuUtil, memoryUtil, powerDraw, powerLimit, clockCore, clockMemory,
        driverVersion, pciBusId
      ] = line.split(', ').map(value => value.trim());

      const vramUtilization = memoryTotal && memoryUsed
        ? parseFloat(((parseInt(memoryUsed) / parseInt(memoryTotal)) * 100).toFixed(2))
        : null;

      return {
        index: parseInt(index),
        model: name,
        vendor: 'NVIDIA',
        bus: pciBusId,
        vram: {
          total: parseInt(memoryTotal),
          used: parseInt(memoryUsed),
          free: parseInt(memoryFree),
          utilizationPercent: vramUtilization
        },
        utilization: parseFloat(gpuUtil),
        memory_utilization: parseFloat(memoryUtil),
        temperature: parseFloat(temperature),
        power: {
          draw: parseFloat(powerDraw),
          limit: parseFloat(powerLimit)
        },
        clocks: {
          graphics: parseFloat(clockCore),
          memory: parseFloat(clockMemory)
        },
        driver_version: driverVersion
      };
    });

    log.debug('Collected GPU details using nvidia-smi', 'GPU', gpuDetails);
    return gpuDetails;

  } catch (err) {
    log.error(`Error getting GPU details: ${err.message}`, 'GPU', { stack: err.stack });
    return fallbackGpuDetails();
  }
}

// Fallback GPU details using systeminformation
async function fallbackGpuDetails() {
  try {
    const graphics = await si.graphics();
    return graphics.controllers.map(gpu => ({
      index: gpu.deviceId || 0,
      model: gpu.model || 'Unknown',
      vendor: gpu.vendor || 'Unknown',
      bus: gpu.bus || 'N/A',
      vram: {
        total: gpu.memoryTotal || 'N/A',
        used: gpu.memoryUsed || 'N/A',
        free: gpu.memoryFree || 'N/A',
        utilizationPercent: null
      },
      utilization: gpu.utilizationGpu || 'N/A',
      memory_utilization: gpu.utilizationMemory || 'N/A',
      temperature: gpu.temperatureGpu || 'N/A',
      power: {
        draw: gpu.powerDraw || 'N/A',
        limit: gpu.powerLimit || 'N/A'
      },
      clocks: {
        graphics: gpu.clockCore || 'N/A',
        memory: gpu.clockMemory || 'N/A'
      },
      driver_version: gpu.driverVersion || 'N/A'
    }));
  } catch (err) {
    log.error(`Error in fallback GPU details: ${err.message}`, 'GPU', { stack: err.stack });
    return [];
  }
}

// Get network statistics
async function getNetworkStats() {
  try {
    const networkStats = await si.networkStats();
    return networkStats.map(adapter => ({
      interface: adapter.iface,
      rx_bytes: adapter.rx_bytes,
      tx_bytes: adapter.tx_bytes,
      rx_sec: adapter.rx_sec,
      tx_sec: adapter.tx_sec,
      rx_packets: adapter.rx_packets || 0,
      tx_packets: adapter.tx_packets || 0,
      rx_errors: adapter.rx_errors || 0,
      tx_errors: adapter.tx_errors || 0
    }));
  } catch (err) {
    log.error(`Error getting network stats: ${err.message}`, 'NETWORK', { stack: err.stack });
    return [];
  }
}

// Get system metrics
async function getMetrics() {
  try {
    // CPU load
    const loadData = await si.currentLoad();
    const overallCpuUsage = loadData.currentLoad;
    const perCoreUsage = loadData.cpus ? loadData.cpus.map(cpu => parseFloat(cpu.load.toFixed(2))) : [];

    // CPU temperature
    const cpuTemperature = await getCpuTemperature();

    // Memory metrics
    const mem = await si.mem();
    const actualUsedMemory = mem.total - mem.available;
    const usedPercent = parseFloat(((actualUsedMemory / mem.total) * 100).toFixed(2));

    // Disk info
    const disk = await si.fsSize();
    let diskMetrics = disk && disk.length > 0 ? {
      total: disk[0].size,
      used: disk[0].used,
      free: disk[0].available,
      usedPercent: parseFloat((disk[0].use).toFixed(2))
    } : { total: 0, used: 0, free: 0, usedPercent: 0 };

    // GPU and network stats
    const gpuInfo = await getGpuDetails();
    const networkInfo = await getNetworkStats();

    // System info
    const cpuInfo = os.cpus();
    const systemInfo = {
      hostname: os.hostname(),
      platform: process.platform,
      arch: os.arch(),
      release: os.release(),
      nodeVersion: process.version,
      cpuModel: cpuInfo.length > 0 ? cpuInfo[0].model : 'Unknown'
    };

    const result = {
      cpu: {
        usage: parseFloat(overallCpuUsage.toFixed(2)),
        temperature: cpuTemperature,
        cores: {
          physical: cpuInfo.length,
          logical: cpuInfo.length
        },
        model: systemInfo.cpuModel,
        per_core: perCoreUsage,
        frequency: {
          current: cpuInfo.length > 0 ? cpuInfo[0].speed : null
        }
      },
      memory: {
        total: mem.total,
        used: actualUsedMemory,
        free: mem.free,
        available: mem.available,
        usedPercent: usedPercent,
        buffers: mem.buffers || 0,
        cached: mem.cached || 0
      },
      swap: {
        total: mem.swaptotal || 0,
        used: mem.swapused || 0,
        free: (mem.swaptotal || 0) - (mem.swapused || 0),
        usedPercent: mem.swaptotal ? parseFloat(((mem.swapused / mem.swaptotal) * 100).toFixed(2)) : 0
      },
      disk: diskMetrics,
      gpu: gpuInfo,
      network: networkInfo,
      uptime: {
        seconds: os.uptime(),
        formatted: formatUptime(os.uptime())
      },
      system: systemInfo,
      timestamp: moment().toISOString()
    };

    log.debug('Collected system metrics', 'METRICS', result);
    return result;
  } catch (err) {
    log.error(`Error getting metrics: ${err.message}`, 'METRICS', { stack: err.stack });
    return null;
  }
}

// Get process information
async function getProcesses() {
  try {
    const processes = await si.processes();
    const pids = processes.list.map(p => p.pid);
    const stats = await pidusage(pids);
    
    const result = processes.list
      .map(proc => {
        const usage = stats[proc.pid] || {};
        const totalMemory = os.totalmem();
        const cpuValue = usage.cpu || 0;
        const memValue = (usage.memory || 0) / totalMemory * 100;
        
        const uptimeSeconds = proc.started ? (Date.now() - new Date(proc.started).getTime()) / 1000 : null;
        const uptime = uptimeSeconds ? formatUptime(Math.floor(uptimeSeconds)) : null;
        
        return {
          pid: proc.pid,
          name: proc.name,
          command: proc.command,
          user: proc.user,
          started: proc.started,
          uptime: uptime,
          cpu: parseFloat(cpuValue.toFixed(2)),
          memory: parseFloat(memValue.toFixed(2)),
          memory_bytes: usage.memory || 0,
          status: proc.state,
          threads: proc.threads || 0
        };
      })
      .sort((a, b) => b.cpu - a.cpu)
      .slice(0, 10);
    
    log.debug(`Retrieved top ${result.length} processes by CPU usage`, 'PROCESSES');
    return result;
  } catch (err) {
    log.error(`Error getting processes: ${err.message}`, 'PROCESSES', { stack: err.stack });
    return [];
  }
}

// Parse log entries
function parseLogEntry(line) {
  try {
    return JSON.parse(line);
  } catch (e) {
    const match = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3}) \[(INFO|ERROR|WARN|DEBUG)\] (?:\[([^\]]+)\] )?(.+)$/);
    if (match) {
      return {
        timestamp: match[1],
        level: match[2],
        context: match[3] || 'SERVER',
        message: match[4],
        details: null
      };
    }
    return { raw: line };
  }
}

// Get logs
function getLogs(maxLogs = 100) {
  try {
    const logFiles = fs.readdirSync(logDir)
      .filter(file => file.startsWith('server-') && file.endsWith('.log'))
      .map(file => path.join(logDir, file))
      .sort((a, b) => fs.statSync(b).mtime.getTime() - fs.statSync(a).mtime.getTime());
    
    if (logFiles.length === 0) {
      return [];
    }
    
    let logs = [];
    let fileIndex = 0;
    
    while (logs.length < maxLogs && fileIndex < logFiles.length) {
      const fileData = fs.readFileSync(logFiles[fileIndex], 'utf8');
      const fileLines = fileData.split('\n')
        .filter(line => line.trim() !== '')
        .map(line => parseLogEntry(line.trim()));
      
      logs = [...fileLines, ...logs];
      fileIndex++;
    }
    
    return logs.slice(-maxLogs);
  } catch (err) {
    log.error(`Error reading logs: ${err.message}`, 'LOGS', { stack: err.stack });
    return [];
  }
}

// API Routes
app.get('/api/health', (req, res) => {
  const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
  log.info('Health check endpoint called', 'API', { request_id: requestId });
  res.json({ 
    status: 'online', 
    serverTime: new Date().toISOString(),
    request_id: requestId
  });
});

app.get('/api/metrics', async (req, res) => {
  const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
  log.info('Metrics endpoint called', 'API', { request_id: requestId });
  const data = await getMetrics();
  if (data) {
    res.json(data);
  } else {
    res.status(500).json({ error: 'Failed to get metrics', request_id: requestId });
  }
});

app.get('/api/gpu', async (req, res) => {
  const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
  log.info('GPU details endpoint called', 'API', { request_id: requestId });
  const data = await getGpuDetails();
  res.json(data);
});

app.get('/api/processes', async (req, res) => {
  const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
  log.info('Processes endpoint called', 'API', { request_id: requestId });
  const data = await getProcesses();
  res.json(data);
});

app.get('/api/logs', (req, res) => {
  const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
  const limit = parseInt(req.query.limit) || 100;
  log.info(`Logs endpoint called, requesting ${limit} entries`, 'API', { request_id: requestId });
  const data = getLogs(limit);
  res.json(data);
});

// Socket.io event handlers
io.on('connection', (socket) => {
  const clientIp = socket.handshake.address;
  const clientId = socket.id;
  log.info(`Client connected from ${clientIp} with session ID ${clientId}`, 'SOCKET');
  socket.emit('connection_status', { 
    status: 'connected', 
    serverTime: new Date().toISOString() 
  });

  socket.on('disconnect', () => {
    log.info(`Client disconnected: ${clientId}`, 'SOCKET');
  });

  socket.on('requestData', async (data) => {
    try {
      const serverId = data?.serverId;
      log.info(`Data requested for server ${serverId || 'unknown'} from client ${clientId}`, 'SOCKET');
      
      const [metrics, processes, gpu, logs] = await Promise.all([
        getMetrics(),
        getProcesses(),
        getGpuDetails(),
        getLogs()
      ]);
      
      socket.emit('metrics', metrics);
      socket.emit('processes', processes);
      socket.emit('gpu', gpu);
      socket.emit('logs', logs);
    } catch (err) {
      log.error(`Error handling data request: ${err.message}`, 'SOCKET', { stack: err.stack });
      socket.emit('error', { message: 'Failed to fetch data', error: err.message });
    }
  });

  socket.on('requestGpuDetails', async () => {
    try {
      log.info(`GPU details requested by client ${clientId}`, 'SOCKET');
      const gpuDetails = await getGpuDetails();
      socket.emit('gpuDetails', gpuDetails);
    } catch (err) {
      log.error(`Error handling GPU details request: ${err.message}`, 'SOCKET', { stack: err.stack });
      socket.emit('error', { message: 'Failed to fetch GPU details', error: err.message });
    }
  });

  socket.on('requestLogs', async (options = {}) => {
    try {
      const limit = options.limit || 100;
      log.info(`Logs requested by client ${clientId}, limit: ${limit}`, 'SOCKET');
      const logs = getLogs(limit);
      socket.emit('logs', logs);
    } catch (err) {
      log.error(`Error handling logs request: ${err.message}`, 'SOCKET', { stack: err.stack });
      socket.emit('error', { message: 'Failed to fetch logs', error: err.message });
    }
  });
});

// Express error handling middleware
app.use((err, req, res, next) => {
  log.error(err.message, 'API', { stack: err.stack });
  res.status(500).json({ error: 'Internal Server Error' });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  const systemInfo = {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    hostname: os.hostname(),
    cpus: os.cpus().length,
    memory: `${Math.round(os.totalmem() / (1024 * 1024 * 1024))} GB`,
    ip: Object.values(os.networkInterfaces())
      .flat()
      .filter(details => details.family === 'IPv4' && !details.internal)
      .map(details => details.address)[0] || 'localhost'
  };
  
  log.info(`Server started on port ${PORT}`, 'STARTUP', systemInfo);
});

// Process-level error handling
process.on('uncaughtException', (err) => {
  log.error(`Uncaught Exception: ${err.message}`, 'SYSTEM', { stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  log.error('Unhandled Rejection at:', 'SYSTEM', { reason, promise });
});

// Graceful shutdown
const shutdown = () => {
  log.info('Received shutdown signal, closing server gracefully...', 'SHUTDOWN');
  server.close(() => {
    log.info('Closed remaining connections', 'SHUTDOWN');
    process.exit(0);
  });

  setTimeout(() => {
    log.error('Forcefully shutting down after timeout', 'SHUTDOWN');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Export for testing
module.exports = { app, server };
