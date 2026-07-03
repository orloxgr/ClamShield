const { app, BrowserWindow, Tray, Menu, nativeImage, session, shell, powerMonitor, ipcMain } = require('electron');
const path = require('path');
const { spawn, fork } = require('child_process');
const fs = require('fs');
const net = require('net');
const { randomBytes } = require('crypto');

const http = require('http');

app.commandLine.appendSwitch('autoplay-policy', 'no-user-gesture-required');

let mainWindow;
let serverProcess;
let tray = null;
let isQuiting = false;
let activeAlerts = new Map();
let primaryDisplay;
let resultsReminderWindow = null;
let scanSummaryWindow = null;
let updateAvailableWindow = null;
let debugLoggingEnabled = false;
const lastUpdateCheckAt = {};
let appUpdateChecking = false;
let scheduledScanChecking = false;
let scheduledScanRun = null;
let currentApiPort = null;
const apiSessionToken = randomBytes(32).toString('hex');
const gotSingleInstanceLock = app.requestSingleInstanceLock();

if (!gotSingleInstanceLock) {
  app.quit();
}

function apiHeaders(extra = {}) {
  return { ...extra, 'X-ClamShield-Session': apiSessionToken };
}

async function setApiSessionCookie(port) {
  await session.defaultSession.cookies.set({
    url: `http://127.0.0.1:${port}`,
    name: 'clamshield_session',
    value: apiSessionToken,
    path: '/',
    httpOnly: true,
    secure: false,
    sameSite: 'strict'
  });
}

function getProgramDataDir() {
  return process.platform === 'win32'
    ? path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'ClamShield')
    : path.join(__dirname, 'data', 'ClamShield');
}

function getLogsDir() {
  return path.join(getProgramDataDir(), 'logs');
}

function getAppStateDbPath() {
  return path.join(getProgramDataDir(), 'app_state.sqlite');
}

function logArgToString(arg) {
  if (arg instanceof Error) return arg.stack || arg.message;
  if (typeof arg === 'string') return arg;
  try {
    return JSON.stringify(arg);
  } catch {
    return String(arg);
  }
}

function writeMainLog(level, args) {
  try {
    fs.mkdirSync(getLogsDir(), { recursive: true });
    const line = `[${new Date().toISOString()}] [${String(level).toUpperCase()}] ${args.map(logArgToString).join(' ')}\n`;
    fs.appendFileSync(path.join(getLogsDir(), 'electron-main.log'), line, 'utf8');
  } catch {
    // Logging must never stop the app from launching.
  }
}

const originalConsole = {
  log: console.log.bind(console),
  warn: console.warn.bind(console),
  error: console.error.bind(console),
  debug: console.debug.bind(console)
};

console.log = (...args) => {
  originalConsole.log(...args);
  if (debugLoggingEnabled) writeMainLog('info', args);
};
console.debug = (...args) => {
  originalConsole.debug(...args);
  if (debugLoggingEnabled) writeMainLog('debug', args);
};
console.warn = (...args) => {
  originalConsole.warn(...args);
  if (debugLoggingEnabled) writeMainLog('warn', args);
};
console.error = (...args) => {
  originalConsole.error(...args);
  if (debugLoggingEnabled) writeMainLog('error', args);
};

process.on('uncaughtException', (error) => {
  writeMainLog('fatal', ['Uncaught exception', error]);
  originalConsole.error('Uncaught exception:', error);
});

process.on('unhandledRejection', (reason) => {
  writeMainLog('fatal', ['Unhandled rejection', reason]);
  originalConsole.error('Unhandled rejection:', reason);
});

function attachWindowLogging(win, label) {
  if (!win || !win.webContents) return;
  win.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL) => {
    if (debugLoggingEnabled) {
      writeMainLog('error', [`${label} failed to load`, { errorCode, errorDescription, validatedURL }]);
    }
  });
  win.webContents.on('render-process-gone', (_event, details) => {
    const crash = {
      reason: details && details.reason,
      exitCode: details && details.exitCode
    };
    if (debugLoggingEnabled) {
      try {
        crash.url = win.webContents.getURL();
        crash.title = win.getTitle();
        crash.osProcessId = win.webContents.getOSProcessId();
        crash.isVisible = win.isVisible();
        crash.isDestroyed = win.isDestroyed();
      } catch (error) {
        if (debugLoggingEnabled) writeMainLog('debug', [`${label} crash detail enrichment failed`, error]);
      }
    }
    writeMainLog('fatal', [`${label} renderer process gone`, crash]);
  });
  win.webContents.on('unresponsive', () => {
    if (debugLoggingEnabled) writeMainLog('warn', [`${label} window became unresponsive`]);
  });
  win.webContents.on('console-message', (_event, level, message, line, sourceId) => {
    const isErrorLevel = level >= 2;
    if (debugLoggingEnabled) {
      writeMainLog(isErrorLevel ? 'error' : 'debug', [`${label} console`, { message, line, sourceId }]);
    }
  });
}

function parseStoredSettingValue(value) {
  if (typeof value !== 'string') return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function sanitizeSettingsForStorage(settings) {
  const safeSettings = { ...(settings || {}) };
  delete safeSettings.securiteInfoToken;
  delete safeSettings.securiteInfoUrl;
  delete safeSettings.securiteInfoSetupText;
  return safeSettings;
}

function readSettingsFromSqlite() {
  let db = null;
  try {
    const { DatabaseSync } = require('node:sqlite');
    db = new DatabaseSync(getAppStateDbPath());
    db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    const rows = db.prepare('SELECT key, value FROM settings').all();
    if (!rows.length) return null;
    return rows.reduce((settings, row) => {
      settings[row.key] = parseStoredSettingValue(row.value);
      return settings;
    }, {});
  } catch {
    return null;
  } finally {
    try { db && db.close(); } catch {}
  }
}

function writeSettingsToSqlite(settings) {
  let db = null;
  try {
    fs.mkdirSync(getProgramDataDir(), { recursive: true });
    const { DatabaseSync } = require('node:sqlite');
    db = new DatabaseSync(getAppStateDbPath());
    db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    const safeSettings = sanitizeSettingsForStorage(settings);
    const insert = db.prepare('INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)');
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('DELETE FROM settings').run();
      for (const [key, value] of Object.entries(safeSettings)) {
        insert.run(key, JSON.stringify(value ?? null));
      }
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  } catch {
    // Startup settings are best-effort; the server owns normal persistence.
  } finally {
    try { db && db.close(); } catch {}
  }
}

function readLegacySettings() {
  try {
    const settingsPath = path.join(getProgramDataDir(), 'settings.json');
    return JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
  } catch {
    return null;
  }
}

function readAppSettings() {
  const sqliteSettings = readSettingsFromSqlite();
  const settings = sqliteSettings || readLegacySettings() || {};
  if (!sqliteSettings && Object.keys(settings).length > 0) {
    writeSettingsToSqlite(settings);
  }
  debugLoggingEnabled = settings.enableDebugLog === true;
  return settings;
}

async function handleThreatEvent(threat, port) {
  if (!threat || !threat.id || activeAlerts.has(threat.id)) return;
  activeAlerts.set(threat.id, true);
  let playSound = false;
  try {
    const status = await requestJson(port, '/api/status');
    const settings = status.settings || {};
    playSound = settings.playSoundOnAlert === true;
    debugLoggingEnabled = settings.enableDebugLog === true;
  } catch {
    // If status is temporarily unavailable, still show the threat alert.
  }
  createAlertWindow(threat, port, playSound);
}

function handleApiEvent(eventName, data, port) {
  if (eventName === 'threat') {
    handleThreatEvent(data, port).catch(error => console.warn('Failed to handle threat event', error.message));
  } else if (eventName === 'scan-summary') {
    if (data && !(scanSummaryWindow && !scanSummaryWindow.isDestroyed())) {
      createScanSummaryWindow(data, port);
    }
  } else if (eventName === 'results-reminder') {
    if (data && data.show && !(resultsReminderWindow && !resultsReminderWindow.isDestroyed())) {
      createResultsReminderWindow(data, port);
    }
  }
}

function connectApiEvents(port) {
  let retryTimer = null;
  const scheduleReconnect = () => {
    if (isQuiting || retryTimer) return;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      connectApiEvents(port);
    }, 3000);
    retryTimer.unref?.();
  };

  const req = http.request({
    hostname: '127.0.0.1',
    port,
    path: '/api/events',
    method: 'GET',
    headers: apiHeaders({ Accept: 'text/event-stream' })
  }, (res) => {
    if (res.statusCode !== 200) {
      res.resume();
      scheduleReconnect();
      return;
    }
    let buffer = '';
    res.on('data', chunk => {
      buffer += chunk.toString();
      let boundary = buffer.indexOf('\n\n');
      while (boundary !== -1) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        let eventName = 'message';
        const dataLines = [];
        for (const line of block.split('\n')) {
          if (line.startsWith(':')) continue;
          if (line.startsWith('event:')) eventName = line.slice(6).trim();
          if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
        }
        if (dataLines.length) {
          try {
            handleApiEvent(eventName, JSON.parse(dataLines.join('\n')), port);
          } catch (error) {
            console.warn('Failed to parse ClamShield event', error.message);
          }
        }
        boundary = buffer.indexOf('\n\n');
      }
    });
    res.on('end', scheduleReconnect);
    res.on('error', scheduleReconnect);
  });
  req.on('error', scheduleReconnect);
  req.end();
}

function createAlertWindow(threat, port, playSound) {
   const { screen } = require('electron');
   if(!primaryDisplay) primaryDisplay = screen.getPrimaryDisplay();
   const workArea = primaryDisplay.workArea;

   const alertWidth = 460;
   const alertHeight = 190;
   const offset = (activeAlerts.size - 1) * 210; 

   const alertWin = new BrowserWindow({
      width: alertWidth,
      height: alertHeight,
      x: workArea.x + workArea.width - alertWidth - 20,
      y: workArea.y + workArea.height - alertHeight - 20 - offset,
      frame: false,
      transparent: false,
      backgroundColor: '#0f172a',
      alwaysOnTop: true,
      skipTaskbar: true,
      resizable: false,
      title: "ClamShield Alert",
      icon: path.join(__dirname, 'public/icon.png'),
      webPreferences: {
         nodeIntegration: false,
         contextIsolation: true,
         preload: getPublicAssetPath('alert-preload.cjs')
      }
   });
   
   activeAlerts.set(threat.id, alertWin);
   attachWindowLogging(alertWin, 'Threat alert');

   alertWin.on('closed', () => {
      activeAlerts.delete(threat.id);
   });
   
   console.debug('Opening threat alert window', { threatId: threat.id, playSound });
   alertWin.loadFile(getPublicAssetPath('alert.html'), {
      query: {
         id: String(threat.id || ''),
         name: String(threat.threatName || 'Unknown threat'),
         path: String(threat.originalPath || 'Unknown path'),
         mode: String(threat.mode || 'decision'),
         title: String(threat.title || ''),
         subtitle: String(threat.subtitle || ''),
         playSound: playSound ? 'true' : 'false'
      }
   }).catch(err => {
      console.error("Failed to load alert HTML", err);
      activeAlerts.delete(threat.id);
      if (!alertWin.isDestroyed()) alertWin.close();
   });
}

function createResultsReminderWindow(reminder, port) {
   const { screen } = require('electron');
   if(!primaryDisplay) primaryDisplay = screen.getPrimaryDisplay();
   const workArea = primaryDisplay.workArea;

   resultsReminderWindow = new BrowserWindow({
      width: 440,
      height: 180,
      x: workArea.x + workArea.width - 440 - 20,
      y: workArea.y + workArea.height - 180 - 20,
      frame: false,
      transparent: false,
      backgroundColor: '#0f172a',
      alwaysOnTop: true,
      skipTaskbar: true,
      resizable: false,
      title: "ClamShield Results Reminder",
      icon: path.join(__dirname, 'public/icon.png'),
      webPreferences: {
         nodeIntegration: false,
         contextIsolation: true
      }
   });

   attachWindowLogging(resultsReminderWindow, 'Results reminder');

   resultsReminderWindow.on('closed', () => {
      resultsReminderWindow = null;
   });

   resultsReminderWindow.webContents.on('will-navigate', (event, targetUrl) => {
      if (targetUrl === `http://127.0.0.1:${port}/results`) {
         event.preventDefault();
         if (mainWindow) {
            mainWindow.show();
            mainWindow.loadURL(targetUrl).catch(err => console.error("Failed to open Results", err));
         }
         if (resultsReminderWindow && !resultsReminderWindow.isDestroyed()) {
            resultsReminderWindow.close();
         }
      }
   });

   const reminderUrl = `http://127.0.0.1:${port}/results-reminder.html?count=${encodeURIComponent(reminder.count || 0)}&port=${port}`;
   resultsReminderWindow.loadURL(reminderUrl).catch(err => console.error("Failed to load results reminder HTML", err));
}

function createScanSummaryWindow(summary, port) {
   const { screen } = require('electron');
   if(!primaryDisplay) primaryDisplay = screen.getPrimaryDisplay();
   const workArea = primaryDisplay.workArea;

   scanSummaryWindow = new BrowserWindow({
      width: 460,
      height: 205,
      x: workArea.x + workArea.width - 460 - 20,
      y: workArea.y + workArea.height - 205 - 20,
      frame: false,
      transparent: false,
      backgroundColor: '#0f172a',
      alwaysOnTop: true,
      skipTaskbar: true,
      resizable: false,
      title: "ClamShield Scan Summary",
      icon: path.join(__dirname, 'public/icon.png'),
      webPreferences: {
         nodeIntegration: false,
         contextIsolation: true
      }
   });

   attachWindowLogging(scanSummaryWindow, 'Scan summary');

   scanSummaryWindow.on('closed', () => {
      scanSummaryWindow = null;
   });

   scanSummaryWindow.webContents.on('will-navigate', (event, targetUrl) => {
      if (targetUrl === `http://127.0.0.1:${port}/results` || targetUrl === `http://127.0.0.1:${port}/quarantine`) {
         event.preventDefault();
         if (mainWindow) {
            mainWindow.show();
            mainWindow.loadURL(targetUrl).catch(err => console.error("Failed to open scan summary target", err));
         }
         if (scanSummaryWindow && !scanSummaryWindow.isDestroyed()) {
            scanSummaryWindow.close();
         }
      }
   });

   const params = new URLSearchParams({
      port: String(port),
      title: String(summary.title || 'Scan finished'),
      message: String(summary.message || ''),
      detail: String(summary.detail || ''),
      target: String(summary.target || ''),
      action: String(summary.action || 'results')
   });
   scanSummaryWindow.loadURL(`http://127.0.0.1:${port}/scan-summary.html?${params.toString()}`)
      .catch(err => console.error("Failed to load scan summary HTML", err));
}

function createUpdateAvailableWindow(update, config, port) {
   const { screen } = require('electron');
   if(!primaryDisplay) primaryDisplay = screen.getPrimaryDisplay();
   const workArea = primaryDisplay.workArea;

   if (updateAvailableWindow && !updateAvailableWindow.isDestroyed()) {
      updateAvailableWindow.close();
   }

   updateAvailableWindow = new BrowserWindow({
      width: 460,
      height: 190,
      x: workArea.x + workArea.width - 460 - 20,
      y: workArea.y + workArea.height - 190 - 20,
      frame: false,
      transparent: false,
      backgroundColor: '#0f172a',
      alwaysOnTop: true,
      skipTaskbar: true,
      resizable: false,
      title: `${config.label} Update`,
      icon: path.join(__dirname, 'public/icon.png'),
      webPreferences: {
         nodeIntegration: false,
         contextIsolation: true
      }
   });

   attachWindowLogging(updateAvailableWindow, 'Update available');

   updateAvailableWindow.on('closed', () => {
      updateAvailableWindow = null;
   });

   updateAvailableWindow.webContents.on('will-navigate', (event, targetUrl) => {
      if (targetUrl === `http://127.0.0.1:${port}/updates`) {
         event.preventDefault();
         openUpdatesTab(port);
         if (updateAvailableWindow && !updateAvailableWindow.isDestroyed()) {
            updateAvailableWindow.close();
         }
      }
   });

   const params = new URLSearchParams({
      port: String(port),
      label: String(config.label || 'ClamShield'),
      current: String(update.currentVersion || update.currentLabel || 'Unknown'),
      latest: String(update.latestVersion || 'Unknown'),
      mode: String(config.mode || 'available'),
      installPath: String(config.installPath || ''),
      skipPath: String(config.skipPath || ''),
      remindPath: String(config.remindPath || '')
   });
   updateAvailableWindow.loadURL(`http://127.0.0.1:${port}/update-available.html?${params.toString()}`).catch(err => {
      console.error("Failed to load update popup HTML", err);
      if (updateAvailableWindow && !updateAvailableWindow.isDestroyed()) {
         updateAvailableWindow.close();
      }
   });
}

function getFreePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

function requestJson(port, pathName, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: pathName,
      method,
      headers: payload ? {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        ...apiHeaders()
      } : apiHeaders()
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = data ? JSON.parse(data) : {};
          if (res.statusCode >= 400) {
            reject(new Error(parsed.error || `HTTP ${res.statusCode}`));
          } else {
            resolve(parsed);
          }
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function getPublicAssetPath(fileName) {
  return path.join(__dirname, 'public', fileName);
}

ipcMain.handle('clamshield-alert-action', async (_event, payload = {}) => {
  const threatId = String(payload.id || '');
  const action = String(payload.action || '');
  if (!currentApiPort || !threatId || !action) {
    throw new Error('The alert action is missing required data.');
  }
  return requestJson(
    currentApiPort,
    `/api/pending-threats/${encodeURIComponent(threatId)}/action`,
    'POST',
    { action }
  );
});

ipcMain.handle('clamshield-alert-log', async (_event, payload = {}) => {
  if (!currentApiPort) return { success: false };
  try {
    return await requestJson(currentApiPort, '/api/client-log', 'POST', {
      level: String(payload.level || 'error'),
      message: String(payload.message || 'Threat popup log'),
      details: payload.details || {}
    });
  } catch {
    return { success: false };
  }
});

function openUpdatesTab(port) {
  if (!mainWindow) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
  mainWindow.loadURL(`http://127.0.0.1:${port}/updates`).catch(err => console.error('Failed to open Updates', err));
}

async function checkUpdatePrompt(port, settings, config) {
  if (settings[config.enabledKey] === false) return;
  if (settings[config.notifyAvailableKey] === false) return;
  if (Number(settings[config.remindAfterKey] || 0) > Date.now()) return;
  if (config.skipWhenSilent && settings.appSilentAutoInstall === true) return;

  const intervalMs = Math.max(1, Number(settings[config.intervalKey] || config.defaultIntervalHours)) * 60 * 60 * 1000;
  if (Date.now() - Number(lastUpdateCheckAt[config.id] || 0) < intervalMs) return;
  lastUpdateCheckAt[config.id] = Date.now();

  try {
    const update = await requestJson(port, config.checkPath);
    if (!update.updateAvailable) return;
    if (updateAvailableWindow && !updateAvailableWindow.isDestroyed()) return;
    createUpdateAvailableWindow(update, config, port);
  } catch (error) {
    console.warn(`${config.label} update prompt failed`, error.message);
    if (settings[config.notifyFailedKey] === true) {
      createUpdateAvailableWindow({
        currentVersion: error.message || String(error),
        latestVersion: '',
        updateAvailable: false
      }, {
        ...config,
        mode: 'failed'
      }, port);
    }
  }
}

function pollAppUpdates(port) {
  setInterval(async () => {
    if (appUpdateChecking) return;
    appUpdateChecking = true;
    try {
      const status = await requestJson(port, '/api/status');
      const settings = status.settings || {};
      debugLoggingEnabled = settings.enableDebugLog === true;
      const updateConfigs = [
        {
          id: 'app',
          label: 'ClamShield',
          enabledKey: 'appUpdateCheckEnabled',
          notifyAvailableKey: 'appUpdateNotifyAvailable',
          notifyFailedKey: 'appUpdateNotifyFailed',
          remindAfterKey: 'appUpdateRemindAfter',
          intervalKey: 'appUpdateIntervalHours',
          defaultIntervalHours: 168,
          checkPath: '/api/app-update',
          installPath: '/api/app-update/install',
          skipPath: '/api/app-update/skip',
          remindPath: '/api/app-update/remind',
          skipWhenSilent: true
        },
        {
          id: 'clamav-engine',
          label: 'ClamAV Engine',
          enabledKey: 'clamavEngineUpdateCheckEnabled',
          notifyAvailableKey: 'clamavEngineUpdateNotifyAvailable',
          notifyFailedKey: 'clamavEngineUpdateNotifyFailed',
          remindAfterKey: 'clamavEngineRemindAfter',
          intervalKey: 'clamavEngineUpdateIntervalHours',
          defaultIntervalHours: 24,
          checkPath: '/api/clamav-engine-update',
          installPath: '/api/clamav-engine-update/install',
          skipPath: '/api/clamav-engine-update/skip',
          remindPath: '/api/clamav-engine-update/remind'
        },
        {
          id: 'yara-engine',
          label: 'YARA Engine',
          enabledKey: 'yaraEngineUpdateCheckEnabled',
          notifyAvailableKey: 'yaraEngineUpdateNotifyAvailable',
          notifyFailedKey: 'yaraEngineUpdateNotifyFailed',
          remindAfterKey: 'yaraEngineRemindAfter',
          intervalKey: 'yaraEngineUpdateIntervalHours',
          defaultIntervalHours: 24,
          checkPath: '/api/yara-engine-update',
          installPath: '/api/yara-engine-update/install',
          skipPath: '/api/yara-engine-update/skip',
          remindPath: '/api/yara-engine-update/remind'
        }
      ];
      for (const config of updateConfigs) {
        await checkUpdatePrompt(port, settings, config);
      }
    } finally {
      appUpdateChecking = false;
    }
  }, 60000);
}

function localDateKey(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function getScheduledScanTiming(settings, now) {
  const frequency = settings.scheduledScanFrequency === 'monthly' ? 'monthly' : 'weekly';
  const time = /^([01]\d|2[0-3]):[0-5]\d$/.test(settings.scheduledScanTime || '')
    ? settings.scheduledScanTime
    : '03:00';
  const [hours, minutes] = time.split(':').map(Number);
  const dueAt = new Date(now);
  dueAt.setHours(hours, minutes, 0, 0);

  if (frequency === 'monthly') {
    const monthDays = Array.isArray(settings.scheduledScanMonthDays) ? settings.scheduledScanMonthDays.map(Number) : [1];
    if (!monthDays.includes(now.getDate())) return null;
  } else {
    const weekdays = Array.isArray(settings.scheduledScanWeekdays) ? settings.scheduledScanWeekdays.map(Number) : [0];
    if (!weekdays.includes(now.getDay())) return null;
  }

  const idleThresholdSeconds = Math.max(1, Number(settings.scheduledScanIdleMinutes || 15)) * 60;
  return {
    frequency,
    time,
    dueAt,
    monitorFrom: new Date(dueAt.getTime() - idleThresholdSeconds * 1000),
    idleThresholdSeconds,
    runKey: `${frequency}:${localDateKey(now)}:${time}`
  };
}

function getScheduledRunKey(settings, now) {
  const timing = getScheduledScanTiming(settings, now);
  if (!timing || now < timing.dueAt) return null;
  return timing.runKey;
}

function buildScheduledScanQueue(settings) {
  const queue = [];
  if (settings.scheduledScanFullDisk === true) {
    queue.push({ type: 'disk', label: 'Full disk scan' });
  }
  if (settings.scheduledScanFullDisk !== true && Array.isArray(settings.scheduledScanDirectories)) {
    const seen = new Set();
    for (const directory of settings.scheduledScanDirectories) {
      const target = String(directory || '').trim();
      const key = target.toLowerCase();
      if (!target || seen.has(key)) continue;
      seen.add(key);
      queue.push({ type: 'folder', target, label: target });
    }
  }
  if (settings.scheduledScanMemory === true) {
    queue.push({ type: 'memory', label: 'Running process memory' });
  }
  return queue;
}

async function publishScheduledScanRuntime(port, payload) {
  try {
    await requestJson(port, '/api/scheduled-scan/runtime', 'POST', payload);
  } catch (error) {
    console.warn('Failed to publish scheduled scan status', error.message);
  }
}

function activeScanJobIds(status, currentJobId = '') {
  return Array.isArray(status?.activeScanJobIds)
    ? status.activeScanJobIds.filter(jobId => jobId && jobId !== currentJobId)
    : [];
}

async function publishScheduledScanWaitingForScan(port, idleSeconds, queueIndex = 0, totalTargets = 0) {
  await publishScheduledScanRuntime(port, {
    state: 'waiting-scan',
    message: 'Waiting for the current on-demand or scheduled scan to finish.',
    activeJobId: '',
    currentTarget: '',
    queueIndex,
    totalTargets,
    idleSeconds
  });
}

async function startScheduledScanTarget(port) {
  if (!scheduledScanRun || scheduledScanRun.index >= scheduledScanRun.queue.length) return false;
  const status = await requestJson(port, '/api/status');
  const idleSeconds = scheduledScanRun.idleOnly ? powerMonitor.getSystemIdleTime() : 0;
  if (activeScanJobIds(status, scheduledScanRun.jobId).length > 0) {
    await publishScheduledScanWaitingForScan(port, idleSeconds, scheduledScanRun.index + 1, scheduledScanRun.queue.length);
    return false;
  }
  const target = scheduledScanRun.queue[scheduledScanRun.index];
  let response;
  try {
    response = await requestJson(port, '/api/scan', 'POST', {
      type: target.type,
      target: target.target,
      source: 'scheduled'
    });
  } catch (error) {
    if (/another .*scan.*running/i.test(error.message || '')) {
      await publishScheduledScanWaitingForScan(port, idleSeconds, scheduledScanRun.index + 1, scheduledScanRun.queue.length);
      return false;
    }
    throw error;
  }
  scheduledScanRun.jobId = response.jobId;
  scheduledScanRun.currentTarget = target;
  await publishScheduledScanRuntime(port, {
    state: 'running',
    message: `Scanning ${target.label}`,
    activeJobId: response.jobId,
    currentTarget: target.label,
    queueIndex: scheduledScanRun.index + 1,
    totalTargets: scheduledScanRun.queue.length,
    idleSeconds
  });
  return true;
}

async function stopScheduledScan(port, reason, resultLabel) {
  if (scheduledScanRun?.jobId) {
    await requestJson(port, `/api/scan/${encodeURIComponent(scheduledScanRun.jobId)}/cancel`, 'POST', {
      discard: true,
      reason
    }).catch(error => console.warn('Failed to stop scheduled scan job', error.message));
  }
  const completedAt = new Date().toISOString();
  await publishScheduledScanRuntime(port, {
    state: 'stopped',
    message: reason,
    activeJobId: '',
    currentTarget: scheduledScanRun?.currentTarget?.label || '',
    queueIndex: scheduledScanRun ? scheduledScanRun.index + 1 : 0,
    totalTargets: scheduledScanRun?.queue?.length || 0,
    idleSeconds: scheduledScanRun?.idleOnly ? powerMonitor.getSystemIdleTime() : 0,
    lastRunAt: completedAt,
    lastResult: resultLabel,
    persist: true
  });
  scheduledScanRun = null;
}

function pollScheduledScans(port) {
  const tick = async () => {
    if (scheduledScanChecking) return;
    scheduledScanChecking = true;
    try {
      const status = await requestJson(port, '/api/status');
      const settings = status.settings || {};

      if (scheduledScanRun) {
        const idleSeconds = scheduledScanRun.idleOnly ? powerMonitor.getSystemIdleTime() : 0;
        if (settings.scheduledScanEnabled !== true) {
          await stopScheduledScan(port, 'Scheduled scanning was disabled.', 'Stopped because scheduled scanning was disabled');
          return;
        }
        const previousIdleSeconds = Number(scheduledScanRun.lastIdleSeconds || idleSeconds);
        const userActivityResumed = idleSeconds + 2 < previousIdleSeconds;
        scheduledScanRun.lastIdleSeconds = idleSeconds;
        if (settings.scheduledScanIdleOnly !== false && userActivityResumed) {
          await stopScheduledScan(port, 'User activity resumed; the scheduled scan was stopped.', 'Stopped when user activity resumed');
          return;
        }

        if (!scheduledScanRun.jobId) {
          if (scheduledScanRun.index >= scheduledScanRun.queue.length) {
            scheduledScanRun = null;
            return;
          }
          if (activeScanJobIds(status).length > 0) {
            await publishScheduledScanWaitingForScan(port, idleSeconds, scheduledScanRun.index + 1, scheduledScanRun.queue.length);
            return;
          }
          await startScheduledScanTarget(port);
          return;
        }

        const job = await requestJson(port, `/api/scan/${encodeURIComponent(scheduledScanRun.jobId)}`);
        if (job.status !== 'done') {
          await publishScheduledScanRuntime(port, {
            state: 'running',
            message: `Scanning ${scheduledScanRun.currentTarget.label}`,
            activeJobId: scheduledScanRun.jobId,
            currentTarget: scheduledScanRun.currentTarget.label,
            queueIndex: scheduledScanRun.index + 1,
            totalTargets: scheduledScanRun.queue.length,
            idleSeconds
          });
          return;
        }

        if (Number(job.result || 0) < 0) {
          await stopScheduledScan(port, 'The scheduled scan stopped because the scanner returned an error.', 'Scanner error');
          return;
        }
        if (Number(job.result || 0) === 1) scheduledScanRun.detections = true;
        scheduledScanRun.index += 1;
        scheduledScanRun.jobId = '';

        if (scheduledScanRun.index < scheduledScanRun.queue.length) return;

        const completedAt = new Date().toISOString();
        const lastResult = scheduledScanRun.detections ? 'Completed with detections' : 'Completed with no detections';
        await publishScheduledScanRuntime(port, {
          state: 'complete',
          message: lastResult,
          activeJobId: '',
          currentTarget: '',
          queueIndex: scheduledScanRun.queue.length,
          totalTargets: scheduledScanRun.queue.length,
          idleSeconds,
          lastRunAt: completedAt,
          lastResult,
          persist: true
        });
        scheduledScanRun = null;
        return;
      }

      if (settings.scheduledScanEnabled !== true) {
        if (status.scheduledScanRuntime?.state !== 'disabled') {
          await publishScheduledScanRuntime(port, {
            state: 'disabled',
            message: 'Scheduled scanning is disabled.',
            idleSeconds: 0
          });
        }
        return;
      }

      if (settings.lastScheduledScanResult === 'Running') {
        await publishScheduledScanRuntime(port, {
          state: 'stopped',
          message: 'The previous scheduled scan ended when ClamShield closed.',
          idleSeconds: 0,
          lastRunAt: new Date().toISOString(),
          lastResult: 'Interrupted when ClamShield closed',
          persist: true
        });
        return;
      }

      const now = new Date();
      const timing = getScheduledScanTiming(settings, now);
      if (!timing) {
        if (status.scheduledScanRuntime?.state === 'waiting-idle') {
          await publishScheduledScanRuntime(port, {
            state: 'idle',
            message: 'Waiting for the next scheduled scan.',
            idleSeconds: 0
          });
        }
        return;
      }

      if (settings.scheduledScanIdleOnly === false && now < timing.dueAt) {
        return;
      }

      if (settings.scheduledScanIdleOnly !== false && now < timing.monitorFrom) {
        if (status.scheduledScanRuntime?.state === 'waiting-idle') {
          await publishScheduledScanRuntime(port, {
            state: 'idle',
            message: `Inactivity monitoring starts ${Math.round(timing.idleThresholdSeconds / 60)} minutes before the scheduled scan.`,
            idleSeconds: 0
          });
        }
        return;
      }

      const idleSeconds = settings.scheduledScanIdleOnly !== false ? powerMonitor.getSystemIdleTime() : 0;
      if (settings.scheduledScanIdleOnly !== false && now < timing.dueAt) {
        const minutesUntilStart = Math.max(1, Math.ceil((timing.dueAt.getTime() - now.getTime()) / 60000));
        await publishScheduledScanRuntime(port, {
          state: 'waiting-idle',
          message: `Monitoring keyboard and mouse inactivity for the scheduled scan in ${minutesUntilStart} minute${minutesUntilStart === 1 ? '' : 's'}.`,
          idleSeconds
        });
        return;
      }

      const runKey = getScheduledRunKey(settings, now);
      if (!runKey || settings.lastScheduledScanRunKey === runKey) return;

      const queue = buildScheduledScanQueue(settings);
      if (queue.length === 0) {
        await publishScheduledScanRuntime(port, {
          state: 'error',
          message: 'The scheduled scan has no selected targets.',
          idleSeconds,
          lastRunKey: runKey,
          lastRunAt: new Date().toISOString(),
          lastResult: 'No scan targets selected',
          persist: true
        });
        return;
      }

      if (activeScanJobIds(status).length > 0) {
        await publishScheduledScanWaitingForScan(port, idleSeconds);
        return;
      }

      if (settings.scheduledScanIdleOnly !== false && idleSeconds < timing.idleThresholdSeconds) {
        const remainingMinutes = Math.max(1, Math.ceil((timing.idleThresholdSeconds - idleSeconds) / 60));
        await publishScheduledScanRuntime(port, {
          state: 'waiting-idle',
          message: `Waiting for ${remainingMinutes} more minute${remainingMinutes === 1 ? '' : 's'} of keyboard and mouse inactivity.`,
          idleSeconds
        });
        return;
      }

      scheduledScanRun = {
        runKey,
        queue,
        index: 0,
        jobId: '',
        currentTarget: null,
        detections: false,
        lastIdleSeconds: idleSeconds,
        idleOnly: settings.scheduledScanIdleOnly !== false
      };
      await publishScheduledScanRuntime(port, {
        state: 'running',
        message: 'Starting scheduled scan...',
        activeJobId: '',
        currentTarget: '',
        queueIndex: 0,
        totalTargets: queue.length,
        idleSeconds,
        lastRunKey: runKey,
        lastRunAt: new Date().toISOString(),
        lastResult: 'Running',
        persist: true
      });
      await startScheduledScanTarget(port);
    } catch (error) {
      console.warn('Scheduled scan check failed', error.message);
      if (scheduledScanRun) {
        await publishScheduledScanRuntime(port, {
          state: 'error',
          message: `Scheduled scan error: ${error.message}`,
          activeJobId: scheduledScanRun.jobId || '',
          currentTarget: scheduledScanRun.currentTarget?.label || '',
          queueIndex: scheduledScanRun.index + 1,
          totalTargets: scheduledScanRun.queue.length,
          idleSeconds: scheduledScanRun.idleOnly ? powerMonitor.getSystemIdleTime() : 0,
          lastRunAt: new Date().toISOString(),
          lastResult: `Error: ${error.message}`,
          persist: true
        });
        scheduledScanRun = null;
      }
    } finally {
      scheduledScanChecking = false;
    }
  };

  const timer = setInterval(tick, 10000);
  timer.unref?.();
  setTimeout(tick, 3000);
}

function createWindow(port, startHidden = false) {
  let rendererRecovering = false;
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    title: 'ClamShield',
    autoHideMenuBar: true,
    show: !startHidden,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    },
    icon: path.join(__dirname, 'public/icon.png')
  });
  attachWindowLogging(mainWindow, 'Main window');
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^(https?:\/\/|mailto:)/i.test(url)) {
      shell.openExternal(url).catch(error => console.warn('Failed to open external link', error.message));
    }
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, targetUrl) => {
    const localOrigin = `http://127.0.0.1:${port}`;
    if (targetUrl.startsWith(localOrigin)) return;
    event.preventDefault();
    if (/^(https?:\/\/|mailto:)/i.test(targetUrl)) {
      shell.openExternal(targetUrl).catch(error => console.warn('Failed to open external link', error.message));
    }
  });

  // Wait a moment for server to start, then load
  const loadURL = () => {
    mainWindow.loadURL(`http://127.0.0.1:${port}`).catch(() => {
      setTimeout(loadURL, 500); // Retry until server is up
    });
  };
  
  loadURL();

  mainWindow.webContents.on('render-process-gone', (_event, details) => {
    if (rendererRecovering || isQuiting || details.reason === 'clean-exit') return;
    rendererRecovering = true;
    console.warn('Main window renderer stopped; reloading UI', details);
    setTimeout(() => {
      rendererRecovering = false;
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.loadURL(`http://127.0.0.1:${port}`).catch(err => console.error("Failed to recover main window", err));
      }
    }, 1000);
  });

  mainWindow.on('close', function (event) {
    if (!isQuiting) {
      event.preventDefault();
      mainWindow.hide();
      event.returnValue = false;
    }
  });

  mainWindow.on('closed', function () {
    mainWindow = null;
  });
}

function createTray() {
  const iconExt = process.platform === 'win32' ? 'favicon.ico' : 'icon.png';
  const iconPath = path.join(__dirname, `public/${iconExt}`);
  const trayIcon = fs.existsSync(iconPath) ? nativeImage.createFromPath(iconPath) : nativeImage.createEmpty();
  
  tray = new Tray(trayIcon);
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Open ClamShield', click: () => { if (mainWindow) mainWindow.show(); } },
    { type: 'separator' },
    { label: 'Quit', click: () => {
        isQuiting = true;
        app.quit();
      } 
    }
  ]);
  tray.setToolTip('ClamShield - Windows GUI for ClamAV');
  tray.setContextMenu(contextMenu);
  
  tray.on('click', () => {
    if (mainWindow) {
      mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
    }
  });
}

function startServer(port) {

  const serverPath = path.join(__dirname, 'dist/server.cjs');
  const serverDevPath = path.join(__dirname, 'server.ts');

  try {
    if (fs.existsSync(serverPath)) {
      // Production build (run directly in main process)
      process.env.PORT = port.toString();
      process.env.NODE_ENV = 'production';
      process.env.CLAMSHIELD_API_TOKEN = apiSessionToken;
      require(serverPath);
      serverProcess = { kill: () => {} }; // dummy object to maintain compatibility
    } else {
      // Fallback to dev server
      serverProcess = spawn(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['tsx', `"${serverDevPath}"`], {
        cwd: __dirname,
        env: { ...process.env, PORT: port.toString(), CLAMSHIELD_API_TOKEN: apiSessionToken },
        shell: true
      });
    }

    if (serverProcess && serverProcess.stdout && typeof serverProcess.stdout.on === 'function') {
      serverProcess.stdout.on('data', (data) => console.log(`Server: ${data}`));
    }
    if (serverProcess && serverProcess.stderr && typeof serverProcess.stderr.on === 'function') {
      serverProcess.stderr.on('data', (data) => console.error(`Server Error: ${data}`));
    }
  } catch (err) {
    console.error("Failed to start server:", err);
  }
}

app.on('ready', async () => {
  if (!gotSingleInstanceLock) return;
  const port = await getFreePort();
  currentApiPort = port;
  const settings = readAppSettings();
  const startHidden = process.argv.includes('--minimized') || settings.startMinimized === true;
  writeMainLog('info', ['ClamShield Electron ready', { port, startHidden, argv: process.argv, version: app.getVersion() }]);
  console.log('ClamShield Electron starting', { port, startHidden, debugLoggingEnabled });
  await setApiSessionCookie(port);
  startServer(port);
  writeMainLog('info', ['ClamShield backend process requested', { port }]);
  createTray();
  createWindow(port, startHidden);
  connectApiEvents(port);
  pollAppUpdates(port);
  pollScheduledScans(port);
});

app.on('second-instance', () => {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (!mainWindow.isVisible()) mainWindow.show();
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.focus();
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    if (serverProcess) serverProcess.kill();
    app.quit();
  }
});

app.on('activate', function () {
  if (mainWindow === null) {
    // Note: getFreePort should ideally be reused, but here we just pass the existing process.env.PORT
    createWindow(process.env.PORT || 3000);
  }
});

app.on('before-quit', () => {
    if (serverProcess) serverProcess.kill();
});
