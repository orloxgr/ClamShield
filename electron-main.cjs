const { app, BrowserWindow, Tray, Menu, nativeImage, dialog, session } = require('electron');
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
let debugLoggingEnabled = false;
let appUpdatePromptVersion = null;
let lastAppUpdateCheckAt = 0;
let appUpdateChecking = false;
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

function readAppSettings() {
  try {
    const settingsPath = path.join(getProgramDataDir(), 'settings.json');
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    debugLoggingEnabled = settings.enableDebugLog === true;
    return settings;
  } catch {
    debugLoggingEnabled = false;
    return {};
  }
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
    if (settings.shieldShowPopup === false) {
      activeAlerts.delete(threat.id);
      return;
    }
  } catch {
    // If status is temporarily unavailable, still show the threat alert.
  }
  createAlertWindow(threat, port, playSound);
}

function handleApiEvent(eventName, data, port) {
  if (eventName === 'threat') {
    handleThreatEvent(data, port).catch(error => console.warn('Failed to handle threat event', error.message));
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
         contextIsolation: true
      }
   });
   
   activeAlerts.set(threat.id, alertWin);
   attachWindowLogging(alertWin, 'Threat alert');

   alertWin.on('closed', () => {
      activeAlerts.delete(threat.id);
   });
   
   const alertUrl = `http://127.0.0.1:${port}/alert.html?id=${encodeURIComponent(threat.id)}&name=${encodeURIComponent(threat.threatName)}&path=${encodeURIComponent(threat.originalPath)}&port=${port}&playSound=${playSound}`;
   
   console.debug('Opening threat alert window', { threatId: threat.id, playSound });
   alertWin.loadURL(alertUrl).catch(err => console.error("Failed to load alert HTML", err));
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

function pollAppUpdates(port) {
  setInterval(async () => {
    if (appUpdateChecking) return;
    appUpdateChecking = true;
    try {
      const status = await requestJson(port, '/api/status');
      const settings = status.settings || {};
      debugLoggingEnabled = settings.enableDebugLog === true;
      if (settings.appUpdateCheckEnabled === false) return;
      if (settings.appSilentAutoInstall === true) return;
      const intervalMs = Math.max(1, Number(settings.appUpdateIntervalHours || 168)) * 60 * 60 * 1000;
      if (Date.now() - lastAppUpdateCheckAt < intervalMs) return;
      lastAppUpdateCheckAt = Date.now();

      const update = await requestJson(port, '/api/app-update');
      if (!update.updateAvailable || appUpdatePromptVersion === update.latestVersion) return;
      appUpdatePromptVersion = update.latestVersion;

      const choice = dialog.showMessageBoxSync(mainWindow || undefined, {
        type: 'info',
        title: 'ClamShield Update Available',
        message: `ClamShield ${update.latestVersion} is available.`,
        detail: `Installed version: ${update.currentVersion}\nLatest version: ${update.latestVersion}`,
        buttons: ['Install', 'Skip this version', 'Disable update checks', 'Later'],
        defaultId: 0,
        cancelId: 3
      });

      if (choice === 0) {
        await requestJson(port, '/api/app-update/install', 'POST');
      } else if (choice === 1) {
        await requestJson(port, '/api/app-update/skip', 'POST', { version: update.latestVersion });
      } else if (choice === 2) {
        await requestJson(port, '/api/app-update/disable', 'POST');
      } else {
        appUpdatePromptVersion = null;
      }
    } catch (error) {
      console.warn('ClamShield update prompt failed', error.message);
    } finally {
      appUpdateChecking = false;
    }
  }, 60000);
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
