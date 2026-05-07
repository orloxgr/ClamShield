const { app, BrowserWindow, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const { spawn, fork } = require('child_process');
const fs = require('fs');
const net = require('net');

const http = require('http');

app.commandLine.appendSwitch('autoplay-policy', 'no-user-gesture-required');

let mainWindow;
let serverProcess;
let tray = null;
let isQuiting = false;
let activeAlerts = new Map();
let primaryDisplay;
let resultsReminderWindow = null;

function getProgramDataDir() {
  return process.platform === 'win32'
    ? path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'ClamShield')
    : path.join(__dirname, 'data', 'ClamShield');
}

function readAppSettings() {
  try {
    const settingsPath = path.join(getProgramDataDir(), 'settings.json');
    return JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
  } catch {
    return {};
  }
}

function pollThreats(port) {
  setInterval(() => {
    http.get(`http://127.0.0.1:${port}/api/pending-threats`, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const threats = JSON.parse(data);
          if (Array.isArray(threats)) {
            threats.forEach(threat => {
               if (!activeAlerts.has(threat.id)) {
                  activeAlerts.set(threat.id, true); // Placeholder to avoid double triggers
                  http.get(`http://127.0.0.1:${port}/api/status`, (setRes) => {
                     let setData = '';
                     setRes.on('data', c => setData += c);
                     setRes.on('end', () => {
                        let playSound = false;
                        try {
                           const s = JSON.parse(setData);
                           playSound = s.settings.playSoundOnAlert !== false; // Default to true if undefined
                           if (s.settings.shieldShowPopup === false) {
                              activeAlerts.delete(threat.id);
                              return;
                           }
                        } catch(e) {}
                        createAlertWindow(threat, port, playSound);
                     });
                  }).on('error', () => {
                     createAlertWindow(threat, port, true);
                  });
               }
            });
          }
        } catch (e) {}
      });
    }).on('error', () => {});
  }, 2000);
}

function createAlertWindow(threat, port, playSound) {
   const { screen, shell } = require('electron');
   if(!primaryDisplay) primaryDisplay = screen.getPrimaryDisplay();
   const workArea = primaryDisplay.workArea;
   
   if (playSound) shell.beep();

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

   alertWin.on('closed', () => {
      activeAlerts.delete(threat.id);
   });
   
   const alertUrl = `http://127.0.0.1:${port}/alert.html?id=${encodeURIComponent(threat.id)}&name=${encodeURIComponent(threat.threatName)}&path=${encodeURIComponent(threat.originalPath)}&port=${port}&playSound=${playSound}`;
   
   alertWin.loadURL(alertUrl).catch(err => console.error("Failed to load alert HTML", err));
}

function pollResultsReminder(port) {
  setInterval(() => {
    if (resultsReminderWindow && !resultsReminderWindow.isDestroyed()) return;
    http.get(`http://127.0.0.1:${port}/api/results-reminder`, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const reminder = JSON.parse(data);
          if (reminder && reminder.show) {
            createResultsReminderWindow(reminder, port);
          }
        } catch (e) {}
      });
    }).on('error', () => {});
  }, 30000);
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

function createWindow(port, startHidden = false) {
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

  // Wait a moment for server to start, then load
  const loadURL = () => {
    mainWindow.loadURL(`http://127.0.0.1:${port}`).catch(() => {
      setTimeout(loadURL, 500); // Retry until server is up
    });
  };
  
  loadURL();

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
      require(serverPath);
      serverProcess = { kill: () => {} }; // dummy object to maintain compatibility
    } else {
      // Fallback to dev server
      serverProcess = spawn(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['tsx', `"${serverDevPath}"`], {
        cwd: __dirname,
        env: { ...process.env, PORT: port.toString() },
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
  const port = await getFreePort();
  const settings = readAppSettings();
  const startHidden = process.argv.includes('--minimized') || settings.startMinimized === true;
  startServer(port);
  createTray();
  createWindow(port, startHidden);
  pollThreats(port);
  pollResultsReminder(port);
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
