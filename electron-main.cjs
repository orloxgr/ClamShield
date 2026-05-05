const { app, BrowserWindow, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

let mainWindow;
let serverProcess;
let tray = null;
let isQuiting = false;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    },
    icon: path.join(__dirname, 'public/icon.png')
  });

  // Wait a moment for server to start, then load
  const loadURL = () => {
    mainWindow.loadURL('http://127.0.0.1:3000').catch(() => {
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
  const iconPath = path.join(__dirname, 'public/icon.png');
  // Fallback to empty nativeImage if icon is missing to avoid crashing
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
  tray.setToolTip('ClamShield Antivirus');
  tray.setContextMenu(contextMenu);
  
  tray.on('click', () => {
    if (mainWindow) {
      mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
    }
  });
}

function startServer() {

  const serverPath = path.join(__dirname, 'dist/server.cjs');
  const serverDevPath = path.join(__dirname, 'server.ts');

  if (fs.existsSync(serverPath)) {
    // Production build (avoids shell escaping issues with spaces in paths)
    serverProcess = spawn('node', [serverPath], {
      cwd: __dirname,
      env: { ...process.env, PORT: '3000', NODE_ENV: 'production' }
    });
  } else {
    // Fallback to dev server
    serverProcess = spawn(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['tsx', `"${serverDevPath}"`], {
      cwd: __dirname,
      env: { ...process.env, PORT: '3000' },
      shell: true
    });
  }

  serverProcess.stdout.on('data', (data) => console.log(`Server: ${data}`));
  serverProcess.stderr.on('data', (data) => console.error(`Server Error: ${data}`));
}

app.on('ready', () => {
  startServer();
  createWindow();
  createTray();
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    if (serverProcess) serverProcess.kill();
    app.quit();
  }
});

app.on('activate', function () {
  if (mainWindow === null) {
    createWindow();
  }
});

app.on('before-quit', () => {
    if (serverProcess) serverProcess.kill();
});
