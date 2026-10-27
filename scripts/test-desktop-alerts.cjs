// Real popup HTML, preload and IPC; no engines, user settings or installed app.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const root = path.resolve(__dirname, '..');
if (!process.versions.electron) {
  const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clamshield-alerts-'));
  const env = { ...process.env, CLAMSHIELD_ALERT_TEST_DIR: testDir };
  delete env.ELECTRON_RUN_AS_NODE;
  const result = require('node:child_process').spawnSync(require('electron'), [__filename], {
    cwd: root, env, stdio: 'inherit', windowsHide: true, timeout: 45000
  });
  const resolved = path.resolve(testDir);
  if (path.dirname(resolved) === path.resolve(os.tmpdir()) && path.basename(resolved).startsWith('clamshield-alerts-')) {
    try { fs.rmSync(resolved, { recursive: true, force: true }); } catch {}
  }
  if (result.error) console.error(result.error.message);
  process.exit(result.status ?? 1);
}

const { app, BrowserWindow, ipcMain } = require('electron');
const ts = require('typescript');
app.on('window-all-closed', () => {});
app.setPath('userData', path.join(process.env.CLAMSHIELD_ALERT_TEST_DIR, 'profile'));
app.setPath('sessionData', path.join(process.env.CLAMSHIELD_ALERT_TEST_DIR, 'session'));
const source = fs.readFileSync(path.join(root, 'electron-main.cjs'), 'utf8');
const tree = ts.createSourceFile('electron-main.cjs', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
const functionSource = name => {
  const node = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert.ok(node, name); return node.getText(tree);
};
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate) {
  const end = Date.now() + 7000;
  while (!await predicate()) { if (Date.now() > end) throw new Error('Popup test timed out'); await delay(20); }
}

app.whenReady().then(async () => {
  const windows = [], actions = [];
  try {
    const activeAlerts = new Map();
    const context = new Function('__dirname', 'BrowserWindow', 'path', 'activeAlerts', 'dismissedAlerts', 'readAppSettings', 'getPublicAssetPath', 'trackNotification', 'attachWindowLogging',
      `${['handleThreatEvent', 'handleApiEvent', 'createAlertWindow'].map(functionSource).join('\n')}
       return { handleThreatEvent, handleApiEvent };`)(
      root, BrowserWindow, path, activeAlerts, new Set(), () => ({ playSoundOnAlert: false }), file => path.join(root, 'public', file),
      win => windows.push(win), () => {});
    let failAction = true, holdAction = false, release;
    ipcMain.handle('clamshield-alert-action', async (_event, payload) => {
      actions.push(payload);
      if (holdAction) await new Promise(resolve => release = resolve);
      return failAction ? { success: false, error: 'The file is no longer at this location. Choose Decide later to keep the detection in Results.' } : { success: true };
    });
    ipcMain.handle('clamshield-alert-log', () => ({ success: true }));
    const clam = { id: 'one', originalPath: 'D:\\Test\\sample.zip', threatName: 'Test.Signature', engine: 'ClamAV' };
    const open = async threat => {
      await context.handleThreatEvent(threat, 1234);
      const win = windows.at(-1);
      await until(async () => !win.webContents.isLoading() && await win.webContents.executeJavaScript('Boolean(document.getElementById("quarantineBtn") && window.clamshieldAlert)'));
      return win;
    };
    const win = await open(clam);
    await context.handleThreatEvent({ ...clam, detections: [clam, { engine: 'VirusTotal' }] }, 1234);
    await context.handleThreatEvent({ ...clam, id: 'duplicate-provider' }, 1234);
    assert.equal(windows.length, 1, 'one popup per file');
    await until(async () => /ClamAV \+ VirusTotal/.test(await win.webContents.executeJavaScript('document.getElementById("providers").textContent')));
    await win.webContents.executeJavaScript('document.getElementById("quarantineBtn").click()');
    await until(async () => await win.webContents.executeJavaScript('!document.getElementById("actionError").hidden && !document.getElementById("quarantineBtn").disabled'));
    const geometry = await win.webContents.executeJavaScript(`(() => {
      const message = document.getElementById('actionError'), buttons = document.querySelector('.actions');
      return { text: message.textContent, messageBottom: message.getBoundingClientRect().bottom, buttonsTop: buttons.getBoundingClientRect().top,
        buttonsBottom: buttons.getBoundingClientRect().bottom, height: innerHeight };
    })()`);
    assert.match(geometry.text, /Decide later/);
    assert.ok(geometry.messageBottom <= geometry.buttonsTop, 'failure text is visible above actions');
    assert.ok(geometry.buttonsBottom <= geometry.height, 'actions remain inside popup');
    if (process.env.CLAMSHIELD_ALERT_SCREENSHOT_DIR) {
      const directory = process.env.CLAMSHIELD_ALERT_SCREENSHOT_DIR;
      fs.mkdirSync(directory, { recursive: true });
      await win.webContents.executeJavaScript('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
      fs.writeFileSync(path.join(directory, 'threat-popup-error.png'), (await win.webContents.capturePage()).toPNG());
    }
    failAction = false;
    await win.webContents.executeJavaScript('document.getElementById("laterBtn").click()');
    await until(() => win.isDestroyed());
    assert.equal(actions.at(-1).action, 'results');
    await context.handleThreatEvent(clam, 1234);
    assert.equal(windows.length, 1, 'SSE reconnect must not reopen dismissed IDs');

    const second = await open({ ...clam, id: 'two' });
    holdAction = true;
    await second.webContents.executeJavaScript('document.getElementById("closeBtn").click(); window.dispatchEvent(new KeyboardEvent("keydown", {key:"Escape"}));');
    await until(() => Boolean(release));
    assert.equal(actions.length, 3, 'repeated dismiss events trigger one action');
    release();
    await until(() => second.isDestroyed());
    assert.equal(actions.at(-1).action, 'results', 'X retains detection in Results');
    const third = await open({ ...clam, id: 'three' });
    context.handleApiEvent('threat-resolved', { id: 'three' }, 1234);
    await until(() => third.isDestroyed());
    console.log('PASS: real Electron popup deduplication, provider updates, visible errors, retry, dismiss, IPC and resolution.');
    app.exit(0);
  } catch (error) {
    console.error(error);
    for (const win of windows) if (!win.isDestroyed()) win.destroy();
    app.exit(1);
  }
});
