// Exercises the real Electron navigation events, preload IPC and React mount.
// No ClamShield backend, engines, installed app or user settings are started.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const root = path.resolve(__dirname, '..');

if (!process.versions.electron) {
  const { spawnSync } = require('node:child_process');
  const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clamshield-navigation-'));
  const env = { ...process.env, CLAMSHIELD_DESKTOP_TEST_DIR: testDir };
  delete env.ELECTRON_RUN_AS_NODE;
  const result = spawnSync(require('electron'), [__filename], { cwd: root, env, stdio: 'inherit', windowsHide: true, timeout: 90000 });
  const resolved = path.resolve(testDir);
  if (path.dirname(resolved) === path.resolve(os.tmpdir()) && path.basename(resolved).startsWith('clamshield-navigation-')) {
    try { fs.rmSync(resolved, { recursive: true, force: true }); } catch {}
  }
  if (result.error) console.error(result.error.message);
  process.exit(result.status ?? 1);
}

const { app, BrowserWindow, ipcMain } = require('electron');
const http = require('node:http');
const ts = require('typescript');
const { buildSync } = require('esbuild');
app.setPath('userData', path.join(process.env.CLAMSHIELD_DESKTOP_TEST_DIR, 'profile'));
app.setPath('sessionData', path.join(process.env.CLAMSHIELD_DESKTOP_TEST_DIR, 'session'));
const source = fs.readFileSync(path.join(root, 'electron-main.cjs'), 'utf8');
const tree = ts.createSourceFile('electron-main.cjs', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
const functions = ['trustedMainSender', 'markWindowUiReady', 'verifyWindowStartup', 'attachWindowLogging'].map(name => {
  const node = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert.ok(node, name); return node.getText(tree);
}).join('\n');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate, timeout = 7000) {
  const end = Date.now() + timeout;
  while (!predicate()) { if (Date.now() >= end) throw new Error('Timed out waiting for the real React readiness handshake'); await delay(20); }
}

app.whenReady().then(async () => {
  let win, server;
  try {
    const bundle = buildSync({ stdin: { contents: `
      import React, { useEffect } from 'react';
      import { createRoot } from 'react-dom/client';
      import { BrowserRouter, useNavigate, useLocation } from 'react-router-dom';
      import UiErrorBoundary from './src/components/UiErrorBoundary';
      function Fixture() {
        const navigate = useNavigate(); const location = useLocation();
        useEffect(() => { window.fixtureNavigate = navigate; }, [navigate]);
        return <main>Working interface: {location.pathname}</main>;
      }
      createRoot(document.getElementById('root')).render(<UiErrorBoundary><BrowserRouter><Fixture/></BrowserRouter></UiErrorBoundary>);
    `, loader: 'tsx', resolveDir: root }, bundle: true, write: false, format: 'iife', define: { 'process.env.NODE_ENV': '"production"' } }).outputFiles[0].text;
    server = http.createServer((req, res) => {
      if (req.url === '/app.js') { res.writeHead(200, { 'Content-Type': 'text/javascript' }); res.end(bundle); }
      else { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(`<html><body><div id="root"><div class="startup-shell">Starting…</div></div>${req.url === '/empty' ? '' : '<script src="/app.js"></script>'}</body></html>`); }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port, origin = `http://127.0.0.1:${port}`;
    const failures = [], logs = [];
    win = new BrowserWindow({ show: false, webPreferences: { contextIsolation: true, nodeIntegration: false, preload: path.join(root, 'public/desktop-preload.cjs') } });
    // Native Electron objects must remain in their original JavaScript realm.
    const context = new Function('mainWindow', 'currentApiPort', 'URL', 'require', 'windowDiagnostics', 'debugLoggingEnabled', 'getPublicAssetPath', 'writeMainLog', 'showWindowFailure',
      `const {englishText,t,localizeText}=require(require('node:path').resolve('public/desktop-localization.cjs'));\n${functions}\nreturn { markWindowUiReady, verifyWindowStartup, attachWindowLogging };`)(
      win, port, URL, require, new WeakMap(), true, file => path.join(root, 'public', file),
      (...args) => logs.push(args), (_win, failure) => failures.push(failure));
    let acknowledgements = 0;
    ipcMain.handle('clamshield-ui-ready', event => { const ready = context.markWindowUiReady(event); acknowledgements++; return ready; });
    ipcMain.handle('clamshield-ui-error', (_event, failure) => { failures.push(failure); });
    context.attachWindowLogging(win, 'Main window');
    await win.loadURL(origin);
    await until(() => win.uiMounted && acknowledgements === 1);
    const generation = win.uiDocumentGeneration;
    assert.equal(await win.webContents.executeJavaScript('document.documentElement.dataset.clamshieldUiReady'), 'true');
    for (const route of ['/results', '/', '/exceptions']) {
      await win.webContents.executeJavaScript(`window.fixtureNavigate(${JSON.stringify(route)})`);
      assert.equal(win.uiMounted, true, `readiness after ${route}`);
      assert.equal(win.uiDocumentGeneration, generation, 'SPA navigation must keep the same document');
    }
    console.log('PASS: real Electron IPC acknowledged the React mount; SPA routes kept readiness. Waiting past the former 30-second failure point…');
    await delay(32000);
    assert.equal(failures.length, 0, JSON.stringify(failures));
    assert.ok((await win.webContents.executeJavaScript('document.body.innerText')).includes('Working interface: /exceptions'));
    console.log('PASS: working interface remains visible after 32 seconds.');
    await win.loadURL(origin);
    await until(() => win.uiMounted && acknowledgements === 2);
    assert.ok(win.uiDocumentGeneration > generation, 'full reload starts a new document');
    win.uiMounted = false;
    await context.verifyWindowStartup(win, win.uiDocumentGeneration, origin);
    assert.equal(win.uiMounted, true, 'DOM confirmation protects a rendered interface even without IPC');
    assert.equal(failures.length, 0);
    await win.loadURL(origin + '/empty');
    await context.verifyWindowStartup(win, win.uiDocumentGeneration, origin + '/empty');
    assert.equal(failures.length, 1);
    assert.equal(failures[0].code, 'UI_START_TIMEOUT');
    console.log('PASS: full reload, DOM fallback and a genuinely unmounted page behave correctly.');
    clearTimeout(win.uiReadyTimer);
    win.destroy(); server.close(); app.exit(0);
  } catch (error) {
    console.error(error);
    if (win && !win.isDestroyed()) { clearTimeout(win.uiReadyTimer); win.destroy(); }
    server?.close(); app.exit(1);
  }
});
