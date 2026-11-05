// Real React/Electron renderer against fixtures. Never connects to the installed app.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const root = path.resolve(__dirname, '..');
if (!process.versions.electron) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clamshield-provider-ui-'));
  const env = { ...process.env, CLAMSHIELD_PROVIDER_UI_DIR: directory }; delete env.ELECTRON_RUN_AS_NODE;
  const run = require('node:child_process').spawnSync(require('electron'), [__filename], { cwd: root, env, windowsHide: true, stdio: 'inherit', timeout: 60000 });
  // Keep this temporary fixture directory: it contains screenshots for visual review.
  console.log('Provider settings screenshots:', directory);
  if (run.error) console.error(run.error.message);
  process.exit(run.status ?? 1);
}
const { app, BrowserWindow, ipcMain } = require('electron');
const http = require('node:http');
const { buildSync } = require('esbuild');
const runtime = require('../public/localization-runtime.cjs');
const profile = process.env.CLAMSHIELD_PROVIDER_UI_DIR;
app.setPath('userData', path.join(profile, 'profile'));
app.setPath('sessionData', path.join(profile, 'session'));
app.on('window-all-closed', () => {});
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate, label) { const deadline = Date.now() + 8000; while (!await predicate()) { if (Date.now() > deadline) throw new Error('Timed out: ' + label); await pause(30); } }
app.whenReady().then(async () => {
  let server, win; const requests = [], errors = [];
  const settings = { languageCode: 'en', eulaAccepted: true, shieldEnabled: true, yaraEnabled: true };
  const status = { settings, stats: {}, hasEngine: true, hasDb: true, virusTotalCloud: {},
    securiteInfo: { connected: true, plan: 'paid', installedCount: 4, expectedCount: 4, selectedDatabases: ['securiteinfo.ign2', 'securiteinfoold.hdb', 'javascript.ndb', 'securiteinfo.yara'] }, saneSecurity: {} };
  let language = runtime.englishPack;
  try {
    const bundle = buildSync({ stdin: { contents: `import React from 'react';import {createRoot} from 'react-dom/client';import App from './src/App';import {applyLanguage} from './src/lib/i18n';window.fixtureLanguage=applyLanguage;window.fixtureErrors=[];window.addEventListener('error',e=>window.fixtureErrors.push(e.message));createRoot(document.getElementById('root')).render(<App/>);`, resolveDir: root, loader: 'tsx' }, bundle: true, write: false, format: 'iife', define: { 'process.env.NODE_ENV': '"production"' } }).outputFiles[0].text;
    const css = fs.readdirSync(path.join(root, 'dist/assets')).find(file => file.endsWith('.css'));
    server = http.createServer(async (req, res) => {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/bundle.js') { res.setHeader('Content-Type', 'text/javascript'); return res.end(bundle); }
      if (url.pathname === '/style.css') { res.setHeader('Content-Type', 'text/css'); return res.end(fs.readFileSync(path.join(root, 'dist/assets', css))); }
      if (url.pathname.startsWith('/api/')) {
        res.setHeader('Content-Type', 'application/json'); let body = { items: [], total: 0, profiles: [] };
        if (req.method === 'POST') { let raw = ''; for await (const chunk of req) raw += chunk; const parsed = JSON.parse(raw || '{}'); requests.push({ url: url.pathname, body: parsed });
          if (url.pathname.endsWith('/configure')) { const key = url.pathname.includes('securiteinfo') ? 'securiteInfo' : 'saneSecurity'; status[key] = { ...status[key], connected: true, selectedDatabases: parsed.databases, expectedCount: parsed.databases.length }; }
          if (url.pathname === '/api/settings') {
            if (parsed.virusTotalShieldPopupMinDetections === 8) { res.statusCode = 500; return res.end(JSON.stringify({error:'Fixture settings write failed'})); }
            Object.assign(settings, parsed);
          }
        }
        if (url.pathname === '/api/status') body = status;
        if (url.pathname === '/api/languages/current') body = language;
        return res.end(JSON.stringify(body));
      }
      res.setHeader('Content-Type', 'text/html'); res.end('<html><head><link rel="stylesheet" href="/style.css"></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = 'http://127.0.0.1:' + server.address().port;
    win = new BrowserWindow({ show: false, width: 1180, height: 840, webPreferences: { contextIsolation: true, nodeIntegration: false } });
    win.webContents.on('render-process-gone', (_e, value) => errors.push(value));
    const js = code => win.webContents.executeJavaScript(code);
    const click = text => js(`(()=>{const b=[...document.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)});if(!b)throw Error('Missing button: '+${JSON.stringify(text)});b.click();})()`);
    const snapshot = () => js(`(()=>{const d=document.querySelector('[role=dialog]');return {files:[...d.querySelectorAll('input[type=checkbox]')].map(b=>b.getAttribute('aria-label')),checked:[...d.querySelectorAll('input[type=checkbox]:checked')].map(b=>b.getAttribute('aria-label')),overflow:d.scrollWidth>d.clientWidth,footerVisible:d.querySelector('footer').getBoundingClientRect().bottom<=innerHeight};})()`);
    await win.loadURL(origin + '/');
    await until(() => js(`Boolean(document.querySelector('button[aria-label="Manage SecuriteInfo"]'))`), 'dashboard provider');
    await js(`document.querySelector('button[aria-label="Manage SecuriteInfo"]').click()`);
    await until(() => js(`Boolean(document.querySelector('[role=dialog]'))`), 'dashboard dialog');
    const dashboard = await snapshot(); assert.equal(dashboard.files.length, 15); assert.equal(dashboard.checked.length, 4); assert.equal(dashboard.overflow, false); assert.equal(dashboard.footerVisible, true);
    await js(`document.querySelector('input[aria-label="javascript.ndb"]').click()`);
    await click('Save'); await until(() => requests.some(r => r.url === '/api/securiteinfo/configure'), 'save selection');
    assert.deepEqual(requests.at(-1).body.databases, ['securiteinfo.ign2', 'securiteinfoold.hdb', 'securiteinfo.yara']);
    assert.ok(!requests.some(r => r.url === '/api/update'));
    await win.loadURL(origin + '/updates');
    await until(() => js(`Boolean([...document.querySelectorAll('h3')].find(n=>n.textContent==='SecuriteInfo Signatures'))`), 'updates');
    await js(`[...document.querySelectorAll('h3')].find(n=>n.textContent==='SecuriteInfo Signatures').closest('section').querySelector('button').click()`);
    await click('Manage SecuriteInfo');
    await until(() => js(`Boolean(document.querySelector('[role=dialog]'))`), 'updates dialog');
    assert.deepEqual((await snapshot()).files, dashboard.files); assert.equal((await snapshot()).checked.length, 3);
    language = JSON.parse(fs.readFileSync(path.join(root, 'languages/el.json'), 'utf8'));
    await js(`window.fixtureLanguage(${JSON.stringify(language)})`); await pause(100);
    win.setSize(940, 740); await pause(100);
    assert.equal((await snapshot()).overflow, false); assert.equal((await snapshot()).footerVisible, true);
    fs.writeFileSync(path.join(profile, 'securiteinfo-greek.png'), (await win.webContents.capturePage()).toPNG());
    await js(`window.fixtureLanguage(${JSON.stringify(runtime.englishPack)})`);
    await js(`document.querySelector('[role=dialog] header button').click()`);
    await js(`[...document.querySelectorAll('h3')].find(n=>n.textContent==='SaneSecurity Signatures').closest('section').querySelector('button').click()`);
    await click('Manage SaneSecurity');
    await until(() => js(`Boolean(document.querySelector('[role=dialog]'))`), 'SaneSecurity dialog');
    assert.equal((await snapshot()).files.length, 20); assert.equal((await snapshot()).checked.length, 20);
    await click('Deselect all databases'); assert.equal((await snapshot()).checked.length, 0);
    await click('Save'); await until(() => requests.some(r => r.url === '/api/sanesecurity/configure'), 'empty selection');
    assert.deepEqual(requests.at(-1).body.databases, []);
    fs.writeFileSync(path.join(profile, 'sanesecurity.png'), (await win.webContents.capturePage()).toPNG());
    assert.equal((await snapshot()).overflow, false); assert.equal((await snapshot()).footerVisible, true);
    await win.loadURL(origin + '/shield');
    await until(() => js(`Boolean(document.getElementById('vt-shield-popup-threshold'))`), 'VT popup threshold');
    assert.deepEqual(await js(`(()=>{const r=document.getElementById('vt-shield-popup-threshold');return {min:r.min,max:r.max,value:r.value}})()`), {min:'1',max:'20',value:'4'});
    await js(`(()=>{const r=document.getElementById('vt-shield-popup-threshold');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(r,'7');r.dispatchEvent(new Event('input',{bubbles:true}));r.dispatchEvent(new Event('change',{bubbles:true}));})()`);
    await until(() => requests.some(r => r.url === '/api/settings' && r.body.virusTotalShieldPopupMinDetections === 7), 'save VT popup threshold');
    assert.deepEqual(requests.at(-1).body, {virusTotalShieldPopupMinDetections:7});
    await js(`(()=>{const r=document.getElementById('vt-shield-popup-threshold');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(r,'8');r.dispatchEvent(new Event('input',{bubbles:true}));})()`);
    await until(() => js(`document.body.textContent.includes('Fixture settings write failed') && document.getElementById('vt-shield-popup-threshold').value==='7'`), 'failed preference save stays visible and rolls back');
    assert.deepEqual(await js('window.fixtureErrors'), []); assert.deepEqual(errors, []);
    console.log('Provider settings UI passed: shared entry points, descriptions, preserved choices, all defaults, empty selection, Greek layout, visible footer, VT slider bounds/default, saved preference and visible save failure with rollback.');
  } finally { if (win && !win.isDestroyed()) win.destroy(); if (server) await new Promise(resolve => server.close(resolve)); app.quit(); }
}).catch(error => { console.error(error); app.exit(1); });
