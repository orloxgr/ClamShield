// Real renderer/native windows against local fixtures; no engines or user data.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const root = path.resolve(__dirname, '..');
if (!process.versions.electron) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clamshield-i18n-ui-'));
  const env = { ...process.env, CLAMSHIELD_I18N_TEST_DIR: directory }; delete env.ELECTRON_RUN_AS_NODE;
  const result = require('node:child_process').spawnSync(require('electron'), [__filename], { cwd: root, env, windowsHide: true, stdio: 'inherit', timeout: 90000 });
  if (path.dirname(directory) === os.tmpdir() && path.basename(directory).startsWith('clamshield-i18n-ui-')) fs.rmSync(directory, { recursive: true, force: true });
  if (result.error) console.error(result.error.message);
  process.exit(result.status ?? 1);
}
const { app, BrowserWindow, ipcMain } = require('electron');
const http = require('node:http');
const ts = require('typescript');
const { buildSync } = require('esbuild');
const runtime = require('../public/localization-runtime.cjs');
const english = runtime.englishPack;
const packs = Object.fromEntries(fs.readdirSync(path.join(root, 'languages')).filter(name => name.endsWith('.json') && name !== 'template.json').map(name => {
  const pack = runtime.validateLanguagePack(JSON.parse(fs.readFileSync(path.join(root, 'languages', name), 'utf8')));
  return [pack.language.code, pack];
}));
const spanish = packs.es;
const vocabulary = { Dashboard: 'Panel', Shield: 'Escudo', 'Real-Time Shield': 'Escudo en tiempo real', 'On-Demand Scan': 'Análisis manual', 'Scheduled Scanner': 'Análisis programado', Results: 'Resultados', Exceptions: 'Excepciones', Quarantine: 'Cuarentena', 'DNS Protection': 'Protección DNS', Updates: 'Actualizaciones', History: 'Historial', Settings: 'Ajustes', Language: 'Idioma', 'Add file': 'Añadir archivo', 'Add folder': 'Añadir carpeta', 'Report false positive': 'Informar falso positivo' };
runtime.validateLanguagePack(spanish);
const maximum = structuredClone(english); maximum.language = { code: 'de', name: 'Layout test', direction: 'ltr' };
for (const entry of Object.values(maximum.strings)) {
  entry.translation = entry.english.replace(/\{\{\w+\}\}|[aeiou]/g, value => value.startsWith('{{') ? value : ({ a: 'á', e: 'ë', i: 'í', o: 'ó', u: 'ú' })[value]);
  entry.translation += 'W'.repeat(entry.maxChars - Array.from(entry.translation).length);
}
runtime.validateLanguagePack(maximum);
const evil = structuredClone(spanish);
const dashboardKey = Object.keys(evil.strings).find(key => evil.strings[key].english === 'Dashboard');
evil.strings[dashboardKey].translation = '<img src=x onerror=x=1>';
runtime.validateLanguagePack(evil);
const settings = { languageCode: 'en', eulaAccepted: true, yaraEnabled: true, shieldEnabled: true, customWatchedFolders: [], watchedFolders: {}, scheduledScanEnabled: false, scheduledScanDirectories: [], scheduledScanWeekdays: [1], scheduledScanMonthDays: [1], scheduledScanTime: '12:00', scheduledScanFrequency: 'weekly' };
const status = { appVersion: 'fixture', settings, hasEngine: true, hasDb: true, hasYaraEngine: true, hasYaraRules: true, stats: {}, virusTotalCloud: { enabled: false }, securiteInfo: {}, saneSecurity: {} };
app.setPath('userData', path.join(process.env.CLAMSHIELD_I18N_TEST_DIR, 'profile'));
app.setPath('sessionData', path.join(process.env.CLAMSHIELD_I18N_TEST_DIR, 'session'));
app.on('window-all-closed', () => {});
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate, label) { const end = Date.now() + 9000; while (!await predicate()) { if (Date.now() > end) throw new Error('Timed out: ' + label); await pause(25); } }
app.whenReady().then(async () => {
  let win, server; const popups = [], failures = [], requests = []; let selected = english;
  try {
    const bundle = buildSync({ stdin: { contents: `import React from 'react';import {createRoot} from 'react-dom/client';import App from './src/App';import {applyLanguage,initializeLanguage} from './src/lib/i18n';window.fixtureApply=applyLanguage;window.fixtureErrors=[];window.addEventListener('error',e=>window.fixtureErrors.push(e.message));void initializeLanguage();createRoot(document.getElementById('root')).render(<App/>);`, resolveDir: root, loader: 'tsx' }, bundle: true, write: false, format: 'iife', define: { 'process.env.NODE_ENV': '"production"' } }).outputFiles[0].text;
    const cssName = fs.readdirSync(path.join(root, 'dist/assets')).find(name => name.endsWith('.css'));
    server = http.createServer(async (req, res) => {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/bundle.js') { res.setHeader('Content-Type', 'text/javascript'); return res.end(bundle); }
      if (url.pathname === '/style.css') { res.setHeader('Content-Type', 'text/css'); return res.end(fs.readFileSync(path.join(root, 'dist/assets', cssName))); }
      if (url.pathname.startsWith('/fixture/')) { res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({ '/fixture/max': maximum, '/fixture/evil': evil, '/fixture/english': english }[url.pathname])); }
      const asset = path.basename(url.pathname);
      const allowed = ['alert.html', 'scan-summary.html', 'results-reminder.html', 'update-available.html', 'startup.html', 'startup.css', 'shield.svg', 'localization-browser.js', 'localize-page.js'];
      if (allowed.includes(asset)) { res.setHeader('Content-Type', asset.endsWith('.js') ? 'text/javascript' : asset.endsWith('.css') ? 'text/css' : asset.endsWith('.svg') ? 'image/svg+xml' : 'text/html'); return res.end(fs.readFileSync(path.join(root, 'public', asset))); }
      if (url.pathname.startsWith('/api/')) {
        requests.push([req.method, url.pathname]); res.setHeader('Content-Type', 'application/json');
        let body = { items: [], total: 0, profiles: [], adapters: [] };
        if (url.pathname === '/api/status' || url.pathname === '/api/settings') body = status;
        if (url.pathname === '/api/languages/current') body = selected;
        if (url.pathname === '/api/languages') {
          if (req.method === 'POST') { let raw = ''; for await (const chunk of req) raw += chunk; selected = packs[JSON.parse(raw).code] || english; }
          body = { languages: Object.values(packs).map(pack => pack.language), language: selected, selected: selected.language.code, errors: [], directories: [] };
        }
        if (url.pathname === '/api/scheduled-scan') body = { settings, runtime: {} };
        return res.end(JSON.stringify(body));
      }
      res.setHeader('Content-Type', 'text/html'); res.end('<html><head><link rel="stylesheet" href="/style.css"></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); const port = server.address().port, origin = 'http://127.0.0.1:' + port;
    win = new BrowserWindow({ show: false, width: 1180, height: 840, webPreferences: { contextIsolation: true, nodeIntegration: false, preload: path.join(root, 'public/desktop-preload.cjs') } });
    win.webContents.on('render-process-gone', (_e, details) => failures.push(details));
    ipcMain.handle('clamshield-ui-ready', () => true); ipcMain.handle('clamshield-ui-error', (_event, value) => failures.push(value));
    ipcMain.handle('clamshield-language-refresh', () => true);
    ipcMain.handle('clamshield-language', () => selected);
    await win.loadURL(origin + '/settings');
    await until(async () => await win.webContents.executeJavaScript(`Boolean(document.querySelector('#application-language option[value="es"]') && !document.getElementById('application-language').disabled)`), 'settings');
    const labels = await win.webContents.executeJavaScript(`Object.fromEntries([...document.querySelectorAll('#application-language option')].map(node=>[node.value,node.textContent]))`);
    assert.equal(Object.keys(labels).length, Object.keys(packs).length);
    assert.equal(labels.en, 'English');
    assert.equal(labels.es, runtime.languageLabel(packs.es.language));
    assert.equal(labels.el, runtime.languageLabel(packs.el.language));
    const settingsKey = Object.keys(english.strings).find(key => english.strings[key].english === 'Settings');
    for (const pack of Object.values(packs)) {
      await win.webContents.executeJavaScript(`document.getElementById('application-language').value=${JSON.stringify(pack.language.code)};document.getElementById('application-language').dispatchEvent(new Event('change',{bubbles:true}))`);
      await until(async () => await win.webContents.executeJavaScript(`document.documentElement.lang === ${JSON.stringify(pack.language.code)} && !document.getElementById('application-language').disabled`), pack.language.code + ': selected');
      assert.equal(await win.webContents.executeJavaScript('document.documentElement.dir'), pack.language.direction);
      assert.equal(await win.webContents.executeJavaScript('document.querySelector("main h1").textContent'), runtime.translate(pack, settingsKey));
    }
    await win.webContents.executeJavaScript(`document.getElementById('application-language').value='es';document.getElementById('application-language').dispatchEvent(new Event('change',{bubbles:true}))`);
    await until(async () => await win.webContents.executeJavaScript('document.documentElement.lang === "es"'), 'Spanish selected');
    assert.equal(selected.language.code, 'es');
    const pages = [['/', 'Dashboard'], ['/shield', 'Real-Time Shield'], ['/scan', 'On-Demand Scan'], ['/scheduled-scanner', 'Scheduled Scanner'], ['/results', 'Results'], ['/exceptions', 'Exceptions'], ['/quarantine', 'Quarantine'], ['/dns-protection', 'DNS Protection'], ['/updates', 'Updates'], ['/history', 'History'], ['/settings', 'Settings']];
    for (const [route, name] of pages) {
      await win.webContents.executeJavaScript(`document.querySelector('nav a[href=${JSON.stringify(route)}]').click()`);
      await until(async () => await win.webContents.executeJavaScript(`Boolean([...document.querySelectorAll('main h1')].find(node=>node.textContent===${JSON.stringify(vocabulary[name])}))`), route);
    }
    assert.deepEqual(await win.webContents.executeJavaScript('window.fixtureErrors'), []);
    await win.webContents.executeJavaScript('(async()=>window.fixtureApply(await fetch("/fixture/evil").then(r=>r.json())))()');
    assert.equal(await win.webContents.executeJavaScript('document.querySelector("nav").textContent.includes("<img src=x onerror=x=1>")'), true);
    assert.equal(await win.webContents.executeJavaScript('document.querySelector("nav img")'), null);
    assert.equal(await win.webContents.executeJavaScript('typeof window.x'), 'undefined');
    await win.webContents.executeJavaScript('(async()=>window.fixtureApply(await fetch("/fixture/max").then(r=>r.json())))()');
    for (const [route] of pages) {
      await win.webContents.executeJavaScript(`document.querySelector('nav a[href=${JSON.stringify(route)}]').click()`); await pause(70);
      const geometry = await win.webContents.executeJavaScript(`({width:innerWidth,document:document.documentElement.scrollWidth,nav:[...document.querySelectorAll('nav a')].map(n=>({width:n.clientWidth,content:n.scrollWidth}))})`);
      assert.ok(geometry.document <= geometry.width + 2, route + ': document overflow');
      assert.ok(geometry.nav.every(n => n.content <= n.width + 2), route + ': sidebar overflow ' + JSON.stringify(geometry));
    }
    selected = packs.ar;
    // Native pages receive data over the real sandboxed preload bridge.
    for (const page of ['startup.html', 'alert.html', 'results-reminder.html', 'scan-summary.html', 'update-available.html']) {
      const popup = new BrowserWindow({ show: false, width: 460, height: 320, webPreferences: { contextIsolation: true, nodeIntegration: false, preload: path.join(root, 'public/language-preload.cjs') } }); popups.push(popup);
      if (page === 'alert.html') await popup.loadFile(path.join(root, 'public', page), { query: { count: '2', port: String(port) } });
      else await popup.loadURL(origin + '/' + page + '?count=2&port=' + port);
      await until(async () => await popup.webContents.executeJavaScript('document.documentElement.dir === "rtl"'), page + ': RTL');
      assert.equal(await popup.webContents.executeJavaScript('document.querySelectorAll("script[src*=localization-browser]").length'), 1);
      popup.webContents.send('clamshield-language-changed', english);
      await until(async () => await popup.webContents.executeJavaScript('document.documentElement.lang === "en"'), page + ': reset');
    }
    assert.equal(failures.length, 0, JSON.stringify(failures));
    assert.ok(requests.some(([method, route]) => method === 'POST' && route === '/api/languages'));
    assert.ok(!requests.some(([method, route]) => method === 'POST' && !['/api/languages', '/api/client-log'].includes(route)), 'switching language must not trigger scanning/settings changes');
    console.log('PASS: all 16 shipped languages and credit labels, all 11 tabs in Spanish, maximum-length sidebar layout, literal malicious text, real Arabic RTL and all 5 native pages.');
    for (const popup of popups) popup.destroy(); win.destroy(); server.close(); app.exit(0);
  } catch (error) {
    console.error(error); if(win&&!win.isDestroyed()) console.error(await win.webContents.executeJavaScript('JSON.stringify({errors:window.fixtureErrors,route:location.pathname,body:document.body.innerText.slice(0,300)})').catch(()=>'')); for (const popup of popups) if (!popup.isDestroyed()) popup.destroy(); if (win && !win.isDestroyed()) win.destroy(); server?.close(); app.exit(1);
  }
});
