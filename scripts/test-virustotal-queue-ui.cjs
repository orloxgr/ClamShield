const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const root = path.resolve(__dirname, '..');
if (!process.versions.electron) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clamshield-vt-ui-'));
  const env = { ...process.env, CLAMSHIELD_VT_UI_TEST_DIR: directory };
  delete env.ELECTRON_RUN_AS_NODE;
  const result = require('node:child_process').spawnSync(require('electron'), [__filename], { cwd: root, env, windowsHide: true, stdio: 'inherit', timeout: 45000 });
  const resolved = path.resolve(directory);
  if (path.dirname(resolved) === path.resolve(os.tmpdir()) && path.basename(resolved).startsWith('clamshield-vt-ui-')) {
    try { fs.rmSync(resolved, { recursive: true, force: true }); } catch {}
  }
  if (result.error) console.error(result.error.message);
  process.exit(result.status ?? 1);
}
const { app, BrowserWindow } = require('electron');
const http = require('node:http');
const { buildSync } = require('esbuild');
app.setPath('userData', path.join(process.env.CLAMSHIELD_VT_UI_TEST_DIR, 'profile'));
app.setPath('sessionData', path.join(process.env.CLAMSHIELD_VT_UI_TEST_DIR, 'session'));
app.on('window-all-closed', () => {});
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate) {
  const end = Date.now() + 8000;
  while (!await predicate()) { if (Date.now() > end) throw new Error('VirusTotal UI fixture timed out'); await delay(30); }
}
app.whenReady().then(async () => {
  let win, server;
  try {
    const bundle = buildSync({ stdin: { contents: `import React from 'react'; import {createRoot} from 'react-dom/client'; import {BrowserRouter} from 'react-router-dom';
      import Dashboard from './src/pages/Dashboard'; import Results from './src/pages/Results';
      createRoot(document.getElementById('root')).render(<BrowserRouter>{location.pathname === '/results' ? <Results/> : <Dashboard/>}</BrowserRouter>);`,
      resolveDir: root, loader: 'tsx' }, bundle: true, write: false, format: 'iife', define: { 'process.env.NODE_ENV': '"production"' } }).outputFiles[0].text;
    const cssName = fs.readdirSync(path.join(root, 'dist/assets')).find(name => name.endsWith('.css'));
    assert.ok(cssName, 'Run npm run build before UI verification');
    const now = Date.now();
    const tasks = [
      { id: 'a', source: 'results', filePath: 'D:\\Downloads\\unknown-sample.zip', state: 'Hash check scheduled', submission: 'Hash lookup only; no file upload is recorded for this task.', nextAttemptAt: now + 60000 },
      { id: 'b', source: 'shield', filePath: 'D:\\Downloads\\pending-upload.zip', state: 'Upload queued', submission: 'Hash checked: no report. File upload has not completed.' },
      { id: 'c', source: 'scan', filePath: 'D:\\Scans\\uploaded-sample.zip', state: 'Awaiting analysis', submission: 'File uploaded; report not available yet.', analysisId: 'fixture-analysis', nextAttemptAt: now + 120000 }
    ];
    const findings = [
      { id: 'unknown', timestamp: now, originalPath: tasks[0].filePath, threatName: 'Test.Unknown', source: 'manual', sha256: 'abc', virusTotalRefinement: { status: 'unknown', report: { found: false }, checkedAt: now } },
      { id: 'uploaded', timestamp: now - 1, originalPath: tasks[2].filePath, threatName: 'Test.Uploaded', source: 'manual', sha256: 'def', virusTotalChecks: { resultsUploadedUnknownHash: 'def', resultsUploadCheckAfter: now + 120000 }, virusTotalRefinement: { status: 'unknown', report: { found: false }, checkedAt: now } },
      { id: 'unchecked', timestamp: now - 2, originalPath: 'D:\\Scans\\unchecked.zip', threatName: 'Test.NotChecked', source: 'manual' },
      { id: 'changed', timestamp: now - 3, originalPath: 'C:\\Chrome\\Preferences', threatName: 'Test.Changed', source: 'scheduled', virusTotalChecks: { resultsBlockedReason: 'file' }, virusTotalRefinement: { status: 'blocked', message: 'File changed during upload; the VirusTotal analysis belongs to different content. Restore access to the original file and retry, or remove this finding if the file is already gone.' } }
    ];
    const methods = [];
    const submissions = [];
    const removals = [];
    server = http.createServer((req, res) => {
      methods.push(req.method);
      const url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname === '/bundle.js') { res.setHeader('Content-Type', 'text/javascript'); res.end(bundle); return; }
      if (url.pathname === '/style.css') { res.setHeader('Content-Type', 'text/css'); res.end(fs.readFileSync(path.join(root, 'dist/assets', cssName))); return; }
      if (url.pathname.startsWith('/api/')) {
        res.setHeader('Content-Type', 'application/json');
        if (url.pathname.endsWith('/dismiss')) {
          assert.equal(req.method, 'POST'); removals.push(url.pathname);
          const index = findings.findIndex(item => url.pathname === '/api/results/' + item.id + '/dismiss');
          if (index >= 0) findings.splice(index, 1);
          res.end(JSON.stringify({ success: true, removed: index >= 0 }));
        }
        else if (url.pathname.endsWith('/virustotal-submit')) {
          assert.equal(req.method, 'POST'); submissions.push(url.pathname);
          findings[0].virusTotalRefinement = { status: 'awaiting_analysis', report: { found: false }, checkedAt: now };
          findings[0].virusTotalChecks = { resultsUploadedUnknownHash: 'abc', resultsUploadAnalysisId: 'new-analysis', resultsUploadCheckAfter: now + 60000 };
          res.end(JSON.stringify({ success: true, refinement: findings[0].virusTotalRefinement, checks: findings[0].virusTotalChecks, report: { found: false }, message: 'File submitted; analysis pending.' }));
        }
        else if (url.pathname === '/api/status') res.end(JSON.stringify({ settings: { shieldEnabled: true }, stats: {}, virusTotalCloud: { enabled: true, configured: true, queuedCount: 3 } }));
        else if (url.pathname === '/api/results') res.end(JSON.stringify({ items: findings, total: findings.length }));
        else if (url.pathname === '/api/virustotal/queue') {
          const source = url.searchParams.get('source') || 'all', search = (url.searchParams.get('search') || '').toLowerCase();
          const items = tasks.filter(item => (source === 'all' || item.source === source) && item.filePath.toLowerCase().includes(search));
          res.end(JSON.stringify({ items, total: items.length, totalPending: 3, counts: { results: 1, shield: 1, scan: 1 }, page: 1, pageSize: 50, enabled: true, configured: true }));
        } else res.end(JSON.stringify({ enabled: true, configured: true }));
        return;
      }
      res.setHeader('Content-Type', 'text/html'); res.end('<html><head><link rel="stylesheet" href="/style.css"></head><body class="bg-slate-950 text-slate-200"><div id="root"></div><script src="/bundle.js"></script></body></html>');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    win = new BrowserWindow({ width: 1100, height: 900, show: false, webPreferences: { contextIsolation: true, nodeIntegration: false } });
    const text = () => win.webContents.executeJavaScript('document.body.innerText');
    const click = label => win.webContents.executeJavaScript(`Array.from(document.querySelectorAll('button')).find(button=>button.textContent.trim()===${JSON.stringify(label)}).click()`);
    await win.loadURL(origin);
    await until(async () => (await text()).includes('View queue'));
    await click('View queue');
    await until(async () => (await text()).includes('fixture-analysis'));
    assert.match(await text(), /Hash check scheduled/); assert.match(await text(), /Upload queued/); assert.match(await text(), /Awaiting analysis/);
    if (process.env.CLAMSHIELD_VT_SCREENSHOT_DIR) {
      await win.webContents.executeJavaScript('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
      fs.mkdirSync(process.env.CLAMSHIELD_VT_SCREENSHOT_DIR, { recursive: true });
      fs.writeFileSync(path.join(process.env.CLAMSHIELD_VT_SCREENSHOT_DIR, 'virustotal-queue.png'), (await win.webContents.capturePage()).toPNG());
    }
    await click('Shield (1)');
    await until(async () => { const value = await text(); return value.includes('pending-upload.zip') && !value.includes('fixture-analysis'); });
    await win.webContents.executeJavaScript(`document.querySelector('[aria-label="Search queued files"]').focus();`);
    await win.webContents.insertText('no-such-file');
    await until(async () => (await text()).includes('No pending tasks match'));
    await win.webContents.executeJavaScript('document.querySelector("[role=dialog]").dispatchEvent(new KeyboardEvent("keydown",{key:"Escape",bubbles:true}))');
    await until(async () => !await win.webContents.executeJavaScript('Boolean(document.querySelector("[role=dialog]"))'));
    await win.loadURL(origin + '/results');
    await until(async () => (await text()).includes('Upload required'));
    const resultText = await text();
    assert.match(resultText, /Awaiting analysis/); assert.match(resultText, /Not checked with VT/);
    assert.match(resultText, /not uploaded by ClamShield/); assert.match(resultText, /quarantine/);
    if (process.env.CLAMSHIELD_VT_SCREENSHOT_DIR) {
      await win.webContents.executeJavaScript('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
      fs.writeFileSync(path.join(process.env.CLAMSHIELD_VT_SCREENSHOT_DIR, 'virustotal-result-states.png'), (await win.webContents.capturePage()).toPNG());
    }
    assert.ok(methods.every(method => method === 'GET'), 'viewing the queue must not submit files');
    assert.doesNotMatch(resultText, /Unknown to VirusTotal|report unavailable|follow-ups have ended/);
    await click('Upload for analysis');
    await until(async () => (await text()).includes('Uploaded samples may be shared'));
    assert.equal(submissions.length, 0, 'opening confirmation must not upload');
    await click('Cancel');
    assert.equal(submissions.length, 0);
    await click('Upload for analysis');
    await win.webContents.executeJavaScript('Array.from(document.querySelector("[role=dialog]").querySelectorAll("button")).find(b=>b.textContent==="Upload for analysis").click()');
    await until(async () => submissions.length === 1 && !await win.webContents.executeJavaScript('Boolean(document.querySelector("[role=dialog]"))'));
    assert.equal(submissions[0], '/api/results/unknown/virustotal-submit');
    assert.ok(methods.filter(method => method !== 'GET').every(method => method === 'POST'));
    const changedRow = await win.webContents.executeJavaScript('Array.from(document.querySelectorAll("article")).find(row=>row.textContent.includes("Test.Changed")).innerText');
    assert.match(changedRow, /File changed/); assert.match(changedRow, /Scan current file/);
    assert.doesNotMatch(changedRow, /Restore access|Retry check/);
    const targetUrl = await win.webContents.executeJavaScript('Array.from(document.querySelectorAll("a")).find(a=>a.textContent==="Scan current file").getAttribute("href")');
    assert.equal(new URL(targetUrl, origin).searchParams.get('file'), 'C:\\Chrome\\Preferences');
    await win.webContents.executeJavaScript('Array.from(document.querySelectorAll("article")).find(row=>row.textContent.includes("Test.Changed")).querySelectorAll("button")[2].click()');
    await until(async () => (await text()).includes('Remove finding from Results'));
    assert.equal(removals.length, 0);
    assert.match(await text(), /file stays on disk and remains eligible for future scans/);
    await click('Cancel'); assert.equal(removals.length, 0);
    await win.webContents.executeJavaScript('Array.from(document.querySelectorAll("article")).find(row=>row.textContent.includes("Test.Changed")).querySelectorAll("button")[2].click()');
    await click('Remove finding');
    await until(async () => !(await text()).includes('Test.Changed'));
    assert.deepEqual(removals, ['/api/results/changed/dismiss']);
    console.log('PASS: real Dashboard queue button, source filters, search, close, actionable Results states, read-only queue and explicit upload confirmation, changed-file guidance and confirmed finding removal.');
    win.destroy(); server.close(); app.exit(0);
  } catch (error) { console.error(error); if (win && !win.isDestroyed()) win.destroy(); server?.close(); app.exit(1); }
});
