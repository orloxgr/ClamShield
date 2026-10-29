import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import express from 'express';
import sourceTools from '../scripts/test-source.cjs';

test('the production interface routes register on Express 5 and distinguish pages from missing assets', async t => {
    const source = fs.readFileSync('server/bootstrap.ts', 'utf8').replace(/\r\n/g, '\n');
    const start = source.indexOf('        app.use(express.static(distPath));');
    const end = source.indexOf('\n    }\n    app.use((error:', start);
    assert.ok(start >= 0 && end > start, 'production interface registration must be present');
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clamshield-http-'));
    t.after(() => {
        assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
        assert.ok(path.basename(directory).startsWith('clamshield-http-'));
        fs.rmSync(directory, { recursive: true, force: true });
    });
    fs.copyFileSync('index.html', path.join(directory, 'index.html'));
    const app = express();
    // Keep RegExp literals in Express's realm (its route matcher uses instanceof).
    new Function('app', 'express', 'path', 'distPath', 'englishText',
        sourceTools.transpile(source.slice(start, end)))(app, express, path, directory, key => key);
    app.use((error, _req, res, _next) => res.status(error.status || 500).json({ error: 'request failed' }));
    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>(resolve => server.once('listening', resolve));
    t.after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const origin = `http://127.0.0.1:${address.port}`;
    for (const route of ['/', '/results', '/settings']) {
        const response = await fetch(origin + route);
        assert.equal(response.status, 200, route);
        assert.match(await response.text(), /id="root"/);
    }
    const missing = await fetch(origin + '/assets/nonexistent-interface.js');
    assert.equal(missing.status, 404);
    assert.match(missing.headers.get('content-type') || '', /application\/json/);
});
