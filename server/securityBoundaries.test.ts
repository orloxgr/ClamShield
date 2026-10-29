import assert from 'node:assert/strict';
import test from 'node:test';
import express from 'express';
import http from 'node:http';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import ts from 'typescript';
import { requireLocalApiSession, apiSessionToken, apiCookieName, apiHeaderName } from './core/security';

test('API mutations require a valid session, local Host and matching browser Origin', async t => {
    const app = express(); let writes = 0;
    app.use(requireLocalApiSession);
    app.post('/api/change', (_req, res) => { writes++; res.json({ success: true }); });
    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>(resolve => server.once('listening', resolve));
    t.after(() => { server.closeAllConnections(); server.close(); });
    const port = (server.address() as any).port;
    const send = (headers: Record<string, string>) => new Promise<number>((resolve, reject) => {
        const request = http.request({ hostname: '127.0.0.1', port, path: '/api/change', method: 'POST', headers }, response => {
            response.resume(); response.on('end', () => resolve(response.statusCode!));
        }); request.on('error', reject); request.end();
    });
    for (const headers of [
        {}, { [apiHeaderName]: 'wrong' }, { Cookie: `${apiCookieName}=%ZZ` },
        { [apiHeaderName]: apiSessionToken, Host: `attacker.example:${port}` },
        { [apiHeaderName]: apiSessionToken, Host: '127.0.0.1:1' },
        { Cookie: `${apiCookieName}=${apiSessionToken}`, Origin: 'https://attacker.example' },
        { Cookie: `${apiCookieName}=${apiSessionToken}`, Origin: 'null' }
    ]) assert.equal(await send(headers), 403);
    assert.equal(writes, 0);
    assert.equal(await send({ [apiHeaderName]: apiSessionToken }), 200);
    assert.equal(await send({ Cookie: `${apiCookieName}=${apiSessionToken}`, Origin: `http://127.0.0.1:${port}` }), 200);
    assert.equal(writes, 2);
});

const source = fs.readFileSync('electron-main.cjs', 'utf8');
const tree = ts.createSourceFile('electron-main.cjs', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
function desktopFixture() {
    const handlers = new Map<string, any>(), calls: any[] = [];
    function window(url: string) {
        const win = { closed: false, webContents: { mainFrame: {}, getURL: () => url }, isDestroyed: () => win.closed };
        return win;
    }
    const main = window('http://127.0.0.1:1234/');
    const alert = window('http://127.0.0.1:1234/alert.html?id=threat-1');
    const reminder = window('http://127.0.0.1:1234/results-reminder.html');
    const activeAlerts = new Map([['threat-1', alert]]);
    const context = vm.createContext({ URL, require: createRequire(import.meta.url),
        englishText: (s: string) => s, mainWindow: main, resultsReminderWindow: reminder,
        scanSummaryWindow: null, updateAvailableWindow: null, activeAlerts, currentApiPort: 1234,
        windowDiagnostics: new WeakMap(), getPublicAssetPath: (p: string) => 'C:/ClamShield/public/' + p,
        requestJson: async (...args: any[]) => { calls.push(args); return { success: true }; },
        ipcMain: { handle: (name: string, handler: any) => handlers.set(name, handler) }
    });
    for (const name of ['trustedMainSender', 'trustedLanguageSender', 'trustedAlertSender']) {
        const node = tree.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === name)!;
        vm.runInContext(node.getText(tree), context);
    }
    for (const name of ['clamshield-alert-action', 'clamshield-alert-log', 'clamshield-results-reminder-action']) {
        const node = tree.statements.find(n => ts.isExpressionStatement(n) && ts.isCallExpression(n.expression) && n.expression.expression.getText(tree) === 'ipcMain.handle' && n.expression.arguments[0]?.getText(tree) === `'${name}'`)!;
        assert.ok(node, `Missing production handler ${name}`);
        vm.runInContext(node.getText(tree), context);
    }
    const event = (win = alert, subframe = false) => ({ sender: win.webContents, senderFrame: subframe ? {} : win.webContents.mainFrame });
    return { handlers, calls, main, alert, reminder, event, window, activeAlerts };
}
test('alert IPC rejects forged IDs, other windows, remote content and subframes before any API call', async () => {
    const f = desktopFixture(), action = f.handlers.get('clamshield-alert-action');
    const payload = { id: 'threat-1', action: 'quarantine' };
    await assert.rejects(action(f.event(), { ...payload, id: 'threat-2' }));
    await assert.rejects(action(f.event(f.main), payload));
    await assert.rejects(action(f.event(f.reminder), payload));
    await assert.rejects(action(f.event(f.alert, true), payload));
    await assert.rejects(action(f.event(), { ...payload, action: 'execute' }));
    const remote = f.window('https://attacker.example/alert.html?id=threat-1');
    f.activeAlerts.set('threat-1', remote);
    await assert.rejects(action(f.event(remote), payload));
    f.activeAlerts.set('threat-1', f.alert);
    f.alert.closed = true;
    await assert.rejects(action(f.event(), payload));
    assert.equal(f.calls.length, 0);
    f.alert.closed = false;
    assert.equal((await action(f.event(), payload)).success, true);
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0][1], '/api/pending-threats/threat-1/action');
});
test('reminder actions and alert logging remain bound to their owning windows', async () => {
    const f = desktopFixture(), reminder = f.handlers.get('clamshield-results-reminder-action'), log = f.handlers.get('clamshield-alert-log');
    await assert.rejects(reminder(f.event(), { action: 'forget' }));
    await assert.rejects(reminder(f.event(f.reminder), { action: 'quarantine' }));
    await assert.rejects(log(f.event(f.main), { message: 'forged' }));
    assert.equal(f.calls.length, 0);
    await reminder(f.event(f.reminder), { action: 'open' });
    await log(f.event(), { message: 'actual alert error' });
    assert.equal(f.calls.length, 2);
});
