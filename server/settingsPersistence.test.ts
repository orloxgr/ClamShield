import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import { stateFixture, testModule } from './testModule';

test('settings survive reopening the database and explicit default resets', async t => {
    const f = stateFixture(t);
    const storage = testModule('modules/settings/server/storage.ts', f.dependencies);
    storage.saveSettingsRows({ language: 'el', enableDebugLog: true });
    storage.saveSettingsPatchRows({ language: 'en', enableDebugLog: false }, ['language', 'enableDebugLog']);
    const { DatabaseSync } = await import('node:sqlite');
    const reopened = new DatabaseSync(f.databasePath);
    try {
        assert.equal(reopened.prepare("SELECT value FROM settings WHERE key='language'").get().value, '"en"');
        assert.equal(reopened.prepare("SELECT value FROM settings WHERE key='enableDebugLog'").get().value, 'false');
    } finally { reopened.close(); }
});
test('failed settings commit rolls back every row and leaves runtime flags unchanged', async t => {
    const f = stateFixture(t), runtimeState = { debugLoggingEnabled: false, currentLogsDir: 'old-log' };
    const storage = testModule('modules/settings/server/storage.ts', f.dependencies);
    storage.saveSettingsRows({ enableDebugLog: false, logsDir: 'old-log' });
    f.db.exec("CREATE TRIGGER fail_settings BEFORE INSERT ON settings WHEN NEW.key='logsDir' BEGIN SELECT RAISE(ABORT, 'disk failed'); END");
    const service = testModule('modules/settings/server/service.ts', {
        ...f.dependencies, './storage': storage, '../../../server/core/runtimeState': { runtimeState }
    });
    await assert.rejects(service.saveConfig({ enableDebugLog: true, logsDir: 'new-log' }), /disk failed/);
    assert.equal(runtimeState.debugLoggingEnabled, false);
    assert.equal(runtimeState.currentLogsDir, 'old-log');
    assert.equal(f.db.prepare("SELECT value FROM settings WHERE key='enableDebugLog'").get().value, 'false');
});
test('provider credentials are excluded from general settings persistence', async t => {
    const f = stateFixture(t);
    const storage = testModule('modules/settings/server/storage.ts', f.dependencies);
    const service = testModule('modules/settings/server/service.ts', { ...f.dependencies, './storage': storage, '../../../server/core/runtimeState': { runtimeState: {} } });
    await service.saveConfig({ language: 'el', securiteInfoToken: 'private', securiteInfoUrl: 'private', securiteInfoSetupText: 'private' });
    assert.ok(!JSON.stringify(f.db.prepare('SELECT * FROM settings').all()).includes('private'));
});
test('removing exceptions and their reports is atomic when report deletion fails', async t => {
    const f = stateFixture(t);
    const service = testModule('modules/exceptions/server/service.ts', f.dependencies);
    const a = path.join(f.directory, 'a'), b = path.join(f.directory, 'b');
    await service.saveExceptions([a, b], 'manual');
    await service.saveExceptionReports({ [a]: { originalPath: a, threatName: 'A' }, [b]: { originalPath: b, threatName: 'B' } });
    f.db.exec("CREATE TRIGGER fail_reports BEFORE DELETE ON exception_reports BEGIN SELECT RAISE(ABORT, 'report delete failed'); END");
    await assert.rejects(service.saveExceptions([b]), /report delete failed/);
    assert.equal((await service.getExceptions()).length, 2);
    assert.equal(Object.keys(await service.getExceptionReports()).length, 2);
    f.db.exec('DROP TRIGGER fail_reports');
    await service.saveExceptions([b]);
    assert.deepEqual(Array.from(await service.getExceptions()), [b]);
    assert.equal(Object.keys(await service.getExceptionReports()).length, 1);
    assert.equal(f.db.prepare('SELECT origin FROM exceptions').get().origin, 'manual');
    assert.equal(service.isExcluded(path.join(b, 'child'), [b]), true);
    assert.equal(service.isExcluded(b + '-sibling', [b]), false);
});

function settingsRoute(save: () => Promise<void>, defender: () => Promise<any> = async () => ({ Success: true })) {
    let handler: any; const sideEffects: string[] = [];
    const route = testModule('modules/settings/server/routes/postApiSettings.ts', {
        '../service': { saveConfig: save, ensureDirs: async () => {} },
        '../storage': { saveSettingsPatchRows: () => { throw new Error('disk failed'); } },
        '../../../../server/platform/defender': { syncDefenderCompatibilityExclusions: defender },
        '../../../../server/platform/contextMenu': { writeWindowsContextMenuState: async () => sideEffects.push('context-menu') }
    });
    const context: any = { settings: { language: 'en', enableDebugLog: false, defenderCompatibilityExclusionsEnabled: false },
        virusTotalScanQueue: { disableConfirmations: () => sideEffects.push('queue') },
        scheduleVirusTotalScan: () => sideEffects.push('schedule') };
    route.registerPostApiSettings({ post: (_p: string, fn: any) => { handler = fn; } }, context);
    const response: any = { code: 200, body: null, status(code: number) { this.code = code; return this; }, json(body: any) { this.body = body; return this; } };
    return { context, sideEffects, response, send: (body: any) => handler({ body }, response) };
}
test('settings API persistence failure preserves live settings and does not restart protection', async () => {
    const f = settingsRoute(async () => { throw new Error('disk failed'); });
    const before = f.context.settings;
    await f.send({ enableDebugLog: true });
    assert.equal(f.response.code, 500);
    assert.equal(f.context.settings, before);
    assert.deepEqual(f.sideEffects, []);
    await f.send({ virusTotalShowLimitWarnings: false });
    assert.equal(f.response.code, 500);
    assert.equal(f.context.settings, before);
    assert.deepEqual(f.sideEffects, []);
});
test('settings API does not persist or claim success when Windows refuses exclusions', async () => {
    let saves = 0;
    const f = settingsRoute(async () => { saves++; }, async () => ({ Success: false, Message: 'Blocked by Windows policy' }));
    await f.send({ defenderCompatibilityExclusionsEnabled: true });
    assert.equal(f.response.code, 409);
    assert.equal(saves, 0);
    assert.equal(f.context.settings.defenderCompatibilityExclusionsEnabled, false);
    assert.deepEqual(f.sideEffects, []);
});
