import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { stateFixture } from './testModule';
import { cleanupDefenderForUninstall } from './uninstall';

test('uninstall removes configured Defender exclusions without changing saved settings', async t => {
    const f = stateFixture(t), calls: any[] = [];
    const saved = { defenderCompatibilityExclusionsEnabled: true, quarantineDir: "C:\\custom's quarantine", yaraDir: 'D:\\YARA' };
    for (const [key, value] of Object.entries(saved)) f.db.prepare('INSERT INTO settings(key, value) VALUES (?, ?)').run(key, JSON.stringify(value));
    const result = await cleanupDefenderForUninstall({ databasePath: f.databasePath, legacyPath: path.join(f.directory, 'missing.json'), syncExclusions: async settings => { calls.push(settings); return { Success: true } as any; } });
    assert.equal(result.Success, true);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].defenderCompatibilityExclusionsEnabled, false);
    assert.equal(calls[0].quarantineDir, saved.quarantineDir);
    assert.equal(calls[0].yaraDir, saved.yaraDir);
    assert.equal(f.db.prepare('SELECT value FROM settings WHERE key = ?').get('defenderCompatibilityExclusionsEnabled')?.value, 'true');
});

test('blocked cleanup stops uninstall rather than silently leaving exclusions', async t => {
    const f = stateFixture(t);
    f.db.prepare('INSERT INTO settings(key, value) VALUES (?, ?)').run('defenderCompatibilityExclusionsEnabled', 'true');
    await assert.rejects(cleanupDefenderForUninstall({ databasePath: f.databasePath, syncExclusions: async () => ({ Success: false, Message: 'Device policy blocked removal' } as any) }), /Device policy blocked removal/);
    assert.equal(fs.existsSync(f.databasePath), true);
});

test('uninstall does not change Defender when compatibility exclusions were never enabled', async t => {
    const f = stateFixture(t);
    await cleanupDefenderForUninstall({ databasePath: f.databasePath, syncExclusions: async () => { assert.fail('Must not change Defender'); } });
});

test('legacy settings are read as data and malformed settings are not executed or ignored', async t => {
    const f = stateFixture(t), legacyPath = path.join(f.directory, 'legacy.json');
    fs.writeFileSync(legacyPath, JSON.stringify({ defenderCompatibilityExclusionsEnabled: true, quarantineDir: 'C:\\legacy quarantine' }));
    let actual: any;
    await cleanupDefenderForUninstall({ databasePath: path.join(f.directory, 'absent.sqlite'), legacyPath, syncExclusions: async settings => { actual = settings; return { Success: true } as any; } });
    assert.equal(actual.quarantineDir, 'C:\\legacy quarantine');
    f.db.prepare('INSERT INTO settings(key, value) VALUES (?, ?)').run('defenderCompatibilityExclusionsEnabled', 'arbitrary code');
    await assert.rejects(cleanupDefenderForUninstall({ databasePath: f.databasePath, syncExclusions: async () => { assert.fail('Invalid settings must fail before changes'); } }));
});
