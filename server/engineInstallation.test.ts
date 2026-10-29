import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import path from 'node:path';
import { stateFixture, testModule } from './testModule';

async function fixture(t: any, overrides: Record<string, any> = {}) {
    const state = stateFixture(t), engine = path.join(state.directory, 'clamav'), staging = path.join(state.directory, 'staging');
    await fs.mkdir(engine); await fs.mkdir(staging);
    await fs.writeFile(path.join(engine, 'clamscan.exe'), 'working-engine');
    await fs.writeFile(path.join(staging, 'clamscan.exe'), 'new-engine');
    const core = testModule('server/core/files.ts', {
        'fs/promises': { ...fs, ...overrides },
        './paths': { engineBaseDir: state.directory },
        './utils': { sleep: async () => {} }
    }, { console: { warn() {}, debug() {} } });
    return { ...state, engine, staging, core };
}
test('engine activation replaces only after staging completes', async t => {
    const f = await fixture(t);
    await f.core.commitStagedEngineDirectory(f.staging, f.engine);
    assert.equal(await fs.readFile(path.join(f.engine, 'clamscan.exe'), 'utf8'), 'new-engine');
    assert.deepEqual((await fs.readdir(f.directory)).filter(n => n.includes('.previous-')), []);
});
test('Windows locking the staged engine restores the previous working engine', async t => {
    let stage = '';
    const f = await fixture(t, { rename: async (a: string, b: string) => {
        if (a === stage) throw Object.assign(new Error('locked'), { code: 'EACCES' });
        return fs.rename(a, b);
    } }); stage = f.staging;
    await assert.rejects(f.core.commitStagedEngineDirectory(f.staging, f.engine), { code: 'EACCES' });
    assert.equal(await fs.readFile(path.join(f.engine, 'clamscan.exe'), 'utf8'), 'working-engine');
    assert.equal(await fs.readFile(path.join(f.staging, 'clamscan.exe'), 'utf8'), 'new-engine');
});
test('failed staging copy leaves the active engine untouched', async t => {
    const f = await fixture(t, { cp: async () => { throw new Error('copy failed'); } });
    await assert.rejects(f.core.adoptClamavEngineFolder(f.staging), /copy failed/);
    assert.equal(await fs.readFile(path.join(f.engine, 'clamscan.exe'), 'utf8'), 'working-engine');
});
test('backup cleanup failure preserves the newly activated engine and backup', async t => {
    const f = await fixture(t, { rm: async () => { throw new Error('backup locked'); } });
    await f.core.commitStagedEngineDirectory(f.staging, f.engine);
    assert.equal(await fs.readFile(path.join(f.engine, 'clamscan.exe'), 'utf8'), 'new-engine');
    const backup = (await fs.readdir(f.directory)).find(n => n.includes('.previous-'))!;
    assert.equal(await fs.readFile(path.join(f.directory, backup, 'clamscan.exe'), 'utf8'), 'working-engine');
});
test('failed engine recovery reports the retained backup instead of deleting it', async t => {
    let stage = '';
    const f = await fixture(t, { rename: async (a: string, b: string) => {
        if (a === stage || a.includes('.previous-')) throw new Error('rename blocked');
        return fs.rename(a, b);
    } }); stage = f.staging;
    await assert.rejects(f.core.commitStagedEngineDirectory(f.staging, f.engine), /previous engine is retained at/);
    const backup = (await fs.readdir(f.directory)).find(n => n.includes('.previous-'))!;
    assert.equal(await fs.readFile(path.join(f.directory, backup, 'clamscan.exe'), 'utf8'), 'working-engine');
});

test('ClamAV install rejects a failed download or incomplete archive before engine activation', async t => {
    const f = stateFixture(t); let activate = 0, save = 0, failDownload = true;
    const install = testModule('engines/clamav/server/install.ts', {
        '../../../modules/updates/server/providers': { getLatestClamAVEngineRelease: async () => ({ downloadUrl: 'https://example.invalid/engine.zip', latestVersion: '2.0.0' }) },
        '../../../server/core/paths': { engineBaseDir: f.directory },
        '../../../server/core/runtimeState': { runtimeState: {} },
        '../../../server/core/downloads': { downloadToFile: async () => { if (failDownload) throw new Error('connection lost'); }, extractZip: async () => {} },
        '../../../server/core/files': { findExtractedClamavDir: async () => '', adoptClamavEngineFolder: async () => { activate++; } },
        '../../../modules/settings/server/service': { saveConfig: async () => { save++; } }
    });
    await assert.rejects(install.installClamAVEngine({}), /connection lost/);
    failDownload = false;
    await assert.rejects(install.installClamAVEngine({}));
    assert.equal(activate, 0); assert.equal(save, 0);
});
test('YARA install rejects a package without executable before activation or settings changes', async t => {
    const f = stateFixture(t); let activate = 0, save = 0;
    const install = testModule('engines/yara/server/install.ts', {
        '../../../modules/updates/server/providers': { getLatestYaraEngineRelease: async () => ({ downloadUrl: 'https://example.invalid/yara.zip', latestVersion: '4.6.0' }) },
        '../../../server/core/runtimeState': { runtimeState: {} },
        '../../../server/core/downloads': { downloadToFile: async () => {}, extractZip: async () => {}, findFileByName: async () => null },
        '../../../server/core/files': { adoptYaraEngineFolder: async () => { activate++; } },
        '../../../modules/settings/server/service': { saveConfig: async () => { save++; } }
    });
    const settings = { yaraDir: path.join(f.directory, 'yara'), yaraCacheDir: f.directory };
    await assert.rejects(install.installYaraEngine(settings));
    assert.equal(activate, 0); assert.equal(save, 0);
    assert.equal(Object.hasOwn(settings, 'yaraEngineInstalledVersion'), false);
});
