import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { testModule } from './testModule';

function fixture(ports: Record<string, any> = {}) {
    return testModule('addons/sanesecurity/server/tools.ts', {
        '../../../server/core/downloads': { downloadFile: async () => { throw new Error('Unexpected network request'); } },
        '../../../server/platform/processes': { runHiddenProcess: async () => { throw new Error('Unexpected executable'); } },
        '../../../server/core/files': { commitStagedEngineDirectory: async () => { throw new Error('Unexpected activation'); } },
        './constants': {}, ...ports
    });
}

test('native helper extraction rejects links and paths outside the binary/license allowlist', () => {
    const { safeNativeArchiveEntry: accepts } = fixture();
    assert.equal(accepts('usr/bin/rsync.exe', 'File'), true);
    assert.equal(accepts('./ucrt64/bin/7z.dll', 'File'), true);
    for (const name of ['../rsync.exe', '/usr/bin/rsync.exe', 'usr/bin/../../bad.exe', 'usr/bin/a.exe:stream', 'usr/bin/a.ps1', 'etc/post-install.sh', 'usr\\bin\\rsync.exe'])
        assert.equal(accepts(name, 'File'), false, name);
    for (const type of ['SymbolicLink', 'Link', 'Directory']) assert.equal(accepts('usr/bin/rsync.exe', type), false);
});

test('a failed package hash cannot execute or replace the active native tools', async t => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'clamshield-native-'));
    t.after(async () => {
        assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
        assert.ok(path.basename(directory).startsWith('clamshield-native-'));
        await fs.rm(directory, { recursive: true, force: true });
    });
    const active = path.join(directory, 'active');
    await fs.mkdir(active);
    await fs.writeFile(path.join(active, 'retained.txt'), 'existing tools');
    const tools = fixture({ '../../../server/core/downloads': { downloadFile: async (_url, target) => fs.writeFile(target, 'invalid archive') } });
    await assert.rejects(tools.installNativeTools(active, path.join(directory, 'cache'), () => {}), /checksum verification failed/);
    assert.equal(await fs.readFile(path.join(active, 'retained.txt'), 'utf8'), 'existing tools');
    assert.deepEqual((await fs.readdir(directory)).sort(), ['active', 'cache']);
    assert.deepEqual(await fs.readdir(path.join(directory, 'cache')), []);
});

test('native version verification rejects an older executable rather than accepting it', async () => {
    const tools = fixture({ '../../../server/platform/processes': { runHiddenProcess: async () => ({ code: 0, stdout: 'rsync version 3.3.0', stderr: '' }) } });
    await assert.rejects(tools.verifyNativeTools('unused'), /expected 3\.5\.1, received 3\.3\.0/);
});
