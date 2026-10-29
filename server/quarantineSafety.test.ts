import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { stateFixture, testModule } from './testModule';

const files = testModule('modules/quarantine/server/files.ts');
const sha = (content: string) => createHash('sha256').update(content).digest('hex');
async function fixture(t: any) {
    const state = stateFixture(t);
    const quarantineDir = path.join(state.directory, 'quarantine');
    await fs.mkdir(quarantineDir);
    const storage = testModule('modules/quarantine/server/storage.ts', state.dependencies);
    const originalPath = path.join(state.directory, 'original', 'document.txt');
    const fileName = 'isolated-document';
    await fs.writeFile(path.join(quarantineDir, fileName), 'test-content');
    await storage.saveQuarantineMap({ [fileName]: { originalPath, threatName: 'Test.Detection', sha256: sha('test-content') } });
    return { ...state, quarantineDir, storage, originalPath, fileName };
}
test('restore commits original bytes, verified exception and history together', async t => {
    const f = await fixture(t);
    await f.storage.restoreQuarantinedFileAndAddException(f, f.fileName);
    assert.equal(await fs.readFile(f.originalPath, 'utf8'), 'test-content');
    await assert.rejects(fs.access(path.join(f.quarantineDir, f.fileName)));
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM quarantine_map').get().n, 0);
    assert.equal(f.db.prepare('SELECT kind FROM exceptions').get().kind, 'file');
    assert.equal(f.db.prepare('SELECT sha256 FROM exception_reports').get().sha256, sha('test-content'));
    assert.equal(f.db.prepare('SELECT type FROM history').get().type, 'quarantine-restore');
});
test('restore never overwrites a newly created original, even with matching contents', async t => {
    const f = await fixture(t);
    await fs.mkdir(path.dirname(f.originalPath));
    await fs.writeFile(f.originalPath, 'new-document');
    await assert.rejects(f.storage.restoreQuarantinedFileAndAddException(f, f.fileName));
    assert.equal(await fs.readFile(f.originalPath, 'utf8'), 'new-document');
    assert.equal(await fs.readFile(path.join(f.quarantineDir, f.fileName), 'utf8'), 'test-content');
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM exceptions').get().n, 0);
});
test('failed restore metadata transaction rolls back the file, reports and exception', async t => {
    const f = await fixture(t);
    f.db.exec("CREATE TRIGGER fail_history BEFORE INSERT ON history BEGIN SELECT RAISE(ABORT, 'disk failed'); END");
    await assert.rejects(f.storage.restoreQuarantinedFileAndAddException(f, f.fileName), /disk failed/);
    assert.equal(await fs.readFile(path.join(f.quarantineDir, f.fileName), 'utf8'), 'test-content');
    await assert.rejects(fs.access(f.originalPath));
    for (const table of ['exceptions', 'exception_reports', 'history']) assert.equal(f.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM quarantine_map').get().n, 1);
});
test('changed or missing quarantine content and invalid IDs cannot create exceptions', async t => {
    const f = await fixture(t);
    await fs.writeFile(path.join(f.quarantineDir, f.fileName), 'changed-content');
    await assert.rejects(f.storage.restoreQuarantinedFileAndAddException(f, f.fileName), /changed during transfer/);
    await assert.rejects(fs.access(f.originalPath));
    await fs.unlink(path.join(f.quarantineDir, f.fileName));
    for (const name of [f.fileName, '../document', '..', 'a:b', '__proto__']) await assert.rejects(f.storage.restoreQuarantinedFileAndAddException(f, name));
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM exceptions').get().n, 0);
});
test('failed source deletion retains original bytes and cleans only our own destination', async t => {
    const f = stateFixture(t), source = path.join(f.directory, 'source'), target = path.join(f.directory, 'target');
    await fs.writeFile(source, 'preserve');
    const injected = testModule('modules/quarantine/server/files.ts', { 'fs/promises': { ...fs, unlink: async (p: string) => {
        if (p === source) throw Object.assign(new Error('locked'), { code: 'EACCES' });
        return fs.unlink(p);
    } } });
    await assert.rejects(injected.moveFileWithoutOverwrite(source, target), /locked/);
    assert.equal(await fs.readFile(source, 'utf8'), 'preserve');
    await assert.rejects(fs.access(target));
    await fs.writeFile(target, 'other-owner');
    await assert.rejects(files.moveFileWithoutOverwrite(source, target), { code: 'EEXIST' });
    assert.equal(await fs.readFile(target, 'utf8'), 'other-owner');
});
test('quarantine rejects non-regular sources and preserves distinct same-name files', async t => {
    const f = stateFixture(t), q = path.join(f.directory, 'q');
    await assert.rejects(files.quarantineFile(f.directory, 'Test', q), /non-regular/);
    for (const folder of ['a', 'b']) {
        await fs.mkdir(path.join(f.directory, folder));
        await fs.writeFile(path.join(f.directory, folder, 'same.txt'), folder);
        const result = await files.quarantineFile(path.join(f.directory, folder, 'same.txt'), 'Test', q);
        assert.equal(result.metadata.sha256, sha(folder));
    }
    assert.equal((await fs.readdir(q)).length, 2);
});
