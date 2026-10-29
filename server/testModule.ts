import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import ts from 'typescript';
import os from 'node:os';
const require = createRequire(import.meta.url);
// Execute the actual module with explicit external ports (DB, process, filesystem).
// Tests can inject failures without starting the real app or touching ProgramData.
export function testModule(file: string, dependencies: Record<string, any> = {}, globals: Record<string, any> = {}) {
    const filename = path.resolve(file), module = { exports: {} as any };
    const code = ts.transpileModule(fs.readFileSync(filename, 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText;
    vm.runInNewContext(code, {
        module, exports: module.exports, Buffer, process, console, setTimeout, clearTimeout, setInterval, clearInterval,
        __filename: filename, __dirname: path.dirname(filename),
        require: (name: string) => Object.hasOwn(dependencies, name) ? dependencies[name] : require(name.startsWith('.') ? path.resolve(path.dirname(filename), name) : name),
        ...globals
    }, { filename });
    return module.exports;
}

export function stateFixture(t: { after: (fn: () => void) => void }) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clamshield-safety-'));
    const databasePath = path.join(directory, 'state.sqlite');
    const schema = testModule('server/core/database/schema.ts', {
        '../paths': { appStateDbPath: databasePath, nodeRequire: require },
        '../runtimeState': { runtimeState: {} }
    });
    const db = schema.getAppStateDb();
    t.after(() => {
        db.close();
        assertTemporaryDirectory(directory);
        fs.rmSync(directory, { recursive: true, force: true });
    });
    return { db, directory, databasePath,
        dependencies: { '../../../server/core/database/schema': { getAppStateDb: () => db }, '../../../server/core/database/migrations': { ensureAppStateReady: async () => {} } } };
}
function assertTemporaryDirectory(directory: string) {
    if (path.dirname(path.resolve(directory)) !== path.resolve(os.tmpdir()) || !path.basename(directory).startsWith('clamshield-safety-'))
        throw new Error('Refusing to clean a non-test directory');
}
