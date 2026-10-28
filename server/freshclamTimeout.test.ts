import { readBackendSource, serverTestContext } from "./testSupport";
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import vm from "node:vm";
import { EventEmitter } from "node:events";
import ts from "typescript";

function fixture() {
    const source = readBackendSource();
    const tree = ts.createSourceFile("server.ts", source, ts.ScriptTarget.Latest, true);
    const declaration = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === "runFreshclamWithConfig");
    assert.ok(declaration);
    const child = Object.assign(new EventEmitter(), { stdout: new EventEmitter(), stderr: new EventEmitter(), kill: () => { kills++; } });
    let kills = 0, args: string[] = [];
    let ready!: () => void;
    const started = new Promise<void>(resolve => { ready = resolve; });
    const lines: string[] = [];
    const context = serverTestContext({
        freshclamRunTimeoutMs: 15, pathExists: async () => true, setTimeout, clearTimeout,
        spawn: (_exe: string, passedArgs: string[]) => { args = passedArgs; return child; }
    });
    vm.runInContext(ts.transpileModule(`${declaration.getText(tree)}\nglobalThis.run = runFreshclamWithConfig;`, {
        compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS }
    }).outputText, context);
    const run = (options: any = {}) => context.run({ freshclamPath: "freshclam.exe", databaseDir: "test-db" }, {
        configPath: "test.conf", securiteInfoEnabled: true, officialEnabled: false,
        redact: (line: string) => line.replaceAll("private-token", "[redacted]")
    }, { onLine: (line: string) => lines.push(line), onProcess: ready, ...options });
    return { run, child, lines, started, args: () => args, kills: () => kills };
}

test("SecuriteInfo-only FreshClam runs use the existing timeout by default and keep token redaction", { timeout: 2000 }, async () => {
    const f = fixture();
    const pending = f.run();
    await f.started;
    f.child.stdout.emit("data", Buffer.from("Downloading private-token/signatures\n"));
    assert.equal(await pending, -2);
    assert.equal(f.kills(), 1);
    assert.ok(f.args().includes("--update-db=custom"));
    assert.ok(f.lines.some(line => line.includes("[redacted]")));
    assert.ok(f.lines.some(line => line.includes("was stopped")));
    assert.ok(f.lines.every(line => !line.includes("private-token")));
});

test("successful and failed child exits settle normally and clear the timeout", async () => {
    for (const code of [0, 1]) {
        const f = fixture(); const pending = f.run();
        await f.started;
        f.child.emit("close", code);
        assert.equal(await pending, code); assert.equal(f.kills(), 0);
    }
    const f = fixture(); const pending = f.run();
    await f.started;
    f.child.emit("error", new Error("private-token startup failure"));
    await assert.rejects(pending, /\[redacted\] startup failure/);
    assert.equal(f.kills(), 0);
});
