import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { EventEmitter } from "node:events";
import ts from "../scripts/test-source.cjs";
import { serverTestContext } from "./testSupport";

function declarations(file: string, names: string[]) {
    const source = fs.readFileSync(file, "utf8");
    const tree = ts.createSourceFile(file, source);
    return names.map(name => {
        const node = tree.statements.find((node: any) => ts.isFunctionDeclaration(node) && node.name?.text === name);
        assert.ok(node, `Missing production function ${name}`);
        return node.getText(tree).replace(/^export /, "");
    }).join("\n");
}
const flush = () => new Promise(resolve => setImmediate(resolve));
const silent = { log() {}, debug() {}, warn() {}, error() {} };

test("a replaced clamd's late close/error cannot clear the current daemon or cause another spawn", async () => {
    const children: any[] = [];
    let concurrentConfigs = 0, maxConcurrentConfigs = 0;
    const context = serverTestContext({
        console: silent, clamdProcess: null, clamdConfSignature: "", isSimulated: false,
        getClamdConfSignature: (settings: any) => settings.signature,
        ensureClamdConfContent: async () => {
            concurrentConfigs++;
            maxConcurrentConfigs = Math.max(maxConcurrentConfigs, concurrentConfigs);
            await flush();
            concurrentConfigs--;
        },
        sleep: async () => {}, applyShieldLowImpactPriority() {}, recordClamdOutput() {},
        spawn: () => {
            const child = Object.assign(new EventEmitter(), {
                stdout: new EventEmitter(), stderr: new EventEmitter(), kills: 0,
                kill() { this.kills++; }
            });
            children.push(child);
            return child;
        }
    });
    vm.runInContext(ts.transpile(`let clamdManagement = Promise.resolve();\n${declarations("engines/clamav/server/daemon.ts", ["manageClamd", "applyClamdSettings"])}\nglobalThis.manage = manageClamd;`), context);
    const settings = { clamdPath: "clamd.exe", clamdConf: "clamd.conf", offloadToMemory: true, signature: "first" };
    await context.manage(settings);
    const old = children[0];
    await context.manage({ ...settings, signature: "replacement" });
    const replacement = children[1];
    assert.equal(old.kills, 1);
    old.emit("close", 0);
    old.emit("error", new Error("late failure from retired daemon"));
    assert.equal(context.clamdProcess, replacement);
    assert.equal(context.clamdConfSignature, "replacement");
    await Promise.all(Array.from({ length: 6 }, () => context.manage({ ...settings, signature: "replacement" })));
    assert.equal(children.length, 2, "Concurrent workers must share the replacement daemon");
    assert.equal(maxConcurrentConfigs, 1, "Daemon configuration changes must be serialized");
    replacement.emit("close", 0);
    assert.equal(context.clamdProcess, null, "The current daemon must still clear its own state on exit");
});

test("stopping/restarting Shield drops its old backlog instead of continuing to scan old downloads", async () => {
    const watchers: any[] = [], children: any[] = [];
    const context = serverTestContext({
        console: silent, path, isSimulated: false, shieldWatcher: null,
        pendingThreatStore: { fileAdded() {} }, shieldScanCache: { get() {} },
        activeJobs: {}, appendJobLogs() {}, createScanHeartbeat: () => 0,
        getResolvedSystemPaths: async () => ({ Downloads: "C:/Downloads" }),
        existingUniqueDirs: async (paths: string[]) => paths,
        createBuiltInScanPathSkipper: () => () => false,
        normalizePositiveNumber: (_value: any, fallback: number) => fallback,
        getScanIntensityProfile: () => ({ workers: 1 }),
        getFileFingerprint: async () => ({ size: 5, mtimeMs: 10, scannedAt: 20 }),
        displayFileName: path.basename,
        buildClamScanArgs: (_settings: any, _clamd: any, _type: any, file: string) => [file],
        getClamScanChildTimeoutMs: () => 60000,
        applyShieldLowImpactPriority() {}, setTimeout, clearTimeout, clearInterval() {},
        chokidar: { watch: () => {
            const watcher = Object.assign(new EventEmitter(), { closed: false, async close() { this.closed = true; } });
            watchers.push(watcher);
            return watcher;
        } },
        spawn: (_exe: string, args: string[]) => {
            const child = Object.assign(new EventEmitter(), { args, stdout: new EventEmitter(), stderr: new EventEmitter(), kill() {} });
            children.push(child);
            return child;
        }
    });
    vm.runInContext(ts.transpile(`${declarations("modules/shield/server/worker.ts", ["createStartShield"])}\nglobalThis.start = createStartShield(context);`), context);
    const settings = { shieldEnabled: true, monitorDownloads: true, clamscanPath: "clamscan.exe" };
    await context.start(settings);
    watchers[0].emit("add", "C:/Downloads/first.txt");
    watchers[0].emit("add", "C:/Downloads/second.txt");
    watchers[0].emit("add", "C:/Downloads/third.txt");
    await flush();
    assert.equal(children.length, 1);
    await context.start({ ...settings, shieldEnabled: false });
    assert.equal(watchers[0].closed, true);
    // An already-running scan may finish; it must never drain the retired queue.
    children[0].emit("error", new Error("scanner finished after Shield stopped"));
    await flush(); await flush();
    assert.equal(children.length, 1, "The retired queue must not launch its second or third file");
    watchers[0].emit("add", "C:/Downloads/late-old-event.txt");
    await flush();
    assert.equal(children.length, 1);
    await context.start(settings);
    watchers[1].emit("add", "C:/Downloads/real-new-download.txt");
    await flush();
    assert.equal(children.length, 2, "The new Shield run must still scan real downloads");
    children[1].emit("error", new Error("test scanner finished"));
    await flush();
    await context.start({ ...settings, shieldEnabled: false });
});
