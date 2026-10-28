import { readBackendSource, serverTestContext } from "./testSupport";
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import vm from "node:vm";
import ts from "typescript";
import { createRequire } from "node:module";
import { EventEmitter } from "node:events";
import { PendingThreats } from "../modules/shield/server/pendingThreats";
const require = createRequire(import.meta.url);
const { notificationLayout } = require("../public/notification-layout.cjs");
const fingerprint = { size: 308, mtimeMs: 100 };
const clam = { id: "clam", originalPath: "D:\\Downloads\\eicar.zip", threatName: "Eicar", engine: "ClamAV" };
const vt = { ...clam, id: "vt", originalPath: "d:/Downloads/eicar.zip", threatName: "VirusTotal: 57 detections", engine: "VirusTotal" };

test("independent providers share one decision, retaining both detection records", () => {
    const store = new PendingThreats();
    const first = store.register(clam, fingerprint);
    const second = store.register(vt, fingerprint);
    assert.equal(first, second);
    assert.equal(store.items.length, 1);
    assert.equal(second.id, "clam");
    assert.deepEqual(second.detections.map((d: any) => d.engine), ["ClamAV", "VirusTotal"]);
    store.register(vt, fingerprint);
    assert.equal(second.detections.length, 2);
});

test("completed decisions suppress late cloud reports but allow a new file at the same path", () => {
    const store = new PendingThreats();
    store.register(clam, fingerprint);
    store.resolve("clam");
    assert.equal(store.wasResolved("clam"), true);
    assert.equal(store.register(vt, fingerprint), null);
    assert.equal(store.register(vt, null), null);
    assert.ok(store.register({ ...clam, id: "new" }, { ...fingerprint, mtimeMs: 200 }));
    assert.equal(store.items.length, 1);
});

test("resolving one alert while another is added does not remove the wrong file", () => {
    const store = new PendingThreats();
    store.register(clam, fingerprint);
    store.register({ ...clam, id: "second", originalPath: "D:\\other.zip" }, fingerprint);
    store.resolve("clam");
    store.resolve("clam");
    assert.equal(store.items[0].id, "second");
});

test("recreating a downloaded file starts a new incident even with identical size and mtime", () => {
    const store = new PendingThreats();
    store.register(clam, fingerprint);
    store.resolve("clam");
    store.fileAdded(clam.originalPath);
    assert.ok(store.register({ ...clam, id: "download-again" }, fingerprint));
});

test("a file removed by another program still has a reviewable detection", () => {
    const store = new PendingThreats();
    assert.ok(store.register(clam, null));
});

test("notification positions use monitor work areas, including negative origins and DPI-scaled sizes", () => {
    const area = { x: -1536, y: 80, width: 1536, height: 824 };
    const sizes = [{ width: 460, height: 240 }, { width: 440, height: 180 }];
    const [a, b] = notificationLayout(area, sizes);
    assert.equal(a.x + a.width, -20);
    assert.equal(a.y + a.height, 884);
    assert.ok(b.y + b.height < a.y);
    const [remaining] = notificationLayout(area, [sizes[1]]);
    assert.equal(remaining.y + remaining.height, 884);
});

test("notification overflow waits for a free slot instead of placing windows off-screen", () => {
    const area = { x: 200, y: -600, width: 800, height: 600 };
    const layout = notificationLayout(area, Array(10).fill({ width: 460, height: 240 }));
    assert.equal(layout.filter(Boolean).length, 2);
    for (const rect of layout.filter(Boolean)) {
        assert.ok(rect.x >= area.x && rect.y >= area.y);
        assert.ok(rect.x + rect.width <= area.x + area.width);
        assert.ok(rect.y + rect.height <= area.y + area.height);
    }
});

test("native notification controller selects the active monitor, reflows after close and handles unplugging", () => {
    const source = fs.readFileSync("electron-main.cjs", "utf8");
    const tree = ts.createSourceFile("electron-main.cjs", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    const code = ["reflowNotifications", "trackNotification"].map(name => {
        const node = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
        assert.ok(node); return node.getText(tree);
    }).join("\n");
    const primary = { id: 1, workArea: { x: 0, y: 0, width: 1920, height: 1040 } };
    const secondary = { id: 2, workArea: { x: -1280, y: 100, width: 1280, height: 680 } };
    let displays = [primary, secondary];
    const screen = Object.assign(new EventEmitter(), {
        getAllDisplays: () => displays, getPrimaryDisplay: () => primary,
        getCursorScreenPoint: () => ({ x: -400, y: 400 }),
        getDisplayNearestPoint: () => secondary
    });
    const context = serverTestContext({ require: () => ({ screen }), notificationWindows: new Map(), notificationScreenListeners: false, notificationLayout });
    vm.runInContext(code, context);
    function window() {
        let bounds: any = { width: 460, height: 240 }, visible = false;
        return Object.assign(new EventEmitter(), {
            isDestroyed: () => false, getBounds: () => bounds,
            setBounds: (b: any) => bounds = b, isVisible: () => visible,
            showInactive: () => visible = true, hide: () => visible = false
        });
    }
    const first = window(), second = window();
    context.trackNotification(first); first.emit("ready-to-show");
    context.trackNotification(second); second.emit("ready-to-show");
    assert.equal(first.getBounds().x + first.getBounds().width, -20);
    assert.equal(first.getBounds().y + first.getBounds().height, 760);
    assert.ok(second.getBounds().y < first.getBounds().y);
    first.emit("closed");
    assert.equal(second.getBounds().y + second.getBounds().height, 760);
    displays = [primary]; screen.emit("display-removed");
    assert.equal(second.getBounds().x + second.getBounds().width, 1900);
    assert.equal(second.getBounds().y + second.getBounds().height, 1020);
});

// Exercise the production action route without starting scanners or touching user data.
function actionFixture() {
    const source = readBackendSource();
    const tree = ts.createSourceFile("server.ts", source, ts.ScriptTarget.Latest, true);
    let route = "";
    function visit(node: ts.Node) {
        if (ts.isCallExpression(node) && node.expression.getText(tree) === "app.post" &&
            node.arguments[0]?.getText(tree) === '"/api/pending-threats/:id/action"') route = node.getText(tree);
        ts.forEachChild(node, visit);
    }
    visit(tree); assert.ok(route);
    const store = new PendingThreats(); store.register(clam, fingerprint); store.register(vt, fingerprint);
    const saved: any[] = [], events: any[] = [], quarantines: any[] = [];
    let handler: any, error: any, block: Promise<void> | null = null;
    const context = serverTestContext({
        app: { post: (_path: string, callback: any) => handler = callback },
        pendingThreatStore: store, pendingThreats: store.items, pendingThreatActions: new Map(),
        settings: { quarantineDir: "isolated", yaraRuleset: "core" },
        quarantineFile: async (...args: any[]) => { quarantines.push(args); if (block) await block; if (error) throw error; return { fileName: "isolated", metadata: {} }; },
        getQuarantineMap: async () => ({}), saveQuarantineMap: async () => {},
        getExceptions: async () => [], saveExceptions: async () => {}, rememberExceptionDetection: async () => {},
        addScanResult: async (result: any) => saved.push(result), normalizeYaraRuleset: (v: any) => v,
        sendApiEvent: (...args: any[]) => events.push(args), console: { error: () => {} }
    });
    vm.runInContext(ts.transpile(route, { target: ts.ScriptTarget.ES2022 }), context);
    const action = async (action: string, id = "clam") => {
        const response = { code: 200, body: null as any, status(code: number) { this.code = code; return this; }, json(body: any) { this.body = body; return this; } };
        await handler({ params: { id }, body: { action } }, response); return response;
    };
    return { store, saved, events, quarantines, action, fail: (e: any) => error = e, block: (p: Promise<void>) => block = p };
}

test("one quarantine resolves all provider evidence and repeated clicks do not move a file twice", async () => {
    const f = actionFixture();
    assert.equal((await f.action("quarantine")).body.success, true);
    assert.equal(f.store.items.length, 0);
    assert.equal(f.events[0][0], "threat-resolved");
    assert.equal((await f.action("quarantine")).body.alreadyResolved, true);
    assert.equal(f.quarantines.length, 1);
});

test("concurrent conflicting actions cannot act on the same file twice", async () => {
    const f = actionFixture(); let release!: () => void;
    f.block(new Promise<void>(resolve => release = resolve));
    const first = f.action("quarantine");
    assert.equal((await f.action("exception")).code, 409);
    release(); await first;
    assert.equal(f.quarantines.length, 1);
});

test("a vanished file returns an actionable message and can still be saved to Results", async () => {
    const f = actionFixture();
    f.fail(Object.assign(new Error("copyfile ENOENT"), { code: "ENOENT" }));
    const failed = await f.action("quarantine");
    assert.equal(failed.body.code, "FILE_UNAVAILABLE");
    assert.match(failed.body.error, /Decide later/);
    assert.equal(f.store.items.length, 1);
    assert.equal((await f.action("results")).body.success, true);
    assert.equal(f.saved.length, 2);
    assert.deepEqual(f.saved.map(result => result.engine), ["ClamAV", "VirusTotal"]);
});
