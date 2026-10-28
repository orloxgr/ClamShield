import {englishText, t, localizeText} from "../shared/localization/runtime";
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { EventEmitter } from "node:events";
import ts from "typescript";

const source = fs.readFileSync("electron-main.cjs", "utf8");
const tree = ts.createSourceFile("electron-main.cjs", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
function functionSource(name: string) {
    const node = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
    assert.ok(node); return node.getText(tree);
}
const flush = () => new Promise(resolve => setImmediate(resolve));

function pollingFixture() {
    let now = 0;
    const failures: any[] = [];
    const timers: Array<{ callback: () => void; delay: number }> = [];
    const requests: any[] = [], navigations: string[] = [];
    const window = Object.assign(new EventEmitter(), {
        url: "file:///app/public/startup.html", destroyed: false,
        isDestroyed: () => window.destroyed,
        webContents: { getURL: () => window.url },
        loadURL: async (url: string) => { navigations.push(url); window.url = url; }
    });
    const context = vm.createContext({ englishText, t, localizeText, getDesktopLanguage: () => {},
        Date: { now: () => now },
        showWindowFailure: (_window: any, error: any) => failures.push(error),
        isQuiting: false, apiHeaders: () => ({ "X-ClamShield-Session": "test-session" }),
        setTimeout: (callback: () => void, delay: number) => { const timer = { callback, delay }; timers.push(timer); return timer; },
        clearTimeout: (timer: any) => { const i = timers.indexOf(timer); if (i >= 0) timers.splice(i, 1); },
        http: { get: (options: any, receive: (response: any) => void) => {
            const request = Object.assign(new EventEmitter(), {
                options, receive, destroyed: false, timeout: null as any,
                setTimeout: (ms: number, callback: () => void) => { request.timeout = { ms, callback }; },
                destroy: () => { request.destroyed = true; request.emit("error", new Error("closed")); }
            });
            requests.push(request); return request;
        } }
    });
    vm.runInContext(`${functionSource("waitForWindowBackend")}\nglobalThis.wait = waitForWindowBackend;`, context);
    const reply = (index: number, statusCode = 200) => {
        const response = Object.assign(new EventEmitter(), { statusCode, resume: () => {} });
        requests[index].receive(response); response.emit("end");
    };
    context.wait(window, 1234);
    return { window, timers, requests, navigations, reply, failures, advance: (ms: number) => { now += ms; } };
}

test("a backend that never becomes ready surfaces a diagnostic instead of waiting forever", () => {
    const f = pollingFixture();
    f.requests[0].emit("error", new Error("ECONNREFUSED"));
    f.advance(45000);
    f.timers.shift()!.callback();
    assert.equal(f.failures[0].code, "BACKEND_TIMEOUT");
    assert.equal(f.requests.length, 1);
    assert.equal(f.navigations.length, 0);
});

test("the startup shell stays visible through connection failures and opens the app only when the lightweight endpoint is ready", async () => {
    const f = pollingFixture();
    assert.equal(f.requests[0].options.path, "/api/ready");
    assert.equal(f.requests[0].options.headers["X-ClamShield-Session"], "test-session");
    f.requests[0].emit("error", new Error("ECONNREFUSED"));
    assert.equal(f.navigations.length, 0); assert.equal(f.timers.length, 1);
    f.timers.shift()!.callback(); f.reply(1, 503);
    assert.equal(f.navigations.length, 0);
    f.timers.shift()!.callback(); f.reply(2);
    await flush();
    assert.deepEqual(f.navigations, ["http://127.0.0.1:1234"]);
    assert.ok(f.requests.every(request => request.options.path !== "/api/status"));
});

test("startup polling times out stalled requests and stops when the window closes or another app route is opened", () => {
    const f = pollingFixture();
    assert.equal(f.requests[0].timeout.ms, 1500);
    f.requests[0].timeout.callback();
    assert.equal(f.requests[0].destroyed, true);
    f.window.url = "http://127.0.0.1:1234/quarantine";
    f.timers.shift()!.callback();
    assert.equal(f.requests.length, 1); assert.equal(f.navigations.length, 0);
    const closing = pollingFixture(); closing.window.emit("closed");
    assert.equal(closing.requests[0].destroyed, true);
    assert.equal(closing.timers.length, 0);
});

test("the main window uses a dark background and paints its bundled local page before switching to the backend", async () => {
    for (const hidden of [false, true]) {
        let resolveFile!: () => void;
        const fileLoaded = new Promise<void>(resolve => { resolveFile = resolve; });
        const events: string[] = [];
        class Window extends EventEmitter {
            options: any;
            webContents = Object.assign(new EventEmitter(), { setWindowOpenHandler: () => {} });
            constructor(options: any) { super(); this.options = options; }
            loadFile(file: string) { events.push(file); return fileLoaded; }
            isDestroyed() { return false; }
        }
        const context = vm.createContext({ englishText, t, localizeText, getDesktopLanguage: () => {},
            BrowserWindow: Window, path, __dirname: "/app", mainWindow: null,
            attachWindowLogging: () => {}, getPublicAssetPath: (file: string) => `/app/public/${file}`,
            waitForWindowBackend: () => events.push("backend-probe"), console
        });
        vm.runInContext(`${functionSource("createWindow")}\nglobalThis.create = createWindow;`, context);
        const starting = context.create(1234, hidden);
        assert.equal(context.mainWindow.options.backgroundColor, "#020617");
        assert.equal(context.mainWindow.options.show, !hidden);
        resolveFile(); await flush();
        assert.deepEqual(events, ["/app/public/startup.html"], "do not replace the shell before it is painted");
        context.mainWindow.emit("ready-to-show"); await starting;
        assert.deepEqual(events, ["/app/public/startup.html", "backend-probe"]);
    }
});

test("the actual ready handler waits for the startup paint before loading backend code and preserves minimized launch", async () => {
    let handler = "";
    const visit = (node: ts.Node) => {
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.expression.getText(tree) === "app" &&
            node.expression.name.text === "on" && node.arguments[0] && ts.isStringLiteral(node.arguments[0]) && node.arguments[0].text === "ready") {
            handler = node.arguments[1].getText(tree);
        }
        ts.forEachChild(node, visit);
    };
    visit(tree); assert.ok(handler);
    let paint!: () => void;
    const painted = new Promise<void>(resolve => { paint = resolve; });
    const events: string[] = [];
    const context = vm.createContext({ englishText, t, localizeText, getDesktopLanguage: () => {},
        gotSingleInstanceLock: true, getFreePort: async () => 1234, currentApiPort: null, readAppSettings: () => ({}),
        process: { argv: ["ClamShield.exe", "--minimized"] }, app: { getVersion: () => "test" }, debugLoggingEnabled: false,
        writeMainLog: () => {}, console: { log: () => {} }, setApiSessionCookie: async () => {}, createTray: () => {},
        createWindow: async (_port: number, hidden: boolean) => { assert.equal(hidden, true); events.push("shell"); await painted; },
        isQuiting: false, mainWindow: { isDestroyed: () => false }, startServer: () => events.push("backend"),
        startContextMenuBridge: () => {}, connectApiEvents: () => {}, pollAppUpdates: () => {}, pollScheduledScans: () => {},
        handleContextMenuRequest: async () => {}
    });
    vm.runInContext(`globalThis.ready = ${handler};`, context);
    const starting = context.ready(); await flush();
    assert.deepEqual(events, ["shell"]);
    paint(); await starting;
    assert.deepEqual(events, ["shell", "backend"]);
});
