import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import vm from "node:vm";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import ts from "typescript";
const require = createRequire(import.meta.url);
const {
  sanitize,
  createDiagnostic,
  errorHtml,
} = require("../public/desktop-diagnostics.cjs");
const source = fs.readFileSync("electron-main.cjs", "utf8");
const tree = ts.createSourceFile(
  "electron-main.cjs",
  source,
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.JS,
);
function functionSource(name: string) {
  const node = tree.statements.find(
    (node) => ts.isFunctionDeclaration(node) && node.name?.text === name,
  );
  assert.ok(node);
  return node.getText(tree);
}

test("diagnostics redact credentials and URL queries and safely render error text", () => {
  const record = createDiagnostic(
    {
      stage: "Loading interface",
      code: "HTTP 404",
      message: '<script>alert("bad")</script>',
      url: "http://127.0.0.1:1234/scan?token=private#secret",
      details: {
        apiKey: "private",
        cookie: "private",
        message: "Session known-secret password=private",
      },
    },
    { version: "test", os: "Windows" },
    ["known-secret"],
  );
  assert.ok(record.id);
  assert.ok(record.time);
  assert.equal(record.url, "http://127.0.0.1:1234/scan");
  assert.ok(!JSON.stringify(record).includes("private"));
  assert.ok(!JSON.stringify(record).includes("known-secret"));
  const html = errorHtml(record);
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(!html.includes('<script>alert("bad")'));
  for (const label of [
    "Retry",
    "Copy diagnostics",
    "Open logs folder",
    "Technical details",
    "HTTP 404",
  ])
    assert.ok(html.includes(label));
  assert.equal(sanitize(new Error("token=secret")).message, "token=[redacted]");
});

function loggingFixture() {
  const failures: any[] = [],
    logs: any[] = [],
    timers: any[] = [];
  const win = Object.assign(new EventEmitter(), {
    webContents: Object.assign(new EventEmitter(), {
      executeJavaScript: async (_code: string): Promise<any> => ({ mounted: false, readyState: "complete" }),
    }),
    isDestroyed: () => false,
  });
  const context = vm.createContext({
    mainWindow: win,
    currentApiPort: 1234,
    debugLoggingEnabled: false,
    windowDiagnostics: new WeakMap(),
    writeMainLog: (...args: any[]) => logs.push(args),
    showWindowFailure: (_win: any, failure: any) => failures.push(failure),
    clearTimeout: () => {},
    setTimeout: (callback: any, delay: number) => {
      timers.push({ callback, delay });
      return 1;
    },
  });
  vm.runInContext(
    `${functionSource("verifyWindowStartup")}\n${functionSource("attachWindowLogging")}\nglobalThis.attach = attachWindowLogging;\nglobalThis.verify = verifyWindowStartup;`,
    context,
  );
  context.attach(win, "Main window");
  return { win, failures, logs, timers, verify: context.verify };
}
test("HTTP errors, resource navigation failures and renderer crashes surface with debug logging disabled", () => {
  const f = loggingFixture();
  f.win.webContents.emit("did-navigate", {}, "http://127.0.0.1:1234/", 404);
  assert.equal(f.failures[0].code, "HTTP 404");
  f.win.webContents.emit(
    "did-fail-load",
    {},
    -105,
    "Name not resolved",
    "http://127.0.0.1:1234/",
    true,
  );
  assert.equal(f.failures[1].code, -105);
  assert.ok(f.logs.length);
  f.win.webContents.emit(
    "did-fail-load",
    {},
    -3,
    "Aborted",
    "http://127.0.0.1:1234/",
    true,
  );
  assert.equal(
    f.failures.length,
    2,
    "intentional navigation replacement is ignored",
  );
  f.win.webContents.emit("console-message", {
    level: "error",
    message: "Missing module",
    sourceId: "index.js",
  });
  assert.ok(JSON.stringify(f.logs).includes("Missing module"));
  f.win.webContents.emit(
    "render-process-gone",
    {},
    { reason: "crashed", exitCode: 1 },
  );
  assert.equal(f.failures[2].code, "RENDERER_crashed");
});
test("an HTTP page that never mounts the app times out; a mounted interface does not", async () => {
  const f = loggingFixture();
  f.win.webContents.emit(
    "did-start-navigation",
    {},
    "http://127.0.0.1:1234/",
    false,
    true,
  );
  assert.equal(f.timers[0].delay, 30000);
  await f.timers[0].callback();
  assert.equal(f.failures[0].code, "UI_START_TIMEOUT");
  const mounted = loggingFixture();
  mounted.win.webContents.emit(
    "did-start-navigation",
    {},
    "http://127.0.0.1:1234/exceptions",
    false,
    true,
  );
  (mounted.win as any).uiMounted = true;
  await mounted.timers[0].callback();
  assert.equal(mounted.failures.length, 0);
});

test("navigating between React pages must not restart the startup watchdog", () => {
  const f = loggingFixture();
  (f.win as any).uiMounted = true;
  for (const route of ["/results", "/", "/exceptions"]) {
    f.win.webContents.emit("did-start-navigation", {}, `http://127.0.0.1:1234${route}`, true, true);
    assert.equal((f.win as any).uiMounted, true);
    assert.equal(f.timers.length, 0);
  }
  assert.equal(f.failures.length, 0);
});

test("current Electron same-document event details and subframes preserve readiness", () => {
  const f = loggingFixture();
  (f.win as any).uiMounted = true;
  f.win.webContents.emit("did-start-navigation", { url: "http://127.0.0.1:1234/results", isSameDocument: true, isMainFrame: true });
  f.win.webContents.emit("did-start-navigation", { url: "http://127.0.0.1:1234/child", isSameDocument: false, isMainFrame: false });
  assert.equal((f.win as any).uiMounted, true);
  assert.equal(f.timers.length, 0);
});

test("a rendered interface without an IPC acknowledgement is never replaced by a timeout page", async () => {
  const f = loggingFixture();
  f.win.webContents.executeJavaScript = async () => ({ mounted: true, readyState: "complete" });
  f.win.webContents.emit("did-start-navigation", {}, "http://127.0.0.1:1234/", false, true);
  await f.timers[0].callback();
  assert.equal((f.win as any).uiMounted, true);
  assert.equal(f.failures.length, 0);
});

test("an inconclusive probe and obsolete document timers cannot interrupt the current interface", async () => {
  const f = loggingFixture();
  f.win.webContents.emit("did-start-navigation", {}, "http://127.0.0.1:1234/", false, true);
  f.win.webContents.emit("did-start-navigation", {}, "http://127.0.0.1:1234/results", false, true);
  await f.timers[0].callback();
  assert.equal(f.failures.length, 0);
  f.win.webContents.executeJavaScript = async () => { throw new Error("Readiness unavailable"); };
  await f.timers[1].callback();
  assert.equal(f.failures.length, 0);
  assert.ok(JSON.stringify(f.logs).includes("Could not verify interface readiness"));
});
test("failure page display stops pending retries, logs once and preserves a readable fallback", async () => {
  const records = new WeakMap(),
    logs: any[] = [],
    urls: string[] = [];
  let stopped = false;
  const win = {
    isDestroyed: () => false,
    stopBackendWait: () => {
      stopped = true;
    },
    loadURL: async (url: string) => {
      urls.push(url);
    },
  };
  const context = vm.createContext({
    isQuiting: false,
    windowDiagnostics: records,
    app: { getVersion: () => "test" },
    os: { platform: () => "win32", release: () => "test", arch: () => "x64" },
    apiSessionToken: "secret-session",
    contextMenuBridgeToken: "secret-bridge",
    createDiagnostic,
    errorHtml,
    clearTimeout: () => {},
    writeMainLog: (...args: any[]) => logs.push(args),
  });
  vm.runInContext(
    `${functionSource("showWindowFailure")}\nglobalThis.show=showWindowFailure;`,
    context,
  );
  context.show(win, {
    code: "HTTP 404",
    message: "Could not load",
    details: "secret-session",
  });
  context.show(win, { code: "DUPLICATE", message: "Ignored" });
  assert.equal(urls.length, 1);
  assert.equal(stopped, true);
  assert.equal(logs.length, 1);
  const html = decodeURIComponent(urls[0].split(",").slice(1).join(","));
  assert.ok(html.includes("ClamShield could not load"));
  assert.ok(!html.includes("secret-session"));
});

test("the preload captures missing scripts before React and does not recurse on the diagnostics page", async () => {
  const run = (protocol: string) => {
    const events: Record<string, any> = {},
      calls: any[] = [];
    const context = vm.createContext({
      location: { protocol },
      window: {
        addEventListener: (name: string, handler: any) => {
          events[name] = handler;
        },
      },
      require: () => ({
        contextBridge: { exposeInMainWorld: () => {} },
        ipcRenderer: {
          invoke: async (...args: any[]) => {
            calls.push(args);
          },
        },
      }),
    });
    vm.runInContext(
      fs.readFileSync("public/desktop-preload.cjs", "utf8"),
      context,
    );
    events.error({
      target: {
        tagName: "SCRIPT",
        src: "http://127.0.0.1:1234/assets/missing.js",
      },
    });
    return calls;
  };
  assert.equal(run("http:")[0][1].code, "RESOURCE_LOAD_FAILED");
  assert.equal(run("data:").length, 0);
});

test("desktop diagnostics IPC rejects other frames and unsafe external protocols", async () => {
  const handlers: Record<string, any> = {},
    opened: string[] = [];
  const frame = {},
    sender = {
      mainFrame: frame,
      getURL: () => "http://127.0.0.1:1234/exceptions",
    };
  const win = { isDestroyed: () => false, webContents: sender };
  const context = vm.createContext({
    URL,
    require,
    mainWindow: win,
    currentApiPort: 1234,
    windowDiagnostics: new WeakMap(),
    getPublicAssetPath: () => "/app/public/startup.html",
    ipcMain: {
      handle: (channel: string, handler: any) => {
        handlers[channel] = handler;
      },
    },
    shell: {
      openExternal: async (url: string) => {
        opened.push(url);
      },
    },
  });
  let code = functionSource("trustedMainSender");
  const visit = (node: ts.Node) => {
    if (
      ts.isCallExpression(node) &&
      node.expression.getText(tree) === "ipcMain.handle" &&
      ts.isStringLiteral(node.arguments[0]) &&
      node.arguments[0].text === "clamshield-open-external"
    )
      code += `\n${node.getText(tree)};`;
    ts.forEachChild(node, visit);
  };
  visit(tree);
  vm.runInContext(code, context);
  const open = handlers["clamshield-open-external"];
  await assert.rejects(
    open({ sender, senderFrame: {} }, "https://example.invalid"),
    /Untrusted/,
  );
  await assert.rejects(
    open({ sender, senderFrame: frame }, "file:///C:/Windows/test.exe"),
    /Unsupported/,
  );
  await open({ sender, senderFrame: frame }, "https://example.invalid/report");
  assert.deepEqual(opened, ["https://example.invalid/report"]);
});

test("copy diagnostics waits for the asynchronous Electron clipboard and reports write failures", async () => {
  const handlers: Record<string, any> = {};
  const frame = {}, sender = { mainFrame: frame, getURL: () => "http://127.0.0.1:1234/" };
  const win = { isDestroyed: () => false, webContents: sender };
  const diagnostics = new WeakMap(); diagnostics.set(win, { diagnostic: { id: "test" } });
  let release!: () => void;
  const pending = new Promise<void>(resolve => release = resolve);
  const clipboard = { writeText: async (_text: string) => pending };
  const context = vm.createContext({
    URL, require, mainWindow: win, currentApiPort: 1234, windowDiagnostics: diagnostics,
    getPublicAssetPath: () => "/app/public/startup.html", clipboard,
    ipcMain: { handle: (name: string, callback: any) => handlers[name] = callback }
  });
  let code = functionSource("trustedMainSender");
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(tree) === "ipcMain.handle" && node.arguments[0]?.getText(tree) === "'clamshield-copy-diagnostics'") code += `\n${node.getText(tree)};`;
    ts.forEachChild(node, visit);
  };
  visit(tree); vm.runInContext(code, context);
  let completed = false;
  const copy = handlers["clamshield-copy-diagnostics"]({ sender, senderFrame: frame }).then(() => completed = true);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(completed, false);
  release(); await copy;
  assert.equal(completed, true);
  clipboard.writeText = async () => { throw new Error("Clipboard unavailable"); };
  await assert.rejects(handlers["clamshield-copy-diagnostics"]({ sender, senderFrame: frame }), /Clipboard unavailable/);
});
