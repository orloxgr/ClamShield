import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import vm from "node:vm";
import ts from "typescript";
import { DatabaseSync } from "node:sqlite";
import { freshScanEvidence } from "./resultEvidence";

test("a fresh detection cannot inherit a previous file version's hashes, submission or verdict", () => {
  const previous = { sha256: "a".repeat(64), md5: "old-md5", virusTotalChecks: { resultsUploadAnalysisId: "old-id" }, virusTotalRefinement: { status: "blocked" } };
  const refreshed = { ...previous, ...freshScanEvidence({ threatName: "New local detection" }, previous) };
  assert.equal(refreshed.sha256, ""); assert.equal(refreshed.md5, "");
  assert.deepEqual(refreshed.virusTotalChecks, {}); assert.equal(refreshed.virusTotalRefinement, null);
  assert.deepEqual(freshScanEvidence({ sha256: previous.sha256 }, previous), {});
  assert.deepEqual(freshScanEvidence({ virusTotalRefinement: { status: "needs_review" } }, previous), {});
});

const source = fs.readFileSync("server.ts", "utf8");
const tree = ts.createSourceFile("server.ts", source, ts.ScriptTarget.Latest, true);
function productionFunction(name: string) {
  const node = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert.ok(node); return node.getText(tree);
}

test("removal deletes only the selected finding, preserves exclusions and records the decision once", async () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec("CREATE TABLE scan_results(id TEXT PRIMARY KEY, original_path TEXT); CREATE TABLE exceptions(path TEXT); CREATE TABLE history(payload TEXT);");
    db.prepare("INSERT INTO scan_results VALUES (?, ?)").run("old", "C:\\Chrome\\Preferences");
    db.prepare("INSERT INTO scan_results VALUES (?, ?)").run("other", "C:\\keep.exe");
    db.prepare("INSERT INTO exceptions VALUES (?)").run("C:\\existing-exception.exe");
    let handler: any, notified = 0;
    const context = vm.createContext({ app: { post: (_route: string, callback: any) => { handler = callback; } },
      ensureAppStateReady: async () => {}, getAppStateDb: () => db,
      scanResultsChangedHandler: () => { notified++; }, console,
      randomBytes: () => ({ toString: () => "test" }),
      insertHistoryRow: (_db: any, entry: any) => db.prepare("INSERT INTO history VALUES (?)").run(JSON.stringify(entry)),
      runAppStateTransaction: (_db: any, callback: any) => { db.exec("BEGIN"); try { callback(); db.exec("COMMIT"); } catch (error) { db.exec("ROLLBACK"); throw error; } }
    });
    let route = "";
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && node.expression.getText(tree) === "app.post" &&
          ts.isStringLiteral(node.arguments[0]) && node.arguments[0].text === "/api/results/:id/dismiss") route = node.getText(tree);
      ts.forEachChild(node, visit);
    };
    visit(tree); assert.ok(route);
    vm.runInContext(ts.transpile(route), context);
    const response = { code: 200, body: null as any, status(code: number) { this.code = code; return this; }, json(body: any) { this.body = body; return this; } };
    await handler({ params: { id: "old" } }, response);
    assert.equal(response.code, 200); assert.equal(response.body.removed, true);
    assert.deepEqual(db.prepare("SELECT id FROM scan_results").all().map(row => row.id), ["other"]);
    assert.equal(db.prepare("SELECT path FROM exceptions").get()!.path, "C:\\existing-exception.exe");
    const history = JSON.parse(String(db.prepare("SELECT payload FROM history").get()!.payload));
    assert.equal(history.type, "results-dismiss"); assert.match(history.actionTaken, /File kept; no exception added/);
    await handler({ params: { id: "old" } }, response);
    assert.equal(response.body.removed, false);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM history").get()!.n, 1);
    assert.ok(notified > 0);
  } finally { db.close(); }
});

test("a delayed VirusTotal response cannot overwrite a newer detection or restore a dismissed finding", async () => {
  let row: any = { timestamp: 2 }, writes = 0;
  const context = vm.createContext({ ensureAppStateReady: async () => {}, scanResultSelectSql: () => "SELECT * FROM scan_results",
    getAppStateDb: () => ({ prepare: () => ({ get: () => row }) }), mapScanResultRow: (value: any) => value,
    insertScanResultRow: () => { writes++; } });
  vm.runInContext(ts.transpile(productionFunction("persistVirusTotalResult")), context);
  await context.persistVirusTotalResult({ id: "same-path", timestamp: 1 }); assert.equal(writes, 0);
  row = null; await context.persistVirusTotalResult({ id: "dismissed", timestamp: 1 }); assert.equal(writes, 0);
  row = { timestamp: 1 }; await context.persistVirusTotalResult({ id: "same", timestamp: 1 }); assert.equal(writes, 1);
});
