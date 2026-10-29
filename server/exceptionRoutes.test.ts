import { readBackendSource, serverTestContext } from "./testSupport";
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import vm from "node:vm";
import { DatabaseSync } from "node:sqlite";
import ts from "../scripts/test-source.cjs";
import { reportStatus, updateReportStatus } from "../modules/exceptions/server/reporting";
const source = readBackendSource();
const tree = ts.createSourceFile(
  "server.ts",
  source,
  ts.ScriptTarget.Latest,
  true,
);
function functionSource(name: string) {
  const node = tree.statements.find(
    (node) => ts.isFunctionDeclaration(node) && node.name?.text === name,
  );
  assert.ok(node);
  return node.getText(tree);
}
function fixture() {
  const db = new DatabaseSync(":memory:"),
    handlers: Record<string, any> = {};
  db.exec(`CREATE TABLE exceptions(normalized_path TEXT PRIMARY KEY, path TEXT);
        CREATE TABLE exception_reports(normalized_path TEXT PRIMARY KEY,original_path TEXT,threat_name TEXT,engine TEXT,source TEXT,yara_ruleset TEXT,sha256 TEXT,detected_at INTEGER,added_at INTEGER,false_positive_opened_at INTEGER,false_positive_last_opened_at INTEGER,false_positive_channels TEXT,payload TEXT);`);
  db.prepare("INSERT INTO exceptions VALUES (?,?)").run(
    "c:\\test.exe",
    "C:\\test.exe",
  );
  const context = serverTestContext({
    app: {
      post: (route: string, handler: any) => {
        handlers[route] = handler;
      },
    },
    getAppStateDb: () => db,
    ensureAppStateReady: async () => {},
    normalizedStatePath: (value: string) => value.toLowerCase(),
    asRecord: (value: any) => value || {},
    parseAppStateJson: (value: string) => JSON.parse(value),
    appStateJson: JSON.stringify,
    optionalNumber: (value: any) => value ?? null,
    reportStatus,
    updateReportStatus,
    existsSync: () => false,
    buildFalsePositiveReport: (report: any) => ({ details: report.threatName }),
    runAppStateTransaction: (_db: any, callback: any) => {
      db.exec("BEGIN");
      try {
        callback();
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  });
  let code = functionSource("insertExceptionReportRow");
  const visit = (node: any) => {
    if (
      ts.isCallExpression(node) &&
      node.expression.getText(tree) === "app.post" &&
      ts.isStringLiteral(node.arguments[0]) &&
      [
        "/api/exceptions/report-false-positive",
        "/api/exceptions/report-status",
        "/api/exceptions/delete-selected",
      ].includes(node.arguments[0].text)
    )
      code += `\n${node.getText(tree)};`;
    ts.forEachChild(node, visit);
  };
  visit(tree);
  vm.runInContext(
    ts.transpile(code, {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.None,
    }),
    context,
  );
  (context as any).insertExceptionReportRow(db, "c:\\test.exe", {
    originalPath: "C:\\test.exe",
    threatName: "Test.Signature",
    falsePositiveOpenedAt: 123,
  });
  const request = async (route: string, body: any) => {
    const result = {
      code: 200,
      body: null as any,
      status(code: number) {
        this.code = code;
        return this;
      },
      json(body: any) {
        this.body = body;
        return this;
      },
    };
    await handlers[route]({ body }, result);
    return result;
  };
  return {
    db,
    request,
    payload: () =>
      JSON.parse(
        String(
          db.prepare("SELECT payload FROM exception_reports").get()?.payload,
        ),
      ),
  };
}
test("report preview is read-only and resetting a legacy report persists across subsequent previews", async () => {
  const f = fixture();
  try {
    const before = f.payload();
    const preview = await f.request("/api/exceptions/report-false-positive", {
      path: "C:\\test.exe",
    });
    assert.equal(preview.code, 200);
    assert.equal(preview.body.report.reportStatus, "unconfirmed");
    assert.deepEqual(f.payload(), before);
    await f.request("/api/exceptions/report-status", {
      path: "C:\\test.exe",
      action: "reset",
    });
    assert.equal(f.payload().reportStatus, "not_reported");
    assert.equal(f.payload().falsePositiveOpenedAt, undefined);
    const again = await f.request("/api/exceptions/report-false-positive", {
      path: "C:\\test.exe",
    });
    assert.equal(again.body.report.reportStatus, "not_reported");
    assert.equal(again.body.details, "Test.Signature");
    assert.equal(
      f.db.prepare("SELECT COUNT(*) AS n FROM exceptions").get()?.n,
      1,
    );
  } finally {
    f.db.close();
  }
});
test("confirmation is persisted and deleted exceptions cannot subsequently be marked as sent", async () => {
  const f = fixture();
  try {
    await f.request("/api/exceptions/report-status", {
      path: "C:\\test.exe",
      action: "sent",
    });
    assert.equal(f.payload().reportStatus, "sent");
    assert.ok(f.payload().reportSentAt);
    const removed = await f.request("/api/exceptions/delete-selected", {
      paths: ["C:\\test.exe"],
    });
    assert.equal(removed.body.removedCount, 1);
    assert.equal(
      f.db.prepare("SELECT COUNT(*) AS n FROM exception_reports").get()?.n,
      0,
    );
    assert.equal(
      (
        await f.request("/api/exceptions/report-status", {
          path: "C:\\test.exe",
          action: "sent",
        })
      ).code,
      400,
    );
  } finally {
    f.db.close();
  }
});
