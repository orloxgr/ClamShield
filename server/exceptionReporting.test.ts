import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import {
  exceptionQuery,
  reportStatus,
  updateReportStatus,
} from "../modules/exceptions/server/reporting";

test("legacy opened reports are unconfirmed; reset, confirmation and reopening preserve honest status", () => {
  const original = {
    threatName: "Test",
    sha256: "abc",
    falsePositiveOpenedAt: 123,
  };
  assert.equal(reportStatus(original), "unconfirmed");
  assert.equal(reportStatus(null), "not_applicable");
  const sent = updateReportStatus(original, "sent", 456);
  assert.equal(reportStatus(sent), "sent");
  assert.equal(sent.reportSentAt, 456);
  assert.equal(reportStatus(updateReportStatus(sent, "prepare", 789)), "sent");
  const reset = updateReportStatus(sent, "reset");
  assert.equal(reportStatus(reset), "not_reported");
  assert.equal(reset.reportSentAt, undefined);
  assert.equal(reset.threatName, "Test");
  assert.equal(reset.sha256, "abc");
  assert.equal(
    reportStatus(updateReportStatus(reset, "prepare")),
    "unconfirmed",
  );
  assert.throws(() => updateReportStatus(original, "accepted"));
  assert.equal(original.falsePositiveOpenedAt, 123);
});

test("SQL filters search the complete collection and consistently distinguish origins, providers and report states", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(`CREATE TABLE exceptions(normalized_path TEXT, path TEXT, added_at INTEGER, kind TEXT, origin TEXT);
            CREATE TABLE exception_reports(normalized_path TEXT, engine TEXT, threat_name TEXT, source TEXT,
                false_positive_opened_at INTEGER, false_positive_last_opened_at INTEGER, payload TEXT);`);
    const add = (
      key: string,
      name: string,
      origin: string,
      kind: string,
      report?: any,
    ) => {
      db.prepare("INSERT INTO exceptions VALUES (?,?,?,?,?)").run(
        key,
        name,
        new Date("2026-10-27T12:00:00").getTime(),
        kind,
        origin,
      );
      if (report)
        db.prepare("INSERT INTO exception_reports VALUES (?,?,?,?,?,?,?)").run(
          key,
          report.engine || "ClamAV",
          report.threatName,
          report.source || "scan",
          report.falsePositiveOpenedAt || null,
          null,
          JSON.stringify(report),
        );
    };
    add("a", "C:\\100%_file.exe", "unknown", "file", {
      threatName: "SaneSecurity.Test",
      source: "shield",
      falsePositiveOpenedAt: 1,
    });
    add("b", "C:\\other.exe", "unknown", "file", {
      threatName: "securiteinfo.Test",
      reportStatus: "sent",
        source: "shield",
        addedFrom: "scan",
    });
    add("c", "C:\\folder", "manual", "folder");
    add("d", "C:\\different.exe", "unknown", "file", {
      threatName: "Win.Test",
      reportStatus: "not_reported",
      falsePositiveOpenedAt: 1,
    });
    const find = (options: any) => {
      const q = exceptionQuery(options);
      return db
        .prepare(
          `SELECT e.normalized_path AS id FROM exceptions e LEFT JOIN exception_reports r ON e.normalized_path=r.normalized_path${q.where} ORDER BY ${q.orderBy}`,
        )
        .all(...q.params)
        .map((row) => row.id);
    };
    assert.deepEqual(
      find({
        provider: "SaneSecurity",
        origin: "shield",
        status: "unconfirmed",
      }),
      ["a"],
    );
    assert.deepEqual(find({ provider: "SecuriteInfo", status: "sent" }), ["b"]);
      assert.deepEqual(find({ origin: "scan", status: "sent" }), ["b"], "the place an exception was added is distinct from the detection source");
    assert.deepEqual(
      find({ origin: "manual", kind: "folder", status: "not_applicable" }),
      ["c"],
    );
    assert.deepEqual(find({ status: "not_reported" }), ["d"]);
    assert.deepEqual(
      find({ search: "100%_" }),
      ["a"],
      "LIKE wildcards in file paths are literal",
    );
    assert.deepEqual(
      find({ search: "Win.Test" }),
      ["d"],
      "search includes the detection name",
    );
    assert.deepEqual(find({ dateRange: "custom", dateFrom: "2026-10-28" }), []);
    assert.equal(
      find({
        dateRange: "custom",
        dateFrom: "2026-10-27",
        dateTo: "2026-10-27",
      }).length,
      4,
    );
    assert.throws(() =>
      exceptionQuery({
        dateRange: "custom",
        dateFrom: "2026-10-28",
        dateTo: "2026-10-27",
      }),
    );
    assert.deepEqual(find({ search: "' OR 1=1 --" }), []);
  } finally {
    db.close();
  }
});
