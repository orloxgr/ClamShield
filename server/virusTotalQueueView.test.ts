import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { VirusTotalScanQueue } from "../addons/virustotal/server/virusTotalScanQueue";
import { describeQueueItem, getVirusTotalQueuePage } from "../addons/virustotal/server/virusTotalQueueView";
import { describeVirusTotalResult } from "../addons/virustotal/shared/state";

const settings = { virusTotalAutoRefineEnabled: true, virusTotalShieldBackgroundCheckEnabled: true };
const runtime = { enabled: true, configured: true, now: 100 };
function fixture() {
  const db = new DatabaseSync(":memory:");
  const queue = new VirusTotalScanQueue(db);
  db.exec(`CREATE TABLE scan_results(id TEXT PRIMARY KEY, source TEXT, original_path TEXT, timestamp INTEGER,
    virus_total_refinement_status TEXT, virus_total_checks TEXT);`);
  const result = (id: string, status = "", checks = {}, source = "manual") => db.prepare("INSERT INTO scan_results VALUES (?, ?, ?, ?, ?, ?)")
    .run(id, source, `D:\\Downloads\\${id}.zip`, 1, status, JSON.stringify(checks));
  return { db, queue, result };
}

test("one paginated view covers Results, Shield and scan files without writing or contacting VirusTotal", () => {
  const f = fixture();
  try {
    f.result("pending"); f.result("unknown", "unknown");
    f.result("uploaded", "unknown", { resultsUploadedUnknownHash: "abc", resultsUploadCheckAfter: 500, resultsUploadFollowupCount: 1 });
    f.result("stopped", "unknown", { resultsUploadedUnknownHash: "abc", resultsUploadCheckAfter: 500, resultsUploadFollowupCount: 5 });
    f.queue.start("scan1", "folder", "D:\\folder");
    f.queue.addFiles("scan1", Array.from({ length: 103 }, (_, i) => ({ filePath: `D:\\folder\\file-${i}.exe`, size: 1, mtimeMs: 1 })));
    f.queue.finishEnumeration("scan1");
    const shield = [{ id: "shield:1", filePath: "D:\\Shield\\test.zip", phase: "needs_upload", createdAt: 2 }];
    const before = f.db.prepare("SELECT total_changes() AS n").get()!.n;
    const first: any = getVirusTotalQueuePage(f.db, settings, shield, runtime);
    assert.deepEqual(first.counts, { results: 4, shield: 1, scan: 103 });
    assert.equal(first.total, 108); assert.equal(first.items.length, 50);
    const last: any = getVirusTotalQueuePage(f.db, settings, shield, runtime, { page: 3 });
    assert.equal(last.items.length, 8);
    const uploaded: any = getVirusTotalQueuePage(f.db, settings, shield, runtime, { search: "UPLOADED", source: "results" });
    assert.equal(uploaded.total, 1); assert.equal(uploaded.items[0].state, "Awaiting analysis");
    assert.equal(uploaded.items[0].nextAttemptAt, 500);
    assert.equal(f.db.prepare("SELECT total_changes() AS n").get()!.n, before);
    const empty: any = getVirusTotalQueuePage(f.db, settings, shield, runtime, { search: "%" });
    assert.equal(empty.total, 0, "search characters are literal, not SQL wildcards");
  } finally { f.db.close(); }
});

test("disabled automatic refinement does not claim that unrequested Results checks are queued", () => {
  const f = fixture();
  try {
    f.result("manual"); f.result("shield", "", {}, "shield");
    const result: any = getVirusTotalQueuePage(f.db, { ...settings, virusTotalAutoRefineEnabled: false }, [], runtime);
    assert.equal(result.total, 1); assert.equal(result.items[0].recordId, "shield");
  } finally { f.db.close(); }
});

test("active checks, upload queues, paused scans, confirmation and disabled cloud remain distinct", () => {
  const base = { source: "scan", recordId: "4", phase: "pending", enumerated: 1 };
  assert.equal(describeQueueItem(base, { ...runtime, activeScanId: 4 }).state, "Checking hash");
  assert.equal(describeQueueItem({ ...base, phase: "needs_upload" }, runtime).state, "Upload queued");
  assert.equal(describeQueueItem({ ...base, phase: "needs_upload" }, { ...runtime, activeScanId: 4 }).state, "Uploading file");
  assert.equal(describeQueueItem({ ...base, paused: 1 }, runtime).state, "Paused");
  assert.equal(describeQueueItem({ ...base, requiresConfirmation: 1 }, runtime).state, "Waiting for confirmation");
  assert.equal(describeQueueItem(base, { ...runtime, enabled: false }).state, "Cloud checks disabled");
  assert.equal(describeQueueItem(base, { ...runtime, configured: false }).state, "Waiting for API key");
  const scheduled = describeQueueItem(base, { ...runtime, lookupNextAt: 1000 });
  assert.equal(scheduled.state, "Hash check scheduled"); assert.equal(scheduled.nextAttemptAt, 1000);
  const retry = describeQueueItem({ ...base, source: "results" }, { ...runtime, resultsNextAt: 1000, resultsWaitReason: "Daily quota reached" });
  assert.equal(retry.state, "Waiting to retry"); assert.equal(retry.message, "Daily quota reached");
  assert.equal(describeQueueItem({ ...base, source: "results", recordId: "r" }, { ...runtime, activeResultsId: "r", activeResultsPhase: "needs_upload" }).state, "Uploading file");
});

test("opening an upload page does not imply file submission", () => {
  const item = { sha256: "abc", virusTotalRefinement: { status: "unknown", checkedAt: 1, report: { found: false } }, virusTotalChecks: { upload: true, cloud: true } };
  const state = describeVirusTotalResult(item);
  assert.equal(state.state, "upload_required"); assert.equal(state.uploaded, false);
  assert.match(state.message, /not uploaded/);
});

test("a subsequent missing report cannot erase an accepted upload or imply a clean result", () => {
  const item = { sha256: "abc", virusTotalRefinement: { status: "unknown", label: "Unknown", checkedAt: 1, report: { found: false } },
    virusTotalChecks: { resultsUploadedUnknownHash: "abc", resultsUploadCheckAfter: 500, resultsUploadFollowupCount: 2 } };
  const waiting = describeVirusTotalResult(item);
  assert.equal(waiting.state, "awaiting_analysis"); assert.equal(waiting.uploaded, true); assert.equal(waiting.nextCheckAt, 500);
  assert.match(waiting.message, /quarantine/);
  item.virusTotalChecks.resultsUploadFollowupCount = 5;
  const continued = describeVirusTotalResult(item);
  assert.equal(continued.state, "awaiting_analysis"); assert.equal(continued.nextCheckAt, 500);
  assert.match(continued.message, /automatically/);
  item.sha256 = "changed";
  assert.equal(describeVirusTotalResult(item).uploaded, false);
});

test("unchecked and failed checks cannot look like completed unknown checks", () => {
  assert.equal(describeVirusTotalResult({}).state, "not_checked");
  assert.equal(describeVirusTotalResult({ virusTotalRefinement: { status: "error", message: "Rate limited" } }).state, "blocked");
  assert.equal(describeVirusTotalResult({ virusTotalRefinement: { status: "error", report: { found: false }, message: "Rate limited" } }).state, "blocked");
});

test("accepted submissions continue even when automatic initial checks are disabled", () => {
  const f = fixture();
  try {
    f.result("uploaded", "unknown", { resultsUploadedUnknownHash: "abc", resultsUploadCheckAfter: 500 });
    const page: any = getVirusTotalQueuePage(f.db, {}, [], runtime);
    assert.equal(page.total, 1); assert.equal(page.items[0].state, "Awaiting analysis");
    assert.match(page.items[0].submission, /automatically/);
  } finally { f.db.close(); }
});
