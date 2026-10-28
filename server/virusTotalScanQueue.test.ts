import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { VirusTotalScanQueue } from "../addons/virustotal/server/virusTotalScanQueue";

const record = (name: string) => ({ filePath: path.resolve(name), size: 10, mtimeMs: 1 });
const report = (hash: string, malicious = 0) => ({ hash, found: true, stats: { malicious, suspicious: 0 } });
function fixture() {
    const db = new DatabaseSync(":memory:");
    let time = Date.now();
    const queue = new VirusTotalScanQueue(db, () => time);
    const lookups: string[] = [];
    const detections: string[] = [];
    let hashes = 0;
    const deps = {
        keyId: "test-key-fingerprint",
        fingerprint: async (_file: string) => ({ size: 10, mtimeMs: 1 }),
        hash: async (file: string) => { hashes++; return file; },
        lookup: async (hash: string) => { lookups.push(hash); return report(hash, hash.includes("missed") ? 8 : 0); },
        upload: async (_file: string, hash: string, _canContinue: () => Promise<boolean>) => `analysis-${hash}`,
        analysis: async (_id: string, hash: string): Promise<any> => report(hash),
        excluded: async (_file: string) => false,
        detection: async (item: any, _report: any) => { detections.push(item.file_path); }
    };
    return { db, queue, deps, lookups, detections, hashes: () => hashes, advance: (ms = 60_000) => { time += ms; } };
}

test("queues all files without the context-menu 100-file cap and finds a locally missed threat", async t => {
    const { db, queue, deps, lookups, detections } = fixture();
    t.after(() => db.close());
    queue.start("scan", "disk", "C:\\");
    queue.addFiles("scan", [record("clean.txt"), record("missed-by-both.exe"), ...Array.from({ length: 1005 }, (_, i) => record(`clean-${i}.bin`))]);
    assert.equal(queue.get("scan")?.total, 1007);
    assert.equal(queue.next(), undefined, "do not run an incompletely collected scan");
    queue.finishEnumeration("scan");
    while (await queue.processNext(deps)) {}
    assert.equal(lookups.length, 1007);
    assert.deepEqual(detections, [record("missed-by-both.exe").filePath]);
    assert.equal(queue.get("scan")?.checked, 1007);
    assert.equal(queue.get("scan")?.detections, 1);
    assert.equal(queue.get("scan")?.status, "done");
});

test("duplicate paths are idempotent and duplicate hashes share a report", async t => {
    const { db, queue, deps, lookups } = fixture();
    t.after(() => db.close());
    queue.start("scan", "folder", "fixtures");
    queue.addFiles("scan", [record("one.txt"), record("one.txt"), record("copy.txt")]);
    queue.finishEnumeration("scan");
    const shared = { ...deps, hash: async () => "same-content" };
    while (await queue.processNext(shared)) {}
    assert.equal(queue.get("scan")?.total, 2);
    assert.equal(queue.get("scan")?.checked, 2);
    assert.equal(lookups.length, 1);
});

test("API quota failures preserve pending work and the computed hash for retry", async t => {
    const { db, queue, deps, hashes } = fixture();
    t.after(() => db.close());
    queue.start("scan", "file", "one.txt");
    queue.addFiles("scan", [record("one.txt")]);
    queue.finishEnumeration("scan");
    const quotaError = Object.assign(new Error("daily quota"), { status: 429, nextAllowedAt: Date.now() + 86400000 });
    await assert.rejects(queue.processNext({ ...deps, lookup: async () => { throw quotaError; } }), quotaError);
    assert.equal(queue.get("scan")?.pending, 1);
    assert.equal(queue.get("scan")?.checked, 0);
    await queue.processNext(deps);
    assert.equal(hashes(), 1);
    assert.equal(queue.get("scan")?.status, "done");
});

test("pause during a lookup suppresses detection and resumes with the report already received", async t => {
    const { db, queue, deps, detections, lookups } = fixture();
    t.after(() => db.close());
    queue.start("scan", "file", "missed.exe");
    queue.addFiles("scan", [record("missed.exe")]);
    queue.finishEnumeration("scan");
    await queue.processNext({ ...deps, lookup: async hash => {
        lookups.push(hash);
        queue.setState("scan", "paused");
        return report(hash, 8);
    } });
    assert.equal(detections.length, 0);
    assert.equal(queue.get("scan")?.pending, 1);
    queue.setState("scan", "active");
    await queue.processNext(deps);
    assert.equal(detections.length, 1);
    assert.equal(lookups.length, 1);
});

test("cancel removes work, prevents new additions, and can restart without corrupt totals", async t => {
    const { db, queue, deps, lookups } = fixture();
    t.after(() => db.close());
    queue.start("scan", "file", "one.txt");
    queue.addFiles("scan", [record("one.txt")]);
    queue.finishEnumeration("scan");
    queue.setState("scan", "cancelled");
    queue.addFiles("scan", [record("two.txt")]);
    assert.equal(await queue.processNext(deps), false);
    assert.equal(lookups.length, 0);
    queue.start("scan", "file", "one.txt");
    queue.addFiles("scan", [record("one.txt")]);
    queue.finishEnumeration("scan");
    await queue.processNext(deps);
    assert.equal(queue.get("scan")?.total, 1);
    assert.equal(queue.get("scan")?.status, "done");
});

test("missing/excluded/changing files are skipped and missing hashes wait for upload and analysis", async t => {
    const { db, queue, deps, lookups, detections } = fixture();
    t.after(() => db.close());
    queue.start("scan", "folder", "fixtures");
    queue.addFiles("scan", [record("excluded"), record("missing"), record("changing"), record("unknown")]);
    queue.finishEnumeration("scan");
    let changed = false;
    const custom = { ...deps,
        excluded: async (file: string) => file.endsWith("excluded"),
        fingerprint: async (file: string) => file.endsWith("missing") ? null : ({ size: changed && file.endsWith("changing") ? 11 : 10, mtimeMs: 1 }),
        hash: async (file: string) => { if (file.endsWith("changing")) changed = true; return file; },
        lookup: async (hash: string) => { lookups.push(hash); return { hash, found: false }; }
    };
    while (await queue.processNext(custom)) {}
    assert.equal(lookups.length, 1);
    assert.equal(detections.length, 0);
    assert.equal(queue.get("scan")?.skipped, 3);
    assert.equal(queue.get("scan")?.needsUpload, 0);
    assert.equal(queue.get("scan")?.checked, 0);
    assert.equal(queue.get("scan")?.analysing, 1);
});

test("cancelling during an in-flight lookup cannot produce findings or recreate deleted work", async t => {
    const { db, queue, deps, detections } = fixture();
    t.after(() => db.close());
    queue.start("scan", "file", "missed.exe");
    queue.addFiles("scan", [record("missed.exe")]);
    queue.finishEnumeration("scan");
    await queue.processNext({ ...deps, lookup: async hash => {
        queue.setState("scan", "cancelled");
        return report(hash, 8);
    } });
    assert.equal(detections.length, 0);
    assert.equal(queue.get("scan")?.status, "cancelled");
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM vt_scan_reports").get()?.count, 0);
    assert.equal(queue.next(), undefined);
});

test("an expired duplicate-content report triggers a new lookup", async t => {
    const { db, queue, deps, lookups } = fixture();
    t.after(() => db.close());
    queue.start("scan", "folder", "fixtures");
    queue.addFiles("scan", [record("one.txt"), record("copy.txt")]);
    queue.finishEnumeration("scan");
    const shared = { ...deps, hash: async () => "same-content" };
    await queue.processNext(shared);
    db.prepare("UPDATE vt_scan_reports SET checked_at = 0").run();
    await queue.processNext(shared);
    assert.equal(lookups.length, 2);
});

test("ready queues survive restart; unfinished enumeration waits for local resume", async t => {
    const buildDir = path.resolve("build");
    fs.mkdirSync(buildDir, { recursive: true });
    const root = fs.mkdtempSync(path.join(buildDir, "vt-queue-test-"));
    const file = path.join(root, "queue.sqlite");
    let db = new DatabaseSync(file);
    t.after(() => { db.close(); assert.equal(path.dirname(root), buildDir); fs.rmSync(root, { recursive: true, force: true }); });
    let queue = new VirusTotalScanQueue(db);
    queue.start("ready", "file", "ready.txt");
    queue.addFiles("ready", [record("ready.txt")]);
    queue.finishEnumeration("ready");
    queue.start("partial", "disk", "C:\\");
    queue.addFiles("partial", [record("partial.txt")]);
    db.close();
    db = new DatabaseSync(file);
    queue = new VirusTotalScanQueue(db);
    queue.recover();
    assert.equal(queue.get("ready")?.status, "active");
    assert.equal(queue.get("partial")?.status, "paused");
    assert.equal(queue.next()?.job_id, "ready");
    assert.equal(queue.list().length, 2);
});

test("files of any size, including empty files, are eligible and jobs take turns", async t => {
    const { db, queue, deps } = fixture();
    t.after(() => db.close());
    queue.start("first", "folder", "first");
    queue.addFiles("first", [record("first-a"), record("first-b")]);
    queue.finishEnumeration("first");
    queue.start("second", "file", "second");
    queue.addFiles("second", [{ ...record("second"), size: 0 }, { ...record("large"), size: 1024 ** 4 }]);
    queue.finishEnumeration("second");
    assert.equal(queue.next()?.job_id, "first");
    await queue.processNext(deps);
    assert.equal(queue.next()?.job_id, "second");
    await queue.processNext({ ...deps, fingerprint: async () => ({ size: 0, mtimeMs: 1 }) });
    await queue.processNext(deps);
    await queue.processNext({ ...deps, fingerprint: async () => ({ size: 1024 ** 4, mtimeMs: 1 }) });
    assert.equal(queue.get("second")?.checked, 2);
});

test("a missing hash is uploaded, waits for completed analysis, and detects a locally missed threat", async t => {
    const { db, queue, deps, detections, advance } = fixture();
    t.after(() => db.close());
    queue.start("scan", "file", "missed.exe");
    queue.addFiles("scan", [record("missed.exe")]);
    queue.finishEnumeration("scan");
    let uploads = 0, polls = 0;
    const cloud = { ...deps,
        lookup: async hash => ({ hash, found: false }),
        upload: async (_file, _hash, canContinue) => { assert.equal(await canContinue(), true); uploads++; return "analysis-1"; },
        analysis: async (_id, hash) => { polls++; return polls === 1 ? null : report(hash, 7); }
    };
    await queue.processNext(cloud);
    assert.equal(queue.get("scan")?.needsUpload, 1);
    assert.equal(queue.get("scan")?.checked, 0);
    await queue.processNext(cloud);
    assert.equal(queue.get("scan")?.analysing, 1);
    assert.equal(await queue.processNext(cloud), false, "do not poll before the saved delay");
    advance(); await queue.processNext(cloud);
    assert.equal(queue.get("scan")?.checked, 0, "queued analysis is not a clean verdict");
    assert.equal(await queue.processNext(cloud), false);
    advance(); await queue.processNext(cloud);
    assert.equal(uploads, 1);
    assert.equal(polls, 2);
    assert.equal(queue.get("scan")?.checked, 1);
    assert.equal(queue.get("scan")?.detections, 1);
    assert.equal(queue.get("scan")?.needsUpload, 0);
    assert.equal(queue.get("scan")?.analysing, 0);
    assert.deepEqual(detections, [record("missed.exe").filePath]);
    assert.equal(queue.get("scan")?.status, "done");
});

test("identical content shares one upload and analysis, including after queue recreation", async t => {
    const { db, queue, deps, advance, lookups } = fixture();
    t.after(() => db.close());
    queue.start("scan", "folder", "fixtures");
    queue.addFiles("scan", [record("one"), record("copy")]); queue.finishEnumeration("scan");
    let uploads = 0, polls = 0;
    const cloud = { ...deps, hash: async () => "same",
        lookup: async hash => { lookups.push(hash); return { hash, found: false }; },
        upload: async () => { uploads++; return "saved-id"; },
        analysis: async (id, hash) => { assert.equal(id, "saved-id"); polls++; return report(hash); }
    };
    while (await queue.processNext(cloud)) {}
    assert.equal(queue.get("scan")?.analysing, 2);
    assert.equal(uploads, 1); assert.equal(lookups.length, 1);
    const resumeAt = queue.nextWakeAt()! + 1;
    const restarted = new VirusTotalScanQueue(db, () => resumeAt);
    restarted.recover();
    // Use a stable time for the resumed analysis, rather than changing real clocks.
    advance();
    while (await restarted.processNext(cloud)) {}
    assert.equal(uploads, 1); assert.equal(polls, 1);
    assert.equal(restarted.get("scan")?.checked, 2);
    assert.equal(restarted.get("scan")?.status, "done");
});

test("lookup quota exhaustion does not prevent pending uploads or contributed analyses", async t => {
    const { db, queue, deps, advance } = fixture(); t.after(() => db.close());
    queue.start("scan", "folder", "fixtures");
    queue.addFiles("scan", [record("contribution"), record("lookup")]); queue.finishEnumeration("scan");
    await queue.processNext({ ...deps, lookup: async hash => ({ hash, found: false }) });
    const upload = queue.next();
    queue.retry({ ...upload, status: "pending" }, Object.assign(new Error("daily limit"), { localQuotaLimit: true, nextAllowedAt: Date.now() + 86400_000 }));
    assert.equal(queue.next()?.status, "needs_upload");
    await queue.processNext(deps);
    advance(); await queue.processNext(deps);
    assert.equal(queue.get("scan")?.checked, 1);
    assert.equal(queue.get("scan")?.pending, 1);
    assert.equal(queue.next(), undefined);
    queue.wakeLookups(); await queue.processNext(deps);
    assert.equal(queue.get("scan")?.status, "done");
});

test("pausing after submission persists its ID and cancelling during upload deletes it", async t => {
    const { db, queue, deps, advance, detections } = fixture(); t.after(() => db.close());
    queue.start("scan", "file", "one"); queue.addFiles("scan", [record("one")]); queue.finishEnumeration("scan");
    await queue.processNext({ ...deps, lookup: async hash => ({ hash, found: false }) });
    await queue.processNext({ ...deps, upload: async () => { queue.setState("scan", "paused"); return "saved"; } });
    assert.equal(queue.get("scan")?.status, "paused");
    assert.equal(queue.get("scan")?.analysing, 1);
    assert.equal(await queue.processNext(deps), false);
    advance(); queue.setState("scan", "active");
    await queue.processNext({ ...deps, upload: async () => { throw new Error("must not reupload"); }, analysis: async (id, hash) => {
        assert.equal(id, "saved"); queue.setState("scan", "paused"); return report(hash, 9);
    } });
    assert.equal(detections.length, 0);
    queue.setState("scan", "active"); await queue.processNext(deps);
    assert.equal(detections.length, 1);
    queue.start("cancel", "file", "two"); queue.addFiles("cancel", [record("two")]); queue.finishEnumeration("cancel");
    await queue.processNext({ ...deps, lookup: async hash => ({ hash, found: false }) });
    await queue.processNext({ ...deps, upload: async () => { queue.setState("cancel", "cancelled"); return "discard"; } });
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM vt_scan_submissions WHERE job_id = 'cancel'").get()?.n, 0);
    assert.equal(queue.get("cancel")?.pending, 0);
    assert.equal(queue.get("cancel")?.analysing, 0);
});

test("changed files, provider upload limits, and rejected files do not stall the queue", async t => {
    const { db, queue, deps, advance } = fixture(); t.after(() => db.close());
    queue.start("scan", "folder", "fixtures");
    queue.addFiles("scan", [record("large"), record("reject"), record("change")]); queue.finishEnumeration("scan");
    let changed = false;
    const cloud = { ...deps,
        fingerprint: async file => ({ size: file.endsWith("large") ? 651 * 1024 ** 2 : 10, mtimeMs: changed && file.endsWith("change") ? 2 : 1 }),
        lookup: async hash => ({ hash, found: false }),
        upload: async file => { if (file.endsWith("reject")) throw Object.assign(new Error("unsupported file"), { fileError: true }); changed = true; return "changed-id"; }
    };
    while (await queue.processNext(cloud)) {}
    assert.equal(queue.get("scan")?.skipped, 2);
    advance(); await queue.processNext(cloud);
    assert.equal(queue.get("scan")?.checked, 0, "a changed uploaded file must be rehashed and rechecked");
    assert.equal(queue.next()?.status, "pending");
});

test("old finished missing-hash entries are migrated into the upload queue exactly once", async t => {
    const { db, queue } = fixture(); t.after(() => db.close());
    queue.start("legacy", "file", "one"); queue.addFiles("legacy", [record("one")]); queue.finishEnumeration("legacy");
    db.prepare("UPDATE vt_scan_jobs SET status = 'done', checked = 1, unknown = 1 WHERE job_id = 'legacy'").run();
    db.prepare("UPDATE vt_scan_files SET status = 'checked', sha256 = 'old-hash'").run();
    db.prepare("INSERT INTO vt_scan_reports(job_id, sha256, report, checked_at) VALUES ('legacy', 'old-hash', ?, ?)").run(JSON.stringify({ hash: "old-hash", found: false }), Date.now());
    db.prepare("DELETE FROM vt_scan_queue_meta").run();
    const migrated = new VirusTotalScanQueue(db);
    assert.equal(migrated.get("legacy")?.status, "active");
    assert.equal(migrated.get("legacy")?.checked, 0);
    assert.equal(migrated.get("legacy")?.needsUpload, 1);
    assert.equal(migrated.next()?.status, "needs_upload");
    new VirusTotalScanQueue(db);
    assert.equal(migrated.get("legacy")?.needsUpload, 1);
    assert.equal(migrated.get("legacy")?.checked, 0);
});

test("key rotation rechecks a missing hash rather than reusing another key's contribution", async t => {
    const { db, queue, deps } = fixture(); t.after(() => db.close());
    queue.start("scan", "file", "one"); queue.addFiles("scan", [record("one")]); queue.finishEnumeration("scan");
    await queue.processNext({ ...deps, lookup: async hash => ({ hash, found: false }) });
    await queue.processNext(deps);
    const next = queue.nextWakeAt()!;
    const rotated = new VirusTotalScanQueue(db, () => next + 1);
    await rotated.processNext({ ...deps, keyId: "different-key" });
    assert.equal(rotated.next()?.status, "pending");
    let lookups = 0;
    await rotated.processNext({ ...deps, keyId: "different-key", lookup: async hash => { lookups++; return report(hash); } });
    assert.equal(lookups, 1); assert.equal(rotated.get("scan")?.status, "done");
});

test("a blocked large-upload setup sleeps until quota refresh and invalid analysis IDs recheck the hash", async t => {
    const { db, queue, deps, advance } = fixture(); t.after(() => db.close());
    queue.start("scan", "file", "one"); queue.addFiles("scan", [record("one")]); queue.finishEnumeration("scan");
    await queue.processNext({ ...deps, lookup: async hash => ({ hash, found: false }) });
    const item = queue.next();
    queue.retry(item, Object.assign(new Error("large URL needs quota"), { localQuotaLimit: true, nextAllowedAt: Date.now() + 86400_000 }));
    assert.equal(queue.next(), undefined, "a quota-blocked upload must not busy-loop");
    queue.wakeLookups(); await queue.processNext(deps);
    advance();
    await queue.processNext({ ...deps, analysis: async () => { throw Object.assign(new Error("expired ID"), { analysisMissing: true }); } });
    assert.equal(queue.next()?.status, "pending");
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM vt_scan_submissions").get()?.n, 0);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM vt_scan_reports").get()?.n, 0);
    await queue.processNext(deps);
    assert.equal(queue.get("scan")?.status, "done");
});

test("warnings gate only scans above four files and never contact VirusTotal before acceptance", async t => {
    const { db, queue, deps, lookups } = fixture(); t.after(() => db.close());
    queue.start("small", "folder", "small");
    queue.addFiles("small", Array.from({ length: 4 }, (_, i) => record(`small-${i}`))); queue.finishEnumeration("small", true);
    assert.equal(queue.get("small")?.requiresConfirmation, false);
    while (await queue.processNext(deps)) {}
    queue.start("large", "folder", "large");
    queue.addFiles("large", Array.from({ length: 40 }, (_, i) => record(`large-${i}`))); queue.finishEnumeration("large", true);
    assert.equal(queue.pendingConfirmation()?.jobId, "large");
    assert.equal(queue.nextWakeAt(), null);
    assert.equal(await queue.processNext(deps), false);
    assert.equal(lookups.length, 4);
    assert.equal(queue.confirm("large", true), true);
    await queue.processNext(deps);
    assert.equal(lookups.length, 5);
    queue.setState("large", "paused"); queue.start("large", "folder", "large"); queue.finishEnumeration("large", true);
    assert.equal(queue.get("large")?.requiresConfirmation, false, "do not warn repeatedly on resume");
    assert.equal(queue.confirm("large", true), false);
});

test("declining cancels only the cloud queue; disabling warnings releases a waiting queue", async t => {
    const { db, queue, deps, lookups } = fixture(); t.after(() => db.close());
    const add = (id: string) => { queue.start(id, "folder", id); queue.addFiles(id, Array.from({ length: 5 }, (_, i) => record(`${id}-${i}`))); queue.finishEnumeration(id, true); };
    add("decline");
    assert.equal(queue.confirm("decline", false), true);
    assert.equal(queue.get("decline")?.status, "cancelled");
    assert.equal(await queue.processNext(deps), false); assert.equal(lookups.length, 0);
    add("disable"); queue.disableConfirmations();
    assert.equal(queue.pendingConfirmation(), null);
    await queue.processNext(deps); assert.equal(lookups.length, 1);
    add("restart");
    const recovered = new VirusTotalScanQueue(db); recovered.recover();
    assert.equal(recovered.get("restart")?.requiresConfirmation, true, "a restart cannot bypass unanswered confirmation");
    queue.setState("disable", "paused");
    assert.equal(recovered.next(), undefined);
});
