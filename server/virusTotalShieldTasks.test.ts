import assert from "node:assert/strict";
import test from "node:test";
import { stateFixture, testModule } from "./testModule";
import { ShieldVirusTotalQueue } from "../addons/virustotal/server/shieldQueue";
import { describeQueueItem } from "../addons/virustotal/server/virusTotalQueueView";

const hash = "a".repeat(64), filePath = "D:\\Downloads\\sample.zip";
function workerFixture() {
    const runtime: any = { virusTotalShieldRunning: false, virusTotalShieldNextAllowedAt: 0 };
    const findings: any[] = [], history: any[] = [], detections: any[] = [], scheduled: number[] = [];
    let analysisError: any = { analysisMissing: true }, uploadError: any = null, uploads = 0, polls = 0, lookups = 0;
    let report: any = { found: false, hash };
    const worker = testModule("addons/virustotal/server/workers.ts", {
        "../../../modules/exceptions/server/service": {},
        "../../../modules/history/server/storage": { addHistory: async (entry: any) => { history.push(entry); } },
        "../../../modules/results/server/storage": { addScanResult: async (entry: any) => { findings.push(entry); } },
        "../../../server/core/runtimeState": { runtimeState: runtime },
        "../../../server/core/utils": { hashFile: async () => hash },
        "../../../server/scanning/files": {}, "../../../server/scanning/targets": {},
        "./account": { loadVirusTotalApiKey: async () => "fixture-key" },
        "./status": {},
        "./refinement": {
            virusTotalFileAnalysis: {
                analysis: async () => { polls++; if (analysisError) throw analysisError; return report; },
                upload: async () => { uploads++; if (uploadError) throw uploadError; return "new-analysis"; }
            }, getVirusTotalDetectionCount: (value: any) => Number(value.stats?.malicious || 0) + Number(value.stats?.suspicious || 0),
            buildVirusTotalThreatName: () => "VirusTotal positive"
        },
        "./requests": { fetchVirusTotalFileReport: async () => { lookups++; return report; },
            getVirusTotalShieldUploadMaxBytes: () => 32 * 1024 ** 2, formatVirusTotalUploadSize: String,
            summarizeVirusTotalFileReport: (_hash: string, value: any) => value },
        fs: { existsSync: () => true }, "fs/promises": { stat: async () => ({ isFile: () => true, size: 42 }) }
    });
    const context: any = { settings: { virusTotalCloudEnabled: true, virusTotalShieldBackgroundCheckEnabled: true, virusTotalShieldUploadUnknownEnabled: true },
        virusTotalShieldQueue: new Map([[filePath, { filePath, queuedAt: 1, uploadedHash: hash, analysisId: "missing-analysis" }]]),
        scheduleShieldVirusTotalCheck: (delay: number) => scheduled.push(delay),
        handleVirusTotalShieldDetection: async (_file: string, report: any) => { detections.push(report); return "Pending"; }
    };
    return { context, findings, history, detections, scheduled, run: worker.createProcessNextShieldVirusTotalCheck(context),
        report: (value: any) => { report = value; }, analysisError: (value: any) => { analysisError = value; },
        uploadError: (value: any) => { uploadError = value; }, counts: () => ({ uploads, polls, lookups }) };
}

test("missing Shield analysis remains actionable without creating findings, alerts or retry loops", async () => {
    const f = workerFixture(); await f.run();
    const task = f.context.virusTotalShieldQueue.get(filePath);
    assert.equal(task.blockedReason, "analysis"); assert.equal(task.analysisId, "missing-analysis");
    assert.match(task.message, /Recheck the hash/);
    await f.run();
    assert.equal(f.counts().polls, 1); assert.equal(f.scheduled.length, 0);
    assert.equal(f.findings.length, 0); assert.equal(f.detections.length, 0); assert.equal(f.history.length, 0);
    const view = describeQueueItem({ id: "shield:one", source: "shield", enumerated: 1, phase: "blocked", ...task }, { enabled: true, configured: true });
    assert.deepEqual(view.actions, ["recheck", "remove"]); assert.equal(view.nextAttemptAt, 0);
    assert.match(view.submission, /not a malware finding/); assert.doesNotMatch(view.submission, /Results/);
});

test("manual hash recheck does not resubmit an unavailable analysis and reveals explicit upload", async () => {
    const f = workerFixture();
    f.context.virusTotalShieldQueue.get(filePath).recheckHash = true;
    await f.run();
    const task = f.context.virusTotalShieldQueue.get(filePath);
    assert.equal(task.blockedReason, "upload"); assert.deepEqual(f.counts(), { uploads: 0, polls: 0, lookups: 1 });
    assert.equal(f.findings.length, 0);
    assert.deepEqual(describeQueueItem({ source: "shield", enumerated: 1, phase: "blocked", ...task }, { enabled: true, configured: true }).actions, ["recheck", "upload", "remove"]);
});

test("rejected uploads remain queue tasks while actual positive reports still reach detection handling", async () => {
    const failed = workerFixture();
    Object.assign(failed.context.virusTotalShieldQueue.get(filePath), { pendingUploadHash: hash });
    failed.uploadError({ fileError: true, message: "Upload rejected" }); await failed.run();
    assert.equal(failed.context.virusTotalShieldQueue.get(filePath).blockedReason, "file");
    assert.equal(failed.findings.length, 0); assert.equal(failed.detections.length, 0);
    const positive = workerFixture(); positive.analysisError(null);
    positive.report({ found: true, hash, stats: { malicious: 10 } }); await positive.run();
    assert.equal(positive.detections.length, 1); assert.equal(positive.history[0].threatsFound, 1);
    assert.equal(positive.context.virusTotalShieldQueue.size, 0);
    const clean = workerFixture(); clean.analysisError(null);
    clean.report({ found: true, hash, stats: { undetected: 62 } }); await clean.run();
    assert.equal(clean.context.virusTotalShieldQueue.size, 0); assert.equal(clean.detections.length, 0);
});

test("upgrade moves only synthetic findings to durable tasks and preserves real detections and the old records", t => {
    const { db } = stateFixture(t);
    const insert = db.prepare(`INSERT INTO scan_results(id, timestamp, original_path, engine, source, threat_name, sha256,
        virus_total_checks, virus_total_refinement_stats, payload) VALUES (?, 1, ?, ?, 'shield', ?, ?, ?, ?, '{}')`);
    insert.run("synthetic", filePath, "VirusTotal", "VirusTotal analysis requires review", hash,
        JSON.stringify({ resultsUploadAnalysisId: "old-id", resultsUploadedUnknownHash: hash }), "{}");
    insert.run("clam", "D:\\real-local.zip", "ClamAV", "Win.Test", hash, "{}", "{}");
    insert.run("vt", "D:\\real-cloud.zip", "VirusTotal", "VirusTotal: 10 detections", hash, "{}", '{"malicious":10}');
    insert.run("evidence", "D:\\positive-evidence.zip", "VirusTotal", "VirusTotal analysis requires review", hash, "{}", '{"malicious":10}');
    const queue = new ShieldVirusTotalQueue(db);
    assert.equal(queue.size, 1);
    assert.deepEqual(db.prepare("SELECT id FROM scan_results ORDER BY id").all().map(row => row.id), ["clam", "evidence", "vt"]);
    assert.equal(db.prepare("SELECT id FROM vt_shield_legacy_results").get()!.id, "synthetic");
    const [key, task] = [...queue][0]; assert.equal(task.analysisId, "old-id"); assert.equal(task.blockedReason, "analysis");
    const restarted = new ShieldVirusTotalQueue(db);
    assert.deepEqual(restarted.get(key), task);
    restarted.delete(key); assert.equal(new ShieldVirusTotalQueue(db).size, 0);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM scan_results").get()!.n, 3);
});

test("queue actions enforce recheck before upload and cannot act on active tasks or arbitrary paths", async () => {
    let action: any;
    const task: any = { filePath, queuedAt: 1, blockedReason: "analysis", sha256: hash, analysisId: "old" };
    const context: any = { settings: { virusTotalCloudEnabled: true }, virusTotalShieldQueue: new Map([["fixture", task]]), scheduleShieldVirusTotalCheck: () => {} };
    const module = testModule("addons/virustotal/server/routes/getApiVirustotalQueue.ts", {
        "../../../../server/core/runtimeState": { runtimeState: {} }, "../account": { loadVirusTotalApiKey: async () => "key" },
        "../requests": { getVirusTotalShieldUploadMaxBytes: () => 100 },
        "node:fs/promises": { stat: async () => ({ isFile: () => true, size: 42 }) }
    });
    module.registerGetApiVirustotalQueue({ get: () => {}, post: (_path: string, handler: any) => { action = handler; } }, context);
    async function request(body: any) {
        const response = { statusCode: 200, body: null as any, status(code: number) { this.statusCode = code; return this; }, json(value: any) { this.body = value; return this; } };
        await action({ body }, response); return response;
    }
    assert.equal((await request({ id: "shield:fixture", action: "upload" })).statusCode, 409);
    assert.equal((await request({ id: "shield:fixture", action: "recheck", filePath: "C:\\arbitrary" })).statusCode, 200);
    assert.equal(context.virusTotalShieldQueue.get("fixture").filePath, filePath);
    assert.equal(context.virusTotalShieldQueue.get("fixture").recheckHash, true);
    assert.equal((await request({ id: "shield:fixture", action: "remove" })).statusCode, 409);
    context.virusTotalShieldQueue.set("fixture", { ...task, blockedReason: "upload" });
    assert.equal((await request({ id: "shield:fixture", action: "upload" })).statusCode, 200);
    assert.equal(context.virusTotalShieldQueue.get("fixture").pendingUploadHash, hash);
    assert.equal((await request({ id: "shield:missing", action: "remove" })).statusCode, 404);
});

test("actual VirusTotal detections have the VirusTotal provider in both stored rows and SQL filters", t => {
    const { db, dependencies } = stateFixture(t);
    const storage = testModule("modules/results/server/storage.ts", dependencies);
    assert.equal(storage.getScanResultFindingSource({ engine: "VirusTotal", threatName: "VirusTotal: 10 detections" }), "VirusTotal");
    db.prepare(`INSERT INTO scan_results(id, timestamp, engine, threat_name, payload) VALUES ('real', 1, 'VirusTotal', 'VirusTotal: 10 detections', '{}')`).run();
    assert.equal(db.prepare(`SELECT ${storage.scanResultFindingSourceSql()} AS provider FROM scan_results`).get()!.provider, "VirusTotal");
});
