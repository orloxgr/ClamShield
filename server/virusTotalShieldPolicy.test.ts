import assert from "node:assert/strict";
import test from "node:test";
import { stateFixture, testModule } from "./testModule";
import { PendingThreats } from "../modules/shield/server/pendingThreats";
import { virusTotalShieldPopupThreshold } from "../addons/virustotal/shared/shieldPolicy";
import { normalizeSettingsPatch } from "../modules/settings/server/validation";
import { defaultSettings } from "../modules/settings/server/schema";
import { nextVirusTotalResultAttempt } from "../addons/virustotal/server/virusTotalResultWorkflow";

const hash = "a".repeat(64);
const file = "C:\\fixtures\\sample.exe";
function fixture(action = "ask", threshold: any = undefined) {
    const results: any[] = [], pending: any[] = [], events: any[] = [], quarantines: any[] = [];
    const module = testModule("modules/shield/server/cloudDetection.ts", {
        "../../exceptions/server/service": { getExceptions: async () => [], isExcluded: () => false },
        "../../../server/scanning/targets": { shouldSkipBuiltInScanPath: () => false },
        "../../results/server/storage": { addScanResult: async (result: any) => results.push(result) },
        "../../quarantine/server/files": { quarantineFile: async () => { const item = { fileName: "sample", metadata: {} }; quarantines.push(item); return item; } },
        "../../quarantine/server/storage": { getQuarantineMap: async () => ({}), saveQuarantineMap: async () => {} }
    });
    const settings: any = { actionOnDetection: action, virusTotalShieldPopupMinDetections: threshold };
    const handle = module.createHandleVirusTotalShieldDetection({ settings, sendApiEvent: (...args: any[]) => events.push(args), queuePendingThreat: async (item: any) => pending.push(item) });
    const report = (detections: number) => ({ hash, found: true, stats: { malicious: detections, suspicious: 0, undetected: 60 }, url: "https://www.virustotal.com/gui/file/" + hash, detections: [{ engine: "Fixture engine", category: "malicious", result: "Fixture" }] });
    return { results, pending, events, quarantines, settings, report, handle: (count: number) => handle(file, report(count)), raw: handle };
}

test("VT popup preference defaults to four, clamps to 1–20 and is accepted by settings validation", () => {
    for (const value of [undefined, null, "", NaN, Infinity]) assert.equal(virusTotalShieldPopupThreshold(value), 4);
    assert.equal(defaultSettings.virusTotalShieldPopupMinDetections, 4);
    for (const [value, expected] of [[0, 1], [1, 1], [4, 4], [20, 20], [99, 20]]) {
        assert.equal(virusTotalShieldPopupThreshold(value), expected);
        assert.equal(normalizeSettingsPatch({ virusTotalShieldPopupMinDetections: value }, defaultSettings).patch.virusTotalShieldPopupMinDetections, expected);
    }
});

test("Ask sends low counts to Results with their complete report; the threshold itself opens a decision popup", async () => {
    for (const count of [1, 2, 3]) {
        const f = fixture(); assert.equal(await f.handle(count), "Sent to Results");
        assert.equal(f.pending.length + f.events.length + f.quarantines.length, 0);
        assert.deepEqual(f.results[0].virusTotalRefinement.report, f.report(count));
        assert.equal(f.results[0].sha256, hash); assert.ok(f.results[0].virusTotalChecks.cloud > 0);
        assert.equal(f.results[0].resultsReminderAt, 0);
        assert.equal(nextVirusTotalResultAttempt(f.results[0]), 0);
    }
    const f = fixture(); assert.equal(await f.handle(4), "Pending");
    assert.deepEqual(f.pending[0].virusTotalRefinement.report, f.report(4));
    assert.equal(f.results.length, 0);
});

test("the setting filters only popups and never suppresses configured automatic quarantine", async () => {
    for (const action of ["quarantine_notify", "quarantine_silent"]) {
        const f = fixture(action); assert.equal(await f.handle(1), "Quarantined");
        assert.equal(f.quarantines.length, 1); assert.equal(f.events.length + f.results.length + f.pending.length, 0);
        assert.deepEqual(f.quarantines[0].metadata.virusTotalRefinement.report, f.report(1));
    }
    const notify = fixture("quarantine_notify"); await notify.handle(4); assert.equal(notify.events.length, 1);
    const silent = fixture("quarantine_silent"); await silent.handle(20); assert.equal(silent.events.length, 0);
    const results = fixture("results_notify"); await results.handle(1); assert.equal(results.results.length, 1); assert.equal(results.events.length, 0);
    await results.handle(4); assert.equal(results.events.length, 1);
});

test("threshold changes take effect on the next report, including suspicious verdicts, and clean/missing reports never alert", async () => {
    const f = fixture("ask", 20); await f.handle(19); assert.equal(f.pending.length, 0);
    await f.handle(20); assert.equal(f.pending.length, 1);
    f.settings.virusTotalShieldPopupMinDetections = 1; await f.handle(1); assert.equal(f.pending.length, 2);
    f.settings.virusTotalShieldPopupMinDetections = 4;
    await f.raw(file, { ...f.report(3), stats: { malicious: 3, suspicious: 1 } }); assert.equal(f.pending.length, 3);
    assert.equal(await f.handle(0), "Ignored"); assert.equal(await f.raw(file, { found: false, hash }), "Ignored");
});

test("popup decisions carry VT evidence to Results in either provider order without another lookup", async () => {
    for (const vtFirst of [false, true]) {
        const cloud = fixture(); await cloud.handle(4);
        const local = { id: "local", originalPath: file, engine: "ClamAV", threatName: "Fixture.Local" };
        const store = new PendingThreats();
        for (const item of vtFirst ? [cloud.pending[0], local] : [local, cloud.pending[0]]) store.register(item, { size: 100, mtimeMs: 20 });
        const saved: any[] = []; let handler: any;
        const route = testModule("modules/results/server/routes/postApiPendingThreatsIdAction.ts", { "../storage": { addScanResult: async (result: any) => saved.push(result) } });
        route.registerPostApiPendingThreatsIdAction({ post: (_: any, action: any) => handler = action }, { pendingThreats: store.items, pendingThreatStore: store, pendingThreatActions: new Map(), settings: {}, sendApiEvent: () => {} });
        const response: any = { status() { return this; }, json(body: any) { this.body = body; } };
        await handler({ params: { id: store.items[0].id }, body: { action: "results" } }, response);
        assert.equal(response.body.success, true);
        for (const result of saved) {
            assert.equal(result.sha256, hash); assert.deepEqual(result.virusTotalRefinement.report, cloud.report(4));
            assert.equal(nextVirusTotalResultAttempt(result), 0);
        }
        assert.equal(saved.length, 2); assert.equal(saved.at(-1).detections.length, 2);
    }
});

test("changing only the popup preference persists it without restarting Shield or engines", async () => {
    let handler: any; const writes: any[] = [];
    const route = testModule("modules/settings/server/routes/postApiSettings.ts", { "../storage": { saveSettingsPatchRows: (settings: any, keys: any) => writes.push([settings, keys]) } });
    const context: any = { settings: { marker: true } };
    route.registerPostApiSettings({ post: (_: any, h: any) => handler = h }, context);
    const response: any = { status() { return this; }, json(body: any) { this.body = body; } };
    await handler({ body: { virusTotalShieldPopupMinDetections: 7 } }, response);
    assert.equal(response.body.success, true); assert.equal(context.settings.virusTotalShieldPopupMinDetections, 7);
    assert.deepEqual(Array.from(writes[0][1]), ["virusTotalShieldPopupMinDetections"]);
});

test("quiet low-count Results keep the VT evidence after storage and cannot generate a Results reminder", async t => {
    const f = stateFixture(t);
    const storage = testModule("modules/results/server/storage.ts", f.dependencies);
    const cloud = fixture(); await cloud.handle(1);
    await storage.addScanResult({ originalPath: file, source: "shield", engine: "VirusTotal", threatName: "Earlier finding" });
    await storage.addScanResult(cloud.results[0]);
    const saved = await storage.getScanResultByOriginalPath(file);
    assert.deepEqual(JSON.parse(JSON.stringify(saved.virusTotalRefinement.report)), cloud.report(1));
    assert.equal(saved.resultsReminderAt, 0); assert.equal((await storage.getResultsReminderSummary()).count, 0);
    await storage.addScanResult({ originalPath: file, source: "shield", engine: "ClamAV", threatName: "Local finding" });
    assert.equal((await storage.getResultsReminderSummary()).count, 1);
});
