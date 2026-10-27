import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs/promises";
import path from "node:path";
import { VirusTotalFileAnalysis } from "./virusTotalFileAnalysis";

const response = (body: any, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers });
async function fixture(t: any, size = 5, fetcher?: typeof fetch) {
    const buildDir = path.resolve("build");
    await fs.mkdir(buildDir, { recursive: true });
    const root = await fs.mkdtemp(path.join(buildDir, "vt-upload-test-"));
    const file = path.join(root, "harmless.txt");
    await fs.writeFile(file, "hello");
    if (size !== 5) await fs.truncate(file, size);
    t.after(async () => { assert.equal(path.dirname(root), buildDir); await fs.rm(root, { recursive: true, force: true }); });
    const calls: { url: string; init: RequestInit }[] = [];
    const recorded: boolean[] = [], slots: boolean[] = [];
    let quotaChecks = 0;
    const client = new VirusTotalFileAnalysis({
        reserveSlot: async wait => { slots.push(wait); },
        checkQuota: async () => { quotaChecks++; },
        recordRequest: async (key, exempt) => { assert.equal(key, "test-key"); recorded.push(exempt); },
        fetch: async (url, init) => { calls.push({ url: String(url), init }); return fetcher ? fetcher(url, init) : response({ data: { id: "saved-analysis" } }); },
        ...(size > 32 * 1024 ** 2 ? { openFile: async () => new Blob(["simulated large file"]) } : {})
    });
    return { client, file, calls, recorded, slots, quotaChecks: () => quotaChecks };
}

test("uploads real file bytes once with the API key and exempts a new contribution from lookup quota", async t => {
    const { client, file, calls, recorded, slots, quotaChecks } = await fixture(t);
    assert.equal(await client.upload("test-key", file, async () => true), "saved-analysis");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://www.virustotal.com/api/v3/files");
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.headers["x-apikey"], "test-key");
    const uploaded = (calls[0].init.body as FormData).get("file") as File;
    assert.equal(uploaded.name, "harmless.txt"); assert.equal(await uploaded.text(), "hello");
    assert.deepEqual(recorded, [true]); assert.deepEqual(slots, [false]); assert.equal(quotaChecks(), 0);
});

test("large files obtain a one-use upload URL and pace the POST after that request", async t => {
    const { client, file, calls, recorded, slots, quotaChecks } = await fixture(t, 33 * 1024 ** 2, async url =>
        String(url).endsWith("/upload_url") ? response({ data: "https://www.virustotal.com/_ah/upload/test" }) : response({ data: { id: "large-id" } }));
    assert.equal(await client.upload("test-key", file, async () => true), "large-id");
    assert.equal(calls[0].url, "https://www.virustotal.com/api/v3/files/upload_url");
    assert.equal(calls[1].url, "https://www.virustotal.com/_ah/upload/test");
    assert.deepEqual(slots, [false, true]); assert.deepEqual(recorded, [false, true]); assert.equal(quotaChecks(), 1);
});

test("analysis polling waits for completion and returns stats and per-engine detections", async t => {
    let polls = 0;
    const { client, recorded, quotaChecks } = await fixture(t, 5, async () => response({ data: { attributes: ++polls === 1
        ? { status: "queued" } : { status: "completed", stats: { malicious: 2, suspicious: 1 }, results: { Engine: { category: "malicious", result: "Test", engine_name: "Engine" } }, date: 123 } }, meta: { file_info: { sha256: "expected-hash" } } }));
    assert.equal(await client.analysis("test-key", "analysis/id", "expected-hash"), null);
    const completed = await client.analysis("test-key", "analysis/id", "expected-hash");
    assert.equal(completed?.data.attributes.last_analysis_stats.malicious, 2);
    assert.equal(completed?.data.attributes.last_analysis_results.Engine.category, "malicious");
    assert.deepEqual(recorded, [true, true]); assert.equal(quotaChecks(), 0);
});

test("provider errors retain HTTP status and Retry-After without exposing server payloads or keys", async t => {
    const { client, file } = await fixture(t, 5, async () => response({ error: "test-key-sensitive" }, 429, { "Retry-After": "120" }));
    await assert.rejects(client.upload("test-key", file, async () => true), (error: any) =>
        error.status === 429 && error.nextAllowedAt >= Date.now() + 119_000 && !error.message.includes("test-key"));
    const invalid = await fixture(t, 5, async () => response({}, 400));
    await assert.rejects(invalid.client.upload("test-key", invalid.file, async () => true), (error: any) => error.fileError && error.status === 400);
    const missing = await fixture(t, 5, async () => response({}, 404));
    await assert.rejects(missing.client.analysis("test-key", "expired", "hash"), (error: any) => error.analysisMissing === true);
});

test("a pause during large-upload setup prevents submitting any bytes", async t => {
    let active = true;
    const { client, file, calls } = await fixture(t, 33 * 1024 ** 2, async () => {
        active = false; return response({ data: "https://www.virustotal.com/_ah/upload/test" });
    });
    await assert.rejects(client.upload("test-key", file, async () => active), /stopped before submission/);
    assert.equal(calls.length, 1); assert.equal(calls[0].init.method, "GET");
});

test("invalid upload URLs, oversized files and mismatched analyses cannot be accepted", async t => {
    const hostile = await fixture(t, 33 * 1024 ** 2, async () => response({ data: "https://example.com/steal-key" }));
    await assert.rejects(hostile.client.upload("test-key", hostile.file, async () => true), /invalid upload URL/);
    assert.equal(hostile.calls.length, 1);
    const large = await fixture(t, 651 * 1024 ** 2);
    await assert.rejects(large.client.upload("test-key", large.file, async () => true), (error: any) => error.fileError === true);
    assert.equal(large.calls.length, 0);
    const mismatch = await fixture(t, 5, async () => response({ data: { attributes: { status: "completed", stats: {}, results: {} } }, meta: { file_info: { sha256: "different" } } }));
    await assert.rejects(mismatch.client.analysis("test-key", "id", "expected"), (error: any) => error.fileError === true && error.fileChanged === true);
    const incomplete = await fixture(t, 5, async () => response({ data: { attributes: { status: "completed" } } }));
    await assert.rejects(incomplete.client.analysis("test-key", "id", "hash"), /incomplete analysis/);
});
