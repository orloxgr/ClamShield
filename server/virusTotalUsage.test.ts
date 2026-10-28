import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { VirusTotalUsage } from "../addons/virustotal/server/virusTotalUsage";

const summary = (used = 10, allowed = 500) => ({ data: {
    api_requests_daily: { user: { used, allowed } },
    api_requests_monthly: { user: { used: used + 100, allowed: 15500 } }
} });
function fixture(fetcher?: (key: string) => Promise<any>) {
    const db = new DatabaseSync(":memory:");
    let time = Date.UTC(2026, 9, 15, 12);
    let calls = 0;
    const usage = new VirusTotalUsage(db, async key => { calls++; return fetcher ? fetcher(key) : summary(); }, () => time);
    usage.setKey("test-key-a");
    return { db, usage, calls: () => calls, advance: (ms: number) => { time += ms; } };
}

test("exempt uploads and analysis polls trigger usage sync without spending the local daily allowance", async t => {
    const { db, usage, calls, advance } = fixture(); t.after(() => db.close());
    await usage.refresh(500);
    for (let i = 0; i < 500; i++) { usage.record(undefined, true); advance(16000); }
    assert.equal(usage.status().day.count, 10);
    assert.equal(usage.status().month.count, 110);
    assert.equal(usage.status().sync.requestsSinceFetch, 500);
    await usage.refresh(500); assert.equal(calls(), 2);
    usage.record();
    assert.equal(usage.status().day.count, 11);
});

test("dashboard polling stays local and auto-refresh happens after 500 requests", async t => {
    const { db, usage, calls, advance } = fixture();
    t.after(() => db.close());
    await usage.refresh(500);
    for (let i = 0; i < 499; i++) {
        usage.record(); advance(16000);
        usage.status(); await usage.refresh(500);
    }
    for (let i = 0; i < 1000; i++) usage.status();
    assert.equal(calls(), 1);
    usage.record(); advance(16000); await usage.refresh(500);
    assert.equal(calls(), 2);
    assert.equal(usage.status().day.count, 10, "provider usage replaces the local estimate, including exempt calls");
    assert.equal(usage.status().sync.requestsSinceFetch, 0);
});

test("concurrent/manual fetches are coalesced and limited to once per minute", async t => {
    let resolveFetch!: (value: any) => void;
    const { db, usage, calls, advance } = fixture(() => new Promise(resolve => { resolveFetch = resolve; }));
    t.after(() => db.close());
    const pending = Array.from({ length: 50 }, () => usage.refresh(500, "manual"));
    await Promise.resolve();
    assert.equal(calls(), 1);
    assert.equal(usage.status().sync.fetching, true);
    resolveFetch(summary()); await Promise.all(pending);
    await usage.refresh(500, "manual");
    assert.equal(calls(), 1);
    advance(60000);
    const next = usage.refresh(500, "manual");
    await Promise.resolve(); resolveFetch(summary()); await next;
    assert.equal(calls(), 2);
});

test("uses actual account allowances and the most restrictive user/group remaining quota", async t => {
    const { db, usage } = fixture(async () => ({ data: {
        api_requests_daily: { user: { used: 20, allowed: 1000 }, group: { used: 98, allowed: 100 } },
        api_requests_monthly: { user: { used: 300, allowed: 20000 } }
    } }));
    t.after(() => db.close());
    await usage.refresh(500);
    assert.equal(usage.status().day.scope, "group");
    assert.equal(usage.status().day.remaining, 2);
    assert.equal(usage.status().month.limit, 20000);
    usage.record();
    assert.equal(usage.status().day.count, 99);
    assert.equal(usage.status().day.source, "estimate_since_sync");
});

test("zero allowance is a real quota, not a missing value", async t => {
    const { db, usage } = fixture(async () => summary(0, 0));
    t.after(() => db.close());
    await usage.refresh(500);
    assert.equal(usage.status().day.limit, 0);
    assert.equal(usage.status().day.remaining, 0);
    assert.equal(usage.status().day.source, "virustotal");
});

test("legacy counters are estimates until the first provider sync corrects them", async t => {
    const { db, usage } = fixture(async () => summary(123));
    t.after(() => db.close());
    usage.seedLegacyCounts(500, 2000);
    assert.equal(usage.status().day.count, 500);
    assert.equal(usage.status().day.source, "local_estimate");
    await usage.refresh(500, "limit");
    assert.equal(usage.status().day.count, 123);
    assert.equal(usage.status().day.remaining, 377);
});

test("key changes and restarts retain separate persisted snapshots and counters", async t => {
    const { db, usage } = fixture();
    t.after(() => db.close());
    await usage.refresh(500);
    usage.record();
    usage.setKey("test-key-b");
    assert.equal(usage.status().day.count, 0);
    usage.record("test-key-a");
    assert.equal(usage.status().day.count, 0, "in-flight requests count against their original key");
    const restarted = new VirusTotalUsage(db, async () => summary(), () => Date.UTC(2026, 9, 15, 12));
    restarted.setKey("test-key-a");
    assert.equal(restarted.status().day.count, 12);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM vt_usage_snapshots WHERE payload LIKE '%test-key%'").get()?.count, 0);
});

test("UTC rollover drops yesterday's usage and triggers a single new-period sync", async t => {
    const { db, usage, calls, advance } = fixture();
    t.after(() => db.close());
    await usage.refresh(500);
    usage.record(); advance(24 * 60 * 60 * 1000);
    assert.equal(usage.status().day.count, 0);
    assert.equal(usage.status().month.count, 111);
    await usage.refresh(500);
    assert.equal(calls(), 2);
    for (let i = 0; i < 10; i++) await usage.refresh(500);
    assert.equal(calls(), 2);
});

test("failed fetches back off and cannot leak keys from transport errors", async t => {
    const { db, usage, calls, advance } = fixture(async () => {
        throw Object.assign(new Error("GET /users/SECRET-API-KEY/overall_quotas failed"), { response: { status: 403 } });
    });
    t.after(() => db.close());
    await usage.refresh(1);
    for (let i = 0; i < 20; i++) { usage.record(); await usage.refresh(1); }
    assert.equal(calls(), 1);
    assert(!JSON.stringify(usage.status()).includes("SECRET-API-KEY"));
    advance(60000); await usage.refresh(1);
    assert.equal(calls(), 1);
    await usage.refresh(1, "manual");
    assert.equal(calls(), 2, "a manual retry is allowed after one minute");
    assert.equal(usage.status().day.source, "local_estimate");
});

test("malformed responses preserve the previous snapshot and missing periods stay estimates", async t => {
    let response: any = { data: { api_requests_monthly: { user: { used: 7, allowed: 100 } } } };
    const { db, usage, advance } = fixture(async () => response);
    t.after(() => db.close());
    usage.record(); usage.record();
    await usage.refresh(500);
    assert.equal(usage.status().day.count, 2);
    assert.equal(usage.status().day.source, "local_estimate");
    assert.equal(usage.status().month.count, 7);
    response = { data: { api_requests_daily: { user: { used: "invalid", allowed: -1 } } } };
    advance(60000); await usage.refresh(500, "manual");
    assert.equal(usage.status().month.count, 7);
    assert(usage.status().sync.error);
});

test("requests made during a fetch remain counted after the snapshot arrives", async t => {
    let finish!: (data: any) => void;
    const { db, usage } = fixture(() => new Promise(resolve => { finish = resolve; }));
    t.after(() => db.close());
    const request = usage.refresh(500);
    await Promise.resolve();
    usage.record(); usage.record();
    finish(summary(10)); await request;
    assert.equal(usage.status().day.count, 12);
    assert.equal(usage.status().day.reportedCount, 10);
});
