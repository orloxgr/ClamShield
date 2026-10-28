import { englishText } from "../../../shared/localization/runtime";
import { createHash } from "node:crypto";
type Quota = {
    allowed: number;
    used: number;
    scope: string;
};
type Snapshot = {
    fetchedAt?: number;
    dayKey?: string;
    monthKey?: string;
    day?: Quota[];
    month?: Quota[];
    baselineDay?: number;
    baselineMonth?: number;
    lastAttemptAt?: number;
    attemptDay?: string;
    attemptMonth?: string;
    attemptTotal?: number;
    error?: string;
};
const dayKey = (now: number) => new Date(now).toISOString().slice(0, 10);
const monthKey = (now: number) => dayKey(now).slice(0, 7);
function parseQuotas(value: any): Quota[] {
    return ["user", "group"].flatMap(scope => {
        const quota = value?.[scope];
        return typeof quota?.allowed === "number" && Number.isFinite(quota.allowed) && quota.allowed >= 0 &&
            typeof quota?.used === "number" && Number.isFinite(quota.used) && quota.used >= 0
            ? [{ allowed: quota.allowed, used: quota.used, scope }] : [];
    });
}
export class VirusTotalUsage {
    private apiKey = "";
    private keyId = "";
    private inFlight = new Map<string, Promise<void>>();
    readonly cooldownMs = 60000;
    constructor(private db: any, private fetchSummary: (apiKey: string) => Promise<any>, private now = Date.now) {
        db.exec(`CREATE TABLE IF NOT EXISTS vt_usage_requests (
            key_id TEXT NOT NULL, period TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(key_id, period));
            CREATE TABLE IF NOT EXISTS vt_usage_snapshots (key_id TEXT PRIMARY KEY, payload TEXT NOT NULL);`);
    }
    setKey(apiKey: string) {
        this.apiKey = apiKey;
        this.keyId = apiKey ? createHash("sha256").update(apiKey).digest("hex") : "";
    }
    seedLegacyCounts(day: number, month: number) {
        if (!this.keyId || this.db.prepare("SELECT 1 FROM vt_usage_requests LIMIT 1").get())
            return;
        const insert = this.db.prepare("INSERT OR IGNORE INTO vt_usage_requests VALUES (?, ?, ?)");
        insert.run(this.keyId, dayKey(this.now()), day);
        insert.run(this.keyId, monthKey(this.now()), month);
        insert.run(this.keyId, "total", Math.max(day, month));
    }
    private count(period: string, keyId = this.keyId) {
        return Number(this.db.prepare("SELECT count FROM vt_usage_requests WHERE key_id = ? AND period = ?").get(keyId, period)?.count || 0);
    }
    private snapshot(keyId = this.keyId): Snapshot {
        const row = this.db.prepare("SELECT payload FROM vt_usage_snapshots WHERE key_id = ?").get(keyId);
        return row ? JSON.parse(row.payload) : {};
    }
    private save(snapshot: Snapshot, keyId: string) {
        this.db.prepare("INSERT INTO vt_usage_snapshots VALUES (?, ?) ON CONFLICT(key_id) DO UPDATE SET payload = excluded.payload")
            .run(keyId, JSON.stringify(snapshot));
    }
    record(apiKey?: string, exempt = false) {
        const keyId = apiKey ? createHash("sha256").update(apiKey).digest("hex") : this.keyId;
        if (!keyId)
            return;
        const now = this.now();
        const increment = this.db.prepare(`INSERT INTO vt_usage_requests VALUES (?, ?, 1)
            ON CONFLICT(key_id, period) DO UPDATE SET count = count + 1`);
        this.db.exec("BEGIN");
        try {
            for (const period of exempt ? ["total"] : ["total", dayKey(now), monthKey(now)])
                increment.run(keyId, period);
            this.db.exec("COMMIT");
        }
        catch (error) {
            this.db.exec("ROLLBACK");
            throw error;
        }
    }
    status() {
        const now = this.now();
        const snapshot = this.snapshot();
        const localDay = this.count(dayKey(now));
        const localMonth = this.count(monthKey(now));
        const period = (quotas: Quota[] | undefined, current: boolean, local: number, baseline: number | undefined, fallback: number) => {
            const delta = current && quotas?.length ? Math.max(0, local - (baseline || 0)) : local;
            const scopes = (quotas?.length ? quotas : [{ allowed: fallback, used: 0, scope: "default" }])
                .map(quota => ({ ...quota, count: (current ? quota.used : 0) + delta }));
            const limiting = scopes.reduce((a, b) => b.allowed - b.count < a.allowed - a.count ? b : a);
            return {
                count: limiting.count, limit: limiting.allowed, remaining: Math.max(0, limiting.allowed - limiting.count),
                reportedCount: current && quotas?.length ? limiting.used : null,
                source: current && quotas?.length ? delta ? "estimate_since_sync" : "virustotal" : "local_estimate",
                scope: limiting.scope
            };
        };
        return {
            day: period(snapshot.day, snapshot.dayKey === dayKey(now), localDay, snapshot.baselineDay, 500),
            month: period(snapshot.month, snapshot.monthKey === monthKey(now), localMonth, snapshot.baselineMonth, 15500),
            sync: {
                fetchedAt: snapshot.fetchedAt || null, lastAttemptAt: snapshot.lastAttemptAt || null,
                nextFetchAllowedAt: snapshot.lastAttemptAt ? snapshot.lastAttemptAt + this.cooldownMs : 0,
                requestsSinceFetch: Math.max(0, this.count("total") - (snapshot.attemptTotal || 0)),
                fetching: this.inFlight.has(this.keyId), error: snapshot.error || ""
            }
        };
    }
    async refresh(everyRequests: number, reason: "automatic" | "manual" | "limit" = "automatic") {
        if (!this.apiKey)
            return;
        const keyId = this.keyId;
        const apiKey = this.apiKey;
        const existing = this.inFlight.get(keyId);
        if (existing)
            return existing;
        const now = this.now();
        const snapshot = this.snapshot(keyId);
        const sinceAttempt = this.count("total", keyId) - (snapshot.attemptTotal || 0);
        const periodChanged = snapshot.attemptDay !== dayKey(now) || snapshot.attemptMonth !== monthKey(now);
        const due = !snapshot.lastAttemptAt || periodChanged || sinceAttempt >= Math.max(1, everyRequests);
        // Failed syncs back off too. Dashboard polling never calls this method.
        const cooldown = snapshot.error ? 15 * 60000 : this.cooldownMs;
        if (snapshot.lastAttemptAt && now - snapshot.lastAttemptAt < (reason === "manual" ? this.cooldownMs : cooldown))
            return;
        if (reason === "automatic" && !due)
            return;
        const baselineDay = this.count(dayKey(now), keyId);
        const baselineMonth = this.count(monthKey(now), keyId);
        const attempt = {
            ...snapshot, lastAttemptAt: now, attemptDay: dayKey(now), attemptMonth: monthKey(now),
            attemptTotal: this.count("total", keyId), error: ""
        };
        this.save(attempt, keyId);
        const promise = Promise.resolve().then(async () => {
            try {
                const response = await this.fetchSummary(apiKey);
                const data = response?.data || response;
                const day = parseQuotas(data?.api_requests_daily);
                const month = parseQuotas(data?.api_requests_monthly);
                if (!day.length && !month.length)
                    throw new Error(englishText("backend.virusTotalUsage.ts.no_quota_data"));
                this.save({
                    ...attempt, fetchedAt: now, dayKey: dayKey(now), monthKey: monthKey(now),
                    day, month, baselineDay, baselineMonth
                }, keyId);
            }
            catch (error: any) {
                const status = Number(error?.response?.status || 0);
                // Axios errors may contain the API key in their URL. Never persist or return them.
                const message = status === 401 || status === 403
                    ? englishText("backend.virusTotalUsage.ts.virustotal_did_not_allow_quota_access_for_this_key_showing_the_ca") : status === 429 ? englishText("backend.virusTotalUsage.ts.virustotal_rate_limited_the_quota_fetch_try_again_later") : englishText("backend.virusTotalUsage.ts.could_not_fetch_virustotal_quotas_showing_the_cached_local_estima");
                this.save({ ...attempt, error: message }, keyId);
            }
            finally {
                this.inFlight.delete(keyId);
            }
        });
        this.inFlight.set(keyId, promise);
        return promise;
    }
}
