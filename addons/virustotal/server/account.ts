import { englishText } from "../../../shared/localization/runtime";
import { normalizeNumberSetting } from "../../../modules/settings/server/validation";
import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { runAppStateTransaction } from "../../../server/core/database/values";
import { virusTotalApiKeySecretPath } from "../../../server/core/paths";
import { runtimeState } from "../../../server/core/runtimeState";
import { loadEncryptedSecret, saveEncryptedSecret } from "../../../server/core/secrets";
import { hashFile, sleep } from "../../../server/core/utils";
import { virusTotalPublicApiLimits } from "./constants";
import { existsSync } from "fs";
export function normalizeVirusTotalHashAlgorithm(value: any) {
    const algorithm = String(value || "sha256").toLowerCase();
    if (["md5", "sha1", "sha256"].includes(algorithm))
        return algorithm;
    throw new Error(englishText("backend.virustotal.unsupported_virustotal_hash_algorithm"));
}
export function markVirusTotalCheckOpened(result: any, action: string) {
    const existing = result.virusTotalChecks && typeof result.virusTotalChecks === "object" && !Array.isArray(result.virusTotalChecks)
        ? result.virusTotalChecks
        : {};
    result.virusTotalChecks = {
        ...existing,
        [action]: Date.now()
    };
}
export async function ensureScanResultHash(results: any[], result: any, algorithm: string) {
    const key = normalizeVirusTotalHashAlgorithm(algorithm);
    let hash = String(result[key] || "");
    const expectedLength = key === "md5" ? 32 : key === "sha1" ? 40 : 64;
    const pattern = new RegExp(`^[a-f0-9]{${expectedLength}}$`, "i");
    if (!pattern.test(hash)) {
        if (!result.originalPath || !existsSync(result.originalPath)) {
            throw new Error(englishText("backend.virustotal.the_original_file_is_unavailable_and_no_saved_hash_exists", {
                value1: String(key.toUpperCase())
            }));
        }
        hash = await hashFile(result.originalPath, key);
        result[key] = hash;
        await ensureAppStateReady();
        getAppStateDb().prepare(`UPDATE scan_results SET ${key} = ? WHERE id = ? AND timestamp = ?`).run(hash, result.id, result.timestamp);
    }
    return hash.toLowerCase();
}
export function normalizeVirusTotalApiKey(value: any) {
    const key = String(value || "").trim();
    if (!key)
        return "";
    if (key.length < 32 || key.length > 256 || /[\s"'<>]/.test(key)) {
        throw new Error(englishText("backend.virustotal.the_virustotal_api_key_format_looks_invalid"));
    }
    return key;
}
export async function saveVirusTotalApiKey(apiKey: string) {
    await saveEncryptedSecret(virusTotalApiKeySecretPath, normalizeVirusTotalApiKey(apiKey));
    runtimeState.virusTotalUsageTracker?.setKey(apiKey);
}
export async function loadVirusTotalApiKey() {
    return await loadEncryptedSecret(virusTotalApiKeySecretPath);
}
export function getVirusTotalUtcDayKey(now = Date.now()) {
    return new Date(now).toISOString().slice(0, 10);
}
export function getVirusTotalUtcMonthKey(now = Date.now()) {
    return new Date(now).toISOString().slice(0, 7);
}
export function getNextUtcDayReset(now = Date.now()) {
    const date = new Date(now);
    return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() + 1);
}
export function getNextUtcMonthReset(now = Date.now()) {
    const date = new Date(now);
    return Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1);
}
export function getVirusTotalUsagePeriodKeys(now = Date.now()) {
    return {
        day: `virustotal:${getVirusTotalUtcDayKey(now)}`,
        month: `virustotal:${getVirusTotalUtcMonthKey(now)}`
    };
}
export async function getVirusTotalUsageStatus() {
    await ensureAppStateReady();
    const now = Date.now();
    const db = getAppStateDb();
    const keys = getVirusTotalUsagePeriodKeys(now);
    const getCount = (key: string) => {
        const row = db.prepare("SELECT count FROM virus_total_usage WHERE period = ?").get(key);
        return Math.max(0, Number(row?.count || 0));
    };
    const account = runtimeState.virusTotalUsageTracker?.status();
    const dayCount = account?.day.count ?? getCount(keys.day);
    const monthCount = account?.month.count ?? getCount(keys.month);
    const dayLimit = account?.day.limit ?? virusTotalPublicApiLimits.perDay;
    const monthLimit = account?.month.limit ?? virusTotalPublicApiLimits.perMonth;
    return {
        rate: {
            maxLookupsPerMinute: 4,
            spacingMs: virusTotalPublicApiLimits.perLookupMs,
            nextLookupAllowedAt: runtimeState.virusTotalNextLookupAllowedAt || null
        },
        day: {
            ...account?.day,
            key: getVirusTotalUtcDayKey(now),
            count: dayCount,
            limit: dayLimit,
            remaining: Math.max(0, dayLimit - dayCount),
            resetsAt: getNextUtcDayReset(now)
        },
        month: {
            ...account?.month,
            key: getVirusTotalUtcMonthKey(now),
            count: monthCount,
            limit: monthLimit,
            remaining: Math.max(0, monthLimit - monthCount),
            resetsAt: getNextUtcMonthReset(now)
        },
        sync: { ...account?.sync, refreshEveryRequests: runtimeState.virusTotalUsageRefreshEveryRequests }
    };
}
export async function assertVirusTotalQuotaAvailable() {
    await runtimeState.virusTotalUsageTracker?.refresh(runtimeState.virusTotalUsageRefreshEveryRequests);
    let usage = await getVirusTotalUsageStatus();
    if (usage.day.remaining === 0 || usage.month.remaining === 0) {
        await runtimeState.virusTotalUsageTracker?.refresh(runtimeState.virusTotalUsageRefreshEveryRequests, "limit");
        usage = await getVirusTotalUsageStatus();
    }
    if (usage.day.count >= usage.day.limit) {
        const error: any = new Error(usage.sync.error
            ? englishText("backend.virustotal.estimated_virustotal_daily_limit_reached_fetch_usage_on_the_dashb") : englishText("backend.virustotal.virustotal_daily_lookup_limit_reached_cloud_checks_will_resume_to"));
        error.status = 429;
        error.localQuotaLimit = true;
        error.nextAllowedAt = usage.sync.error ? Math.min(usage.day.resetsAt, Math.max(Date.now() + 1000, Number(usage.sync.lastAttemptAt || 0) + 15 * 60 * 1000)) : usage.day.resetsAt;
        throw error;
    }
    if (usage.month.count >= usage.month.limit) {
        const error: any = new Error(englishText("backend.virustotal.virustotal_monthly_lookup_limit_reached_cloud_checks_will_resume"));
        error.status = 429;
        error.localQuotaLimit = true;
        error.nextAllowedAt = usage.sync.error ? Math.min(usage.month.resetsAt, Math.max(Date.now() + 1000, Number(usage.sync.lastAttemptAt || 0) + 15 * 60 * 1000)) : usage.month.resetsAt;
        throw error;
    }
}
export function reserveVirusTotalLookupSlot() {
    const now = Date.now();
    if (now < runtimeState.virusTotalNextLookupAllowedAt) {
        const error: any = new Error(englishText("backend.virustotal.virustotal_lookup_rate_limit_queued"));
        error.status = 429;
        error.localRateLimit = true;
        error.nextAllowedAt = runtimeState.virusTotalNextLookupAllowedAt;
        throw error;
    }
    runtimeState.virusTotalNextLookupAllowedAt = now + virusTotalPublicApiLimits.perLookupMs;
}
export async function waitForVirusTotalLookupSlot() {
    for (;;) {
        const delayMs = Math.max(0, runtimeState.virusTotalNextLookupAllowedAt - Date.now());
        if (delayMs > 0)
            await sleep(Math.min(delayMs, 30000));
        try {
            reserveVirusTotalLookupSlot();
            return;
        }
        catch (e: any) {
            if (!e?.localRateLimit)
                throw e;
        }
    }
}
export async function recordVirusTotalLookup(apiKey?: string, exempt = false) {
    await ensureAppStateReady();
    const now = Date.now();
    const db = getAppStateDb();
    const keys = getVirusTotalUsagePeriodKeys(now);
    const increment = db.prepare(`
        INSERT INTO virus_total_usage(period, count, updated_at)
        VALUES (?, 1, ?)
        ON CONFLICT(period) DO UPDATE SET
            count = count + 1,
            updated_at = excluded.updated_at
    `);
    if (!exempt)
        runAppStateTransaction(db, () => {
            increment.run(keys.day, now);
            increment.run(keys.month, now);
        });
    runtimeState.virusTotalUsageTracker?.record(apiKey, exempt);
    if (runtimeState.virusTotalUsageSyncEnabled) {
        runtimeState.virusTotalUsageTracker?.refresh(runtimeState.virusTotalUsageRefreshEveryRequests).catch(() => { });
    }
}
export async function recordVirusTotalLookupSafely(apiKey?: string, exempt = false) {
    try {
        await recordVirusTotalLookup(apiKey, exempt);
    }
    catch (e: any) {
        console.warn(englishText("backend.virustotal.could_not_record_virustotal_api_usage"), e?.message || e);
    }
}
export async function getVirusTotalCloudStatus(settings: any) {
    return {
        enabled: settings.virusTotalCloudEnabled === true,
        autoRefineEnabled: settings.virusTotalAutoRefineEnabled === true,
        resultsUploadUnknownEnabled: settings.virusTotalResultsUploadUnknownEnabled === true,
        resultsUploadMaxSizeMb: normalizeNumberSetting("virusTotalResultsUploadMaxSizeMb", settings.virusTotalResultsUploadMaxSizeMb),
        shieldBackgroundCheckEnabled: settings.virusTotalShieldBackgroundCheckEnabled === true,
        shieldUploadUnknownEnabled: settings.virusTotalShieldUploadUnknownEnabled === true,
        shieldUploadMaxSizeMb: normalizeNumberSetting("virusTotalShieldUploadMaxSizeMb", settings.virusTotalShieldUploadMaxSizeMb),
        configured: Boolean(await loadVirusTotalApiKey()),
        usage: await getVirusTotalUsageStatus()
    };
}
