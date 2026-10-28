import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { asRecord, parseAppStateJson } from "../../../server/core/database/values";
import { runtimeState } from "../../../server/core/runtimeState";
import { getVirusTotalCloudStatus } from "./account";

export function isVirusTotalAutoRefinementCandidate(result: any, settings: any) {
    const source = String(result?.source || "").toLowerCase();
    if (source === "shield")
        return settings.virusTotalShieldBackgroundCheckEnabled === true;
    return settings.virusTotalAutoRefineEnabled === true;
}

export async function getVirusTotalDashboardStatus(settings: any) {
    await ensureAppStateReady();
    const cloudStatus = await getVirusTotalCloudStatus(settings);
    const rows = getAppStateDb().prepare(`
        SELECT source,
               virus_total_refinement_status AS status,
               virus_total_refinement_label AS label,
               virus_total_refinement_message AS message,
               virus_total_refinement_checked_at AS checked_at,
               virus_total_refinement_stats AS stats
        FROM scan_results
    `).all();
    const breakdown: Record<string, number> = {
        likely_false_positive: 0,
        needs_review: 0,
        confirmed_suspicious: 0,
        confirmed_malicious: 0,
        upload_required: 0,
        awaiting_analysis: 0,
        error: 0
    };
    const totals = {
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0
    };
    let checkedCount = 0;
    let queuedCount = 0;
    let lastCheckedAt = 0;
    let lastLabel = "";
    let lastMessage = "";
    for (const row of rows) {
        const statusValue = String(row.status || "").trim();
        if (!statusValue) {
            if (cloudStatus.enabled &&
                isVirusTotalAutoRefinementCandidate(row, settings)) {
                queuedCount++;
            }
            continue;
        }
        if (["likely_false_positive", "needs_review", "confirmed_suspicious", "confirmed_malicious"].includes(statusValue))
            checkedCount++;
        if (Object.prototype.hasOwnProperty.call(breakdown, statusValue))
            breakdown[statusValue]++;
        const stats = asRecord(parseAppStateJson(row.stats, {}));
        totals.malicious += Number(stats.malicious || 0);
        totals.suspicious += Number(stats.suspicious || 0);
        totals.harmless += Number(stats.harmless || 0);
        totals.undetected += Number(stats.undetected || 0);
        const checkedAt = Number(row.checked_at || 0);
        if (checkedAt > lastCheckedAt) {
            lastCheckedAt = checkedAt;
            lastLabel = String(row.label || "");
            lastMessage = String(row.message || "");
        }
    }
    const queue = runtimeState.virusTotalQueueViewHandler?.({ summary: true }, cloudStatus.configured);
    return {
        ...cloudStatus,
        totalFindings: rows.length,
        checkedCount,
        queuedCount: queue?.totalPending ?? queuedCount,
        queueCounts: queue?.counts,
        lastCheckedAt: lastCheckedAt || null,
        lastLabel,
        lastMessage,
        breakdown,
        totals
    };
}
