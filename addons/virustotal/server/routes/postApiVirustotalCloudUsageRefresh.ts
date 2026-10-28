import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { getVirusTotalUsageStatus, loadVirusTotalApiKey } from "../account";
export function registerPostApiVirustotalCloudUsageRefresh(app: any, context: Pick<ApplicationContext, "virusTotalScanNextAllowedAt" | "virusTotalScanQueue" | "scheduleVirusTotalRefinement" | "scheduleShieldVirusTotalCheck" | "scheduleVirusTotalScan">) {
    app.post("/api/virustotal-cloud/usage/refresh", async (_req, res) => {
        try {
            const apiKey = await loadVirusTotalApiKey();
            if (!apiKey || !runtimeState.virusTotalUsageTracker)
                return res.status(400).json({ error: englishText("backend.virustotal.configure_a_virustotal_api_key_first") });
            runtimeState.virusTotalUsageTracker.setKey(apiKey);
            const before = runtimeState.virusTotalUsageTracker.status().sync.fetchedAt;
            await runtimeState.virusTotalUsageTracker.refresh(runtimeState.virusTotalUsageRefreshEveryRequests, "manual");
            const usage = await getVirusTotalUsageStatus();
            if (usage.sync.fetchedAt !== before && usage.day.remaining > 0 && usage.month.remaining > 0) {
                runtimeState.virusTotalRefinementNextAllowedAt = 0;
                runtimeState.virusTotalShieldNextAllowedAt = 0;
                context.virusTotalScanNextAllowedAt = 0;
                context.virusTotalScanQueue.wakeLookups();
                context.scheduleVirusTotalRefinement();
                context.scheduleShieldVirusTotalCheck();
                context.scheduleVirusTotalScan();
            }
            res.json({ usage });
        }
        catch {
            res.status(500).json({ error: englishText("backend.virustotal.could_not_refresh_virustotal_usage") });
        }
    });
}
