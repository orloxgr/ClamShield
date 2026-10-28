import { englishText } from "../../../../shared/localization/runtime";
import { loadVirusTotalApiKey } from "../../../../addons/virustotal/server/account";
import { getVirusTotalResultChecks } from "../../../../addons/virustotal/server/refinement";
import { isVirusTotalAutoRefinementCandidate } from "../../../../addons/virustotal/server/status";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getScanResults, saveScanResults } from "../storage";
export function registerPostApiResultsVirustotalRecheckAll(app: any, context: Pick<ApplicationContext, "settings" | "scheduleVirusTotalRefinement">) {
    app.post("/api/results/virustotal-recheck-all", async (_req, res) => {
        try {
            if (context.settings.virusTotalCloudEnabled !== true || context.settings.virusTotalAutoRefineEnabled !== true) {
                throw new Error(englishText("backend.results.virustotal_cloud_check_is_disabled"));
            }
            if (!await loadVirusTotalApiKey()) {
                throw new Error(englishText("backend.results.virustotal_api_key_is_not_configured"));
            }
            const results = await getScanResults();
            let queuedCount = 0;
            for (const result of results) {
                if (!isVirusTotalAutoRefinementCandidate(result, context.settings))
                    continue;
                result.virusTotalRefinement = null;
                const checks = getVirusTotalResultChecks(result);
                delete checks.cloud;
                checks.resultsWorkflowRetryAt = 1;
                checks.resultsUploadCheckAfter = 1;
                result.virusTotalChecks = checks;
                queuedCount++;
            }
            if (queuedCount > 0)
                await saveScanResults(results);
            context.scheduleVirusTotalRefinement();
            res.json({
                success: true,
                queuedCount,
                message: queuedCount > 0
                    ? englishText("backend.results.result_item_s_queued_for_virustotal_recheck", {
                        queuedCount: String(queuedCount)
                    }) : englishText("backend.results.no_result_items_are_eligible_for_virustotal_recheck")
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
