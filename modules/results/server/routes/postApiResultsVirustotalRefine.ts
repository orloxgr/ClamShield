import { englishText } from "../../../../shared/localization/runtime";
import { loadVirusTotalApiKey } from "../../../../addons/virustotal/server/account";
import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerPostApiResultsVirustotalRefine(app: any, context: Pick<ApplicationContext, "settings" | "scheduleVirusTotalRefinement" | "getVirusTotalRefinementQueueStatus">) {
    app.post("/api/results/virustotal-refine", async (_req, res) => {
        try {
            if (context.settings.virusTotalCloudEnabled !== true || context.settings.virusTotalAutoRefineEnabled !== true) {
                throw new Error(englishText("backend.results.virustotal_false_positive_refinement_is_disabled"));
            }
            if (!await loadVirusTotalApiKey()) {
                throw new Error(englishText("backend.results.virustotal_api_key_is_not_configured"));
            }
            context.scheduleVirusTotalRefinement();
            res.json({ success: true, status: await context.getVirusTotalRefinementQueueStatus() });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
