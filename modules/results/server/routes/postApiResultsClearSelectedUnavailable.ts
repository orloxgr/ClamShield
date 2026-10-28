import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getScanResults, saveScanResults } from "../storage";
import { existsSync } from "fs";
export function registerPostApiResultsClearSelectedUnavailable(app: any, context: ApplicationContext) {
    app.post("/api/results/clear-selected-unavailable", async (req, res) => {
        try {
            const ids = Array.isArray(req.body?.ids)
                ? new Set(req.body.ids.map((item: any) => String(item || "")).filter(Boolean))
                : new Set<string>();
            if (ids.size === 0)
                return res.status(400).json({ success: false, error: englishText("backend.results.no_results_selected") });
            const results = await getScanResults();
            const remaining: any[] = [];
            let removedCount = 0;
            for (const result of results) {
                if (ids.has(String(result.id || "")) && (!result.originalPath || !existsSync(result.originalPath))) {
                    removedCount++;
                    continue;
                }
                remaining.push(result);
            }
            if (removedCount > 0)
                await saveScanResults(remaining);
            res.json({ success: true, removedCount });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
