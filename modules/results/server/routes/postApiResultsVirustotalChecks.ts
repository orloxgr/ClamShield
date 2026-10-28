import { englishText } from "../../../../shared/localization/runtime";
import { markVirusTotalCheckOpened, normalizeVirusTotalHashAlgorithm } from "../../../../addons/virustotal/server/account";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getScanResults, saveScanResults } from "../storage";
export function registerPostApiResultsVirustotalChecks(app: any, context: ApplicationContext) {
    app.post("/api/results/virustotal-checks", async (req, res) => {
        try {
            const action = req.body?.action === "upload"
                ? "upload"
                : normalizeVirusTotalHashAlgorithm(req.body?.action || "md5");
            const ids = Array.isArray(req.body?.ids)
                ? new Set(req.body.ids.map((item: any) => String(item || "")).filter(Boolean))
                : new Set<string>();
            if (ids.size === 0)
                throw new Error(englishText("backend.results.no_result_ids_were_provided"));
            const results = await getScanResults();
            let markedCount = 0;
            for (const result of results) {
                if (!ids.has(String(result.id || "")))
                    continue;
                markVirusTotalCheckOpened(result, action);
                markedCount++;
            }
            if (markedCount > 0)
                await saveScanResults(results);
            res.json({ success: true, markedCount });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
