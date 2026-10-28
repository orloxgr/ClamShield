import { englishText } from "../../../../shared/localization/runtime";
import { ensureScanResultHash, markVirusTotalCheckOpened } from "../../../../addons/virustotal/server/account";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getScanResults, saveScanResults } from "../storage";
export function registerGetApiResultsIdVirustotal(app: any, context: ApplicationContext) {
    app.get("/api/results/:id/virustotal", async (req, res) => {
        try {
            const results = await getScanResults();
            const result = results.find((item: any) => item.id === req.params.id);
            if (!result)
                throw new Error(englishText("backend.results.result_not_found"));
            const sha256 = await ensureScanResultHash(results, result, "sha256");
            markVirusTotalCheckOpened(result, "sha256");
            await saveScanResults(results);
            res.json({
                success: true,
                sha256,
                url: `https://www.virustotal.com/gui/file/${sha256}/detection`,
                uploaded: false,
                message: englishText("backend.results.virustotal_report_prepared_457c10a")
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
