import { englishText } from "../../../../shared/localization/runtime";
import { ensureScanResultHash, markVirusTotalCheckOpened, normalizeVirusTotalHashAlgorithm } from "../../../../addons/virustotal/server/account";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getScanResults, saveScanResults } from "../storage";
export function registerGetApiResultsIdVirustotalHash(app: any, context: ApplicationContext) {
    app.get("/api/results/:id/virustotal-hash", async (req, res) => {
        try {
            const results = await getScanResults();
            const result = results.find((item: any) => item.id === req.params.id);
            if (!result)
                throw new Error(englishText("backend.results.result_not_found"));
            const algorithm = normalizeVirusTotalHashAlgorithm(req.query?.algorithm || "sha256");
            const hash = await ensureScanResultHash(results, result, algorithm);
            markVirusTotalCheckOpened(result, algorithm);
            await saveScanResults(results);
            res.json({
                success: true,
                algorithm,
                hash,
                url: `https://www.virustotal.com/gui/file/${hash}/detection`,
                uploaded: false,
                message: englishText("backend.results.virustotal_report_prepared", {
                    value1: String(algorithm.toUpperCase())
                })
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
