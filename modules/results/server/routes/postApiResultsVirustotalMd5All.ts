import { englishText } from "../../../../shared/localization/runtime";
import { ensureScanResultHash } from "../../../../addons/virustotal/server/account";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getScanResults, saveScanResults } from "../storage";
export function registerPostApiResultsVirustotalMd5All(app: any, context: ApplicationContext) {
    app.post("/api/results/virustotal-md5-all", async (_req, res) => {
        try {
            const results = await getScanResults();
            const checkedItems: any[] = [];
            const skippedItems: any[] = [];
            let changed = false;
            for (const result of results) {
                try {
                    const md5 = await ensureScanResultHash(results, result, "md5");
                    checkedItems.push({
                        id: result.id,
                        threatName: result.threatName || "Unknown Threat",
                        originalPath: result.originalPath || "",
                        md5,
                        url: `https://www.virustotal.com/gui/file/${md5}/detection`
                    });
                    changed = true;
                }
                catch (e: any) {
                    skippedItems.push({
                        id: result.id,
                        originalPath: result.originalPath || "",
                        error: e?.message || String(e)
                    });
                }
            }
            if (changed)
                await saveScanResults(results);
            res.json({
                success: true,
                items: checkedItems,
                skippedItems,
                skippedCount: skippedItems.length,
                uploaded: false,
                message: englishText("backend.results.virustotal_md5_checks_prepared")
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
