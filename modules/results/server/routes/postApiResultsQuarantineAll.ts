import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { addHistory } from "../../../history/server/storage";
import { getScanResults, quarantineResultItem, saveScanResults } from "../storage";
import { existsSync } from "fs";
export function registerPostApiResultsQuarantineAll(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/results/quarantine-all", async (req, res) => {
        const results = await getScanResults();
        const remaining: any[] = [];
        const errors: any[] = [];
        let quarantinedCount = 0;
        let removedUnavailableCount = 0;
        for (const result of results) {
            if (!result.originalPath || !existsSync(result.originalPath)) {
                removedUnavailableCount++;
                continue;
            }
            try {
                await quarantineResultItem(context.settings, result);
                quarantinedCount++;
            }
            catch (e: any) {
                remaining.push(result);
                errors.push({ id: result.id, path: result.originalPath, error: e.message });
            }
        }
        await saveScanResults(remaining);
        await addHistory({
            type: "results-quarantine-all",
            target: "Scan Results",
            result: errors.length === 0 ? 0 : 1,
            threatsFound: quarantinedCount,
            scannedFiles: results.length,
            duration: 0,
            actionTaken: englishText("backend.results.quarantined_result", {
                quarantinedCount: String(quarantinedCount),
                value2: String(quarantinedCount === 1 ? "" : englishText("dns.s"))
            })
        });
        res.status(errors.length === 0 ? 200 : 207).json({
            success: errors.length === 0,
            quarantinedCount,
            removedUnavailableCount,
            errors
        });
    });
}
