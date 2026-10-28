import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getScanResults, saveScanResults } from "../storage";
import { existsSync } from "fs";
export function registerPostApiResultsClearMissing(app: any, context: ApplicationContext) {
    app.post("/api/results/clear-missing", async (req, res) => {
        const results = await getScanResults();
        const remaining = results.filter((result: any) => result.originalPath && existsSync(result.originalPath));
        const removedCount = results.length - remaining.length;
        await saveScanResults(remaining);
        res.json({ success: true, removedCount });
    });
}
