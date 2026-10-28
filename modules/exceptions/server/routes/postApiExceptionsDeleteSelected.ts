import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { ensureAppStateReady } from "../../../../server/core/database/migrations";
import { getAppStateDb } from "../../../../server/core/database/schema";
import { normalizedStatePath, runAppStateTransaction } from "../../../../server/core/database/values";
export function registerPostApiExceptionsDeleteSelected(app: any, context: ApplicationContext) {
    app.post("/api/exceptions/delete-selected", async (req, res) => {
        try {
            const paths = Array.isArray(req.body?.paths)
                ? req.body.paths.map((item: any) => String(item || "")).filter(Boolean)
                : [];
            if (paths.length === 0)
                return res.status(400).json({ success: false, error: englishText("backend.exceptions.no_exceptions_selected") });
            await ensureAppStateReady();
            const db = getAppStateDb();
            const deleteException = db.prepare("DELETE FROM exceptions WHERE normalized_path = ?");
            const deleteReport = db.prepare("DELETE FROM exception_reports WHERE normalized_path = ?");
            let removedCount = 0;
            runAppStateTransaction(db, () => {
                paths.forEach(exceptionPath => {
                    const key = normalizedStatePath(exceptionPath);
                    const result = deleteException.run(key);
                    deleteReport.run(key);
                    removedCount += Number(result.changes || 0);
                });
            });
            res.json({ success: true, removedCount });
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || String(e) });
        }
    });
}
