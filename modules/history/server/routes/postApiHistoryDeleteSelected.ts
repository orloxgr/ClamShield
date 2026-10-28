import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { ensureAppStateReady } from "../../../../server/core/database/migrations";
import { getAppStateDb } from "../../../../server/core/database/schema";
import { runAppStateTransaction } from "../../../../server/core/database/values";
export function registerPostApiHistoryDeleteSelected(app: any, context: ApplicationContext) {
    app.post("/api/history/delete-selected", async (req, res) => {
        try {
            const ids = Array.isArray(req.body?.ids)
                ? req.body.ids.map((item: any) => String(item || "")).filter(Boolean)
                : [];
            if (ids.length === 0)
                return res.status(400).json({ success: false, error: englishText("backend.history.no_history_items_selected") });
            await ensureAppStateReady();
            const db = getAppStateDb();
            const deleteStmt = db.prepare("DELETE FROM history WHERE id = ?");
            let deletedCount = 0;
            runAppStateTransaction(db, () => {
                ids.forEach(id => {
                    const result = deleteStmt.run(id);
                    deletedCount += Number(result.changes || 0);
                });
            });
            res.json({ success: true, deletedCount });
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || String(e) });
        }
    });
}
