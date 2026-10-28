import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { ensureAppStateReady } from "../../../../server/core/database/migrations";
import { getAppStateDb } from "../../../../server/core/database/schema";
import { runAppStateTransaction } from "../../../../server/core/database/values";
import { runtimeState } from "../../../../server/core/runtimeState";
import { insertHistoryRow } from "../../../history/server/rows";
import { randomBytes } from "crypto";
export function registerPostApiResultsIdDismiss(app: any, context: ApplicationContext) {
    app.post("/api/results/:id/dismiss", async (req, res) => {
        try {
            await ensureAppStateReady();
            const db = getAppStateDb();
            let removed = false;
            runAppStateTransaction(db, () => {
                const row = db.prepare("SELECT original_path FROM scan_results WHERE id = ?").get(req.params.id);
                if (!row)
                    return;
                db.prepare("DELETE FROM scan_results WHERE id = ?").run(req.params.id);
                insertHistoryRow(db, { id: `${Date.now()}-${randomBytes(3).toString("hex")}`, date: new Date().toISOString(),
                    type: "results-dismiss", target: row.original_path, result: 0, threatsFound: 0, scannedFiles: 0, duration: 0,
                    actionTaken: englishText("backend.results.removed_finding_from_results_file_kept_no_exception_added") });
                removed = true;
            });
            if (runtimeState.scanResultsChangedHandler)
                Promise.resolve(runtimeState.scanResultsChangedHandler()).catch(e => console.warn(englishText("backend.results.failed_to_notify_dismissed_result"), e));
            res.json({ success: true, removed });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || englishText("results.could_not_remove_the_finding") });
        }
    });
}
