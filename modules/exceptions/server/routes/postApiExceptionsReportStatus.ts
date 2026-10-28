import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { ensureAppStateReady } from "../../../../server/core/database/migrations";
import { getAppStateDb } from "../../../../server/core/database/schema";
import { asRecord, normalizedStatePath, parseAppStateJson } from "../../../../server/core/database/values";
import { reportStatus, updateReportStatus } from "../reporting";
import { insertExceptionReportRow } from "../rows";
import path from "path";
export function registerPostApiExceptionsReportStatus(app: any, context: ApplicationContext) {
    app.post("/api/exceptions/report-status", async (req, res) => {
        try {
            await ensureAppStateReady();
            const db = getAppStateDb(), key = normalizedStatePath(String(req.body?.path || ""));
            const row = db.prepare("SELECT r.payload FROM exception_reports r JOIN exceptions e ON e.normalized_path = r.normalized_path WHERE r.normalized_path = ?").get(key);
            if (!row)
                throw new Error(englishText("backend.exceptions.no_detection_report_exists_for_this_exception"));
            const report = updateReportStatus(asRecord(parseAppStateJson(row.payload, {})), String(req.body?.action || ""));
            insertExceptionReportRow(db, key, report);
            res.json({ success: true, reportStatus: reportStatus(report), reportSentAt: report.reportSentAt || null });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e.message });
        }
    });
}
