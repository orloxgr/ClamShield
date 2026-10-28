import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { ensureAppStateReady } from "../../../../server/core/database/migrations";
import { getAppStateDb } from "../../../../server/core/database/schema";
import { asRecord, normalizedStatePath, parseAppStateJson } from "../../../../server/core/database/values";
import { hashFile } from "../../../../server/core/utils";
import { reportStatus } from "../reporting";
import { buildFalsePositiveReport } from "../service";
import { existsSync } from "fs";
import path from "path";
export function registerPostApiExceptionsReportFalsePositive(app: any, context: ApplicationContext) {
    // Preview is deliberately read-only: opening this dialog does not mean a report was submitted.
    app.post("/api/exceptions/report-false-positive", async (req, res) => {
        try {
            const exceptionPath = String(req.body?.path || "");
            await ensureAppStateReady();
            const db = getAppStateDb();
            if (!db.prepare("SELECT 1 FROM exceptions WHERE normalized_path = ?").get(normalizedStatePath(exceptionPath)))
                throw new Error(englishText("backend.exceptions.this_path_is_not_in_exceptions"));
            const row = db.prepare("SELECT payload FROM exception_reports WHERE normalized_path = ?").get(normalizedStatePath(exceptionPath));
            if (!row)
                throw new Error(englishText("backend.exceptions.no_original_detection_information_is_available_for_this_exception"));
            const report = asRecord(parseAppStateJson(row.payload, {}));
            if (!report.sha256 && existsSync(report.originalPath))
                report.sha256 = await hashFile(report.originalPath).catch(() => "");
            res.json({ success: true, ...buildFalsePositiveReport(report), report: { ...report, reportStatus: reportStatus(report) } });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e.message });
        }
    });
}
