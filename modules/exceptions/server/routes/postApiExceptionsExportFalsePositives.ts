import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { normalizedStatePath } from "../../../../server/core/database/values";
import { addHistory } from "../../../history/server/storage";
import { exportFalsePositiveResults } from "../exports";
import { getExceptionReports, getExceptions } from "../service";
import { exec } from "child_process";
export function registerPostApiExceptionsExportFalsePositives(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/exceptions/export-false-positives", async (req, res) => {
        try {
            const paths = Array.isArray(req.body?.paths)
                ? req.body.paths.map((item: any) => String(item || "")).filter(Boolean)
                : [];
            if (paths.length === 0)
                return res.status(400).json({ success: false, error: englishText("backend.exceptions.no_exceptions_selected") });
            const exceptions = await getExceptions();
            const exceptionSet = new Set(exceptions.map(item => normalizedStatePath(item)));
            const reports = await getExceptionReports();
            const selectedReports: any[] = [];
            for (const exceptionPath of paths) {
                const normalized = normalizedStatePath(exceptionPath);
                if (!exceptionSet.has(normalized))
                    continue;
                const report = reports[normalized] || {};
                selectedReports.push({
                    originalPath: exceptionPath,
                    threatName: report.threatName || "Unknown Threat",
                    engine: report.engine || "",
                    source: report.source || "exception",
                    scanType: report.scanType || "",
                    target: report.target || "",
                    yaraRuleset: report.yaraRuleset || "",
                    sha256: report.sha256 || "",
                    timestamp: report.detectedAt || report.addedAt || Date.now()
                });
            }
            if (selectedReports.length === 0)
                return res.status(404).json({ success: false, error: englishText("backend.exceptions.selected_exceptions_were_not_found") });
            const exportResult = await exportFalsePositiveResults(context.settings, selectedReports, {
                includeSamples: req.body?.includeSamples === true,
                userNote: req.body?.userNote
            });
            if (process.platform === "win32") {
                exec(`explorer /select,"${exportResult.zipPath}"`);
            }
            await addHistory({
                type: "exceptions-export-false-positives",
                target: exportResult.zipPath,
                result: 0,
                threatsFound: 0,
                scannedFiles: selectedReports.length,
                duration: 0,
                actionTaken: englishText("backend.exceptions.exported_exception_false_positive_candidate", {
                    length: String(selectedReports.length),
                    value2: String(selectedReports.length === 1 ? "" : englishText("dns.s"))
                })
            });
            res.json({
                success: true,
                ...exportResult
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
