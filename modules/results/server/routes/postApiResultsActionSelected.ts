import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getExceptions, rememberExceptionDetection, saveExceptions } from "../../../exceptions/server/service";
import { addHistory } from "../../../history/server/storage";
import { getScanResults, quarantineResultItem, saveScanResults } from "../storage";
import { existsSync } from "fs";
export function registerPostApiResultsActionSelected(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/results/action-selected", async (req, res) => {
        try {
            const action = req.body?.action;
            if (action !== "quarantine" && action !== "exception") {
                return res.status(400).json({ success: false, error: englishText("backend.results.invalid_action") });
            }
            const ids = Array.isArray(req.body?.ids)
                ? new Set(req.body.ids.map((item: any) => String(item || "")).filter(Boolean))
                : new Set<string>();
            if (ids.size === 0)
                return res.status(400).json({ success: false, error: englishText("backend.results.no_results_selected") });
            const results = await getScanResults();
            const remaining: any[] = [];
            const errors: any[] = [];
            let affectedCount = 0;
            let removedUnavailableCount = 0;
            const exceptions = action === "exception" ? await getExceptions() : [];
            for (const result of results) {
                if (!ids.has(String(result.id || ""))) {
                    remaining.push(result);
                    continue;
                }
                if (action === "quarantine") {
                    if (!result.originalPath || !existsSync(result.originalPath)) {
                        removedUnavailableCount++;
                        continue;
                    }
                    try {
                        await quarantineResultItem(context.settings, result);
                        affectedCount++;
                    }
                    catch (e: any) {
                        remaining.push(result);
                        errors.push({ id: result.id, path: result.originalPath, error: e.message });
                    }
                }
                else {
                    if (!result.originalPath) {
                        errors.push({ id: result.id, path: "", error: englishText("backend.results.original_path_is_unavailable") });
                        remaining.push(result);
                        continue;
                    }
                    if (!exceptions.includes(result.originalPath)) {
                        exceptions.push(result.originalPath);
                    }
                    await rememberExceptionDetection(result, "scan");
                    affectedCount++;
                }
            }
            if (action === "exception")
                await saveExceptions(exceptions);
            await saveScanResults(remaining);
            await addHistory({
                type: action === "quarantine" ? "results-quarantine-selected" : "results-exception-selected",
                target: "Selected scan results",
                result: errors.length === 0 ? 0 : 1,
                threatsFound: action === "quarantine" ? affectedCount : 0,
                scannedFiles: ids.size,
                duration: 0,
                actionTaken: action === "quarantine"
                    ? englishText("backend.results.quarantined_selected_result", {
                        affectedCount: String(affectedCount),
                        value2: String(affectedCount === 1 ? "" : englishText("dns.s"))
                    }) : englishText("backend.results.added_selected_result_to_exceptions", {
                    affectedCount: String(affectedCount),
                    value2: String(affectedCount === 1 ? "" : englishText("dns.s"))
                })
            });
            res.status(errors.length === 0 ? 200 : 207).json({
                success: errors.length === 0,
                affectedCount,
                removedUnavailableCount,
                errors
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
