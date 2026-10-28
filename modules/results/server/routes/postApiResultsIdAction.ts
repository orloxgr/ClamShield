import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { buildFalsePositiveReport, getExceptions, rememberExceptionDetection, saveExceptions } from "../../../exceptions/server/service";
import { addHistory } from "../../../history/server/storage";
import { getScanResults, quarantineResultItem, saveScanResults } from "../storage";
export function registerPostApiResultsIdAction(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/results/:id/action", async (req, res) => {
        try {
            const action = req.body.action;
            if (action !== "quarantine" && action !== "exception") {
                return res.status(400).json({ success: false, error: englishText("backend.results.invalid_action") });
            }
            const results = await getScanResults();
            const result = results.find((item: any) => item.id === req.params.id);
            if (!result) {
                throw new Error(englishText("backend.results.result_not_found"));
            }
            if (action === "quarantine") {
                const quarantined = await quarantineResultItem(context.settings, result);
                await saveScanResults(results.filter((item: any) => item.id !== req.params.id));
                await addHistory({
                    type: "results-quarantine",
                    target: result.originalPath,
                    result: 0,
                    threatsFound: 1,
                    scannedFiles: 1,
                    duration: 0,
                    actionTaken: englishText("backend.results.quarantined_from_results")
                });
                return res.json({ success: true, quarantined });
            }
            const exceptions = await getExceptions();
            if (!exceptions.includes(result.originalPath)) {
                exceptions.push(result.originalPath);
                await saveExceptions(exceptions);
            }
            const exceptionReport = await rememberExceptionDetection(result, "scan");
            await saveScanResults(results.filter((item: any) => item.id !== req.params.id));
            await addHistory({
                type: "results-exception",
                target: result.originalPath,
                result: 0,
                threatsFound: 0,
                scannedFiles: 1,
                duration: 0,
                actionTaken: englishText("backend.results.added_to_exceptions_from_results")
            });
            res.json({
                success: true,
                falsePositive: exceptionReport ? buildFalsePositiveReport(exceptionReport) : null
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e.message });
        }
    });
}
