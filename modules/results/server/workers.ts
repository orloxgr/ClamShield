import { englishText } from "../../../shared/localization/runtime";
import { loadVirusTotalApiKey } from "../../../addons/virustotal/server/account";
import { runVirusTotalResultCloudCheck } from "../../../addons/virustotal/server/refinement";
import { ApplicationContext } from "../../../server/core/applicationContext";
import { addHistory } from "../../history/server/storage";
import { getResultsReminderState, getResultsReminderSummary, getScanResults } from "./storage";
import express from "express";
export function createGetResultsReminderPayload(context: ApplicationContext) {
    return async () => {
        const reminder = await getResultsReminderSummary();
        if (reminder.count === 0) {
            return { show: false, count: 0, latestTimestamp: 0 };
        }
        const state = await getResultsReminderState();
        const now = Date.now();
        const show = now >= Number(state.remindUntil || 0) && reminder.latestTimestamp > Number(state.forgottenUntil || 0);
        return { show, count: reminder.count, latestTimestamp: reminder.latestTimestamp };
    };
}
export function createBroadcastResultsReminder(context: Pick<ApplicationContext, "sendApiEvent" | "getResultsReminderPayload">) {
    return async () => {
        context.sendApiEvent("results-reminder", await context.getResultsReminderPayload());
    };
}
export function createCheckResultWithVirusTotal(context: Pick<ApplicationContext, "settings" | "scheduleVirusTotalRefinement">) {
    return async (req: express.Request, res: express.Response) => {
        try {
            if (context.settings.virusTotalCloudEnabled !== true) {
                throw new Error(englishText("backend.results.virustotal_cloud_check_is_disabled_add_your_api_key_in_settings_f"));
            }
            const apiKey = await loadVirusTotalApiKey();
            if (!apiKey) {
                throw new Error(englishText("backend.results.virustotal_api_key_is_not_configured_add_it_in_settings_first"));
            }
            const results = await getScanResults();
            const result = results.find((item: any) => item.id === req.params.id);
            if (!result)
                throw new Error(englishText("backend.results.result_not_found"));
            const cloudCheck = await runVirusTotalResultCloudCheck(results, result, context.settings, apiKey, undefined, req.method === "POST");
            context.scheduleVirusTotalRefinement();
            await addHistory({
                type: cloudCheck.uploaded ? "virustotal-results-upload" : "virustotal-cloud-check",
                target: result.originalPath || cloudCheck.sha256,
                result: 0,
                threatsFound: 0,
                scannedFiles: 1,
                duration: 1,
                actionTaken: cloudCheck.uploaded
                    ? cloudCheck.uploadAnalysisId ? englishText("backend.results.uploaded_for_analysis", {
                        uploadAnalysisId: String(cloudCheck.uploadAnalysisId)
                    }) : englishText("backend.results.uploaded_for_analysis_4990dae")
                    : result.virusTotalRefinement?.label || englishText("backend.results.checked")
            }).catch(() => { });
            res.json({
                success: true,
                uploaded: cloudCheck.uploaded,
                report: cloudCheck.report,
                refinement: cloudCheck.refinement,
                checks: result.virusTotalChecks,
                message: cloudCheck.report.found ? englishText("results.virustotal_cloud_check_completed") : cloudCheck.refinement.message
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    };
}
