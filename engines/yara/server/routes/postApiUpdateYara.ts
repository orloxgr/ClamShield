import { englishText } from "../../../../shared/localization/runtime";
import { addHistory } from "../../../../modules/history/server/storage";
import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { updateYaraForgeRules } from "../install";
import { normalizeYaraRuleset } from "../rules";
export function registerPostApiUpdateYara(app: any, context: Pick<ApplicationContext, "settings" | "isRunningClamdScanJob" | "activeJobs" | "appendJobLogs" | "broadcastJobEvent">) {
    app.post("/api/update-yara", async (req, res) => {
        const jobId = "yara-update-" + Date.now().toString();
        const requestedRuleset = normalizeYaraRuleset(req.body?.ruleset || context.settings.yaraRuleset);
        if (requestedRuleset !== context.settings.yaraRuleset) {
            context.settings = { ...context.settings, yaraRuleset: requestedRuleset };
            await saveConfig(context.settings);
        }
        if (context.isRunningClamdScanJob()) {
            return res.status(409).json({ error: englishText("backend.yara.stop_active_scans_before_updating_yara_rules") });
        }
        context.activeJobs[jobId] = { status: "running", logs: [] };
        res.json({ jobId, status: "started" });
        const startedAt = Date.now();
        try {
            context.appendJobLogs(jobId, [englishText("backend.yara.updating_yara_forge_rules", {
                    value1: String(normalizeYaraRuleset(context.settings.yaraRuleset))
                })]);
            const result = await updateYaraForgeRules(context.settings, message => {
                if (context.activeJobs[jobId])
                    context.appendJobLogs(jobId, [message]);
            });
            if (!context.activeJobs[jobId])
                return;
            context.appendJobLogs(jobId, [`YARA update complete: ${result.ruleCount} rules loaded.`]);
            context.activeJobs[jobId].status = "done";
            context.activeJobs[jobId].result = 0;
            context.broadcastJobEvent(jobId);
            await addHistory({
                type: "yara-update",
                target: `YARA Forge ${result.ruleset}`,
                result: 0,
                threatsFound: 0,
                scannedFiles: result.ruleCount,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: englishText("backend.yara.updated")
            });
        }
        catch (e: any) {
            console.error("YARA update failed:", e.message);
            if (context.activeJobs[jobId]) {
                context.appendJobLogs(jobId, [englishText("updates.error", {
                        message: String(e.message)
                    })]);
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = 1;
                context.broadcastJobEvent(jobId);
            }
            await addHistory({
                type: "yara-update",
                target: `YARA Forge ${normalizeYaraRuleset(context.settings.yaraRuleset)}`,
                result: 1,
                threatsFound: 0,
                scannedFiles: 0,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: englishText("common.update_job_progress.failed")
            });
        }
    });
}
