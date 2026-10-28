import { englishText } from "../../../../shared/localization/runtime";
import { addHistory } from "../../../../modules/history/server/storage";
import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { queueYaraEngineUpdate } from "../install";
export function registerPostApiYaraEngineUpdateInstall(app: any, context: Pick<ApplicationContext, "isRunningClamdScanJob" | "activeJobs" | "settings" | "appendJobLogs" | "broadcastJobEvent">) {
    app.post("/api/yara-engine-update/install", async (req, res) => {
        if (context.isRunningClamdScanJob()) {
            return res.status(409).json({ error: englishText("backend.yara.stop_active_scans_before_replacing_the_yara_engine") });
        }
        const jobId = "yara-engine-update-" + Date.now().toString();
        context.activeJobs[jobId] = { status: "running", logs: [] };
        res.json({ jobId, status: "started" });
        const startedAt = Date.now();
        try {
            const result = await queueYaraEngineUpdate(context.settings, message => {
                if (context.activeJobs[jobId])
                    context.appendJobLogs(jobId, [message]);
            });
            if (!context.activeJobs[jobId])
                return;
            context.settings = {
                ...context.settings,
                yaraEngineLastCheck: new Date().toISOString(),
                yaraEngineLastCheckResult: `Installed ${result.installedVersion || result.latestVersion}`
            };
            await saveConfig(context.settings);
            context.appendJobLogs(jobId, [`YARA Engine update complete: ${result.installedVersion || result.latestVersion}.`]);
            context.activeJobs[jobId].status = "done";
            context.activeJobs[jobId].result = 0;
            context.broadcastJobEvent(jobId);
            await addHistory({
                type: "yara-engine-update",
                target: `YARA Engine ${result.latestVersion || ""}`.trim(),
                result: 0,
                threatsFound: 0,
                scannedFiles: 0,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: englishText("backend.yara.installed")
            });
        }
        catch (e: any) {
            context.settings = {
                ...context.settings,
                yaraEngineLastCheck: new Date().toISOString(),
                yaraEngineLastCheckResult: `Install failed: ${e.message || e}`.slice(0, 500)
            };
            await saveConfig(context.settings).catch(() => { });
            console.error("YARA Engine update failed:", e.message);
            if (context.activeJobs[jobId]) {
                context.appendJobLogs(jobId, [englishText("updates.error", {
                        message: String(e.message)
                    })]);
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = 1;
                context.broadcastJobEvent(jobId);
            }
            await addHistory({
                type: "yara-engine-update",
                target: "YARA Engine",
                result: 1,
                threatsFound: 0,
                scannedFiles: 0,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: englishText("common.update_job_progress.failed")
            });
        }
    });
}
