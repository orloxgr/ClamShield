import { englishText } from "../../../../shared/localization/runtime";
import { addHistory } from "../../../../modules/history/server/storage";
import { saveConfig } from "../../../../modules/settings/server/service";
import { parseBareVersion } from "../../../../modules/updates/server/versions";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { queueClamAVEngineUpdate } from "../install";
export function registerPostApiClamavEngineUpdateInstall(app: any, context: Pick<ApplicationContext, "isRunningClamdScanJob" | "activeJobs" | "settings" | "appendJobLogs" | "broadcastJobEvent">) {
    app.post("/api/clamav-engine-update/install", async (req, res) => {
        if (context.isRunningClamdScanJob() || runtimeState.freshclamUpdateInProgress) {
            return res.status(409).json({ error: englishText("backend.clamav.stop_active_scans_or_signature_updates_before_replacing_the_clama") });
        }
        const jobId = "clamav-engine-update-" + Date.now().toString();
        context.activeJobs[jobId] = { status: "running", logs: [] };
        res.json({ jobId, status: "started" });
        const startedAt = Date.now();
        try {
            const result = await queueClamAVEngineUpdate(context.settings, message => {
                if (context.activeJobs[jobId])
                    context.appendJobLogs(jobId, [message]);
            });
            if (!context.activeJobs[jobId])
                return;
            context.settings = {
                ...context.settings,
                clamavEngineLastCheck: new Date().toISOString(),
                clamavEngineLastCheckResult: `Installed ${parseBareVersion(result.installedVersion || result.latestVersion)}`
            };
            await saveConfig(context.settings);
            context.appendJobLogs(jobId, [`ClamAV Engine update complete: ${result.installedVersion || result.latestVersion}.`]);
            context.activeJobs[jobId].status = "done";
            context.activeJobs[jobId].result = 0;
            context.broadcastJobEvent(jobId);
            await addHistory({
                type: "clamav-engine-update",
                target: `ClamAV Engine ${result.latestVersion || ""}`.trim(),
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
                clamavEngineLastCheck: new Date().toISOString(),
                clamavEngineLastCheckResult: `Install failed: ${e.message || e}`.slice(0, 500)
            };
            await saveConfig(context.settings).catch(() => { });
            console.error("ClamAV Engine update failed:", e.message);
            if (context.activeJobs[jobId]) {
                context.appendJobLogs(jobId, [englishText("updates.error", {
                        message: String(e.message)
                    })]);
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = 1;
                context.broadcastJobEvent(jobId);
            }
            await addHistory({
                type: "clamav-engine-update",
                target: "ClamAV Engine",
                result: 1,
                threatsFound: 0,
                scannedFiles: 0,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: englishText("common.update_job_progress.failed")
            });
        }
    });
}
