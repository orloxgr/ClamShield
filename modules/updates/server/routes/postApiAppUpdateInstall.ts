import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { addHistory } from "../../../history/server/storage";
import { downloadAndLaunchClamShieldInstaller } from "../service";
export function registerPostApiAppUpdateInstall(app: any, context: Pick<ApplicationContext, "isRunningClamdScanJob" | "activeJobs" | "settings" | "appendJobLogs" | "broadcastJobEvent" | "scheduleAppExitForUpdate">) {
    app.post("/api/app-update/install", async (req, res) => {
        if (context.isRunningClamdScanJob()) {
            return res.status(409).json({ error: "Stop active scans before installing a ClamShield application update." });
        }
        const jobId = "app-update-" + Date.now().toString();
        context.activeJobs[jobId] = { status: "running", logs: [] };
        res.json({ jobId, status: "started" });
        const startedAt = Date.now();
        try {
            const result = await downloadAndLaunchClamShieldInstaller(context.settings, message => {
                if (context.activeJobs[jobId])
                    context.appendJobLogs(jobId, [message]);
            });
            if (!context.activeJobs[jobId])
                return;
            context.appendJobLogs(jobId, [result.handoffReady
                    ? englishText("backend.updates.clamshield_installer_is_ready_the_app_will_close_then_the_install") : englishText("backend.updates.no_newer_clamshield_version_is_available")]);
            context.activeJobs[jobId].status = "done";
            context.activeJobs[jobId].result = 0;
            context.broadcastJobEvent(jobId);
            await addHistory({
                type: "app-update-install",
                target: `ClamShield ${result.latestVersion || ""}`.trim(),
                result: 0,
                threatsFound: 0,
                scannedFiles: 0,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: result.handoffReady ? englishText("backend.updates.installer_queued") : "No update"
            });
            if (result.handoffReady)
                context.scheduleAppExitForUpdate();
        }
        catch (e: any) {
            console.error("ClamShield app update install failed:", e.message);
            if (context.activeJobs[jobId]) {
                context.appendJobLogs(jobId, [englishText("updates.error", {
                        message: String(e.message)
                    })]);
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = 1;
                context.broadcastJobEvent(jobId);
            }
            await addHistory({
                type: "app-update-install",
                target: "ClamShield",
                result: 1,
                threatsFound: 0,
                scannedFiles: 0,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: englishText("common.update_job_progress.failed")
            });
        }
    });
}
