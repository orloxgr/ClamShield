import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { canResumeScanType } from "../../../../server/scanning/files";
export function registerPostApiScanJobIdCancel(app: any, context: Pick<ApplicationContext, "activeJobs" | "virusTotalScanQueue" | "scanSessions" | "saveJobProgress" | "appendJobLogs" | "broadcastJobEvent" | "cleanupDiscardedScanSession" | "flushPendingClamdDatabaseReloadSoon">) {
    app.post("/api/scan/:jobId/cancel", async (req, res) => {
        const job = context.activeJobs[req.params.jobId];
        if (job) {
            const discardProgress = req.body?.discard === true;
            const reason = String(req.body?.reason || "").trim().slice(0, 300);
            const resumable = !discardProgress && canResumeScanType(job.progress?.type || "");
            context.virusTotalScanQueue.setState(req.params.jobId, resumable ? "paused" : "cancelled");
            if (job.process) {
                job.process.kill();
            }
            if (job.processes) {
                for (const child of Array.from(job.processes))
                    child?.kill?.();
                job.processes.clear();
            }
            job.status = "done";
            let scannedFiles = Number(job.progress?.scannedFiles || 0);
            const shouldCleanupDiscardedFiles = discardProgress && canResumeScanType(job.progress?.type || "");
            if (resumable) {
                context.scanSessions.resetInProgress(req.params.jobId);
                scannedFiles = context.scanSessions.countDoneFiles(req.params.jobId);
            }
            context.saveJobProgress(req.params.jobId, {
                status: resumable ? "paused" : "done",
                phase: resumable ? englishText("settings.paused") : (reason || englishText("common.scan_context.cancelled")),
                currentFile: resumable ? englishText("settings.paused") : (reason || englishText("common.scan_context.cancelled")),
                scannedFiles,
                completedAt: resumable ? undefined : Date.now(),
                result: -1,
                actionTaken: resumable ? englishText("settings.paused") : (reason || englishText("common.scan_context.cancelled"))
            });
            if (shouldCleanupDiscardedFiles) {
                context.scanSessions.markDiscarded(req.params.jobId, reason || "Discarded");
            }
            context.appendJobLogs(req.params.jobId, [
                resumable
                    ? englishText("common.scan_context.scan_paused_you_can_resume_it_later") : reason
                    ? englishText("backend.on_demand.scan_stopped", {
                        reason: String(reason)
                    }) : englishText("common.scan_context.scan_cancelled_by_user")
            ]);
            context.broadcastJobEvent(req.params.jobId);
            res.json({ status: resumable ? "paused" : "cancelled" });
            if (shouldCleanupDiscardedFiles)
                context.cleanupDiscardedScanSession(req.params.jobId);
            context.flushPendingClamdDatabaseReloadSoon();
        }
        else {
            res.status(404).json({ error: englishText("backend.on_demand.job_not_found") });
        }
    });
}
