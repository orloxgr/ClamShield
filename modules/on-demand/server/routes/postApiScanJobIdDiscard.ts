import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerPostApiScanJobIdDiscard(app: any, context: Pick<ApplicationContext, "activeJobs" | "virusTotalScanQueue" | "scanSessions" | "broadcastJobEvent" | "cleanupDiscardedScanSession" | "flushPendingClamdDatabaseReloadSoon">) {
    app.post("/api/scan/:jobId/discard", async (req, res) => {
        try {
            const job = context.activeJobs[req.params.jobId];
            if (job?.process)
                job.process.kill();
            if (job?.processes) {
                for (const child of Array.from(job.processes))
                    child?.kill?.();
                job.processes.clear();
            }
            if (job)
                job.status = "done";
            context.virusTotalScanQueue.setState(req.params.jobId, "cancelled");
            context.scanSessions.markDiscarded(req.params.jobId);
            context.broadcastJobEvent(req.params.jobId, ["Interrupted scan discarded."]);
            res.json({ success: true });
            context.cleanupDiscardedScanSession(req.params.jobId);
            context.flushPendingClamdDatabaseReloadSoon();
        }
        catch (e: any) {
            res.status(500).json({ error: e.message || englishText("backend.on_demand.failed_to_discard_scan") });
        }
    });
}
