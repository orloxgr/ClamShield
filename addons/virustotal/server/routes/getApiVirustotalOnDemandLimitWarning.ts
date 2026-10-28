import { ApplicationContext } from "../../../../server/core/applicationContext";
import { estimateVirusTotalScan, virusTotalLimitWarningsEnabled } from "../virusTotalLimitWarning";
import { getVirusTotalUsageStatus } from "../account";
export function registerGetApiVirustotalOnDemandLimitWarning(app: any, context: Pick<ApplicationContext, "settings" | "virusTotalScanQueue">) {
    app.get("/api/virustotal/on-demand/limit-warning", async (_req, res) => {
        const job = context.settings.virusTotalCloudEnabled === true && virusTotalLimitWarningsEnabled(context.settings.virusTotalShowLimitWarnings)
            ? context.virusTotalScanQueue.pendingConfirmation() : null;
        res.json({ warning: job ? { jobId: job.jobId, target: job.target,
                ...estimateVirusTotalScan(job.pending, await getVirusTotalUsageStatus()) } : null });
    });
}
