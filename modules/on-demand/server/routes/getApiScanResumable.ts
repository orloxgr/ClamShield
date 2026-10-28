import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { scanSessionRowToProgress } from "../../../../server/scanning/files";
export function registerGetApiScanResumable(app: any, context: Pick<ApplicationContext, "scanSessions" | "virusTotalScanQueue">) {
    app.get("/api/scan/resumable", (req, res) => {
        try {
            const row = context.scanSessions.getLatestResumable();
            const progress = scanSessionRowToProgress(row);
            if (progress) {
                const cloudScan = context.virusTotalScanQueue.get(progress.jobId);
                progress.virusTotalAllFiles = Boolean(cloudScan && cloudScan.status !== "cancelled");
            }
            res.json({ available: !!progress, progress });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message || englishText("backend.on_demand.failed_to_load_resumable_scan") });
        }
    });
}
