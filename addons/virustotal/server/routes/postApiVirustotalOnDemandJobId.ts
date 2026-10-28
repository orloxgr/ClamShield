import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { loadVirusTotalApiKey } from "../account";
export function registerPostApiVirustotalOnDemandJobId(app: any, context: Pick<ApplicationContext, "virusTotalScanQueue" | "settings" | "scheduleVirusTotalScan">) {
    app.post("/api/virustotal/on-demand/:jobId", async (req, res) => {
        const job = context.virusTotalScanQueue.get(req.params.jobId);
        if (!job)
            return res.status(404).json({ error: englishText("backend.virustotal.virustotal_scan_queue_not_found") });
        const state = req.body?.state;
        if (!["active", "paused", "cancelled"].includes(state))
            return res.status(400).json({ error: englishText("backend.virustotal.invalid_queue_state") });
        if (job.status === "cancelled" || job.status === "done")
            return res.status(400).json({ error: englishText("backend.virustotal.this_cloud_scan_has_already_ended") });
        if (state === "active" && !job.enumerated)
            return res.status(400).json({ error: englishText("backend.virustotal.resume_the_local_scan_first_to_finish_queuing_its_files") });
        if (state === "active" && (context.settings.virusTotalCloudEnabled !== true || !await loadVirusTotalApiKey())) {
            return res.status(400).json({ error: englishText("backend.virustotal.enable_virustotal_and_configure_its_api_key_in_settings_first") });
        }
        context.virusTotalScanQueue.setState(job.jobId, state);
        context.scheduleVirusTotalScan();
        res.json({ job: context.virusTotalScanQueue.get(job.jobId) });
    });
}
