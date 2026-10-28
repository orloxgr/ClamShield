import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerPostApiVirustotalOnDemandJobIdConfirm(app: any, context: Pick<ApplicationContext, "virusTotalScanQueue" | "scheduleVirusTotalScan">) {
    app.post("/api/virustotal/on-demand/:jobId/confirm", (req, res) => {
        if (typeof req.body?.proceed !== "boolean")
            return res.status(400).json({ error: englishText("backend.virustotal.choose_whether_to_continue_virustotal_checks") });
        if (!context.virusTotalScanQueue.confirm(req.params.jobId, req.body.proceed))
            return res.status(409).json({ error: englishText("backend.virustotal.this_virustotal_queue_is_no_longer_awaiting_confirmation") });
        context.scheduleVirusTotalScan();
        res.json({ success: true });
    });
}
