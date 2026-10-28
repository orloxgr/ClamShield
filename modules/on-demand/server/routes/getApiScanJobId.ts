import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerGetApiScanJobId(app: any, context: Pick<ApplicationContext, "activeJobs">) {
    app.get("/api/scan/:jobId", (req, res) => {
        const job = context.activeJobs[req.params.jobId];
        if (!job) {
            return res.status(404).json({ error: englishText("backend.on_demand.job_not_found") });
        }
        res.json({
            status: job.status,
            logs: job.logs,
            result: job.result,
            progress: job.progress || null
        });
        if (req.query.peek !== "1") {
            // Clear logs after sending them so we don't accumulate too much
            job.logs = [];
        }
    });
}
