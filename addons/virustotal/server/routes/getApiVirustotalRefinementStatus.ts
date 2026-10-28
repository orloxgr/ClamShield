import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerGetApiVirustotalRefinementStatus(app: any, context: Pick<ApplicationContext, "getVirusTotalRefinementQueueStatus">) {
    app.get("/api/virustotal-refinement/status", async (_req, res) => {
        res.json(await context.getVirusTotalRefinementQueueStatus());
    });
}
