import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getVirusTotalDashboardStatus } from "../status";
export function registerGetApiVirustotalCloudStatus(app: any, context: Pick<ApplicationContext, "settings">) {
    app.get("/api/virustotal-cloud/status", async (_req, res) => {
        res.json(await getVirusTotalDashboardStatus(context.settings));
    });
}
