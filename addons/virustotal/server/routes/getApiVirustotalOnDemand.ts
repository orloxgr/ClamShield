import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { loadVirusTotalApiKey } from "../account";
export function registerGetApiVirustotalOnDemand(app: any, context: Pick<ApplicationContext, "virusTotalScanQueue" | "settings" | "virusTotalScanNextAllowedAt">) {
    app.get("/api/virustotal/on-demand", async (_req, res) => {
        res.json({
            job: context.virusTotalScanQueue.get(),
            jobs: context.virusTotalScanQueue.list(),
            enabled: context.settings.virusTotalCloudEnabled === true,
            configured: Boolean(await loadVirusTotalApiKey()),
            nextAllowedAt: Math.max(context.virusTotalScanNextAllowedAt, runtimeState.virusTotalNextLookupAllowedAt)
        });
    });
}
