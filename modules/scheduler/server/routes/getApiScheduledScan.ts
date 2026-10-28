import { ApplicationContext } from "../../../../server/core/applicationContext";
import { normalizeScheduledScanSettings } from "../../../settings/server/validation";
export function registerGetApiScheduledScan(app: any, context: Pick<ApplicationContext, "settings" | "scheduledScanRuntime">) {
    app.get("/api/scheduled-scan", (req, res) => {
        res.json({
            settings: {
                ...normalizeScheduledScanSettings(context.settings),
                lastScheduledScanAt: context.settings.lastScheduledScanAt || "",
                lastScheduledScanResult: context.settings.lastScheduledScanResult || ""
            },
            runtime: context.scheduledScanRuntime
        });
    });
}
