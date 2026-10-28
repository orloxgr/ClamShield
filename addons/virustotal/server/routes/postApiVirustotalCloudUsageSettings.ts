import { englishText } from "../../../../shared/localization/runtime";
import { saveConfig } from "../../../../modules/settings/server/service";
import { normalizeNumberSetting } from "../../../../modules/settings/server/validation";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getVirusTotalUsageStatus } from "../account";
export function registerPostApiVirustotalCloudUsageSettings(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/virustotal-cloud/usage/settings", async (req, res) => {
        try {
            const value = normalizeNumberSetting("virusTotalUsageRefreshEveryRequests", req.body?.refreshEveryRequests);
            context.settings = { ...context.settings, virusTotalUsageRefreshEveryRequests: value };
            await saveConfig(context.settings, { keys: ["virusTotalUsageRefreshEveryRequests"] });
            res.json({ usage: await getVirusTotalUsageStatus() });
        }
        catch {
            res.status(500).json({ error: englishText("backend.virustotal.could_not_save_the_virustotal_usage_refresh_interval") });
        }
    });
}
