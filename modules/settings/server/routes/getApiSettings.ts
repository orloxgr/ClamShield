import { englishText } from "../../../../shared/localization/runtime";
import { getVirusTotalCloudStatus } from "../../../../addons/virustotal/server/account";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { restoreInstalledSignatureProviderSettings } from "../service";
export function registerGetApiSettings(app: any, context: Pick<ApplicationContext, "settings">) {
    app.get("/api/settings", async (_req, res) => {
        try {
            context.settings = await restoreInstalledSignatureProviderSettings(context.settings);
            res.json({
                settings: context.settings,
                virusTotalCloud: await getVirusTotalCloudStatus(context.settings)
            });
        }
        catch (e: any) {
            res.status(500).json({ error: e?.message || englishText("backend.settings.could_not_load_settings") });
        }
    });
}
