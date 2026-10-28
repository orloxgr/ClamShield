import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saveConfig } from "../../../settings/server/service";
import { getLatestClamShieldRelease } from "../service";
export function registerGetApiAppUpdate(app: any, context: Pick<ApplicationContext, "settings">) {
    app.get("/api/app-update", async (req, res) => {
        try {
            const update = await getLatestClamShieldRelease(context.settings);
            context.settings = {
                ...context.settings,
                lastAppUpdateCheck: new Date().toISOString()
            };
            await saveConfig(context.settings).catch(() => { });
            res.json(update);
        }
        catch (e: any) {
            res.status(500).json({ error: e.message || englishText("backend.updates.failed_to_check_for_clamshield_updates") });
        }
    });
}
