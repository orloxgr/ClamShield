import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saveConfig } from "../../../settings/server/service";
export function registerPostApiAppUpdateDisable(app: any, context: Pick<ApplicationContext, "settings" | "scheduleNextAppUpdateCheck">) {
    app.post("/api/app-update/disable", async (req, res) => {
        try {
            context.settings = { ...context.settings, appUpdateCheckEnabled: false };
            await saveConfig(context.settings);
            context.scheduleNextAppUpdateCheck();
            res.json({ success: true, settings: context.settings });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
