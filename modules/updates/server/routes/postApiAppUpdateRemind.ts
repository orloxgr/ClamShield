import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saveConfig } from "../../../settings/server/service";
export function registerPostApiAppUpdateRemind(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/app-update/remind", async (req, res) => {
        try {
            const remindAfter = Number(req.body?.remindAfter || Date.now() + 24 * 60 * 60 * 1000);
            context.settings = { ...context.settings, appUpdateRemindAfter: remindAfter };
            await saveConfig(context.settings);
            res.json({ success: true, appUpdateRemindAfter: remindAfter });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
