import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerPostApiClamavEngineUpdateRemind(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/clamav-engine-update/remind", async (req, res) => {
        try {
            const remindAfter = Number(req.body?.remindAfter || Date.now() + 24 * 60 * 60 * 1000);
            context.settings = { ...context.settings, clamavEngineRemindAfter: remindAfter };
            await saveConfig(context.settings);
            res.json({ success: true, clamavEngineRemindAfter: remindAfter });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
