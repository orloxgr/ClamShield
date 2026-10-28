import { ApplicationContext } from "../../../../server/core/applicationContext";
import { legalNoticeVersion } from "../../../../server/core/paths";
import { saveConfig } from "../service";
export function registerPostApiAcceptEula(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/accept-eula", async (req, res) => {
        context.settings = {
            ...context.settings,
            eulaAccepted: true,
            eulaVersion: legalNoticeVersion,
            eulaAcceptedAt: new Date().toISOString()
        };
        await saveConfig(context.settings);
        res.json({ success: true, settings: context.settings });
    });
}
