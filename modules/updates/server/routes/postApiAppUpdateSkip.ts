import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saveConfig } from "../../../settings/server/service";
import { normalizeVersion } from "../versions";
export function registerPostApiAppUpdateSkip(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/app-update/skip", async (req, res) => {
        try {
            const version = normalizeVersion(req.body?.version || "");
            if (!version || version === "0.0.0") {
                return res.status(400).json({ error: englishText("backend.yara.missing_version_to_skip") });
            }
            context.settings = { ...context.settings, skippedAppVersion: version };
            await saveConfig(context.settings);
            res.json({ success: true, skippedAppVersion: version });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
