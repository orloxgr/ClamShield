import { englishText } from "../../../../shared/localization/runtime";
import { saveConfig } from "../../../../modules/settings/server/service";
import { normalizeVersion } from "../../../../modules/updates/server/versions";
import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerPostApiClamavEngineUpdateSkip(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/clamav-engine-update/skip", async (req, res) => {
        try {
            const version = normalizeVersion(req.body?.version || "");
            if (!version || version === "0.0.0")
                return res.status(400).json({ error: englishText("backend.yara.missing_version_to_skip") });
            context.settings = { ...context.settings, clamavEngineSkippedVersion: version };
            await saveConfig(context.settings);
            res.json({ success: true, clamavEngineSkippedVersion: version });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
