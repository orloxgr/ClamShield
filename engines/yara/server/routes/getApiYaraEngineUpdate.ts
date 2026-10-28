import { englishText } from "../../../../shared/localization/runtime";
import { saveConfig } from "../../../../modules/settings/server/service";
import { getLatestYaraEngineRelease } from "../../../../modules/updates/server/providers";
import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerGetApiYaraEngineUpdate(app: any, context: Pick<ApplicationContext, "settings">) {
    app.get("/api/yara-engine-update", async (req, res) => {
        try {
            const update = await getLatestYaraEngineRelease(context.settings);
            context.settings = {
                ...context.settings,
                yaraEngineLastCheck: new Date().toISOString(),
                yaraEngineLastCheckResult: update.updateAvailable ? `Available ${update.latestVersion}` : update.skipped ? `Skipped ${update.latestVersion}` : "No update"
            };
            await saveConfig(context.settings).catch(() => { });
            res.json(update);
        }
        catch (e: any) {
            context.settings = {
                ...context.settings,
                yaraEngineLastCheck: new Date().toISOString(),
                yaraEngineLastCheckResult: `Check failed: ${e.message || e}`.slice(0, 500)
            };
            await saveConfig(context.settings).catch(() => { });
            res.status(500).json({ error: e.message || englishText("backend.yara.failed_to_check_yara_engine_updates") });
        }
    });
}
