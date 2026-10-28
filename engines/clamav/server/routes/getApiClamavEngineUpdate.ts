import { englishText } from "../../../../shared/localization/runtime";
import { saveConfig } from "../../../../modules/settings/server/service";
import { getLatestClamAVEngineRelease } from "../../../../modules/updates/server/providers";
import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerGetApiClamavEngineUpdate(app: any, context: Pick<ApplicationContext, "settings">) {
    app.get("/api/clamav-engine-update", async (req, res) => {
        try {
            const update = await getLatestClamAVEngineRelease(context.settings);
            context.settings = {
                ...context.settings,
                clamavEngineLastCheck: new Date().toISOString(),
                clamavEngineLastCheckResult: update.updateAvailable ? `Available ${update.latestVersion}` : update.skipped ? `Skipped ${update.latestVersion}` : "No update"
            };
            await saveConfig(context.settings).catch(() => { });
            res.json(update);
        }
        catch (e: any) {
            context.settings = {
                ...context.settings,
                clamavEngineLastCheck: new Date().toISOString(),
                clamavEngineLastCheckResult: `Check failed: ${e.message || e}`.slice(0, 500)
            };
            await saveConfig(context.settings).catch(() => { });
            res.status(500).json({ error: e.message || englishText("backend.clamav.failed_to_check_clamav_engine_updates") });
        }
    });
}
