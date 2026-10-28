import { englishText } from "../../../../shared/localization/runtime";
import { saveConfig } from "../../../../modules/settings/server/service";
import { normalizeNumberSetting } from "../../../../modules/settings/server/validation";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { configureLegacyContextMenuRegistry, writeWindowsContextMenuState } from "../../../../server/platform/contextMenu";
import { loadVirusTotalApiKey, normalizeVirusTotalApiKey, saveVirusTotalApiKey } from "../account";
import { getVirusTotalDashboardStatus } from "../status";
export function registerPostApiVirustotalCloudConfigure(app: any, context: Pick<ApplicationContext, "settings" | "scheduleVirusTotalRefinement" | "scheduleShieldVirusTotalCheck" | "scheduleVirusTotalScan">) {
    app.post("/api/virustotal-cloud/configure", async (req, res) => {
        try {
            const apiKey = normalizeVirusTotalApiKey(req.body?.apiKey || "");
            if (apiKey)
                await saveVirusTotalApiKey(apiKey);
            const configured = Boolean(apiKey || await loadVirusTotalApiKey());
            context.settings = {
                ...context.settings,
                virusTotalCloudEnabled: req.body?.enabled !== false && configured,
                virusTotalAutoRefineEnabled: req.body?.autoRefineEnabled === true && configured,
                virusTotalResultsUploadUnknownEnabled: req.body?.enabled !== false && configured
                    ? req.body?.resultsUploadUnknownEnabled === true
                    : false,
                virusTotalResultsUploadMaxSizeMb: normalizeNumberSetting("virusTotalResultsUploadMaxSizeMb", req.body?.resultsUploadMaxSizeMb),
                virusTotalShieldBackgroundCheckEnabled: req.body?.enabled !== false && configured
                    ? context.settings.virusTotalShieldBackgroundCheckEnabled === true
                    : false,
                virusTotalShieldUploadUnknownEnabled: req.body?.enabled !== false && configured
                    ? context.settings.virusTotalShieldUploadUnknownEnabled === true
                    : false
            };
            await saveConfig(context.settings);
            await writeWindowsContextMenuState(context.settings);
            if (context.settings.windowsContextMenuEnabled === true) {
                await configureLegacyContextMenuRegistry(true, context.settings);
            }
            context.scheduleVirusTotalRefinement();
            context.scheduleShieldVirusTotalCheck();
            context.scheduleVirusTotalScan();
            if (context.settings.virusTotalCloudEnabled === true)
                runtimeState.virusTotalUsageTracker?.refresh(runtimeState.virusTotalUsageRefreshEveryRequests).catch(() => { });
            res.json({
                success: true,
                virusTotalCloud: await getVirusTotalDashboardStatus(context.settings),
                message: configured
                    ? englishText("backend.virustotal.virustotal_cloud_check_is_configured") : englishText("backend.virustotal.virustotal_cloud_check_needs_an_api_key")
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
