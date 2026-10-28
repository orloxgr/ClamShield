import { englishText } from "../../../../shared/localization/runtime";
import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { virusTotalApiKeySecretPath } from "../../../../server/core/paths";
import { runtimeState } from "../../../../server/core/runtimeState";
import { configureLegacyContextMenuRegistry, writeWindowsContextMenuState } from "../../../../server/platform/contextMenu";
import { getVirusTotalDashboardStatus } from "../status";
import fs from "fs/promises";
export function registerPostApiVirustotalCloudDisconnect(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/virustotal-cloud/disconnect", async (_req, res) => {
        try {
            await fs.unlink(virusTotalApiKeySecretPath).catch(() => { });
            runtimeState.virusTotalUsageTracker?.setKey("");
            context.settings = {
                ...context.settings,
                virusTotalCloudEnabled: false,
                virusTotalAutoRefineEnabled: false,
                virusTotalResultsUploadUnknownEnabled: false,
                virusTotalShieldBackgroundCheckEnabled: false,
                virusTotalShieldUploadUnknownEnabled: false
            };
            await saveConfig(context.settings);
            await writeWindowsContextMenuState(context.settings);
            if (context.settings.windowsContextMenuEnabled === true) {
                await configureLegacyContextMenuRegistry(true, context.settings);
            }
            res.json({
                success: true,
                virusTotalCloud: await getVirusTotalDashboardStatus(context.settings),
                message: englishText("backend.virustotal.virustotal_cloud_check_was_disabled_and_the_local_api_key_was_rem")
            });
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || String(e) });
        }
    });
}
