import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { configureWindowsContextMenuPackage, writeWindowsContextMenuState } from "../../../../server/platform/contextMenu";
import { saveConfig } from "../service";
export function registerPostApiWindowsContextMenuConfigure(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/windows-context-menu/configure", async (req, res) => {
        try {
            const enabled = req.body?.enabled === true;
            const contextMenuResult = await configureWindowsContextMenuPackage(enabled, context.settings);
            context.settings = {
                ...context.settings,
                windowsContextMenuEnabled: enabled
            };
            await saveConfig(context.settings, { keys: ["windowsContextMenuEnabled"] });
            await writeWindowsContextMenuState(context.settings);
            res.json({
                success: true,
                settings: context.settings,
                contextMenu: contextMenuResult,
                message: contextMenuResult.warning || (enabled
                    ? englishText("backend.settings.windows_context_menu_integration_is_enabled_restart_file_explorer") : englishText("backend.settings.windows_context_menu_integration_is_disabled"))
            });
        }
        catch (e: any) {
            res.status(409).json({ success: false, error: e?.message || String(e) });
        }
    });
}
