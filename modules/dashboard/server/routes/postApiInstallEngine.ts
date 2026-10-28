import { englishText } from "../../../../shared/localization/runtime";
import { installClamAVEngine } from "../../../../engines/clamav/server/install";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
export function registerPostApiInstallEngine(app: any, context: Pick<ApplicationContext, "isRunningClamdScanJob" | "settings">) {
    app.post("/api/install-engine", async (req, res) => {
        if (process.platform !== "win32") {
            return res.status(400).json({ error: englishText("backend.clamav.auto_install_is_only_supported_on_windows_64_bit") });
        }
        if (context.isRunningClamdScanJob()) {
            return res.status(409).json({ error: englishText("backend.dashboard.stop_active_scans_before_installing_or_replacing_the_clamav_engin") });
        }
        if (runtimeState.isInstalling) {
            return res.json({ status: "already_installing" });
        }
        runtimeState.isInstalling = true;
        runtimeState.installProgress = "Starting download...";
        res.json({ status: "started" });
        try {
            await installClamAVEngine(context.settings, message => runtimeState.installProgress = message);
            runtimeState.isInstalling = false;
            runtimeState.installProgress = "Complete";
        }
        catch (e: any) {
            console.error(englishText("backend.dashboard.install_failed"), e);
            runtimeState.isInstalling = false;
            runtimeState.installProgress = "Error: " + e.message;
        }
    });
}
