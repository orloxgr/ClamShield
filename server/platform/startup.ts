import { englishText } from "../../shared/localization/runtime";
import { execAsync } from "../core/paths";
export async function manageStartup(settings: any) {
    if (process.platform !== "win32")
        return;
    try {
        let command = `"${process.argv[0]}"`;
        if (process.argv.length > 1 && !process.argv[0].endsWith("ClamShield.exe") && !process.argv[0].endsWith("clamshield.exe")) {
            command += ` "${process.argv[1]}"`;
        }
        let targetCommand = (process.argv[0].endsWith("ClamShield.exe") || process.argv[0].endsWith("clamshield.exe")) ? process.execPath : command.replace(/"/g, '\\"');
        const taskName = "ClamShield";
        if (settings.runOnStartup) {
            const startupArgs = settings.startMinimized ? " --minimized" : "";
            const schtasksCmd = `schtasks /create /tn "${taskName}" /tr "\\"${targetCommand}\\"${startupArgs}" /sc onlogon /rl highest /f`;
            await execAsync(schtasksCmd).catch(() => { });
        }
        else {
            await execAsync(`schtasks /delete /tn "${taskName}" /f`).catch(() => { });
        }
    }
    catch (e: any) {
        console.error(englishText("backend.platform.failed_to_set_startup_task"), e.message);
    }
}
