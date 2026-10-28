import { ApplicationContext } from "../../../../server/core/applicationContext";
import { exec } from "child_process";
export function registerGetApiOpenQuarantine(app: any, context: Pick<ApplicationContext, "settings">) {
    app.get("/api/open-quarantine", async (req, res) => {
        try {
            if (process.platform === 'win32') {
                exec(`explorer "${context.settings.quarantineDir}"`);
            }
            else if (process.platform === 'darwin') {
                exec(`open "${context.settings.quarantineDir}"`);
            }
            else {
                exec(`xdg-open "${context.settings.quarantineDir}"`);
            }
            res.json({ success: true });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
