import { ApplicationContext } from "../../../../server/core/applicationContext";
import { restoreDefenderPreferences } from "../../../../server/platform/defender";
export function registerPostApiRestoreDefender(app: any, context: ApplicationContext) {
    app.post("/api/restore-defender", async (req, res) => {
        try {
            const result = await restoreDefenderPreferences();
            res.status(result.Success ? 200 : 409).json({ success: result.Success, ...result });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
