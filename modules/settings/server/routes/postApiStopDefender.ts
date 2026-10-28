import { ApplicationContext } from "../../../../server/core/applicationContext";
import { requestDefenderPause } from "../../../../server/platform/defender";
export function registerPostApiStopDefender(app: any, context: ApplicationContext) {
    app.post("/api/stop-defender", async (req, res) => {
        try {
            const result = await requestDefenderPause();
            res.status(result.Success ? 200 : 409).json({ success: result.Success, ...result });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
