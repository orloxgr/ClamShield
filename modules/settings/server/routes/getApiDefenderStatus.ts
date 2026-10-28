import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getDefenderStatus } from "../../../../server/platform/defender";
export function registerGetApiDefenderStatus(app: any, context: ApplicationContext) {
    app.get("/api/defender-status", async (req, res) => {
        try {
            res.json(await getDefenderStatus());
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
