import { ApplicationContext } from "../../../../server/core/applicationContext";
import { openWindowsSecurity } from "../../../../server/platform/defender";
export function registerPostApiOpenWindowsSecurity(app: any, context: ApplicationContext) {
    app.post("/api/open-windows-security", async (req, res) => {
        try {
            const result = await openWindowsSecurity();
            res.status(result.success ? 200 : 500).json(result);
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e.message });
        }
    });
}
