import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerPostApiAlertDefender(app: any, context: ApplicationContext) {
    app.post("/api/alert-defender", async (req, res) => {
        res.status(409).json({
            success: false,
            Success: false,
            SideBySideMode: true,
            Message: "ClamShield is a user interface for ClamAV and YARA, not an independent antivirus provider, so it does not register itself as one in Windows Security. Use side-by-side mode or the separate Pause Defender action."
        });
    });
}
