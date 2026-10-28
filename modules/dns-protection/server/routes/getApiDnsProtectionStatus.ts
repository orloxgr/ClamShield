import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getDnsProtectionStatus } from "../service";
export function registerGetApiDnsProtectionStatus(app: any, context: Pick<ApplicationContext, "settings">) {
    app.get("/api/dns-protection/status", async (_req, res) => {
        try {
            res.json(await getDnsProtectionStatus(context.settings));
        }
        catch (e: any) {
            res.status(500).json({ error: e?.message || String(e) });
        }
    });
}
