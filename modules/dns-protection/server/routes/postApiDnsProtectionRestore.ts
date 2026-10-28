import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saveConfig } from "../../../settings/server/service";
import { getDnsProtectionStatus, restoreDnsProtectionBackup } from "../service";
export function registerPostApiDnsProtectionRestore(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/dns-protection/restore", async (_req, res) => {
        try {
            await restoreDnsProtectionBackup();
            context.settings = {
                ...context.settings,
                dnsProtectionEnabled: false,
                dnsProtectionProfile: "",
                dnsProtectionAppliedAt: ""
            };
            await saveConfig(context.settings);
            res.json({ success: true, status: await getDnsProtectionStatus(context.settings) });
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || String(e) });
        }
    });
}
