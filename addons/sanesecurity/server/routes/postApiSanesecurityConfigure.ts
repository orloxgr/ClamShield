import { reloadClamdDatabases } from "../../../../engines/clamav/server/daemon";
import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saneSecurityMalwareDatabases } from "../constants";
import { getSaneSecurityStatus, normalizeSaneSecurityProfile, removeSaneSecurityDatabaseFiles } from "../status";
export function registerPostApiSanesecurityConfigure(app: any, context: Pick<ApplicationContext, "settings">) {
app.post("/api/sanesecurity/configure", async (req, res) => {
    try {
        const profile = normalizeSaneSecurityProfile(req.body?.profile);
        context.settings = {
            ...context.settings,
            saneSecurityEnabled: true,
            saneSecurityProfile: profile,
            lastSaneSecurityUpdateResult: "Configured; update required"
        };
        if (profile === "malware") {
            await removeSaneSecurityDatabaseFiles(context.settings.databaseDir, saneSecurityMalwareDatabases);
            await reloadClamdDatabases(context.settings);
        }
        await saveConfig(context.settings);
        res.json({
            success: true,
            message: profile === "complete"
                ? "SaneSecurity Complete is configured. Run an update to install the malware and email-focused databases."
                : "SaneSecurity Malware Protection is configured. Run an update to install its malware-focused databases.",
            saneSecurity: await getSaneSecurityStatus(context.settings)
        });
    }
    catch (e: any) {
        res.status(400).json({ error: e?.message || String(e) });
    }
});
}
