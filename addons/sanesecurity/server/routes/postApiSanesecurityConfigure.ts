import { reloadClamdDatabases } from "../../../../engines/clamav/server/daemon";
import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saneSecurityAllDatabases } from "../constants";
import { getSaneSecurityStatus, removeSaneSecurityDatabaseFiles } from "../status";
import { normalizeDatabaseSelection, saneSecurityDatabaseCatalog } from "../../../../shared/signatureDatabases";
import { runtimeState } from "../../../../server/core/runtimeState";
export function registerPostApiSanesecurityConfigure(app: any, context: Pick<ApplicationContext, "settings">) {
app.post("/api/sanesecurity/configure", async (req, res) => {
    let configuring = false;
    try {
        if (runtimeState.saneSecurityUpdateInProgress || runtimeState.signatureDatabaseConfigurationInProgress)
            return res.status(409).json({ error: "Wait for the signature update to finish before changing databases." });
        runtimeState.signatureDatabaseConfigurationInProgress = configuring = true;
        const databases = normalizeDatabaseSelection(req.body?.databases ?? saneSecurityAllDatabases, saneSecurityDatabaseCatalog);
        const nextSettings = {
            ...context.settings,
            saneSecurityEnabled: true,
            saneSecurityDatabases: databases,
            lastSaneSecurityUpdateResult: "Configured; update required"
        };
        await removeSaneSecurityDatabaseFiles(nextSettings.databaseDir, databases);
        await saveConfig(nextSettings, { keys: ["saneSecurityEnabled", "saneSecurityDatabases", "lastSaneSecurityUpdateResult"] });
        context.settings = nextSettings;
        await reloadClamdDatabases(context.settings);
        res.json({
            success: true,
            message: "Database selection saved.",
            saneSecurity: await getSaneSecurityStatus(context.settings)
        });
    }
    catch (e: any) {
        res.status(400).json({ error: e?.message || String(e) });
    }
    finally { if (configuring) runtimeState.signatureDatabaseConfigurationInProgress = false; }
});
}
