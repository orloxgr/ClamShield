import { reloadClamdDatabases } from "../../../../engines/clamav/server/daemon";
import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getSaneSecurityStatus, removeSaneSecurityDatabaseFiles } from "../status";
export function registerPostApiSanesecurityDisconnect(app: any, context: Pick<ApplicationContext, "settings">) {
app.post("/api/sanesecurity/disconnect", async (req, res) => {
    try {
        context.settings = {
            ...context.settings,
            saneSecurityEnabled: false,
            lastSaneSecurityUpdateResult: "Disconnected"
        };
        const removedFiles = req.body?.removeDatabases === false
            ? []
            : await removeSaneSecurityDatabaseFiles(context.settings.databaseDir);
        await saveConfig(context.settings);
        await reloadClamdDatabases(context.settings);
        res.json({
            success: true,
            removedFiles,
            saneSecurity: await getSaneSecurityStatus(context.settings)
        });
    }
    catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
    }
});
}
