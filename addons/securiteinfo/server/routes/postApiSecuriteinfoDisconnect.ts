import { reloadClamdDatabases } from "../../../../engines/clamav/server/daemon";
import { ensureFreshclamConfig } from "../../../../engines/clamav/server/freshclam";
import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { securiteInfoSecretPath } from "../../../../server/core/paths";
import { getSecuriteInfoStatus, redactSecuriteInfoSecret, removeSecuriteInfoDatabaseFiles } from "../service";
import fs from "fs/promises";
export function registerPostApiSecuriteinfoDisconnect(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/securiteinfo/disconnect", async (req, res) => {
        try {
            context.settings = {
                ...context.settings,
                securiteInfoEnabled: false,
                lastSecuriteInfoUpdateResult: "Disconnected"
            };
            await fs.unlink(securiteInfoSecretPath).catch(() => { });
            const removedFiles = req.body?.removeDatabases === false
                ? []
                : await removeSecuriteInfoDatabaseFiles(context.settings.databaseDir);
            await ensureFreshclamConfig(context.settings);
            await saveConfig(context.settings);
            await reloadClamdDatabases(context.settings);
            res.json({
                success: true,
                removedFiles,
                securiteInfo: await getSecuriteInfoStatus(context.settings)
            });
        }
        catch (e: any) {
            res.status(500).json({ error: redactSecuriteInfoSecret(e?.message || String(e)) });
        }
    });
}
