import { reloadClamdDatabases } from "../../../../engines/clamav/server/daemon";
import { ensureFreshclamConfig } from "../../../../engines/clamav/server/freshclam";
import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { extractSecuriteInfoToken, getConfiguredSecuriteInfoDatabaseNames, getSecuriteInfoStatus, loadSecuriteInfoToken, normalizeSecuriteInfoPlan, redactSecuriteInfoSecret, removeSecuriteInfoDatabaseFiles, saveSecuriteInfoToken } from "../service";
import { availableSecuriteInfoDatabases, normalizeDatabaseSelection, securiteInfoDatabaseCatalog } from "../../../../shared/signatureDatabases";
import { runtimeState } from "../../../../server/core/runtimeState";
export function registerPostApiSecuriteinfoConfigure(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/securiteinfo/configure", async (req, res) => {
        let configuring = false;
        try {
            if (runtimeState.freshclamUpdateInProgress || runtimeState.signatureDatabaseConfigurationInProgress)
                return res.status(409).json({ error: "Wait for the signature update to finish before changing databases." });
            runtimeState.signatureDatabaseConfigurationInProgress = configuring = true;
            const setupText = req.body?.setupText || req.body?.token || "";
            const token = setupText ? extractSecuriteInfoToken(setupText) : await loadSecuriteInfoToken();
            if (!token) throw new Error("Connect SecuriteInfo before saving database settings.");
            const plan = normalizeSecuriteInfoPlan(req.body?.plan);
            const databases = normalizeDatabaseSelection(req.body?.databases ?? availableSecuriteInfoDatabases(plan), securiteInfoDatabaseCatalog)
                .filter(name => availableSecuriteInfoDatabases(plan).includes(name));
            await saveSecuriteInfoToken(token);
            const nextSettings = {
                ...context.settings,
                securiteInfoEnabled: true,
                securiteInfoPlan: plan,
                securiteInfoDatabases: databases,
                securiteInfoIncludePua: databases.includes("securiteinfo-pua-app-and-vulnerabilities.ndb"),
                lastSecuriteInfoUpdateResult: "Connected; update required"
            };
            await removeSecuriteInfoDatabaseFiles(nextSettings.databaseDir, getConfiguredSecuriteInfoDatabaseNames(nextSettings));
            await ensureFreshclamConfig(nextSettings);
            await saveConfig(nextSettings, {
                keys: [
                    "securiteInfoEnabled",
                    "securiteInfoPlan",
                    "securiteInfoIncludePua",
                    "securiteInfoDatabases",
                    "lastSecuriteInfoUpdateResult",
                    "freshclamConf"
                ]
            });
            context.settings = nextSettings;
            await reloadClamdDatabases(context.settings);
            res.json({
                success: true,
                message: "Database selection saved.",
                securiteInfo: await getSecuriteInfoStatus(context.settings)
            });
        }
        catch (e: any) {
            res.status(400).json({ error: redactSecuriteInfoSecret(e?.message || String(e)) });
        }
        finally { if (configuring) runtimeState.signatureDatabaseConfigurationInProgress = false; }
    });
}
