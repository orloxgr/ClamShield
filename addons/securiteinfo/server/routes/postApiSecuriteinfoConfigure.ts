import { englishText } from "../../../../shared/localization/runtime";
import { reloadClamdDatabases } from "../../../../engines/clamav/server/daemon";
import { ensureFreshclamConfig } from "../../../../engines/clamav/server/freshclam";
import { saveConfig } from "../../../../modules/settings/server/service";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { extractSecuriteInfoToken, getConfiguredSecuriteInfoDatabaseNames, getSecuriteInfoStatus, normalizeSecuriteInfoIncludePua, normalizeSecuriteInfoPlan, redactSecuriteInfoSecret, removeSecuriteInfoDatabaseFiles, saveSecuriteInfoToken } from "../service";
export function registerPostApiSecuriteinfoConfigure(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/securiteinfo/configure", async (req, res) => {
        try {
            const token = extractSecuriteInfoToken(req.body?.setupText || req.body?.token || "");
            const plan = normalizeSecuriteInfoPlan(req.body?.plan);
            const includePua = plan === "paid" && normalizeSecuriteInfoIncludePua(req.body?.includePua);
            await saveSecuriteInfoToken(token);
            context.settings = {
                ...context.settings,
                securiteInfoEnabled: true,
                securiteInfoPlan: plan,
                securiteInfoIncludePua: includePua,
                lastSecuriteInfoUpdateResult: "Connected; update required"
            };
            await removeSecuriteInfoDatabaseFiles(context.settings.databaseDir, getConfiguredSecuriteInfoDatabaseNames(context.settings));
            await reloadClamdDatabases(context.settings);
            await ensureFreshclamConfig(context.settings);
            await saveConfig(context.settings, {
                keys: [
                    "securiteInfoEnabled",
                    "securiteInfoPlan",
                    "securiteInfoIncludePua",
                    "lastSecuriteInfoUpdateResult",
                    "freshclamConf"
                ]
            });
            res.json({
                success: true,
                message: plan === "paid"
                    ? `SecuriteInfo paid databases are connected${includePua ? englishText("backend.securiteinfo.with_optional_pua_signatures") : englishText("backend.securiteinfo.without_optional_pua_signatures")}. Run an update to download the configured signatures.`
                    : "SecuriteInfo Basic is connected for securiteinfo.ign2 and securiteinfoold.hdb. Run an update to download them.",
                securiteInfo: await getSecuriteInfoStatus(context.settings)
            });
        }
        catch (e: any) {
            res.status(400).json({ error: redactSecuriteInfoSecret(e?.message || String(e)) });
        }
    });
}
