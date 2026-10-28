import { englishText } from "../../../../shared/localization/runtime";
import { getConfiguredSecuriteInfoDatabaseNames, normalizeSecuriteInfoPlan, removeSecuriteInfoDatabaseFiles } from "../../../../addons/securiteinfo/server/service";
import { checkClamAV, manageClamd, reloadClamdDatabases } from "../../../../engines/clamav/server/daemon";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { cleanupOldLogs } from "../../../../server/core/logs";
import { configureLegacyContextMenuRegistry, writeWindowsContextMenuState } from "../../../../server/platform/contextMenu";
import { syncDefenderCompatibilityExclusions } from "../../../../server/platform/defender";
import { manageStartup } from "../../../../server/platform/startup";
import { virusTotalLimitWarningsEnabled } from "../../../../addons/virustotal/server/virusTotalLimitWarning";
import { ensureDirs, saveConfig } from "../service";
import { saveSettingsPatchRows } from "../storage";
import { normalizeScheduledScanSettings, normalizeSettingsPatch } from "../validation";
export function registerPostApiSettings(app: any, context: Pick<ApplicationContext, "settings" | "virusTotalScanQueue" | "scheduleVirusTotalScan" | "startShield" | "scheduleDefenderEnforcement" | "scheduleNextUpdate" | "scheduleNextYaraUpdate" | "scheduleNextAppUpdateCheck" | "scheduleVirusTotalRefinement" | "scheduleShieldVirusTotalCheck">) {
    app.post("/api/settings", async (req, res) => {
        try {
            const normalizedRequest = normalizeSettingsPatch(req.body, context.settings);
            const requestedSettings = normalizedRequest.patch;
            if (Object.keys(requestedSettings).length === 1 && "virusTotalShowLimitWarnings" in requestedSettings) {
                context.settings = { ...context.settings, virusTotalShowLimitWarnings: requestedSettings.virusTotalShowLimitWarnings };
                // Save just this preference; do not rewrite installation defaults or restart engines.
                saveSettingsPatchRows(context.settings, ["virusTotalShowLimitWarnings"]);
                if (!virusTotalLimitWarningsEnabled(context.settings.virusTotalShowLimitWarnings)) {
                    context.virusTotalScanQueue.disableConfirmations();
                    context.scheduleVirusTotalScan();
                }
                return res.json({ success: true, settings: context.settings });
            }
            if (normalizedRequest.unknownKeys.length > 0) {
                console.warn(englishText("backend.settings.ignored_unknown_settings_keys"), normalizedRequest.unknownKeys.join(", "));
            }
            const securiteInfoDatabaseSelectionChanged = ("securiteInfoPlan" in requestedSettings && requestedSettings.securiteInfoPlan !== context.settings.securiteInfoPlan) ||
                ("securiteInfoIncludePua" in requestedSettings && requestedSettings.securiteInfoIncludePua !== context.settings.securiteInfoIncludePua);
            const hasScheduledScanSettings = Object.keys(requestedSettings).some(key => key.startsWith("scheduledScan"));
            if (hasScheduledScanSettings) {
                Object.assign(requestedSettings, normalizeScheduledScanSettings({
                    ...context.settings,
                    ...requestedSettings
                }));
            }
            const nextSettings = { ...context.settings, ...requestedSettings };
            const settingsKeysToPersist = new Set(Object.keys(requestedSettings));
            if (normalizeSecuriteInfoPlan(nextSettings.securiteInfoPlan) !== "paid") {
                nextSettings.securiteInfoIncludePua = false;
                if ("securiteInfoPlan" in requestedSettings || "securiteInfoIncludePua" in requestedSettings) {
                    settingsKeysToPersist.add("securiteInfoIncludePua");
                }
            }
            let defenderCompatibilityExclusions = null;
            if ("defenderCompatibilityExclusionsEnabled" in requestedSettings) {
                await ensureDirs(nextSettings);
                defenderCompatibilityExclusions = await syncDefenderCompatibilityExclusions(nextSettings);
                if (defenderCompatibilityExclusions?.Success === false) {
                    return res.status(409).json({
                        success: false,
                        error: defenderCompatibilityExclusions.Message || defenderCompatibilityExclusions.Error || englishText("backend.settings.windows_blocked_defender_exclusion_changes"),
                        defenderCompatibilityExclusions
                    });
                }
            }
            context.settings = nextSettings;
            await saveConfig(context.settings, { keys: settingsKeysToPersist });
            if (!virusTotalLimitWarningsEnabled(context.settings.virusTotalShowLimitWarnings))
                context.virusTotalScanQueue.disableConfirmations();
            await writeWindowsContextMenuState(context.settings);
            if (context.settings.windowsContextMenuEnabled === true) {
                await configureLegacyContextMenuRegistry(true, context.settings);
            }
            await ensureDirs(context.settings);
            await cleanupOldLogs(context.settings);
            if (securiteInfoDatabaseSelectionChanged) {
                await removeSecuriteInfoDatabaseFiles(context.settings.databaseDir, getConfiguredSecuriteInfoDatabaseNames(context.settings));
                await reloadClamdDatabases(context.settings);
            }
            res.json({
                success: true,
                settings: context.settings,
                ignoredSettings: normalizedRequest.rejectedKeys,
                defenderCompatibilityExclusions
            });
            Promise.resolve()
                .then(async () => {
                await checkClamAV(context.settings);
                await context.startShield(context.settings);
                await manageClamd(context.settings);
                await manageStartup(context.settings);
                await context.scheduleDefenderEnforcement(false);
                context.scheduleNextUpdate();
                context.scheduleNextYaraUpdate();
                context.scheduleNextAppUpdateCheck();
                context.scheduleVirusTotalRefinement();
                context.scheduleShieldVirusTotalCheck();
                context.scheduleVirusTotalScan();
            })
                .catch(e => console.error(englishText("backend.settings.failed_to_apply_settings_side_effects"), e));
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || englishText("settings.settings_save_failed") });
        }
    });
}
