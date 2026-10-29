import { englishText } from "../../../shared/localization/runtime";
import { getSaneSecurityDatabaseNames, normalizeSaneSecurityProfile } from "../../../addons/sanesecurity/server/status";
import { securiteInfoBasicDatabases, securiteInfoPaidDatabases, securiteInfoPuaDatabase } from "../../../addons/securiteinfo/server/constants";
import { getSecuriteInfoDatabaseNames, loadSecuriteInfoToken, normalizeSecuriteInfoIncludePua, normalizeSecuriteInfoPlan } from "../../../addons/securiteinfo/server/service";
import { loadVirusTotalApiKey } from "../../../addons/virustotal/server/account";
import { ensureAppStateReady, recoverLegacySettingsIfSettingsEmpty } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { asRecord, parseAppStateJson } from "../../../server/core/database/values";
import { defaultLogsDir, installerConsentPath, installerOptionsPath, legalNoticeVersion, programDataDir } from "../../../server/core/paths";
import { runtimeState } from "../../../server/core/runtimeState";
import { ensureAppTempDir } from "../../../server/platform/processes";
import { pathExists } from "../../../server/scanning/files";
import { normalizeShieldDetectionAction } from "../../shield/server/actions";
import { defaultSettings } from "./schema";
import { getPersistedSettingsKeys, saveSettingsPatchRows, settingValuesEqual } from "./storage";
import { normalizeNumberSetting, normalizeScheduledScanSettings } from "./validation";
import fs from "fs/promises";
import path from "path";
// Ensure directories exist
export async function ensureDirs(settings: any) {
    await ensureAppTempDir();
    const dirs = [
        programDataDir,
        settings.databaseDir,
        settings.quarantineDir,
        settings.logsDir,
        settings.yaraDir,
        settings.yaraRulesDir,
        settings.yaraCustomRulesDir,
        settings.yaraCacheDir
    ];
    for (const dir of dirs) {
        try {
            await fs.mkdir(dir, { recursive: true });
        }
        catch (e) {
            console.error(`Failed to create dir: ${dir}`, e);
        }
    }
}
// Load configurations
export async function loadInstallerConsent() {
    try {
        const content = await fs.readFile(installerConsentPath, "utf8");
        const values = Object.fromEntries(content
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(Boolean)
            .map(line => {
            const separator = line.indexOf("=");
            return separator > 0
                ? [line.slice(0, separator), line.slice(separator + 1)]
                : [line, ""];
        }));
        if (values.noticeVersion !== legalNoticeVersion)
            return null;
        return {
            version: values.noticeVersion,
            acceptedAt: values.acceptedAt || ""
        };
    }
    catch {
        return null;
    }
}
export function parseInstallerBoolean(value: any) {
    return /^(1|true|yes|on|checked)$/i.test(String(value || "").trim());
}
export async function loadInstallerOptions() {
    try {
        const content = await fs.readFile(installerOptionsPath, "utf8");
        const values = Object.fromEntries(content
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(Boolean)
            .map(line => {
            const separator = line.indexOf("=");
            return separator > 0
                ? [line.slice(0, separator), line.slice(separator + 1)]
                : [line, ""];
        }));
        return {
            startMinimized: parseInstallerBoolean(values.startMinimized),
            windowsContextMenuEnabled: parseInstallerBoolean(values.windowsContextMenuEnabled)
        };
    }
    catch {
        return null;
    }
}
export function getRuntimeDefaultSettings(installerConsent: any, installerOptions: any) {
    return installerConsent
        ? {
            ...defaultSettings,
            ...(installerOptions || {}),
            eulaAccepted: true,
            eulaVersion: legalNoticeVersion,
            eulaAcceptedAt: installerConsent.acceptedAt
        }
        : { ...defaultSettings, ...(installerOptions || {}) };
}
export function applyLoadedSettingsRuntime(settings: any) {
    runtimeState.virusTotalUsageRefreshEveryRequests = normalizeNumberSetting("virusTotalUsageRefreshEveryRequests", settings.virusTotalUsageRefreshEveryRequests);
    runtimeState.virusTotalUsageSyncEnabled = settings.virusTotalCloudEnabled === true;
    runtimeState.currentLogsDir = settings.logsDir || defaultLogsDir;
    runtimeState.debugLoggingEnabled = settings.enableDebugLog === true;
    return settings;
}
export function parseSettingsRows(rows: any[]) {
    return rows.reduce((settings: any, row: any) => {
        settings[row.key] = parseAppStateJson(row.value, null);
        return settings;
    }, {});
}
export async function restoreVirusTotalShieldCloudSettings(settings: any, parsedSettings: any) {
    const parsed = asRecord(parsedSettings);
    const next = { ...settings };
    const recoveredKeys = new Set<string>();
    const hasShieldBackgroundSetting = Object.prototype.hasOwnProperty.call(parsed, "virusTotalShieldBackgroundCheckEnabled");
    const hasShieldUploadSetting = Object.prototype.hasOwnProperty.call(parsed, "virusTotalShieldUploadUnknownEnabled");
    if (next.virusTotalCloudEnabled === true &&
        next.virusTotalShieldBackgroundCheckEnabled !== true &&
        !hasShieldBackgroundSetting &&
        await loadVirusTotalApiKey()) {
        try {
            const previousShieldCheck = getAppStateDb().prepare(`
                SELECT type FROM history
                WHERE type IN ('virustotal-shield-check', 'virustotal-shield-upload')
                LIMIT 1
            `).get();
            if (previousShieldCheck) {
                next.virusTotalShieldBackgroundCheckEnabled = true;
                recoveredKeys.add("virusTotalShieldBackgroundCheckEnabled");
            }
            if (!hasShieldUploadSetting && String(previousShieldCheck?.type || "") === "virustotal-shield-upload") {
                next.virusTotalShieldUploadUnknownEnabled = true;
                recoveredKeys.add("virusTotalShieldUploadUnknownEnabled");
            }
        }
        catch (e: any) {
            console.warn(englishText("backend.settings.could_not_inspect_virustotal_shield_history_for_settings_recovery"), e?.message || e);
        }
    }
    if (recoveredKeys.size > 0) {
        saveSettingsPatchRows(next, recoveredKeys);
    }
    return next;
}
export async function buildLoadedSettingsFromRows(rows: any[], installerConsent: any, installerOptions: any, recoverInstalledProviders = true) {
    if (!rows.length) {
        return applyLoadedSettingsRuntime(getRuntimeDefaultSettings(installerConsent, installerOptions));
    }
    const parsed = parseSettingsRows(rows);
    const parsedWithInstallerOptions = {
        ...parsed,
        ...(installerOptions || {})
    };
    const actionOnDetection = normalizeShieldDetectionAction(parsedWithInstallerOptions.actionOnDetection || defaultSettings.actionOnDetection);
    const scanDetectionAction = parsedWithInstallerOptions.scanDetectionAction || defaultSettings.scanDetectionAction;
    const settingsConsentAccepted = parsed.eulaAccepted === true && parsed.eulaVersion === legalNoticeVersion;
    const eulaAccepted = settingsConsentAccepted || Boolean(installerConsent);
    const loadedSettings = {
        ...defaultSettings,
        ...parsedWithInstallerOptions,
        ...normalizeScheduledScanSettings(parsedWithInstallerOptions),
        actionOnDetection,
        scanDetectionAction,
        securiteInfoPlan: normalizeSecuriteInfoPlan(parsedWithInstallerOptions.securiteInfoPlan),
        securiteInfoIncludePua: normalizeSecuriteInfoPlan(parsedWithInstallerOptions.securiteInfoPlan) === "paid" && normalizeSecuriteInfoIncludePua(parsedWithInstallerOptions.securiteInfoIncludePua),
        eulaAccepted,
        eulaVersion: eulaAccepted ? legalNoticeVersion : "",
        eulaAcceptedAt: settingsConsentAccepted
            ? String(parsedWithInstallerOptions.eulaAcceptedAt || "")
            : String(installerConsent?.acceptedAt || "")
    };
    const recoveredProviderSettings = recoverInstalledProviders
        ? await restoreInstalledSignatureProviderSettings(loadedSettings)
        : loadedSettings;
    const recoveredSettings = await restoreVirusTotalShieldCloudSettings(recoveredProviderSettings, parsed);
    return applyLoadedSettingsRuntime(recoveredSettings);
}
export async function loadPersistedSettingsBestEffort(installerConsent: any, installerOptions: any) {
    try {
        const db = getAppStateDb();
        await recoverLegacySettingsIfSettingsEmpty(db);
        const rows = db.prepare("SELECT key, value FROM settings").all();
        if (!rows.length)
            return null;
        return await buildLoadedSettingsFromRows(rows, installerConsent, installerOptions, false);
    }
    catch (e: any) {
        console.warn(englishText("backend.settings.could_not_load_persisted_settings_after_app_state_migration_failu"), e?.message || e);
        return null;
    }
}
export async function loadConfig() {
    const installerConsent = await loadInstallerConsent();
    const installerOptions = await loadInstallerOptions();
    runtimeState.pendingInstallerOptionsApplied = Boolean(installerOptions);
    try {
        await ensureAppStateReady();
        const rows = getAppStateDb().prepare("SELECT key, value FROM settings").all();
        return await buildLoadedSettingsFromRows(rows, installerConsent, installerOptions);
    }
    catch (e: any) {
        const persistedSettings = await loadPersistedSettingsBestEffort(installerConsent, installerOptions);
        if (persistedSettings) {
            console.warn(englishText("backend.settings.app_state_migration_failed_loaded_persisted_settings_without_runn"), e?.message || e);
            return persistedSettings;
        }
        console.warn(englishText("backend.settings.failed_to_load_settings_using_runtime_defaults_without_persisting"), e?.message || e);
        return applyLoadedSettingsRuntime(getRuntimeDefaultSettings(installerConsent, installerOptions));
    }
}
export async function saveConfig(settings: any, options: {
    keys?: Iterable<string>;
} = {}) {
    const safeSettings = { ...settings };
    delete safeSettings.securiteInfoToken;
    delete safeSettings.securiteInfoUrl;
    delete safeSettings.securiteInfoSetupText;
    await ensureAppStateReady();
    const persistedKeys = getPersistedSettingsKeys();
    const keysToSave = new Set<string>([
        ...persistedKeys,
        ...[...(options.keys || [])].map(key => String(key))
    ]);
    for (const [key, value] of Object.entries(safeSettings)) {
        if (!Object.prototype.hasOwnProperty.call(defaultSettings, key)) {
            keysToSave.add(key);
            continue;
        }
        if (!settingValuesEqual(value, (defaultSettings as Record<string, any>)[key])) {
            keysToSave.add(key);
        }
    }
    saveSettingsPatchRows(safeSettings, keysToSave);
    runtimeState.virusTotalUsageRefreshEveryRequests = normalizeNumberSetting("virusTotalUsageRefreshEveryRequests", settings.virusTotalUsageRefreshEveryRequests);
    runtimeState.virusTotalUsageSyncEnabled = settings.virusTotalCloudEnabled === true;
    runtimeState.currentLogsDir = settings.logsDir || defaultLogsDir;
    runtimeState.debugLoggingEnabled = settings.enableDebugLog === true;
}
export async function restoreInstalledSignatureProviderSettings(settings: any) {
    const next = { ...settings };
    let changed = false;
    const recoveredKeys = new Set<string>();
    const databaseDir = String(next.databaseDir || defaultSettings.databaseDir);
    const hasDatabase = async (fileName: string) => await pathExists(path.join(databaseDir, fileName));
    const newestDatabaseDate = async (fileNames: string[]) => {
        const dates: string[] = [];
        for (const fileName of fileNames) {
            try {
                dates.push((await fs.stat(path.join(databaseDir, fileName))).mtime.toISOString());
            }
            catch { }
        }
        return dates.sort((a, b) => b.localeCompare(a))[0] || "";
    };
    if (next.securiteInfoEnabled !== true && await loadSecuriteInfoToken()) {
        const paidDatabasesPresent = (await Promise.all(securiteInfoPaidDatabases
            .filter(name => !securiteInfoBasicDatabases.includes(name))
            .map(hasDatabase))).some(Boolean);
        const inferredPlan = paidDatabasesPresent ? "paid" : normalizeSecuriteInfoPlan(next.securiteInfoPlan);
        const expected = getSecuriteInfoDatabaseNames(inferredPlan, await hasDatabase(securiteInfoPuaDatabase));
        const installedCount = (await Promise.all(expected.map(hasDatabase))).filter(Boolean).length;
        if (installedCount === expected.length && installedCount > 0) {
            next.securiteInfoEnabled = true;
            next.securiteInfoPlan = inferredPlan;
            next.securiteInfoIncludePua = inferredPlan === "paid" && await hasDatabase(securiteInfoPuaDatabase);
            if (!next.lastSecuriteInfoUpdate)
                next.lastSecuriteInfoUpdate = await newestDatabaseDate(expected);
            if (!next.lastSecuriteInfoUpdateResult)
                next.lastSecuriteInfoUpdateResult = "Recovered existing installed databases";
            [
                "securiteInfoEnabled",
                "securiteInfoPlan",
                "securiteInfoIncludePua",
                "lastSecuriteInfoUpdate",
                "lastSecuriteInfoUpdateResult"
            ].forEach(key => recoveredKeys.add(key));
            changed = true;
        }
    }
    if (next.saneSecurityEnabled !== true && String(next.lastSaneSecurityUpdateResult || "") !== "Disconnected") {
        const profile = normalizeSaneSecurityProfile(next.saneSecurityProfile);
        const expected = getSaneSecurityDatabaseNames(profile);
        const installedCount = (await Promise.all(expected.map(hasDatabase))).filter(Boolean).length;
        if (installedCount === expected.length && installedCount > 0) {
            next.saneSecurityEnabled = true;
            if (!next.lastSaneSecurityUpdate)
                next.lastSaneSecurityUpdate = await newestDatabaseDate(expected);
            if (!next.lastSaneSecurityUpdateResult)
                next.lastSaneSecurityUpdateResult = "Recovered existing installed databases";
            [
                "saneSecurityEnabled",
                "lastSaneSecurityUpdate",
                "lastSaneSecurityUpdateResult"
            ].forEach(key => recoveredKeys.add(key));
            changed = true;
        }
    }
    if (changed)
        saveSettingsPatchRows(next, recoveredKeys);
    return next;
}
