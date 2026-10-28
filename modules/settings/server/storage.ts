import { englishText } from "../../../shared/localization/runtime";
import { getAppStateDb } from "../../../server/core/database/schema";
import { appStateJson, asRecord, runAppStateTransaction } from "../../../server/core/database/values";
export const auditedSettingsKeys = new Set([
    "runOnStartup",
    "startMinimized",
    "autoDisableDefender",
    "virusTotalCloudEnabled",
    "virusTotalShieldBackgroundCheckEnabled",
    "virusTotalShieldUploadUnknownEnabled",
    "yaraEnabled",
    "yaraRuleset",
    "yaraRulesDir",
    "yaraAutoUpdateEnabled"
]);
export function settingValuesEqual(left: any, right: any) {
    return JSON.stringify(left) === JSON.stringify(right);
}
export function getPersistedSettingsKeys() {
    const db = getAppStateDb();
    return new Set<string>(db.prepare("SELECT key FROM settings").all().map((row: any) => String(row.key)));
}
export function saveSettingsRows(settings: any) {
    const db = getAppStateDb();
    const existingRows = db.prepare("SELECT key, value FROM settings").all();
    const existingSettings = new Map(existingRows.map((row: any) => [String(row.key), row.value]));
    const auditedChanges = [...auditedSettingsKeys]
        .filter(key => existingSettings.has(key))
        .map(key => ({
        key,
        previous: existingSettings.get(key),
        next: appStateJson(asRecord(settings)[key])
    }))
        .filter(change => change.previous !== change.next);
    if (auditedChanges.length > 0) {
        const stack = new Error().stack
            ?.split("\n")
            .slice(2, 8)
            .map(line => line.trim())
            .join(" | ");
        console.warn(englishText("backend.settings.audited_settings_change"), auditedChanges, stack || "");
    }
    const insert = db.prepare("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)");
    runAppStateTransaction(db, () => {
        db.prepare("DELETE FROM settings").run();
        for (const [key, value] of Object.entries(asRecord(settings))) {
            insert.run(key, appStateJson(value));
        }
    });
}
export function saveSettingsPatchRows(settings: any, keys: Iterable<string>) {
    const db = getAppStateDb();
    const safe = asRecord(settings);
    const uniqueKeys = [...new Set([...keys].map(key => String(key)).filter(key => Object.prototype.hasOwnProperty.call(safe, key)))];
    if (uniqueKeys.length === 0)
        return;
    const existingRows = db.prepare("SELECT key, value FROM settings").all();
    const existingSettings = new Map(existingRows.map((row: any) => [String(row.key), row.value]));
    const auditedChanges = uniqueKeys
        .filter(key => auditedSettingsKeys.has(key))
        .map(key => ({
        key,
        previous: existingSettings.get(key),
        next: appStateJson(safe[key])
    }))
        .filter(change => change.previous !== change.next);
    if (auditedChanges.length > 0) {
        const stack = new Error().stack
            ?.split("\n")
            .slice(2, 8)
            .map(line => line.trim())
            .join(" | ");
        console.warn(englishText("backend.settings.audited_settings_change"), auditedChanges, stack || "");
    }
    const insert = db.prepare("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)");
    runAppStateTransaction(db, () => {
        for (const key of uniqueKeys) {
            insert.run(key, appStateJson(safe[key]));
        }
    });
}
