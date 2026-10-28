import { normalizeSaneSecurityProfile } from "../../../addons/sanesecurity/server/status";
import { normalizeSecuriteInfoPlan } from "../../../addons/securiteinfo/server/service";
import { normalizeYaraRuleset } from "../../../engines/yara/server/rules";
import { asRecord, normalizedStatePath } from "../../../server/core/database/values";
import { normalizeScanIntensity } from "../../../server/scanning/intensity";
import { virusTotalLimitWarningsEnabled } from "../../../addons/virustotal/server/virusTotalLimitWarning";
import { normalizeShieldDetectionAction } from "../../shield/server/actions";
import { booleanSettingKeys, defaultSettings, enumSettingKeys, numberSettingSpecs, pathListSettingKeys, pathSettingKeys, readOnlySettingKeys, userWritableSettingKeys } from "./schema";
import path from "path";

export function normalizePositiveNumber(value: any, fallback: number, min: number, max: number) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed))
        return fallback;
    return Math.min(max, Math.max(min, parsed));
}

export function normalizeIntegerList(value: any, min: number, max: number, fallback: number[]) {
    if (!Array.isArray(value))
        return [...fallback];
    const normalized = Array.from(new Set(value
        .map(item => Math.round(Number(item)))
        .filter(item => Number.isFinite(item) && item >= min && item <= max))).sort((a, b) => a - b);
    return normalized.length > 0 ? normalized : [...fallback];
}

export function normalizeScheduledScanSettings(value: any) {
    const raw = value || {};
    const time = typeof raw.scheduledScanTime === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(raw.scheduledScanTime)
        ? raw.scheduledScanTime
        : defaultSettings.scheduledScanTime;
    const directories = Array.isArray(raw.scheduledScanDirectories)
        ? Array.from(new Set(raw.scheduledScanDirectories
            .map((item: any) => String(item || "").trim())
            .filter((item: string) => item && path.isAbsolute(item)))).slice(0, 50)
        : [...defaultSettings.scheduledScanDirectories];
    return {
        scheduledScanEnabled: raw.scheduledScanEnabled === true,
        scheduledScanFrequency: raw.scheduledScanFrequency === "monthly" ? "monthly" : "weekly",
        scheduledScanWeekdays: normalizeIntegerList(raw.scheduledScanWeekdays, 0, 6, defaultSettings.scheduledScanWeekdays),
        scheduledScanMonthDays: normalizeIntegerList(raw.scheduledScanMonthDays, 1, 31, defaultSettings.scheduledScanMonthDays),
        scheduledScanTime: time,
        scheduledScanIdleOnly: raw.scheduledScanIdleOnly !== false,
        scheduledScanIdleMinutes: Math.round(normalizePositiveNumber(raw.scheduledScanIdleMinutes, 15, 1, 240)),
        scheduledScanFullDisk: raw.scheduledScanFullDisk === undefined
            ? defaultSettings.scheduledScanFullDisk
            : raw.scheduledScanFullDisk === true,
        scheduledScanDirectories: directories,
        scheduledScanMemory: raw.scheduledScanMemory === true
    };
}

export function getSettingFallback(key: string, currentSettings: any) {
    const defaults = defaultSettings as Record<string, any>;
    if (currentSettings && Object.prototype.hasOwnProperty.call(currentSettings, key))
        return currentSettings[key];
    if (Object.prototype.hasOwnProperty.call(defaults, key))
        return defaults[key];
    return undefined;
}

export function normalizeSettingsString(value: any, fallback = "", maxLength = 1024) {
    if (typeof value !== "string")
        return fallback;
    const normalized = value.replace(/\0/g, "").trim();
    if (!normalized)
        return fallback;
    return normalized.slice(0, maxLength);
}

export function normalizeSettingsPath(value: any, fallback: any) {
    const fallbackValue = typeof fallback === "string" ? fallback : "";
    const normalized = normalizeSettingsString(value, fallbackValue, 1024);
    if (!normalized)
        return fallbackValue;
    if (/[\r\n"`]/.test(normalized) || /\$\(/.test(normalized))
        return fallbackValue;
    try {
        if (!path.isAbsolute(normalized))
            return fallbackValue;
        return path.resolve(normalized);
    }
    catch {
        return fallbackValue;
    }
}

export function normalizeSettingsPathList(value: any, fallback: any[] = []) {
    const source = Array.isArray(value) ? value : fallback;
    const seen = new Set<string>();
    const normalized: string[] = [];
    for (const item of source) {
        const normalizedPath = normalizeSettingsPath(item, "");
        if (!normalizedPath)
            continue;
        const key = normalizedStatePath(normalizedPath);
        if (!key || seen.has(key))
            continue;
        seen.add(key);
        normalized.push(normalizedPath);
        if (normalized.length >= 100)
            break;
    }
    return normalized;
}

export function normalizeNumberSetting(key: string, value: any) {
    const spec = numberSettingSpecs[key];
    if (!spec)
        return value;
    if (key === "manualScanIntensity" || key === "scheduledScanIntensity" || key === "shieldScanIntensity") {
        return normalizeScanIntensity(value, spec.fallback);
    }
    const normalized = normalizePositiveNumber(value, spec.fallback, spec.min, spec.max);
    return spec.integer ? Math.round(normalized) : normalized;
}

export function normalizeEnumSetting(key: string, value: any) {
    if (key === "defaultAction" || key === "actionOnDetection")
        return normalizeShieldDetectionAction(value);
    if (key === "scanDetectionAction")
        return String(value || "").toLowerCase() === "quarantine" ? "quarantine" : "results";
    if (key === "securiteInfoPlan")
        return normalizeSecuriteInfoPlan(value);
    if (key === "saneSecurityProfile")
        return normalizeSaneSecurityProfile(value);
    if (key === "yaraRuleset")
        return normalizeYaraRuleset(value);
    if (key === "scheduledScanFrequency")
        return String(value || "").toLowerCase() === "monthly" ? "monthly" : "weekly";
    return value;
}

export function normalizeSettingsPatch(rawSettings: any, currentSettings: any) {
    const body = asRecord(rawSettings);
    const patch: Record<string, any> = {};
    const ignoredKeys: string[] = [];
    const unknownKeys: string[] = [];
    for (const [key, value] of Object.entries(body)) {
        if (readOnlySettingKeys.has(key)) {
            ignoredKeys.push(key);
            continue;
        }
        if (!userWritableSettingKeys.has(key)) {
            unknownKeys.push(key);
            continue;
        }
        const fallback = getSettingFallback(key, currentSettings);
        if (pathSettingKeys.has(key)) {
            patch[key] = normalizeSettingsPath(value, fallback);
        }
        else if (pathListSettingKeys.has(key)) {
            patch[key] = normalizeSettingsPathList(value, Array.isArray(fallback) ? fallback : []);
        }
        else if (key === "virusTotalShowLimitWarnings") {
            patch[key] = virusTotalLimitWarningsEnabled(value);
        }
        else if (booleanSettingKeys.has(key)) {
            patch[key] = value === true;
        }
        else if (Object.prototype.hasOwnProperty.call(numberSettingSpecs, key)) {
            patch[key] = normalizeNumberSetting(key, value);
        }
        else if (enumSettingKeys.has(key)) {
            patch[key] = normalizeEnumSetting(key, value);
        }
        else if (key === "scheduledScanWeekdays") {
            patch[key] = normalizeIntegerList(value, 0, 6, defaultSettings.scheduledScanWeekdays);
        }
        else if (key === "scheduledScanMonthDays") {
            patch[key] = normalizeIntegerList(value, 1, 31, defaultSettings.scheduledScanMonthDays);
        }
        else if (key === "scheduledScanTime") {
            patch[key] = typeof value === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(value)
                ? value
                : getSettingFallback(key, currentSettings);
        }
    }
    const rejectedKeys = [...unknownKeys, ...ignoredKeys];
    return { patch, rejectedKeys, unknownKeys, ignoredKeys };
}
