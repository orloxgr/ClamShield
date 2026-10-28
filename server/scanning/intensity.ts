import { englishText } from "../../shared/localization/runtime";
import { normalizePositiveNumber } from "../../modules/settings/server/validation";
import { applyShieldLowImpactPriority, setWindowsProcessPriority } from "../platform/processes";
import os from "os";
export function normalizeScanIntensity(value: any, fallback: number) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed))
        return fallback;
    return Math.min(100, Math.max(1, Math.round(parsed)));
}
export function getScanModeIntensity(settings: any, source: string) {
    if (source === "shield")
        return normalizeScanIntensity(settings.shieldScanIntensity, 41);
    if (source === "scheduled")
        return normalizeScanIntensity(settings.scheduledScanIntensity, 81);
    return normalizeScanIntensity(settings.manualScanIntensity, 81);
}
export function getLogicalCpuCount() {
    return Math.max(1, os.cpus()?.length || 1);
}
export function getScanIntensityProfile(settings: any, totalFiles: number, source: string) {
    const intensity = getScanModeIntensity(settings, source);
    const cpuCount = getLogicalCpuCount();
    const allWorkers = Math.min(32, cpuCount);
    const halfWorkers = Math.min(allWorkers, Math.max(2, Math.ceil(cpuCount * 0.5)));
    const threeQuarterWorkers = Math.min(allWorkers, Math.max(2, Math.ceil(cpuCount * 0.75)));
    const allButOneWorkers = Math.min(allWorkers, Math.max(1, cpuCount - 1));
    let profile = { priorityClass: "Idle", workers: 1, batchSize: 100, delayMs: 500, label: englishText("backend.scanning.extremely_gentle") };
    if (intensity <= 10)
        profile = { priorityClass: "Idle", workers: 1, batchSize: 100, delayMs: 500, label: englishText("backend.scanning.extremely_gentle") };
    else if (intensity <= 20)
        profile = { priorityClass: "Idle", workers: 1, batchSize: 250, delayMs: 250, label: englishText("backend.scanning.very_gentle") };
    else if (intensity <= 30)
        profile = { priorityClass: "BelowNormal", workers: 1, batchSize: 500, delayMs: 150, label: englishText("backend.scanning.gentle") };
    else if (intensity <= 40)
        profile = { priorityClass: "BelowNormal", workers: 1, batchSize: 1000, delayMs: 75, label: englishText("backend.scanning.light") };
    else if (intensity <= 50)
        profile = { priorityClass: "BelowNormal", workers: Math.min(allWorkers, 2), batchSize: 2000, delayMs: 25, label: englishText("backend.scanning.balanced") };
    else if (intensity <= 60)
        profile = { priorityClass: "Normal", workers: Math.min(allWorkers, 2), batchSize: 3000, delayMs: 0, label: englishText("settings.active") };
    else if (intensity <= 70)
        profile = { priorityClass: "Normal", workers: halfWorkers, batchSize: 5000, delayMs: 0, label: englishText("backend.scanning.fast") };
    else if (intensity <= 80)
        profile = { priorityClass: "Normal", workers: threeQuarterWorkers, batchSize: 10000, delayMs: 0, label: englishText("backend.scanning.very_fast") };
    else if (intensity <= 90)
        profile = { priorityClass: "High", workers: allButOneWorkers, batchSize: 15000, delayMs: 0, label: englishText("backend.scanning.maximum_minus_one_core") };
    else
        profile = { priorityClass: "High", workers: allWorkers, batchSize: 25000, delayMs: 0, label: englishText("backend.scanning.maximum") };
    const configured = Number(settings.scanBatchSize || 0);
    let batchSize = profile.batchSize;
    if (Number.isFinite(configured) && configured > 0 && configured !== 250) {
        batchSize = Math.min(25000, Math.max(1, Math.round(configured)));
    }
    if (totalFiles > 0 && totalFiles <= 100) {
        batchSize = Math.max(1, Math.min(25, Math.ceil(totalFiles / Math.max(1, profile.workers))));
    }
    return {
        ...profile,
        intensity,
        cpuCount,
        workers: Math.max(1, Math.min(profile.workers, totalFiles > 0 ? Math.max(1, totalFiles) : profile.workers)),
        batchSize
    };
}
export function getScanBatchSizeForMode(settings: any, totalFiles: number, source: string) {
    return getScanIntensityProfile(settings, totalFiles, source).batchSize;
}
export function getScanBatchDelayForMode(settings: any, source: string) {
    const configured = Math.round(normalizePositiveNumber(settings.scanBatchDelayMs, 0, 0, 60000));
    if (configured > 0)
        return configured;
    return getScanIntensityProfile(settings, 0, source).delayMs;
}
export function getPerWorkerBatchCap(intensity: number, isClamd: boolean) {
    if (intensity <= 20)
        return isClamd ? 20 : 50;
    if (intensity <= 40)
        return isClamd ? 35 : 75;
    if (intensity <= 60)
        return isClamd ? 50 : 100;
    if (intensity <= 80)
        return isClamd ? 75 : 200;
    return isClamd ? 150 : 300;
}
export function applyScanProcessPriority(child: any, settings: any, source: string, label: string) {
    if (source === "shield") {
        applyShieldLowImpactPriority(child, settings, label);
        return;
    }
    const priorityClass = getScanIntensityProfile(settings, 0, source).priorityClass;
    void setWindowsProcessPriority(child?.pid, priorityClass)
        .catch((err: any) => console.warn(englishText("backend.scanning.could_not_set_priority", {
        label: String(label)
    }), err?.message || err));
}
