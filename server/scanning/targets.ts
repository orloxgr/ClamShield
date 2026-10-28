import { englishText } from "../../shared/localization/runtime";
import { normalizeCachePath } from "../../modules/shield/server/cache";
import { sleep } from "../core/utils";
import { existingUniqueFiles } from "../platform/paths";
import { ensureAppTempDir, runPowerShellJson } from "../platform/processes";
import { getClamShieldScanExclusionPaths, windowsLockedScanExclusions } from "./exclusions";
import { randomBytes } from "crypto";
import fs from "fs/promises";
import os from "os";
import path from "path";
export async function getRunningProcessImagePaths() {
    if (process.platform !== "win32")
        return [];
    const script = `
$ErrorActionPreference = 'SilentlyContinue'
$paths = Get-CimInstance Win32_Process |
    Where-Object { $_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath -PathType Leaf) } |
    Select-Object -ExpandProperty ExecutablePath -Unique
'CLAMSHIELD_JSON_START'
@($paths) | ConvertTo-Json -Compress
'CLAMSHIELD_JSON_END'
`;
    try {
        const result = await runPowerShellJson(script);
        return existingUniqueFiles(Array.isArray(result) ? result : [result].filter(Boolean));
    }
    catch (e: any) {
        console.warn(englishText("backend.scanning.failed_to_enumerate_process_executable_paths"), e.message);
        return [];
    }
}
export async function createScanFileList(paths: string[]) {
    const listPath = path.join(await ensureAppTempDir(), `clamshield-scan-list-${Date.now()}-${randomBytes(6).toString("hex")}.txt`);
    await fs.writeFile(listPath, paths.join(os.EOL), "utf8");
    return listPath;
}
export function resolveScanTarget(type: string, target?: string) {
    if (target)
        return target;
    if (type === "disk")
        return process.platform === "win32" ? "C:\\" : "/";
    return target;
}
export function normalizeContextMenuAction(value: any) {
    const action = String(value || "").toLowerCase();
    if (action === "clamav-yara" || action === "clamav-yara-vt" || action === "add-exception")
        return action;
    return "clamav";
}
export function normalizeContextMenuTargets(value: any) {
    const rawTargets = Array.isArray(value) ? value : [];
    const seen = new Set<string>();
    return rawTargets
        .map(item => String(item || "").trim())
        .filter(item => item && path.isAbsolute(item))
        .filter(item => {
        const normalized = normalizeCachePath(item);
        if (!normalized || seen.has(normalized))
            return false;
        seen.add(normalized);
        return true;
    })
        .slice(0, 500);
}
export async function* enumerateContextScanTargetFiles(settings: any, targets: string[]): AsyncGenerator<string> {
    const shouldSkipFile = createManualScanPathSkipper(settings, "context");
    const seen = new Set<string>();
    for (const target of targets) {
        for await (const filePath of walkFiles(target, shouldSkipFile)) {
            const normalized = normalizeCachePath(filePath);
            if (!normalized || seen.has(normalized))
                continue;
            seen.add(normalized);
            yield filePath;
        }
    }
}
export async function* walkFiles(rootPath: string, shouldSkipPath?: (filePath: string) => boolean): AsyncGenerator<string> {
    const stack = [rootPath];
    while (stack.length) {
        const current = stack.pop()!;
        if (shouldSkipPath?.(current))
            continue;
        let stat;
        try {
            stat = await fs.stat(current);
        }
        catch {
            continue;
        }
        if (stat.isFile()) {
            yield current;
            continue;
        }
        if (!stat.isDirectory())
            continue;
        let entries;
        try {
            entries = await fs.readdir(current, { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const entry of entries) {
            if (entry.name === "." || entry.name === "..")
                continue;
            const childPath = path.join(current, entry.name);
            if (shouldSkipPath?.(childPath))
                continue;
            if (entry.isDirectory())
                stack.push(childPath);
            else if (entry.isFile())
                yield childPath;
        }
    }
}
export function isWindowsLockedScanPath(filePath: string) {
    if (process.platform !== "win32")
        return false;
    return windowsLockedScanExclusions.some(pattern => new RegExp(pattern, "i").test(filePath));
}
export function isThunderbirdSummaryFile(filePath: string) {
    return path.extname(filePath).toLowerCase() === ".msf";
}
export function normalizeComparablePath(filePath: string) {
    return path.resolve(filePath).replace(/[\\/]+$/, "").toLowerCase();
}
export function isNormalizedPathInside(childPath: string, parentPath: string) {
    return childPath === parentPath || childPath.startsWith(parentPath + path.sep.toLowerCase()) || childPath.startsWith(parentPath + "/");
}
export function createBuiltInScanPathSkipper(settings: any) {
    const excludedPaths = getClamShieldScanExclusionPaths(settings).map(normalizeComparablePath);
    return (filePath: string) => {
        if (isThunderbirdSummaryFile(filePath))
            return true;
        const normalizedPath = normalizeComparablePath(filePath);
        return excludedPaths.some(excludedPath => isNormalizedPathInside(normalizedPath, excludedPath));
    };
}
export function shouldSkipBuiltInScanPath(settings: any, filePath: string) {
    return createBuiltInScanPathSkipper(settings)(filePath);
}
export function createManualScanPathSkipper(settings: any, type: string) {
    const shouldSkipBuiltIn = createBuiltInScanPathSkipper(settings);
    return (filePath: string) => {
        if (type === "disk" && isWindowsLockedScanPath(filePath))
            return true;
        return shouldSkipBuiltIn(filePath);
    };
}
export async function enumerateScanTargets(settings: any, type: string, target: string) {
    const shouldSkipFile = createManualScanPathSkipper(settings, type);
    if (type === "memory" && process.platform === "win32") {
        const processPaths = await getRunningProcessImagePaths();
        return processPaths.filter(filePath => !shouldSkipFile(filePath));
    }
    const files: string[] = [];
    let stat;
    try {
        stat = await fs.stat(target);
    }
    catch {
        return files;
    }
    if (stat.isFile()) {
        if (!shouldSkipFile(target))
            files.push(target);
        return files;
    }
    if (!stat.isDirectory())
        return files;
    for await (const filePath of walkFiles(target, shouldSkipFile)) {
        files.push(filePath);
        if (files.length % 5000 === 0)
            await sleep(1);
    }
    return files;
}
export async function* enumerateScanTargetFiles(settings: any, type: string, target: string): AsyncGenerator<string> {
    const shouldSkipFile = createManualScanPathSkipper(settings, type);
    if (type === "memory" && process.platform === "win32") {
        const processPaths = await getRunningProcessImagePaths();
        for (const filePath of processPaths) {
            if (!shouldSkipFile(filePath))
                yield filePath;
        }
        return;
    }
    let stat;
    try {
        stat = await fs.stat(target);
    }
    catch {
        return;
    }
    if (stat.isFile()) {
        if (!shouldSkipFile(target))
            yield target;
        return;
    }
    if (!stat.isDirectory())
        return;
    for await (const filePath of walkFiles(target, shouldSkipFile)) {
        yield filePath;
    }
}
export function chunkItems<T>(items: T[], chunkSize: number) {
    const chunks: T[][] = [];
    for (let i = 0; i < items.length; i += chunkSize) {
        chunks.push(items.slice(i, i + chunkSize));
    }
    return chunks;
}
export function getAdaptiveScanBatchSize(totalFiles: number) {
    if (totalFiles <= 100)
        return 1;
    if (totalFiles <= 500)
        return 3;
    if (totalFiles <= 1000)
        return 10;
    return 100;
}
