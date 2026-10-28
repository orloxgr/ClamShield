import { englishText } from "../../../shared/localization/runtime";
import { normalizePositiveNumber } from "../../../modules/settings/server/validation";
import { appTempDir } from "../../../server/core/paths";
import { getClamShieldScanExclusionPatterns, windowsLockedScanExclusions } from "../../../server/scanning/exclusions";
import { createHash } from "crypto";
import fs from "fs/promises";
import path from "path";
export function buildClamdConfContent(settings: any) {
    const maxFileSize = normalizePositiveNumber(settings.maxFileSize, 50, 1, 4096);
    const maxScanTimeMs = getClamScanMaxTimeMs(settings);
    const lines = [
        `DatabaseDirectory ${settings.databaseDir}`,
        `TemporaryDirectory ${appTempDir}`,
        "TCPAddr 127.0.0.1",
        "TCPSocket 3310",
        `MaxFileSize ${maxFileSize}M`,
        `MaxScanSize ${Math.max(maxFileSize, maxFileSize * 2)}M`,
        `MaxScanTime ${maxScanTimeMs}`,
        `ScanArchive ${settings.scanArchives === false ? "no" : "yes"}`,
        `FollowDirectorySymlinks ${settings.followSymlinks ? "yes" : "no"}`,
        `FollowFileSymlinks ${settings.followSymlinks ? "yes" : "no"}`
    ];
    if (settings.enableDebugLog === true) {
        lines.push(`LogFile ${path.join(settings.logsDir, "clamd.log")}`);
        lines.push("LogTime yes");
    }
    getClamShieldScanExclusionPatterns(settings)
        .forEach((pattern: string) => lines.push(`ExcludePath ${pattern}`));
    return `${lines.join("\n")}\n`;
}
export function getClamdConfSignature(settings: any) {
    return createHash("sha256").update(buildClamdConfContent(settings)).digest("hex");
}
export async function ensureClamdConfContent(settings: any) {
    if (!settings.clamdConf)
        return false;
    try {
        await fs.mkdir(path.dirname(settings.clamdConf), { recursive: true });
        let content = "";
        try {
            content = await fs.readFile(settings.clamdConf, "utf8");
        }
        catch (e: any) {
            console.debug(englishText("backend.clamav.clamd_conf_could_not_be_read_writing_managed_config"), e?.message || e);
        }
        const desired = buildClamdConfContent(settings);
        if (content !== desired) {
            await fs.writeFile(settings.clamdConf, desired);
            console.debug(englishText("backend.clamav.clamd_conf_updated_to_match_clamshield_managed_settings"));
            return true;
        }
        return false;
    }
    catch (e: any) {
        console.warn(englishText("backend.clamav.failed_to_ensure_clamd_managed_config"), e?.message || e);
        return false;
    }
}
export function getClamScanMaxTimeMs(_settings: any) {
    return 120000;
}
export function getClamScanChildTimeoutMs(settings: any, fileCount: number) {
    const maxScanTimeMs = getClamScanMaxTimeMs(settings);
    const baseMs = maxScanTimeMs + 60000;
    const perFileMs = 30000;
    const capMs = 30 * 60 * 1000;
    return Math.min(capMs, Math.max(baseMs, Math.max(1, fileCount) * perFileMs));
}
export function buildClamScanArgs(scanSettings: any, isClamd: boolean, type: string, target?: string) {
    const args = isClamd
        ? ["--config-file=" + scanSettings.clamdConf]
        : ["--database=" + scanSettings.databaseDir];
    if (scanSettings.recursive && type !== "file") {
        args.push(isClamd ? "--multiscan" : "--recursive");
    }
    if (!isClamd) {
        const maxFileSize = normalizePositiveNumber(scanSettings.maxFileSize, 50, 1, 4096);
        const maxScanTimeMs = getClamScanMaxTimeMs(scanSettings);
        args.push(`--tempdir=${appTempDir}`);
        args.push(`--max-filesize=${maxFileSize}M`);
        args.push(`--max-scansize=${Math.max(maxFileSize, maxFileSize * 2)}M`);
        args.push(`--max-scantime=${maxScanTimeMs}`);
        args.push(`--scan-archive=${scanSettings.scanArchives === false ? "no" : "yes"}`);
        args.push(`--follow-dir-symlinks=${scanSettings.followSymlinks ? "1" : "0"}`);
        args.push(`--follow-file-symlinks=${scanSettings.followSymlinks ? "1" : "0"}`);
        getClamShieldScanExclusionPatterns(scanSettings).forEach((pattern: string) => {
            args.push(`--exclude=${pattern}`);
        });
        if (process.platform === "win32" && type === "disk") {
            windowsLockedScanExclusions.forEach(pattern => args.push(`--exclude=${pattern}`));
        }
        if (type === "memory") {
            if (target && process.platform === "win32") {
                args.push(`--file-list=${target}`);
            }
            else {
                args.push("--memory");
            }
        }
    }
    if (target && !(type === "memory" && process.platform === "win32"))
        args.push(target);
    return args;
}
export function buildClamFileListArgs(scanSettings: any, isClamd: boolean, listPath: string) {
    const args = isClamd
        ? ["--config-file=" + scanSettings.clamdConf]
        : ["--database=" + scanSettings.databaseDir];
    if (isClamd) {
        args.push("--multiscan");
    }
    else {
        const maxFileSize = normalizePositiveNumber(scanSettings.maxFileSize, 50, 1, 4096);
        const maxScanTimeMs = getClamScanMaxTimeMs(scanSettings);
        args.push(`--tempdir=${appTempDir}`);
        args.push(`--max-filesize=${maxFileSize}M`);
        args.push(`--max-scansize=${Math.max(maxFileSize, maxFileSize * 2)}M`);
        args.push(`--max-scantime=${maxScanTimeMs}`);
        args.push(`--scan-archive=${scanSettings.scanArchives === false ? "no" : "yes"}`);
        args.push(`--follow-dir-symlinks=${scanSettings.followSymlinks ? "1" : "0"}`);
        args.push(`--follow-file-symlinks=${scanSettings.followSymlinks ? "1" : "0"}`);
        getClamShieldScanExclusionPatterns(scanSettings).forEach((pattern: string) => {
            args.push(`--exclude=${pattern}`);
        });
    }
    args.push(`--file-list=${listPath}`);
    return args;
}
export function parseClamOutputPath(line: string) {
    const match = line.match(/^(.+?):\s+(.+)$/);
    return match ? match[1] : "";
}
export function isNoisyClamFileLine(line: string) {
    return /:\s+(OK|Empty file|Symbolic link|Excluded)(?:\.| ERROR)?$/i.test(line) ||
        /^WARNING: File path check failure for:/i.test(line);
}
