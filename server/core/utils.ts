import { englishText } from "../../shared/localization/runtime";
import { dedupePaths } from "../platform/paths";
import { windowsSecuritySoftwareDataDirs, windowsSecuritySoftwareProgramDirs, windowsSecuritySoftwareRootDirs } from "../scanning/exclusions";
import { createHash } from "crypto";
import { createReadStream } from "fs";
import path from "path";
export function formatDuration(totalSeconds: number) {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (hours > 0) {
        return `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
    }
    return `${minutes}:${String(seconds).padStart(2, "0")}`;
}
export function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
export function escapeRegex(value: string) {
    return value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}
export function pathToClamExcludePattern(folderPath: string) {
    const normalized = path.resolve(folderPath).replace(/[\\/]+$/, "");
    // ClamAV uses POSIX regular expressions, which do not support (?:...) groups.
    return `^${escapeRegex(normalized)}([\\\\/]|$)`;
}
export function getWindowsSecuritySoftwareExclusionPaths() {
    if (process.platform !== "win32")
        return [];
    const programData = process.env.PROGRAMDATA || process.env.ProgramData || "C:\\ProgramData";
    const programFiles = process.env.ProgramFiles || process.env.PROGRAMFILES || "C:\\Program Files";
    const programFilesX86 = process.env["ProgramFiles(x86)"] || process.env.PROGRAMFILES_X86 || "C:\\Program Files (x86)";
    const programW6432 = process.env.ProgramW6432 || process.env.PROGRAMW6432 || programFiles;
    const systemDrive = process.env.SystemDrive || process.env.SYSTEMDRIVE || "C:";
    const programRoots = dedupePaths([programFiles, programFilesX86, programW6432].filter(Boolean));
    const paths = [
        ...windowsSecuritySoftwareDataDirs.map(parts => path.join(programData, ...parts)),
        ...programRoots.flatMap(root => windowsSecuritySoftwareProgramDirs.map(parts => path.join(root, ...parts))),
        ...windowsSecuritySoftwareRootDirs.map(parts => path.join(`${systemDrive}\\`, ...parts))
    ];
    return dedupePaths(paths);
}
export function displayFileName(filePath: string) {
    return path.basename(filePath || "").trim() || "Unknown file";
}
export function titleCase(value: string) {
    const normalized = String(value || "").trim();
    return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1).toLowerCase() : "";
}
export async function hashFile(filePath: string, algorithm = "sha256") {
    const hash = createHash(algorithm);
    await new Promise<void>((resolve, reject) => {
        const stream = createReadStream(filePath);
        stream.on("data", chunk => hash.update(chunk));
        stream.on("error", reject);
        stream.on("end", resolve);
    });
    return hash.digest("hex");
}
export function formatBytes(bytes: number) {
    if (bytes >= 1024 * 1024)
        return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
    if (bytes >= 1024)
        return `${Math.round(bytes / 1024)} KB`;
    return `${bytes} B`;
}
export const yaraForgePackages: Record<string, {
    label: string;
    url: string;
    fileName: string;
}> = {
    core: {
        label: englishText("updates.core"),
        url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
        fileName: "yara-rules-core.yar"
    },
    extended: {
        label: englishText("updates.extended"),
        url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
        fileName: "yara-rules-extended.yar"
    },
    full: {
        label: englishText("updates.full"),
        url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip",
        fileName: "yara-rules-full.yar"
    }
};
