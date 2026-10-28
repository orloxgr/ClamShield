import { englishText } from "../../../shared/localization/runtime";
import { runtimeState } from "../../../server/core/runtimeState";
import { runHiddenProcess } from "../../../server/platform/processes";
import fs from "fs/promises";
export function parseClamAVVersionOutput(output: string) {
    const firstLine = output
        .split(/\r\n|\n|\r/g)
        .map(line => line.trim())
        .find(Boolean) || "";
    const versionMatch = firstLine.match(/\bClamAV\s+([^\s/]+)/i);
    return versionMatch ? `ClamAV ${versionMatch[1]}` : firstLine;
}
export async function getClamAVEngineVersion(settings: any, hasEngine: boolean) {
    if (runtimeState.isSimulated)
        return "Simulated mode";
    if (!hasEngine)
        return "Not installed";
    try {
        const stat = await fs.stat(settings.clamscanPath);
        const now = Date.now();
        if (runtimeState.clamAVVersionCache &&
            runtimeState.clamAVVersionCache.path === settings.clamscanPath &&
            runtimeState.clamAVVersionCache.mtimeMs === stat.mtimeMs &&
            runtimeState.clamAVVersionCache.expiresAt > now) {
            return runtimeState.clamAVVersionCache.value;
        }
        const result = await runHiddenProcess(settings.clamscanPath, ["--version"], { timeoutMs: 10000 });
        const parsedVersion = parseClamAVVersionOutput(`${result.stdout}\n${result.stderr}`);
        const value = parsedVersion || "Version unavailable";
        runtimeState.clamAVVersionCache = {
            path: settings.clamscanPath,
            mtimeMs: stat.mtimeMs,
            value,
            expiresAt: now + 5 * 60 * 1000
        };
        return value;
    }
    catch (e: any) {
        console.warn(englishText("backend.clamav.could_not_read_clamav_engine_version"), e?.message || e);
        return "Version unavailable";
    }
}
