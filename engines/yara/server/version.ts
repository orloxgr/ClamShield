import { englishText } from "../../../shared/localization/runtime";
import { extractBareVersion, getRememberedYaraEngineVersion } from "../../../modules/updates/server/versions";
import { runtimeState } from "../../../server/core/runtimeState";
import { runHiddenProcess } from "../../../server/platform/processes";
import { ensureYaraRuntime } from "./install";
import { existsSync } from "fs";
import fs from "fs/promises";
export async function getCurrentYaraEngineVersion(settings: any) {
    if (!settings.yaraPath || !existsSync(settings.yaraPath))
        return "Not installed";
    try {
        await ensureYaraRuntime(settings.yaraPath);
        const stat = await fs.stat(settings.yaraPath);
        const now = Date.now();
        if (runtimeState.yaraVersionCache &&
            runtimeState.yaraVersionCache.path === settings.yaraPath &&
            runtimeState.yaraVersionCache.mtimeMs === stat.mtimeMs &&
            runtimeState.yaraVersionCache.expiresAt > now) {
            return runtimeState.yaraVersionCache.value;
        }
        const result = await runHiddenProcess(settings.yaraPath, ["--version"], { timeoutMs: 10000 });
        const output = `${result.stdout}\n${result.stderr}`.trim();
        const firstLine = output.split(/\r?\n/).map(line => line.trim()).find(Boolean) || "";
        const value = extractBareVersion(output) || getRememberedYaraEngineVersion(settings) || firstLine || "Version unavailable";
        runtimeState.yaraVersionCache = {
            path: settings.yaraPath,
            mtimeMs: stat.mtimeMs,
            value,
            expiresAt: now + 5 * 60 * 1000
        };
        return value;
    }
    catch (e: any) {
        console.warn(englishText("backend.yara.could_not_read_yara_engine_version"), e?.message || e);
        return getRememberedYaraEngineVersion(settings) || "Version unavailable";
    }
}
