import { englishText } from "../../shared/localization/runtime";
import { normalizePositiveNumber } from "../../modules/settings/server/validation";
import { defaultLogsDir } from "./paths";
import fs from "fs/promises";
import path from "path";
export async function cleanupOldLogs(settings: any) {
    const retentionDays = normalizePositiveNumber(settings.logRetentionDays, 7, 1, 365);
    const logsDir = settings.logsDir || defaultLogsDir;
    const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
    try {
        await fs.mkdir(logsDir, { recursive: true });
        const entries = await fs.readdir(logsDir, { withFileTypes: true });
        await Promise.all(entries
            .filter(entry => entry.isFile() && entry.name.toLowerCase().endsWith(".log"))
            .map(async (entry) => {
            const logPath = path.join(logsDir, entry.name);
            try {
                const stat = await fs.stat(logPath);
                if (stat.mtimeMs < cutoff) {
                    await fs.unlink(logPath);
                }
            }
            catch (e) {
                console.warn(englishText("backend.core.failed_to_apply_log_retention_for"), logPath, e);
            }
        }));
    }
    catch (e) {
        console.warn(englishText("backend.core.failed_to_clean_old_logs"), e);
    }
}
