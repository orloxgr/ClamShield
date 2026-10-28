import { englishText } from "../../shared/localization/runtime";
import { ShieldCacheEntry } from "../../modules/shield/server/types";
import { ScanProgress } from "./types";
import fs from "fs/promises";
export async function getFileFingerprint(filePath: string): Promise<ShieldCacheEntry | null> {
    try {
        const stat = await fs.stat(filePath);
        if (!stat.isFile())
            return null;
        return {
            size: stat.size,
            mtimeMs: Math.trunc(stat.mtimeMs),
            scannedAt: Date.now()
        };
    }
    catch {
        return null;
    }
}
export async function getScanFileRecords(filePaths: string[]) {
    const records: Array<{
        filePath: string;
        size: number;
        mtimeMs: number;
    }> = [];
    for (const filePath of filePaths) {
        const fingerprint = await getFileFingerprint(filePath);
        records.push({
            filePath,
            size: fingerprint?.size || 0,
            mtimeMs: fingerprint?.mtimeMs || 0
        });
    }
    return records;
}
export function scanSessionRowToProgress(row: any): ScanProgress | null {
    if (!row)
        return null;
    return {
        jobId: row.job_id,
        type: row.type,
        target: row.target,
        status: row.status,
        phase: row.phase,
        totalFiles: Number(row.total_files || 0),
        scannedFiles: Number(row.scanned_files || 0),
        currentFile: row.current_file || "",
        startedAt: Number(row.started_at || Date.now()),
        updatedAt: Number(row.updated_at || Date.now()),
        completedAt: row.completed_at ? Number(row.completed_at) : undefined,
        threatsFound: Number(row.threats_found || 0),
        errorsFound: Number(row.errors_found || 0),
        result: row.result === null || row.result === undefined ? undefined : Number(row.result),
        actionTaken: row.action_taken || englishText("backend.yara.none"),
        elapsedSeconds: Math.max(0, Math.floor((Date.now() - Number(row.started_at || Date.now())) / 1000)),
        quietSeconds: Math.max(0, Math.floor((Date.now() - Number(row.updated_at || Date.now())) / 1000))
    };
}
export function canResumeScanType(type: string) {
    return type === "disk" || type === "folder" || type === "file";
}
export function fileRecordMatches(row: any, fingerprint: ShieldCacheEntry | null) {
    return !!fingerprint &&
        Number(row.size || 0) === fingerprint.size &&
        Number(row.mtime_ms || 0) === fingerprint.mtimeMs;
}
export function cacheEntryMatches(current: ShieldCacheEntry | null, cached?: ShieldCacheEntry) {
    return !!current && !!cached && current.size === cached.size && current.mtimeMs === cached.mtimeMs;
}
export async function pathExists(filePath?: string) {
    if (!filePath)
        return false;
    try {
        await fs.access(filePath);
        return true;
    }
    catch {
        return false;
    }
}
