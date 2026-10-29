import { englishText } from "../../../shared/localization/runtime";
import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { asRecord, parseAppStateJson, runAppStateTransaction } from "../../../server/core/database/values";
import { normalizedStatePath } from '../../../server/core/database/values';
import { insertExceptionRow, insertExceptionReportRow } from '../../exceptions/server/rows';
import { insertHistoryRow } from '../../history/server/rows';
import { moveFileWithoutOverwrite } from './files';
import { insertQuarantineMapRow } from "./rows";
import fs from "fs/promises";
import path from "path";
export async function saveQuarantineMap(map: Record<string, any>) {
    await ensureAppStateReady();
    const db = getAppStateDb();
    runAppStateTransaction(db, () => {
        db.prepare("DELETE FROM quarantine_map").run();
        for (const [fileName, metadata] of Object.entries(asRecord(map))) {
            insertQuarantineMapRow(db, fileName, metadata);
        }
    });
}
export async function getQuarantineItems(quarantineDir: string) {
    try {
        const files = await fs.readdir(quarantineDir);
        const qMap = await getQuarantineMap();
        const items = await Promise.all(files.map(async (file) => {
            const stat = await fs.stat(path.join(quarantineDir, file));
            let meta = qMap[file];
            if (!meta) {
                const baseMatch = file.match(/^(.*?)(?:\.\d{3})?$/);
                if (baseMatch && qMap[baseMatch[1]]) {
                    meta = qMap[baseMatch[1]];
                }
            }
            const timestamp = Number(meta?.timestamp) || stat.mtimeMs;
            return {
                id: file,
                fileName: file,
                threatName: meta ? meta.threatName : "Unknown Threat",
                originalPath: meta ? meta.originalPath : "Unknown",
                size: stat.size,
                timestamp,
                date: new Date(timestamp).toISOString()
            };
        }));
        return items.sort((a, b) => b.timestamp - a.timestamp);
    }
    catch {
        return [];
    }
}
export async function getQuarantineCount(quarantineDir: string) {
    try {
        return (await fs.readdir(quarantineDir)).length;
    }
    catch {
        return 0;
    }
}
export async function restoreQuarantinedFileAndAddException(settings: any, fileName: string) {
    const safeName = path.basename(fileName);
    if (safeName !== fileName || ['.', '..'].includes(fileName) || /[<>:"/\\|?*\u0000-\u001f]/.test(fileName)) {
        throw new Error(englishText("backend.quarantine.invalid_quarantine_item"));
    }
    const qMap = await getQuarantineMap();
    const metadata = Object.hasOwn(qMap, safeName) ? qMap[safeName] : null;
    const originalPath = metadata?.originalPath;
    if (!originalPath || originalPath === "Unknown" || !path.isAbsolute(originalPath)) {
        throw new Error(englishText("backend.quarantine.original_file_location_is_unknown"));
    }
    const quarantinePath = path.join(settings.quarantineDir, safeName);
    await fs.mkdir(path.dirname(originalPath), { recursive: true });
    let sha256: string;
    try { sha256 = await moveFileWithoutOverwrite(quarantinePath, originalPath, metadata.sha256 || undefined); }
    catch (error: any) {
        if (error?.code === 'EEXIST') throw new Error(englishText('backend.quarantine.a_file_already_exists_at_the_original_location_restore_manually_f'));
        throw error;
    }
    try {
        const db = getAppStateDb(), normalizedPath = normalizedStatePath(originalPath), now = Date.now();
        runAppStateTransaction(db, () => {
            if (!db.prepare('SELECT normalized_path FROM exceptions WHERE normalized_path = ?').get(normalizedPath))
                insertExceptionRow(db, originalPath, now, { kind: 'file', origin: 'quarantine-restore' });
            insertExceptionReportRow(db, normalizedPath, { originalPath, threatName: metadata.threatName || 'Unknown Threat', engine: metadata.engine || 'ClamAV', source: 'quarantine-restore', addedFrom: 'quarantine', sha256, detectedAt: metadata.timestamp || now, addedAt: now });
            db.prepare('DELETE FROM quarantine_map WHERE file_name = ?').run(safeName);
            insertHistoryRow(db, { type: 'quarantine-restore', target: originalPath, result: 0, threatsFound: 0, scannedFiles: 0, duration: 0, actionTaken: englishText('backend.quarantine.restored_and_added_to_exceptions') });
        });
    } catch (error) {
        try { await moveFileWithoutOverwrite(originalPath, quarantinePath, sha256); }
        catch (rollback) { throw new AggregateError([error, rollback], `Restore metadata failed. File recovery needs attention: ${originalPath}; ${quarantinePath}`); }
        throw error;
    }
    return { restoredPath: originalPath };
}

export async function getQuarantineMap() {
    await ensureAppStateReady();
    const rows = getAppStateDb().prepare("SELECT file_name, payload FROM quarantine_map").all();
    const map: Record<string, any> = {};
    for (const row of rows) {
        map[row.file_name] = asRecord(parseAppStateJson(row.payload, {}));
    }
    return map;
}
