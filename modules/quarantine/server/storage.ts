import { englishText } from "../../../shared/localization/runtime";
import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { asRecord, parseAppStateJson, runAppStateTransaction } from "../../../server/core/database/values";
import { getExceptions, rememberExceptionDetection, saveExceptions } from "../../exceptions/server/service";

import { addHistory } from "../../history/server/storage";
import { insertQuarantineMapRow } from "./rows";
import { existsSync } from "fs";
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
    if (safeName !== fileName) {
        throw new Error(englishText("backend.quarantine.invalid_quarantine_item"));
    }
    const qMap = await getQuarantineMap();
    const metadata = qMap[safeName];
    const originalPath = metadata?.originalPath;
    if (!originalPath || originalPath === "Unknown") {
        throw new Error(englishText("backend.quarantine.original_file_location_is_unknown"));
    }
    const quarantinePath = path.join(settings.quarantineDir, safeName);
    await fs.access(quarantinePath);
    if (existsSync(originalPath)) {
        throw new Error(englishText("backend.quarantine.a_file_already_exists_at_the_original_location_restore_manually_f"));
    }
    await fs.mkdir(path.dirname(originalPath), { recursive: true });
    try {
        await fs.rename(quarantinePath, originalPath);
    }
    catch {
        await fs.copyFile(quarantinePath, originalPath);
        await fs.unlink(quarantinePath);
    }
    const exceptions = await getExceptions();
    if (!exceptions.includes(originalPath)) {
        exceptions.push(originalPath);
        await saveExceptions(exceptions);
    }
    await rememberExceptionDetection({
        originalPath,
        threatName: metadata?.threatName || "Unknown Threat",
        engine: metadata?.engine || "ClamAV",
        source: "quarantine-restore",
        sha256: metadata?.sha256 || "",
        timestamp: metadata?.timestamp || Date.now()
    });
    delete qMap[safeName];
    await saveQuarantineMap(qMap);
    await addHistory({
        type: "quarantine-restore",
        target: originalPath,
        result: 0,
        threatsFound: 0,
        scannedFiles: 0,
        duration: 0,
        actionTaken: englishText("backend.quarantine.restored_and_added_to_exceptions")
    });
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
