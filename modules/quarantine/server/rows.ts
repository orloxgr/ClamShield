import { appStateJson, asRecord, optionalNumber } from "../../../server/core/database/values";
import path from "path";

export function insertQuarantineMapRow(db: any, fileName: string, metadata: any) {
    if (!fileName)
        return;
    const payload = asRecord(metadata);
    db.prepare(`
        INSERT OR REPLACE INTO quarantine_map(
            file_name, base_name, original_path, threat_name, sha256, timestamp, payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(fileName, String(payload.baseName || path.basename(fileName)), String(payload.originalPath || ""), String(payload.threatName || ""), String(payload.sha256 || ""), optionalNumber(payload.timestamp), appStateJson(payload));
}
