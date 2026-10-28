import { appStateJson, asRecord, optionalNumber } from "../../../server/core/database/values";
import { randomBytes } from "crypto";

export function insertHistoryRow(db: any, entry: any, fallbackIndex = 0) {
    const payload = asRecord(entry);
    const date = String(payload.date || new Date(optionalNumber(payload.timestamp) || Date.now()).toISOString());
    const id = String(payload.id || `${Date.parse(date) || Date.now()}-${fallbackIndex}-${randomBytes(3).toString("hex")}`);
    db.prepare(`
        INSERT OR REPLACE INTO history(
            id, date, type, target, result, threats_found, scanned_files, duration, action_taken, payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, date, String(payload.type || ""), String(payload.target || ""), optionalNumber(payload.result), optionalNumber(payload.threatsFound), optionalNumber(payload.scannedFiles), optionalNumber(payload.duration), String(payload.actionTaken || ""), appStateJson({ ...payload, id, date }));
}
