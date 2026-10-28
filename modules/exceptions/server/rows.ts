import { appStateJson, asRecord, normalizedStatePath, optionalNumber } from "../../../server/core/database/values";
import { statSync } from "fs";

export function insertExceptionRow(db: any, exceptionPath: any, addedAt = Date.now(), metadata: any = {}) {
    metadata = metadata || {};
    const value = String(exceptionPath || "");
    const normalizedPath = normalizedStatePath(value);
    if (!value || !normalizedPath)
        return;
    let kind = metadata.kind || "unknown";
    if (kind === "unknown") {
        try {
            const stat = statSync(value);
            kind = stat.isDirectory() ? "folder" : stat.isFile() ? "file" : "unknown";
        }
        catch { }
    }
    db.prepare(`INSERT OR REPLACE INTO exceptions(normalized_path, path, added_at, kind, origin) VALUES (?, ?, ?, ?, ?)`)
        .run(normalizedPath, value, addedAt, kind, metadata.origin || "unknown");
}

export function insertExceptionReportRow(db: any, normalizedPath: string, report: any) {
    const payload = asRecord(report);
    const originalPath = String(payload.originalPath || normalizedPath);
    const key = normalizedPath || normalizedStatePath(originalPath);
    if (!key)
        return;
    db.prepare(`
        INSERT OR REPLACE INTO exception_reports(
            normalized_path, original_path, threat_name, engine, source, yara_ruleset, sha256,
            detected_at, added_at, false_positive_opened_at, false_positive_last_opened_at,
            false_positive_channels, payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(key, originalPath, String(payload.threatName || ""), String(payload.engine || ""), String(payload.source || ""), String(payload.yaraRuleset || ""), String(payload.sha256 || ""), optionalNumber(payload.detectedAt), optionalNumber(payload.addedAt), optionalNumber(payload.falsePositiveOpenedAt), optionalNumber(payload.falsePositiveLastOpenedAt), appStateJson(asRecord(payload.falsePositiveChannels)), appStateJson({ ...payload, originalPath }));
}
