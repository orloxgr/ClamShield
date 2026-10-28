import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { appStateJson, asRecord, normalizedStatePath, optionalNumber, runAppStateTransaction } from "../../../server/core/database/values";
import { randomBytes } from "crypto";

export function insertScanResultRow(db: any, result: any, fallbackIndex = 0) {
    const payload = asRecord(result);
    const timestamp = optionalNumber(payload.timestamp) || Date.now();
    const id = String(payload.id || `${timestamp}-${fallbackIndex}-${randomBytes(3).toString("hex")}`);
    const originalPath = String(payload.originalPath || "");
    const virusTotalRefinement = asRecord(payload.virusTotalRefinement);
    const resultsReminderAt = optionalNumber(payload.resultsReminderAt) || 0;
    db.prepare(`
        INSERT OR REPLACE INTO scan_results(
            id, timestamp, original_path, normalized_path, threat_name, engine, source, scan_type,
            target, yara_ruleset, md5, sha1, sha256, virus_total_checks,
            virus_total_refinement_status, virus_total_refinement_label, virus_total_refinement_severity,
            virus_total_refinement_message, virus_total_refinement_checked_at, virus_total_refinement_stats,
            virus_total_refinement_report, results_reminder_at, payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, timestamp, originalPath, normalizedStatePath(originalPath), String(payload.threatName || ""), String(payload.engine || ""), String(payload.source || ""), String(payload.scanType || ""), String(payload.target || ""), String(payload.yaraRuleset || ""), String(payload.md5 || ""), String(payload.sha1 || ""), String(payload.sha256 || ""), appStateJson(asRecord(payload.virusTotalChecks)), String(virusTotalRefinement.status || ""), String(virusTotalRefinement.label || ""), String(virusTotalRefinement.severity || ""), String(virusTotalRefinement.message || ""), optionalNumber(virusTotalRefinement.checkedAt), appStateJson(asRecord(virusTotalRefinement.stats)), appStateJson(asRecord(virusTotalRefinement.report)), resultsReminderAt, appStateJson({ ...payload, id, timestamp, resultsReminderAt }));
}

export function insertScanFailedFileRow(db: any, failure: any, fallbackIndex = 0) {
    const payload = asRecord(failure);
    const timestamp = optionalNumber(payload.timestamp) || Date.now();
    const originalPath = String(payload.originalPath || "");
    const normalizedPath = normalizedStatePath(originalPath);
    if (!originalPath || !normalizedPath)
        return;
    const id = String(payload.id || `${timestamp}-${fallbackIndex}-${randomBytes(3).toString("hex")}`);
    db.prepare(`
        INSERT INTO scan_failed_files(
            id, timestamp, job_id, source, scan_type, target, batch_number, exit_code,
            original_path, normalized_path, reason, status, retry_count, last_retry_at, payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            timestamp = excluded.timestamp,
            job_id = excluded.job_id,
            source = excluded.source,
            scan_type = excluded.scan_type,
            target = excluded.target,
            batch_number = excluded.batch_number,
            exit_code = excluded.exit_code,
            original_path = excluded.original_path,
            normalized_path = excluded.normalized_path,
            reason = excluded.reason,
            status = excluded.status,
            payload = excluded.payload
    `).run(id, timestamp, String(payload.jobId || ""), String(payload.source || ""), String(payload.scanType || ""), String(payload.target || ""), optionalNumber(payload.batchNumber), optionalNumber(payload.exitCode), originalPath, normalizedPath, String(payload.reason || ""), String(payload.status || "pending"), optionalNumber(payload.retryCount) || 0, optionalNumber(payload.lastRetryAt), appStateJson({ ...payload, id, timestamp, originalPath, normalizedPath, status: payload.status || "pending" }));
}

export async function addScanFailedFiles(failures: any[]) {
    const rows = failures.map(asRecord).filter(row => String(row.originalPath || "").trim());
    if (rows.length === 0)
        return 0;
    await ensureAppStateReady();
    const db = getAppStateDb();
    let inserted = 0;
    runAppStateTransaction(db, () => {
        const clearExisting = db.prepare(`
            DELETE FROM scan_failed_files
            WHERE normalized_path = ?
              AND status = 'pending'
        `);
        rows.forEach((failure, index) => {
            clearExisting.run(normalizedStatePath(String(failure.originalPath || "")));
            insertScanFailedFileRow(db, failure, index);
            inserted++;
        });
    });
    return inserted;
}

export function cleanupDuplicateScanResults(db: any) {
    db.prepare(`
        DELETE FROM scan_results
        WHERE normalized_path <> ''
          AND rowid NOT IN (
            SELECT rowid FROM (
              SELECT rowid,
                     ROW_NUMBER() OVER (
                       PARTITION BY normalized_path
                       ORDER BY timestamp DESC, id DESC
                     ) AS rn
              FROM scan_results
              WHERE normalized_path <> ''
            )
            WHERE rn = 1
          )
    `).run();
}

export function cleanupDuplicateScanResultsForPath(db: any, normalizedPath: string) {
    if (!normalizedPath)
        return;
    db.prepare(`
        DELETE FROM scan_results
        WHERE normalized_path = ?
          AND rowid NOT IN (
            SELECT rowid
            FROM scan_results
            WHERE normalized_path = ?
            ORDER BY timestamp DESC, id DESC
            LIMIT 1
          )
    `).run(normalizedPath, normalizedPath);
}
