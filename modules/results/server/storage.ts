import { englishText } from "../../../shared/localization/runtime";
import { normalizeVirusTotalRefinementFilter } from "../../../addons/virustotal/server/refinement";
import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { asRecord, normalizedStatePath, optionalNumber, parseAppStateJson, runAppStateTransaction } from "../../../server/core/database/values";
import { runtimeState } from "../../../server/core/runtimeState";
import { freshScanEvidence } from "./evidence";
import { getQuarantineMap } from "../../quarantine/server/storage";
import { quarantineFile } from "../../quarantine/server/files";
import { saveQuarantineMap } from "../../quarantine/server/storage";
import { cleanupDuplicateScanResults, cleanupDuplicateScanResultsForPath, insertScanResultRow } from "./rows";
import { randomBytes } from "crypto";
import { existsSync } from "fs";
import path from "path";
export function scanResultSelectSql() {
    return `SELECT id, timestamp, original_path, threat_name, engine, source, scan_type, target,
                   yara_ruleset, md5, sha1, sha256, virus_total_checks,
                   virus_total_refinement_status, virus_total_refinement_label,
                   virus_total_refinement_severity, virus_total_refinement_message,
                   virus_total_refinement_checked_at, virus_total_refinement_stats,
                   virus_total_refinement_report, results_reminder_at, payload
            FROM scan_results`;
}
export function getScanResultFindingSource(result: any) {
    const threatName = String(result?.threatName || result?.threat_name || "");
    const engine = String(result?.engine || "");
    if (/^yara:/i.test(threatName) || engine.toLowerCase() === "yara")
        return "YARA";
    if (/securiteinfo\.com(?:[._-]|$)/i.test(threatName) || /^securiteinfo[._-]/i.test(threatName))
        return "SecuriteInfo";
    if (/^sanesecurity[._-]/i.test(threatName))
        return "SaneSecurity";
    return "ClamAV";
}
export function scanResultFindingSourceSql() {
    return `
        CASE
            WHEN LOWER(COALESCE(engine, '')) = 'yara' OR LOWER(COALESCE(threat_name, '')) LIKE 'yara:%' THEN 'YARA'
            WHEN INSTR(LOWER(COALESCE(threat_name, '')), 'securiteinfo.com') > 0
                 OR LOWER(COALESCE(threat_name, '')) LIKE 'securiteinfo.%'
                 OR LOWER(COALESCE(threat_name, '')) LIKE 'securiteinfo_%'
                 OR LOWER(COALESCE(threat_name, '')) LIKE 'securiteinfo-%' THEN 'SecuriteInfo'
            WHEN LOWER(COALESCE(threat_name, '')) LIKE 'sanesecurity.%'
                 OR LOWER(COALESCE(threat_name, '')) LIKE 'sanesecurity_%'
                 OR LOWER(COALESCE(threat_name, '')) LIKE 'sanesecurity-%' THEN 'SaneSecurity'
            ELSE 'ClamAV'
        END
    `;
}
export function mapScanResultRow(row: any) {
    const payload = asRecord(parseAppStateJson(row.payload, {}));
    const virusTotalChecks = asRecord(parseAppStateJson(row.virus_total_checks, {}));
    const refinementStatus = String(row.virus_total_refinement_status || "").trim();
    const refinementStats = asRecord(parseAppStateJson(row.virus_total_refinement_stats, {}));
    const refinementReport = asRecord(parseAppStateJson(row.virus_total_refinement_report, {}));
    const virusTotalRefinement = refinementStatus ? {
        status: refinementStatus,
        label: row.virus_total_refinement_label || "",
        severity: row.virus_total_refinement_severity || "",
        message: row.virus_total_refinement_message || "",
        checkedAt: row.virus_total_refinement_checked_at === null || row.virus_total_refinement_checked_at === undefined
            ? null
            : Number(row.virus_total_refinement_checked_at),
        stats: Object.keys(refinementStats).length > 0 ? refinementStats : null,
        report: Object.keys(refinementReport).length > 0 ? refinementReport : null
    } : null;
    const threatName = row.threat_name || payload.threatName;
    const engine = row.engine || payload.engine;
    return {
        ...payload,
        id: row.id,
        timestamp: Number(row.timestamp || payload.timestamp || 0),
        originalPath: row.original_path || payload.originalPath,
        threatName,
        engine,
        findingSource: getScanResultFindingSource({ threatName, engine }),
        source: row.source || payload.source,
        scanType: row.scan_type || payload.scanType,
        target: row.target || payload.target,
        yaraRuleset: row.yara_ruleset || payload.yaraRuleset,
        md5: row.md5 || payload.md5,
        sha1: row.sha1 || payload.sha1,
        sha256: row.sha256 || payload.sha256,
        resultsReminderAt: row.results_reminder_at === null || row.results_reminder_at === undefined
            ? Number(payload.resultsReminderAt || 0)
            : Number(row.results_reminder_at || 0),
        virusTotalChecks: Object.keys(virusTotalChecks).length > 0 ? virusTotalChecks : payload.virusTotalChecks,
        virusTotalRefinement
    };
}
export async function getScanResults() {
    await ensureAppStateReady();
    const rows = getAppStateDb().prepare(`${scanResultSelectSql()} ORDER BY timestamp DESC`).all();
    return rows.map(mapScanResultRow);
}
export async function getScanResultByOriginalPath(originalPath: string) {
    await ensureAppStateReady();
    const normalizedPath = normalizedStatePath(originalPath);
    if (!normalizedPath)
        return null;
    const row = getAppStateDb()
        .prepare(`${scanResultSelectSql()} WHERE normalized_path = ? ORDER BY timestamp DESC, id DESC LIMIT 1`)
        .get(normalizedPath);
    return row ? mapScanResultRow(row) : null;
}
export function addScanResultDateClause(clauses: string[], params: any[], date: any) {
    const dateValue = String(date || "").trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(dateValue)) {
        const start = new Date(`${dateValue}T00:00:00`).getTime();
        const end = new Date(`${dateValue}T23:59:59.999`).getTime();
        if (Number.isFinite(start) && Number.isFinite(end)) {
            clauses.push("timestamp >= ? AND timestamp <= ?");
            params.push(start, end);
        }
    }
}
export async function getScanResultFindingSourceOptions(options: {
    date?: string;
}) {
    await ensureAppStateReady();
    const clauses: string[] = [];
    const params: any[] = [];
    addScanResultDateClause(clauses, params, options.date);
    const whereSql = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
    const rows = getAppStateDb().prepare(`
        SELECT DISTINCT ${scanResultFindingSourceSql()} AS finding_source
        FROM scan_results${whereSql}
        ORDER BY finding_source COLLATE NOCASE
    `).all(...params);
    return rows
        .map((row: any) => String(row.finding_source || "").trim())
        .filter(Boolean);
}
export async function getScanResultsPage(options: {
    limit?: number | null;
    offset?: number;
    date?: string;
    findingSource?: string;
    virusTotalRefinement?: string;
}) {
    await ensureAppStateReady();
    const clauses: string[] = [];
    const params: any[] = [];
    addScanResultDateClause(clauses, params, options.date);
    const findingSourceValue = String(options.findingSource || "").trim();
    if (findingSourceValue && findingSourceValue.toLowerCase() !== "all") {
        clauses.push(`${scanResultFindingSourceSql()} = ?`);
        params.push(findingSourceValue);
    }
    const refinementFilter = normalizeVirusTotalRefinementFilter(options.virusTotalRefinement);
    if (refinementFilter !== "all") {
        if (refinementFilter === "unrefined") {
            clauses.push("(virus_total_refinement_status IS NULL OR virus_total_refinement_status = '')");
        }
        else if (refinementFilter === "upload_required") {
            clauses.push("(virus_total_refinement_status = 'upload_required' OR (virus_total_refinement_status = 'unknown' AND COALESCE(json_extract(virus_total_checks, '$.resultsUploadedUnknownHash'), '') = ''))");
        }
        else if (refinementFilter === "awaiting_analysis") {
            clauses.push("(virus_total_refinement_status = 'awaiting_analysis' OR (virus_total_refinement_status = 'unknown' AND COALESCE(json_extract(virus_total_checks, '$.resultsUploadedUnknownHash'), '') != ''))");
        }
        else if (refinementFilter === "blocked") {
            clauses.push("virus_total_refinement_status IN ('blocked', 'error')");
        }
        else {
            clauses.push("virus_total_refinement_status = ?");
            params.push(refinementFilter);
        }
    }
    const whereSql = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
    const db = getAppStateDb();
    const safeOffset = Math.max(0, Math.floor(Number(options.offset || 0)));
    const limit = options.limit === null || options.limit === undefined
        ? null
        : Math.max(1, Math.min(500, Math.floor(Number(options.limit) || 50)));
    const total = Number(db.prepare(`SELECT COUNT(*) AS count FROM scan_results${whereSql}`).get(...params)?.count || 0);
    const sql = `${scanResultSelectSql()}${whereSql} ORDER BY timestamp DESC${limit ? " LIMIT ? OFFSET ?" : ""}`;
    const rows = limit
        ? db.prepare(sql).all(...params, limit, safeOffset)
        : db.prepare(sql).all(...params);
    return { items: rows.map(mapScanResultRow), total };
}
export function scanFailedFileSelectSql() {
    return `SELECT id, timestamp, job_id, source, scan_type, target, batch_number, exit_code,
                   original_path, normalized_path, reason, status, retry_count, last_retry_at, payload
            FROM scan_failed_files`;
}
export function mapScanFailedFileRow(row: any) {
    const payload = asRecord(parseAppStateJson(row.payload, {}));
    return {
        ...payload,
        id: row.id,
        timestamp: Number(row.timestamp || payload.timestamp || 0),
        jobId: row.job_id || payload.jobId,
        source: row.source || payload.source,
        scanType: row.scan_type || payload.scanType,
        target: row.target || payload.target,
        batchNumber: row.batch_number === null || row.batch_number === undefined ? payload.batchNumber : Number(row.batch_number),
        exitCode: row.exit_code === null || row.exit_code === undefined ? payload.exitCode : Number(row.exit_code),
        originalPath: row.original_path || payload.originalPath,
        normalizedPath: row.normalized_path || payload.normalizedPath,
        reason: row.reason || payload.reason,
        status: row.status || payload.status || "pending",
        retryCount: row.retry_count === null || row.retry_count === undefined ? Number(payload.retryCount || 0) : Number(row.retry_count),
        lastRetryAt: row.last_retry_at === null || row.last_retry_at === undefined ? payload.lastRetryAt : Number(row.last_retry_at)
    };
}
export async function getScanFailedFilesPage(options: {
    limit?: number | null;
    offset?: number;
    status?: string;
}) {
    await ensureAppStateReady();
    const clauses: string[] = [];
    const params: any[] = [];
    const status = String(options.status || "pending").trim().toLowerCase();
    if (status && status !== "all") {
        clauses.push("status = ?");
        params.push(status);
    }
    const whereSql = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
    const db = getAppStateDb();
    const total = Number(db.prepare(`SELECT COUNT(*) AS count FROM scan_failed_files${whereSql}`).get(...params)?.count || 0);
    const safeOffset = Math.max(0, Math.floor(Number(options.offset || 0)));
    const limit = options.limit === null || options.limit === undefined
        ? null
        : Math.max(1, Math.min(500, Math.floor(Number(options.limit) || 100)));
    const sql = `${scanFailedFileSelectSql()}${whereSql} ORDER BY timestamp DESC${limit ? " LIMIT ? OFFSET ?" : ""}`;
    const rows = limit
        ? db.prepare(sql).all(...params, limit, safeOffset)
        : db.prepare(sql).all(...params);
    return { items: rows.map(mapScanFailedFileRow), total };
}
export async function saveScanResults(results: any[]) {
    await ensureAppStateReady();
    const deduped = new Map<string, any>();
    for (const result of [...results].sort((a: any, b: any) => Number(b.timestamp || 0) - Number(a.timestamp || 0))) {
        const key = normalizedStatePath(result.originalPath || "");
        const mapKey = key || String(result.id || randomBytes(4).toString("hex"));
        if (!deduped.has(mapKey))
            deduped.set(mapKey, result);
    }
    const sortedResults = Array.from(deduped.values()).sort((a: any, b: any) => Number(b.timestamp || 0) - Number(a.timestamp || 0));
    const db = getAppStateDb();
    runAppStateTransaction(db, () => {
        db.prepare("DELETE FROM scan_results").run();
        sortedResults.forEach((result, index) => insertScanResultRow(db, result, index));
        cleanupDuplicateScanResults(db);
    });
    if (runtimeState.scanResultsChangedHandler) {
        Promise.resolve(runtimeState.scanResultsChangedHandler()).catch(e => console.warn(englishText("backend.results.failed_to_notify_scan_results_change"), e));
    }
}
export async function getResultsReminderState() {
    await ensureAppStateReady();
    const rows = getAppStateDb().prepare("SELECT key, value FROM results_reminder").all();
    const state = { remindUntil: 0, forgottenUntil: 0 };
    for (const row of rows) {
        if (row.key === "remindUntil" || row.key === "forgottenUntil") {
            state[row.key] = Number(row.value || 0);
        }
    }
    return state;
}
export async function getResultsReminderSummary() {
    await ensureAppStateReady();
    const row = getAppStateDb().prepare(`
        SELECT COUNT(*) AS count, MAX(results_reminder_at) AS latestTimestamp
        FROM scan_results
        WHERE LOWER(COALESCE(source, '')) = 'shield'
          AND COALESCE(results_reminder_at, 0) > 0
    `).get();
    return {
        count: Number(row?.count || 0),
        latestTimestamp: Number(row?.latestTimestamp || 0)
    };
}
export async function saveResultsReminderState(state: any) {
    await ensureAppStateReady();
    const db = getAppStateDb();
    const upsert = db.prepare("INSERT OR REPLACE INTO results_reminder(key, value) VALUES (?, ?)");
    runAppStateTransaction(db, () => {
        upsert.run("remindUntil", optionalNumber(state?.remindUntil) || 0);
        upsert.run("forgottenUntil", optionalNumber(state?.forgottenUntil) || 0);
    });
    if (runtimeState.scanResultsChangedHandler) {
        Promise.resolve(runtimeState.scanResultsChangedHandler()).catch(e => console.warn(englishText("backend.results.failed_to_notify_results_reminder_change"), e));
    }
}
export async function addScanResult(result: any) {
    const rawOriginalPath = String(result?.originalPath || "").trim();
    if (!rawOriginalPath)
        throw new Error(englishText("backend.results.scan_result_is_missing_the_original_path"));
    const originalPath = path.resolve(rawOriginalPath);
    const source = String(result.source || "").toLowerCase();
    const existing = await getScanResultByOriginalPath(originalPath);
    const timestamp = Date.now();
    const nextResult = existing
        ? {
            ...existing,
            ...freshScanEvidence(result, existing),
            ...result,
            id: existing.id,
            originalPath,
            timestamp,
            resultsReminderAt: source === "shield" ? timestamp : existing.resultsReminderAt || 0
        }
        : {
            id: timestamp.toString() + randomBytes(4).toString("hex"),
            timestamp,
            resultsReminderAt: source === "shield" ? timestamp : 0,
            ...result,
            originalPath
        };
    await ensureAppStateReady();
    const db = getAppStateDb();
    runAppStateTransaction(db, () => {
        insertScanResultRow(db, nextResult, 0);
        cleanupDuplicateScanResultsForPath(db, normalizedStatePath(originalPath));
    });
    if (runtimeState.scanResultsChangedHandler) {
        Promise.resolve(runtimeState.scanResultsChangedHandler()).catch(e => console.warn(englishText("backend.results.failed_to_notify_scan_results_change"), e));
    }
}
export async function removeScanResult(resultId: string) {
    const results = await getScanResults();
    const index = results.findIndex((item: any) => item.id === resultId);
    if (index === -1) {
        throw new Error(englishText("backend.results.result_not_found"));
    }
    const [item] = results.splice(index, 1);
    await saveScanResults(results);
    return item;
}
export async function quarantineResultItem(settings: any, result: any) {
    if (!result.originalPath || !existsSync(result.originalPath)) {
        throw new Error(englishText("backend.results.original_file_is_no_longer_available"));
    }
    const qMap = await getQuarantineMap();
    const quarantined = await quarantineFile(result.originalPath, result.threatName || "Unknown Threat", settings.quarantineDir);
    qMap[quarantined.fileName] = quarantined.metadata;
    await saveQuarantineMap(qMap);
    return quarantined;
}
