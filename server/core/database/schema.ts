import { englishText } from "../../../shared/localization/runtime";
import { appStateDbPath, nodeRequire } from "../paths";
import { runtimeState } from "../runtimeState";
import { asRecord, optionalNumber, parseAppStateJson, runAppStateTransaction } from "./values";
import { mkdirSync } from "fs";
import path from "path";
export function getAppStateDb() {
    if (runtimeState.appStateDb)
        return runtimeState.appStateDb;
    mkdirSync(path.dirname(appStateDbPath), { recursive: true });
    const { DatabaseSync } = nodeRequire("node:sqlite");
    runtimeState.appStateDb = new DatabaseSync(appStateDbPath);
    runtimeState.appStateDb.exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        CREATE TABLE IF NOT EXISTS migrations (
            name TEXT PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS history (
            id TEXT PRIMARY KEY,
            date TEXT NOT NULL,
            type TEXT,
            target TEXT,
            result INTEGER,
            threats_found INTEGER,
            scanned_files INTEGER,
            duration INTEGER,
            action_taken TEXT,
            payload TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_history_date ON history(date);
        CREATE INDEX IF NOT EXISTS idx_history_type_date ON history(type, date);
        CREATE INDEX IF NOT EXISTS idx_history_threats_date ON history(threats_found, date);
        CREATE TABLE IF NOT EXISTS exceptions (
            normalized_path TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            added_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_exceptions_path ON exceptions(path);
        CREATE TABLE IF NOT EXISTS exception_reports (
            normalized_path TEXT PRIMARY KEY,
            original_path TEXT NOT NULL,
            threat_name TEXT,
            engine TEXT,
            source TEXT,
            yara_ruleset TEXT,
            sha256 TEXT,
            detected_at INTEGER,
            added_at INTEGER,
            false_positive_opened_at INTEGER,
            false_positive_last_opened_at INTEGER,
            false_positive_channels TEXT,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS quarantine_map (
            file_name TEXT PRIMARY KEY,
            base_name TEXT,
            original_path TEXT,
            threat_name TEXT,
            sha256 TEXT,
            timestamp INTEGER,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_results (
            id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            original_path TEXT,
            normalized_path TEXT,
            threat_name TEXT,
            engine TEXT,
            source TEXT,
            scan_type TEXT,
            target TEXT,
            yara_ruleset TEXT,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            virus_total_checks TEXT,
            virus_total_refinement_status TEXT,
            virus_total_refinement_label TEXT,
            virus_total_refinement_severity TEXT,
            virus_total_refinement_message TEXT,
            virus_total_refinement_checked_at INTEGER,
            virus_total_refinement_stats TEXT,
            virus_total_refinement_report TEXT,
            results_reminder_at INTEGER,
            payload TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp);
        CREATE INDEX IF NOT EXISTS idx_scan_results_normalized_path ON scan_results(normalized_path);
        CREATE INDEX IF NOT EXISTS idx_scan_results_vt_refinement_status ON scan_results(virus_total_refinement_status);
        CREATE TABLE IF NOT EXISTS scan_failed_files (
            id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            job_id TEXT,
            source TEXT,
            scan_type TEXT,
            target TEXT,
            batch_number INTEGER,
            exit_code INTEGER,
            original_path TEXT,
            normalized_path TEXT,
            reason TEXT,
            status TEXT NOT NULL,
            retry_count INTEGER NOT NULL DEFAULT 0,
            last_retry_at INTEGER,
            payload TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scan_failed_files_status ON scan_failed_files(status, timestamp);
        CREATE INDEX IF NOT EXISTS idx_scan_failed_files_normalized_path ON scan_failed_files(normalized_path);
        CREATE TABLE IF NOT EXISTS results_reminder (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS virus_total_usage (
            period TEXT PRIMARY KEY,
            count INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
    `);
    addAppStateColumnIfMissing(runtimeState.appStateDb, "exceptions", "kind", "TEXT NOT NULL DEFAULT 'unknown'");
    addAppStateColumnIfMissing(runtimeState.appStateDb, "exceptions", "origin", "TEXT NOT NULL DEFAULT 'unknown'");
    return runtimeState.appStateDb;
}
export function addAppStateColumnIfMissing(db: any, tableName: string, columnName: string, definition: string) {
    const columns = new Set(db.prepare(`PRAGMA table_info(${tableName})`).all().map((row: any) => String(row.name)));
    if (!columns.has(columnName)) {
        db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
    }
}
export function hasAppStateColumn(db: any, tableName: string, columnName: string) {
    return db.prepare(`PRAGMA table_info(${tableName})`)
        .all()
        .some((row: any) => String(row.name) === columnName);
}
export function migrateScanResultsVirusTotalRefinementSchema(db: any) {
    addAppStateColumnIfMissing(db, "scan_results", "virus_total_refinement_status", "TEXT");
    addAppStateColumnIfMissing(db, "scan_results", "virus_total_refinement_label", "TEXT");
    addAppStateColumnIfMissing(db, "scan_results", "virus_total_refinement_severity", "TEXT");
    addAppStateColumnIfMissing(db, "scan_results", "virus_total_refinement_message", "TEXT");
    addAppStateColumnIfMissing(db, "scan_results", "virus_total_refinement_checked_at", "INTEGER");
    addAppStateColumnIfMissing(db, "scan_results", "virus_total_refinement_stats", "TEXT");
    addAppStateColumnIfMissing(db, "scan_results", "virus_total_refinement_report", "TEXT");
    db.exec("CREATE INDEX IF NOT EXISTS idx_scan_results_vt_refinement_status ON scan_results(virus_total_refinement_status)");
}
export function migrateScanResultsReminderSchema(db: any) {
    addAppStateColumnIfMissing(db, "scan_results", "results_reminder_at", "INTEGER");
    db.exec("CREATE INDEX IF NOT EXISTS idx_scan_results_source_reminder ON scan_results(source, results_reminder_at)");
    const rows = db.prepare("SELECT id, payload FROM scan_results WHERE results_reminder_at IS NULL").all();
    const update = db.prepare("UPDATE scan_results SET results_reminder_at = ? WHERE id = ?");
    runAppStateTransaction(db, () => {
        for (const row of rows) {
            const payload = asRecord(parseAppStateJson(row.payload, {}));
            update.run(optionalNumber(payload.resultsReminderAt) || 0, row.id);
        }
    });
}
export function ensureScanResultsReminderSchema(db: any) {
    if (!hasAppStateColumn(db, "scan_results", "results_reminder_at")) {
        migrateScanResultsReminderSchema(db);
        return;
    }
    db.exec("CREATE INDEX IF NOT EXISTS idx_scan_results_source_reminder ON scan_results(source, results_reminder_at)");
}
export function migrateHistorySummarySchema(db: any) {
    db.exec(`
        CREATE INDEX IF NOT EXISTS idx_history_type_date ON history(type, date);
        CREATE INDEX IF NOT EXISTS idx_history_threats_date ON history(threats_found, date);
    `);
}
export function assertScanResultsVirusTotalRefinementSchema(db: any) {
    const columns = new Set(db.prepare("PRAGMA table_info(scan_results)").all().map((row: any) => String(row.name)));
    const required = [
        "virus_total_refinement_status",
        "virus_total_refinement_label",
        "virus_total_refinement_severity",
        "virus_total_refinement_message",
        "virus_total_refinement_checked_at",
        "virus_total_refinement_stats",
        "virus_total_refinement_report"
    ];
    const missing = required.filter(column => !columns.has(column));
    if (missing.length > 0) {
        throw new Error(englishText("backend.core.app_state_schema_migration_incomplete_missing_scan_results_column", {
            value1: String(missing.join(", "))
        }));
    }
}
export function assertScanResultsReminderSchema(db: any) {
    if (!hasAppStateColumn(db, "scan_results", "results_reminder_at")) {
        throw new Error(englishText("backend.core.app_state_schema_migration_incomplete_missing_scan_results_column_ba681ff"));
    }
}
