import { englishText } from "../../../shared/localization/runtime";
import { nodeRequire } from "../../../server/core/paths";
import { ScanProgress } from "../../../server/scanning/types";
import { normalizeCachePath } from "../../shield/server/cache";
import { mkdirSync } from "fs";
import path from "path";
export class ScanSessionStore {
    private db: any;
    private upsertStmt: any;
    private insertFileStmt: any;
    private markFileDoneStmt: any;
    private markFilePendingStmt: any;
    private countFilesStmt: any;
    private pendingFilesPageStmt: any;
    private claimFileStmt: any;
    private countDoneFilesStmt: any;
    constructor(dbPath: string) {
        mkdirSync(path.dirname(dbPath), { recursive: true });
        const { DatabaseSync } = nodeRequire("node:sqlite");
        this.db = new DatabaseSync(dbPath);
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS scan_sessions (
                job_id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                total_files INTEGER NOT NULL,
                scanned_files INTEGER NOT NULL,
                current_file TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                completed_at INTEGER,
                threats_found INTEGER NOT NULL,
                errors_found INTEGER NOT NULL,
                result INTEGER,
                action_taken TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_session_files (
                job_id TEXT NOT NULL,
                file_index INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                normalized_path TEXT NOT NULL,
                status TEXT NOT NULL,
                size INTEGER NOT NULL DEFAULT 0,
                mtime_ms INTEGER NOT NULL DEFAULT 0,
                scanned_at INTEGER,
                PRIMARY KEY (job_id, normalized_path)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_sessions_updated_at ON scan_sessions(updated_at);
            CREATE INDEX IF NOT EXISTS idx_scan_session_files_status ON scan_session_files(job_id, status, file_index);
        `);
        this.upsertStmt = this.db.prepare(`
            INSERT INTO scan_sessions (
                job_id, type, target, status, phase, total_files, scanned_files,
                current_file, started_at, updated_at, completed_at, threats_found,
                errors_found, result, action_taken
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                type = excluded.type,
                target = excluded.target,
                status = excluded.status,
                phase = excluded.phase,
                total_files = excluded.total_files,
                scanned_files = excluded.scanned_files,
                current_file = excluded.current_file,
                updated_at = excluded.updated_at,
                completed_at = excluded.completed_at,
                threats_found = excluded.threats_found,
                errors_found = excluded.errors_found,
                result = excluded.result,
                action_taken = excluded.action_taken
        `);
        this.insertFileStmt = this.db.prepare(`
            INSERT INTO scan_session_files (
                job_id, file_index, file_path, normalized_path, status, size, mtime_ms, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id, normalized_path) DO UPDATE SET
                file_index = excluded.file_index,
                file_path = excluded.file_path,
                status = excluded.status,
                size = excluded.size,
                mtime_ms = excluded.mtime_ms,
                scanned_at = excluded.scanned_at
        `);
        this.markFileDoneStmt = this.db.prepare(`
            UPDATE scan_session_files
            SET status = 'done', size = ?, mtime_ms = ?, scanned_at = ?
            WHERE job_id = ? AND normalized_path = ?
        `);
        this.markFilePendingStmt = this.db.prepare(`
            UPDATE scan_session_files
            SET status = 'pending', size = ?, mtime_ms = ?, scanned_at = NULL
            WHERE job_id = ? AND normalized_path = ?
        `);
        this.countFilesStmt = this.db.prepare("SELECT COUNT(*) AS count FROM scan_session_files WHERE job_id = ?");
        this.countDoneFilesStmt = this.db.prepare("SELECT COUNT(*) AS count FROM scan_session_files WHERE job_id = ? AND status = 'done'");
        this.pendingFilesPageStmt = this.db.prepare(`
            SELECT file_index, file_path, size, mtime_ms
            FROM scan_session_files
            WHERE job_id = ? AND status = 'pending'
            ORDER BY file_index ASC
            LIMIT ?
        `);
        this.claimFileStmt = this.db.prepare(`
            UPDATE scan_session_files
            SET status = 'scanning'
            WHERE job_id = ? AND normalized_path = ? AND status = 'pending'
        `);
    }
    save(progress: ScanProgress) {
        this.upsertStmt.run(progress.jobId, progress.type, progress.target, progress.status, progress.phase, progress.totalFiles, progress.scannedFiles, progress.currentFile || "", progress.startedAt, progress.updatedAt, progress.completedAt || null, progress.threatsFound, progress.errorsFound, progress.result ?? null, progress.actionTaken || "None");
    }
    saveFiles(jobId: string, files: Array<{
        filePath: string;
        size: number;
        mtimeMs: number;
    }>) {
        this.db.exec("BEGIN");
        try {
            this.db.prepare("DELETE FROM scan_session_files WHERE job_id = ?").run(jobId);
            this.insertFiles(jobId, files, 0);
            this.db.exec("COMMIT");
        }
        catch (e) {
            this.db.exec("ROLLBACK");
            throw e;
        }
    }
    insertFiles(jobId: string, files: Array<{
        filePath: string;
        size: number;
        mtimeMs: number;
    }>, startIndex: number) {
        files.forEach((file, offset) => {
            this.insertFileStmt.run(jobId, startIndex + offset, file.filePath, normalizeCachePath(file.filePath), "pending", file.size, file.mtimeMs, null);
        });
    }
    appendFiles(jobId: string, files: Array<{
        filePath: string;
        size: number;
        mtimeMs: number;
    }>, startIndex: number) {
        if (files.length === 0)
            return;
        this.db.exec("BEGIN");
        try {
            this.insertFiles(jobId, files, startIndex);
            this.db.exec("COMMIT");
        }
        catch (e) {
            this.db.exec("ROLLBACK");
            throw e;
        }
    }
    countFiles(jobId: string) {
        const row = this.countFilesStmt.get(jobId);
        return Number(row?.count || 0);
    }
    countDoneFiles(jobId: string) {
        const row = this.countDoneFilesStmt.get(jobId);
        return Number(row?.count || 0);
    }
    getLatestResumable() {
        return this.db.prepare(`
            SELECT *
            FROM scan_sessions
            WHERE status IN ('running', 'paused', 'error')
              AND type IN ('disk', 'folder', 'file')
            ORDER BY updated_at DESC
            LIMIT 1
        `).get();
    }
    getSession(jobId: string) {
        return this.db.prepare("SELECT * FROM scan_sessions WHERE job_id = ?").get(jobId);
    }
    getFiles(jobId: string) {
        return this.db.prepare(`
            SELECT *
            FROM scan_session_files
            WHERE job_id = ?
            ORDER BY file_index ASC
        `).all(jobId);
    }
    getFilesPage(jobId: string, afterIndex = -1, limit = 1000) {
        return this.db.prepare(`SELECT file_index, file_path, size, mtime_ms FROM scan_session_files
            WHERE job_id = ? AND file_index > ? ORDER BY file_index LIMIT ?`)
            .all(jobId, afterIndex, limit);
    }
    getPendingFilesPage(jobId: string, limit: number) {
        return this.pendingFilesPageStmt.all(jobId, Math.max(1, Math.floor(limit))).map((row: any) => ({
            filePath: row.file_path,
            size: Number(row.size || 0),
            mtimeMs: Number(row.mtime_ms || 0)
        }));
    }
    claimPendingFilesPage(jobId: string, limit: number) {
        const rows = this.pendingFilesPageStmt.all(jobId, Math.max(1, Math.floor(limit)));
        if (rows.length === 0)
            return [];
        const claimed: Array<{
            filePath: string;
            size: number;
            mtimeMs: number;
        }> = [];
        this.db.exec("BEGIN");
        try {
            for (const row of rows) {
                const normalizedPath = normalizeCachePath(row.file_path);
                const result = this.claimFileStmt.run(jobId, normalizedPath);
                if (!result?.changes)
                    continue;
                claimed.push({
                    filePath: row.file_path,
                    size: Number(row.size || 0),
                    mtimeMs: Number(row.mtime_ms || 0)
                });
            }
            this.db.exec("COMMIT");
            return claimed;
        }
        catch (e) {
            this.db.exec("ROLLBACK");
            throw e;
        }
    }
    resetInProgress(jobId: string) {
        this.db.prepare("UPDATE scan_session_files SET status = 'pending', scanned_at = NULL WHERE job_id = ? AND status = 'scanning'")
            .run(jobId);
    }
    markFilesDone(jobId: string, files: Array<{
        filePath: string;
        size: number;
        mtimeMs: number;
    }>) {
        this.db.exec("BEGIN");
        try {
            const scannedAt = Date.now();
            for (const file of files) {
                this.markFileDoneStmt.run(file.size, file.mtimeMs, scannedAt, jobId, normalizeCachePath(file.filePath));
            }
            this.db.exec("COMMIT");
        }
        catch (e) {
            this.db.exec("ROLLBACK");
            throw e;
        }
    }
    markFilePending(jobId: string, filePath: string, size: number, mtimeMs: number) {
        this.markFilePendingStmt.run(size, mtimeMs, jobId, normalizeCachePath(filePath));
    }
    markDiscarded(jobId: string, phase = "Discarded") {
        this.db.prepare("UPDATE scan_sessions SET status = 'discarded', phase = ?, updated_at = ? WHERE job_id = ?")
            .run(phase, Date.now(), jobId);
    }
    deleteFilesForJobPage(jobId: string, limit = 10000) {
        const result = this.db.prepare(`
            DELETE FROM scan_session_files
            WHERE rowid IN (
                SELECT rowid
                FROM scan_session_files
                WHERE job_id = ?
                LIMIT ?
            )
        `).run(jobId, Math.max(1, Math.floor(limit)));
        return Number(result?.changes || 0);
    }
    deleteFilesForJob(jobId: string) {
        let totalDeleted = 0;
        while (true) {
            const deleted = this.deleteFilesForJobPage(jobId, 50000);
            totalDeleted += deleted;
            if (deleted === 0)
                return totalDeleted;
        }
    }
    discard(jobId: string) {
        this.markDiscarded(jobId);
        this.deleteFilesForJob(jobId);
    }
    resetInterruptedRunningSessions() {
        const now = Date.now();
        try {
            this.db.exec("BEGIN");
            const resetInProgress = this.db.prepare(`
                UPDATE scan_session_files
                SET status = 'pending', scanned_at = NULL
                WHERE status = 'scanning'
                  AND job_id IN (
                    SELECT job_id
                    FROM scan_sessions
                    WHERE status = 'running'
                      AND type IN ('disk', 'folder', 'file')
                  )
            `).run();
            const paused = this.db.prepare(`
                UPDATE scan_sessions
                SET status = 'paused',
                    phase = 'Interrupted when ClamShield closed',
                    current_file = 'Paused',
                    updated_at = ?,
                    result = -1,
                    action_taken = 'Interrupted when ClamShield closed'
                WHERE status = 'running'
                  AND type IN ('disk', 'folder', 'file')
            `).run(now);
            const completed = this.db.prepare(`
                UPDATE scan_sessions
                SET status = 'done',
                    phase = 'Interrupted when ClamShield closed',
                    current_file = 'Interrupted',
                    updated_at = ?,
                    completed_at = ?,
                    result = -1,
                    action_taken = 'Interrupted when ClamShield closed'
                WHERE status = 'running'
                  AND type NOT IN ('disk', 'folder', 'file')
            `).run(now, now);
            this.db.exec("COMMIT");
            return {
                paused: Number(paused?.changes || 0),
                completed: Number(completed?.changes || 0),
                resetFiles: Number(resetInProgress?.changes || 0)
            };
        }
        catch (e) {
            try {
                this.db.exec("ROLLBACK");
            }
            catch { }
            throw e;
        }
    }
    compactCompletedFileLists() {
        try {
            const latestResumable = this.db.prepare(`
                SELECT job_id
                FROM scan_sessions
                WHERE status IN ('running', 'paused', 'error')
                  AND type IN ('disk', 'folder', 'file')
                ORDER BY updated_at DESC
                LIMIT 1
            `).get();
            const retainedJobId = String(latestResumable?.job_id || "");
            this.db.exec("BEGIN");
            this.db.prepare(`
                DELETE FROM scan_session_files
                WHERE job_id IN (
                    SELECT job_id
                    FROM scan_sessions
                    WHERE status NOT IN ('running', 'paused', 'error')
                       OR (
                            status IN ('running', 'paused', 'error')
                            AND type IN ('disk', 'folder', 'file')
                            AND job_id <> ?
                       )
                )
            `).run(retainedJobId);
            this.db.prepare(`
                UPDATE scan_sessions
                SET status = 'discarded',
                    phase = 'Superseded interrupted scan',
                    updated_at = ?
                WHERE status IN ('running', 'paused', 'error')
                  AND type IN ('disk', 'folder', 'file')
                  AND job_id <> ?
            `).run(Date.now(), retainedJobId);
            this.db.exec("COMMIT");
        }
        catch (e: any) {
            try {
                this.db.exec("ROLLBACK");
            }
            catch { }
            console.warn(englishText("backend.on_demand.failed_to_compact_completed_scan_file_lists"), e?.message || e);
        }
    }
}
export function createInitialScanProgress(jobId: string, type: string, target: string): ScanProgress {
    const now = Date.now();
    return {
        jobId,
        type,
        target,
        status: "running",
        phase: englishText("backend.on_demand.starting"),
        totalFiles: 0,
        scannedFiles: 0,
        currentFile: "",
        startedAt: now,
        updatedAt: now,
        threatsFound: 0,
        errorsFound: 0,
        actionTaken: englishText("backend.yara.none"),
        elapsedSeconds: 0,
        quietSeconds: 0
    };
}
