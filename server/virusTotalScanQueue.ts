import path from "node:path";
import { virusTotalWarningFileThreshold } from "./virusTotalLimitWarning";

type FileRecord = { filePath: string; size: number; mtimeMs: number };
type Fingerprint = { size: number; mtimeMs: number };
type QueueDependencies = {
    keyId: string;
    fingerprint: (filePath: string) => Promise<Fingerprint | null>;
    hash: (filePath: string) => Promise<string>;
    lookup: (hash: string) => Promise<any>;
    upload: (filePath: string, hash: string, canContinue: () => Promise<boolean>) => Promise<string>;
    analysis: (analysisId: string, hash: string) => Promise<any | null>;
    excluded: (filePath: string) => Promise<boolean>;
    detection: (item: any, report: any) => Promise<void>;
};

// Persist file paths on disk: a full scan may enqueue millions of files.
export class VirusTotalScanQueue {
    constructor(private db: any, private now = Date.now) {
        db.exec(`
            CREATE TABLE IF NOT EXISTS vt_scan_jobs (
                job_id TEXT PRIMARY KEY, scan_type TEXT NOT NULL, target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active', enumerated INTEGER NOT NULL DEFAULT 0,
                total INTEGER NOT NULL DEFAULT 0, checked INTEGER NOT NULL DEFAULT 0,
                detections INTEGER NOT NULL DEFAULT 0, unknown INTEGER NOT NULL DEFAULT 0,
                skipped INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL, last_checked_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS vt_scan_files (
                id INTEGER PRIMARY KEY, job_id TEXT NOT NULL, normalized_path TEXT NOT NULL,
                file_path TEXT NOT NULL, size INTEGER NOT NULL, mtime_ms INTEGER NOT NULL,
                sha256 TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
                UNIQUE(job_id, normalized_path)
            );
            CREATE INDEX IF NOT EXISTS idx_vt_scan_pending ON vt_scan_files(status, job_id, id);
            CREATE TABLE IF NOT EXISTS vt_scan_reports (
                job_id TEXT NOT NULL, sha256 TEXT NOT NULL, report TEXT NOT NULL, checked_at INTEGER NOT NULL,
                PRIMARY KEY(job_id, sha256)
            );
            CREATE TABLE IF NOT EXISTS vt_scan_submissions (
                job_id TEXT NOT NULL, sha256 TEXT NOT NULL, key_id TEXT NOT NULL,
                analysis_id TEXT NOT NULL, next_poll_at INTEGER NOT NULL,
                PRIMARY KEY(job_id, sha256, key_id)
            );
        `);
        const addColumn = (table: string, name: string, definition: string) => {
            if (!db.prepare(`PRAGMA table_info(${table})`).all().some((column: any) => column.name === name)) {
                db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
            }
        };
        addColumn("vt_scan_files", "next_attempt_at", "INTEGER NOT NULL DEFAULT 0");
        addColumn("vt_scan_jobs", "lookup_after", "INTEGER NOT NULL DEFAULT 0");
        addColumn("vt_scan_jobs", "analysing", "INTEGER NOT NULL DEFAULT 0");
        addColumn("vt_scan_jobs", "confirmation_required", "INTEGER NOT NULL DEFAULT 0");
        addColumn("vt_scan_jobs", "confirmation_accepted", "INTEGER NOT NULL DEFAULT 0");
        addColumn("vt_scan_reports", "key_id", "TEXT NOT NULL DEFAULT ''");
        db.exec(`CREATE INDEX IF NOT EXISTS idx_vt_scan_ready ON vt_scan_files(job_id, status, next_attempt_at, id);
            CREATE TABLE IF NOT EXISTS vt_scan_queue_meta (key TEXT PRIMARY KEY);`);
        if (!db.prepare("SELECT 1 FROM vt_scan_queue_meta WHERE key = 'automatic_uploads'").get()) {
            db.exec("BEGIN");
            try {
                // Earlier versions finished missing hashes without uploading. Resume those files too.
                const jobs = db.prepare("SELECT job_id FROM vt_scan_jobs WHERE unknown > 0 AND status != 'cancelled'").all();
                for (const job of jobs) {
                    const reopened = db.prepare(`UPDATE vt_scan_files SET status = 'needs_upload'
                        WHERE job_id = ? AND status = 'checked' AND sha256 IN
                        (SELECT sha256 FROM vt_scan_reports WHERE job_id = ? AND json_extract(report, '$.found') = 0)`)
                        .run(job.job_id, job.job_id).changes;
                    db.prepare(`UPDATE vt_scan_jobs SET checked = checked - ?, unknown = ?,
                        status = CASE WHEN status = 'done' AND ? > 0 THEN 'active' ELSE status END WHERE job_id = ?`)
                        .run(reopened, reopened, reopened, job.job_id);
                }
                db.prepare("INSERT INTO vt_scan_queue_meta VALUES ('automatic_uploads')").run();
                db.exec("COMMIT");
            } catch (error) { db.exec("ROLLBACK"); throw error; }
        }
    }

    recover() {
        this.db.prepare("UPDATE vt_scan_jobs SET status = 'paused', message = 'Resume the interrupted local scan to finish queuing its files.' WHERE status = 'active' AND enumerated = 0").run();
    }

    start(jobId: string, scanType: string, target: string) {
        if (this.get(jobId)?.status === "cancelled") this.db.prepare("DELETE FROM vt_scan_jobs WHERE job_id = ?").run(jobId);
        this.db.prepare(`INSERT INTO vt_scan_jobs(job_id, scan_type, target, created_at)
            VALUES (?, ?, ?, ?) ON CONFLICT(job_id) DO UPDATE SET status = 'active', enumerated = 0, message = ''`)
            .run(jobId, scanType, target, Date.now());
    }

    addFiles(jobId: string, files: FileRecord[]) {
        if (!files.length || this.get(jobId)?.status === "cancelled") return;
        const insert = this.db.prepare(`INSERT OR IGNORE INTO vt_scan_files(job_id, normalized_path, file_path, size, mtime_ms) VALUES (?, ?, ?, ?, ?)`);
        this.db.exec("BEGIN");
        try {
            let added = 0;
            for (const file of files) {
                const normalized = path.resolve(file.filePath).toLowerCase();
                added += Number(insert.run(jobId, normalized, file.filePath, file.size, file.mtimeMs).changes);
            }
            this.db.prepare("UPDATE vt_scan_jobs SET total = total + ? WHERE job_id = ?").run(added, jobId);
            this.db.exec("COMMIT");
        } catch (error) {
            this.db.exec("ROLLBACK");
            throw error;
        }
    }

    finishEnumeration(jobId: string, warnAboutLimits = false) {
        this.db.prepare(`UPDATE vt_scan_jobs SET enumerated = 1,
            confirmation_required = CASE WHEN ? = 1 AND total - checked - skipped > ? AND confirmation_accepted = 0 THEN 1 ELSE 0 END
            WHERE job_id = ?`).run(Number(warnAboutLimits), virusTotalWarningFileThreshold, jobId);
        this.completeIfDone(jobId);
    }

    pendingConfirmation() {
        const row = this.db.prepare(`SELECT job_id FROM vt_scan_jobs WHERE status = 'active' AND enumerated = 1
            AND confirmation_required = 1 ORDER BY created_at LIMIT 1`).get();
        return row ? this.get(row.job_id) : null;
    }

    confirm(jobId: string, proceed: boolean) {
        const job = this.get(jobId);
        if (!job?.requiresConfirmation || job.status !== "active") return false;
        if (!proceed) this.setState(jobId, "cancelled");
        else this.db.prepare("UPDATE vt_scan_jobs SET confirmation_required = 0, confirmation_accepted = 1 WHERE job_id = ?").run(jobId);
        return true;
    }

    disableConfirmations() {
        this.db.prepare("UPDATE vt_scan_jobs SET confirmation_required = 0, confirmation_accepted = 1 WHERE confirmation_required = 1").run();
    }

    setState(jobId: string, state: "active" | "paused" | "cancelled") {
        this.db.prepare("UPDATE vt_scan_jobs SET status = ?, message = '' WHERE job_id = ?").run(state, jobId);
        if (state === "cancelled") {
            this.db.prepare("UPDATE vt_scan_jobs SET unknown = 0, analysing = 0 WHERE job_id = ?").run(jobId);
            this.db.prepare("DELETE FROM vt_scan_files WHERE job_id = ?").run(jobId);
            this.db.prepare("DELETE FROM vt_scan_reports WHERE job_id = ?").run(jobId);
            this.db.prepare("DELETE FROM vt_scan_submissions WHERE job_id = ?").run(jobId);
        }
        if (state === "active") this.completeIfDone(jobId);
    }

    message(jobId: string, message: string) {
        this.db.prepare("UPDATE vt_scan_jobs SET message = ? WHERE job_id = ?").run(message, jobId);
    }

    get(jobId?: string) {
        const row = jobId
            ? this.db.prepare("SELECT * FROM vt_scan_jobs WHERE job_id = ?").get(jobId)
            : this.db.prepare("SELECT * FROM vt_scan_jobs ORDER BY created_at DESC, rowid DESC LIMIT 1").get();
        if (!row) return null;
        return {
            jobId: row.job_id, scanType: row.scan_type, target: row.target, status: row.status,
            enumerated: row.enumerated === 1, total: Number(row.total), checked: Number(row.checked),
            detections: Number(row.detections), unknown: Number(row.unknown), needsUpload: Number(row.unknown),
            analysing: Number(row.analysing), skipped: Number(row.skipped),
            requiresConfirmation: row.confirmation_required === 1,
            pending: row.status === "cancelled" ? 0 : Math.max(0, row.total - row.checked - row.skipped),
            message: row.message
        };
    }

    list() {
        return this.db.prepare(`SELECT job_id FROM vt_scan_jobs WHERE status IN ('active', 'paused')
            OR job_id = (SELECT job_id FROM vt_scan_jobs ORDER BY created_at DESC, rowid DESC LIMIT 1)
            ORDER BY created_at DESC, rowid DESC`).all().map((row: any) => this.get(row.job_id));
    }

    next() {
        const jobs = this.db.prepare(`SELECT * FROM vt_scan_jobs WHERE status = 'active' AND enumerated = 1 AND confirmation_required = 0
            AND total > checked + skipped ORDER BY last_checked_at, created_at`).all();
        for (const job of jobs) {
            // Finish contributed files even when ordinary hash lookups have exhausted their quota.
            for (const status of ["analysing", "needs_upload", "pending"]) {
                if (status === "pending" && job.lookup_after > this.now()) continue;
                const item = this.db.prepare(`SELECT * FROM vt_scan_files WHERE job_id = ? AND status = ?
                    AND next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT 1`).get(job.job_id, status, this.now());
                if (item) return { ...item, scan_type: job.scan_type, target: job.target };
            }
        }
        return undefined;
    }

    nextWakeAt(): number | null {
        let earliest = Infinity;
        const jobs = this.db.prepare("SELECT job_id, lookup_after FROM vt_scan_jobs WHERE status = 'active' AND enumerated = 1 AND confirmation_required = 0 AND total > checked + skipped").all();
        for (const job of jobs) {
            for (const status of ["pending", "needs_upload", "analysing"]) {
                const row = this.db.prepare(`SELECT next_attempt_at FROM vt_scan_files WHERE job_id = ? AND status = ?
                    ORDER BY next_attempt_at, id LIMIT 1`).get(job.job_id, status);
                if (row) earliest = Math.min(earliest, Math.max(Number(row.next_attempt_at), status === "pending" ? Number(job.lookup_after) : 0));
            }
        }
        return Number.isFinite(earliest) ? earliest : null;
    }

    wakeLookups() {
        this.db.prepare("UPDATE vt_scan_jobs SET lookup_after = 0").run();
        this.db.prepare("UPDATE vt_scan_files SET next_attempt_at = 0 WHERE status = 'needs_upload'").run();
    }

    retry(item: any, error: any) {
        const when = Number(error?.nextAllowedAt) || this.now() + (error?.status === 429 ? 15 * 60_000 : 60_000);
        if (error?.localQuotaLimit) {
            this.db.prepare("UPDATE vt_scan_jobs SET lookup_after = ?").run(when);
            if (item.status !== "pending") this.db.prepare("UPDATE vt_scan_files SET next_attempt_at = ? WHERE id = ?").run(when, item.id);
        } else {
            this.db.prepare("UPDATE vt_scan_files SET next_attempt_at = ? WHERE id = ?").run(when, item.id);
        }
        this.db.prepare("UPDATE vt_scan_jobs SET message = ?, last_checked_at = ? WHERE job_id = ? AND status != 'cancelled'")
            .run(error?.message || "Cloud check failed; waiting to retry.", this.now(), item.job_id);
    }

    private completeIfDone(jobId: string) {
        this.db.prepare(`UPDATE vt_scan_jobs SET status = 'done' WHERE job_id = ?
            AND status = 'active' AND enumerated = 1 AND total = checked + skipped`).run(jobId);
    }

    private transition(item: any, outcome: "pending" | "needs_upload" | "analysing" | "checked" | "skipped", when = 0, detections = 0, message = "") {
        this.db.exec("BEGIN");
        try {
            const old = this.db.prepare("SELECT status FROM vt_scan_files WHERE id = ?").get(item.id);
            if (old && !["checked", "skipped"].includes(old.status)) {
                this.db.prepare("UPDATE vt_scan_files SET status = ?, next_attempt_at = ? WHERE id = ?").run(outcome, when, item.id);
                this.db.prepare(`UPDATE vt_scan_jobs SET checked = checked + ?, skipped = skipped + ?,
                    detections = detections + ?, unknown = unknown + ?, analysing = analysing + ?,
                    message = ?, last_checked_at = ? WHERE job_id = ?`)
                    .run(Number(outcome === "checked"), Number(outcome === "skipped"), Number(detections > 0),
                        Number(outcome === "needs_upload") - Number(old.status === "needs_upload"),
                        Number(outcome === "analysing") - Number(old.status === "analysing"), message, this.now(), item.job_id);
                this.completeIfDone(item.job_id);
            }
            this.db.exec("COMMIT");
        } catch (error) {
            this.db.exec("ROLLBACK");
            throw error;
        }
    }

    private saveReport(item: any, hash: string, report: any, keyId: string) {
        this.db.prepare(`INSERT INTO vt_scan_reports(job_id, sha256, report, checked_at, key_id) VALUES (?, ?, ?, ?, ?) ON CONFLICT(job_id, sha256)
            DO UPDATE SET report = excluded.report, checked_at = excluded.checked_at, key_id = excluded.key_id`)
            .run(item.job_id, hash, JSON.stringify(report), this.now(), keyId);
    }

    async processNext(deps: QueueDependencies, item = this.next()): Promise<boolean> {
        if (!item) return false;
        const currentJob = this.get(item.job_id);
        if (currentJob?.status !== "active" || currentJob.requiresConfirmation) return true;
        if (await deps.excluded(item.file_path)) {
            this.transition(item, "skipped", 0, 0, "Skipped an excluded file.");
            return true;
        }
        const before = await deps.fingerprint(item.file_path);
        if (!before) {
            this.transition(item, "skipped", 0, 0, `File unavailable: ${item.file_path}`);
            return true;
        }
        let sha256 = item.sha256;
        if (!sha256 || before.size !== item.size || before.mtimeMs !== item.mtime_ms) {
            try {
                sha256 = await deps.hash(item.file_path);
            } catch {
                this.transition(item, "skipped", 0, 0, `Could not read: ${item.file_path}`);
                return true;
            }
            this.db.prepare("UPDATE vt_scan_files SET sha256 = ?, size = ?, mtime_ms = ? WHERE id = ?")
                .run(sha256, before.size, before.mtimeMs, item.id);
            if (item.status !== "pending") {
                this.transition(item, "pending");
                return true;
            }
        }
        const hashed = await deps.fingerprint(item.file_path);
        if (!hashed || hashed.size !== before.size || hashed.mtimeMs !== before.mtimeMs) {
            this.transition(item, "skipped", 0, 0, `File changed while hashing: ${item.file_path}`);
            return true;
        }
        const cached = this.db.prepare("SELECT report, key_id FROM vt_scan_reports WHERE job_id = ? AND sha256 = ? AND checked_at > ?")
            .get(item.job_id, sha256, this.now() - 24 * 60 * 60 * 1000);
        if (this.get(item.job_id)?.status !== "active") return true;
        let report = cached ? JSON.parse(cached.report) : null;
        if (report?.found === false && cached.key_id && cached.key_id !== deps.keyId) {
            this.db.prepare("DELETE FROM vt_scan_reports WHERE job_id = ? AND sha256 = ?").run(item.job_id, sha256);
            this.transition(item, "pending");
            return true;
        }
        const submission = this.db.prepare("SELECT * FROM vt_scan_submissions WHERE job_id = ? AND sha256 = ? AND key_id = ?")
            .get(item.job_id, sha256, deps.keyId);
        if (!report?.found) {
            if (submission) {
                if (submission.next_poll_at > this.now()) {
                    this.transition(item, "analysing", submission.next_poll_at);
                    return true;
                }
                try {
                    report = await deps.analysis(submission.analysis_id, sha256);
                } catch (error: any) {
                    if (error?.fileError) {
                        this.transition(item, "skipped", 0, 0, error.message);
                        return true;
                    }
                    if (!error?.analysisMissing) throw error;
                    this.db.prepare("DELETE FROM vt_scan_submissions WHERE job_id = ? AND sha256 = ? AND key_id = ?").run(item.job_id, sha256, deps.keyId);
                    this.db.prepare("DELETE FROM vt_scan_reports WHERE job_id = ? AND sha256 = ?").run(item.job_id, sha256);
                    this.transition(item, "pending");
                    return true;
                }
                if (this.get(item.job_id)?.status === "cancelled") return true;
                if (!report) {
                    const nextPoll = this.now() + 60_000;
                    this.db.prepare("UPDATE vt_scan_submissions SET next_poll_at = ? WHERE job_id = ? AND sha256 = ? AND key_id = ?")
                        .run(nextPoll, item.job_id, sha256, deps.keyId);
                    this.transition(item, "analysing", nextPoll, 0, "Waiting for VirusTotal analysis.");
                    return true;
                }
                this.saveReport(item, sha256, report, deps.keyId);
            } else if (item.status === "analysing") {
                // An analysis belongs to the key that contributed it. Recheck after a key change.
                this.db.prepare("DELETE FROM vt_scan_reports WHERE job_id = ? AND sha256 = ? AND json_extract(report, '$.found') = 0").run(item.job_id, sha256);
                this.transition(item, "pending");
                return true;
            } else if (item.status === "needs_upload") {
                if (before.size > 650 * 1024 * 1024) {
                    this.transition(item, "skipped", 0, 0, `Upload skipped: ${item.file_path} exceeds VirusTotal's 650 MB upload limit.`);
                    return true;
                }
                const canContinue = async () => {
                    const current = await deps.fingerprint(item.file_path);
                    return this.get(item.job_id)?.status === "active" && !(await deps.excluded(item.file_path)) &&
                        current?.size === before.size && current?.mtimeMs === before.mtimeMs;
                };
                let analysisId: string;
                try {
                    analysisId = await deps.upload(item.file_path, sha256, canContinue);
                } catch (error: any) {
                    if (this.get(item.job_id)?.status !== "active") return true;
                    if (error?.fileError || !(await canContinue())) {
                        this.transition(item, "skipped", 0, 0, error?.message || "File changed or was excluded before upload.");
                        return true;
                    }
                    throw error;
                }
                if (this.get(item.job_id)?.status === "cancelled") return true;
                if (!analysisId) throw new Error("VirusTotal did not return an analysis ID; upload will retry.");
                const nextPoll = this.now() + 60_000;
                this.db.prepare("INSERT INTO vt_scan_submissions VALUES (?, ?, ?, ?, ?)")
                    .run(item.job_id, sha256, deps.keyId, analysisId, nextPoll);
                this.transition(item, "analysing", nextPoll, 0, "Waiting for VirusTotal analysis.");
                return true;
            } else {
                if (!report) {
                    report = await deps.lookup(sha256);
                    if (this.get(item.job_id)?.status === "cancelled") return true;
                    this.saveReport(item, sha256, report, deps.keyId);
                }
                if (report?.found === false) {
                    this.transition(item, "needs_upload");
                    return true;
                }
            }
        }
        // A stop/pause may arrive while a lookup is in flight. Keep pending work for resume.
        if (this.get(item.job_id)?.status !== "active") return true;
        const after = await deps.fingerprint(item.file_path);
        if (!after || after.size !== before.size || after.mtimeMs !== before.mtimeMs) {
            this.transition(item, "skipped", 0, 0, `File changed during cloud check: ${item.file_path}`);
            return true;
        }
        const detections = Number(report?.stats?.malicious || 0) + Number(report?.stats?.suspicious || 0);
        if (await deps.excluded(item.file_path)) {
            this.transition(item, "skipped", 0, 0, "Skipped a newly excluded file.");
            return true;
        }
        if (detections > 0) await deps.detection(item, report);
        this.transition(item, "checked", 0, detections);
        return true;
    }
}
