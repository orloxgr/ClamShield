import { asRecord, normalizedStatePath, parseAppStateJson, runAppStateTransaction } from "../../../server/core/database/values";

export type ShieldVirusTotalTask = {
    filePath: string; queuedAt: number; notBefore?: number; uploadedHash?: string;
    pendingUploadHash?: string; forceCloudCheck?: boolean; analysisId?: string;
    blockedReason?: "analysis" | "upload" | "file";
    message?: string; sha256?: string; recheckHash?: boolean;
};

// Operational cloud tasks belong here, never in the malware findings table.
export class ShieldVirusTotalQueue extends Map<string, ShieldVirusTotalTask> {
    constructor(private db: any) {
        super();
        db.exec(`CREATE TABLE IF NOT EXISTS vt_shield_tasks (
            normalized_path TEXT PRIMARY KEY, payload TEXT NOT NULL
        ); CREATE TABLE IF NOT EXISTS vt_shield_legacy_results (
            id TEXT PRIMARY KEY, payload TEXT NOT NULL
        );`);
        this.recoverLegacyResults();
        for (const row of db.prepare("SELECT normalized_path, payload FROM vt_shield_tasks").all()) {
            const task = parseAppStateJson(row.payload, null);
            if (typeof task?.filePath === "string" && task.filePath) super.set(row.normalized_path, task);
        }
    }
    override set(key: string, task: ShieldVirusTotalTask) {
        this.db.prepare("INSERT OR REPLACE INTO vt_shield_tasks VALUES (?, ?)").run(key, JSON.stringify(task));
        return super.set(key, task);
    }
    override delete(key: string) {
        this.db.prepare("DELETE FROM vt_shield_tasks WHERE normalized_path = ?").run(key);
        return super.delete(key);
    }
    override clear() {
        this.db.prepare("DELETE FROM vt_shield_tasks").run();
        super.clear();
    }
    private recoverLegacyResults() {
        const rows = this.db.prepare(`SELECT * FROM scan_results WHERE LOWER(engine) = 'virustotal'
            AND LOWER(source) = 'shield' AND threat_name IN
            ('VirusTotal analysis requires review', 'VirusTotal check requires review')`).all();
        runAppStateTransaction(this.db, () => {
            for (const row of rows) {
                const report = asRecord(parseAppStateJson(row.virus_total_refinement_report, {}));
                const stats = asRecord(parseAppStateJson(row.virus_total_refinement_stats, report.stats || {}));
                const payload = asRecord(parseAppStateJson(row.payload, {}));
                // Preserve any independently recorded positive evidence.
                if (Number(stats?.malicious || 0) > 0 || Number(stats?.suspicious || 0) > 0
                    || Number(report?.stats?.malicious || 0) > 0 || Number(report?.stats?.suspicious || 0) > 0
                    || payload?.detections?.length) continue;
                const checks = asRecord(parseAppStateJson(row.virus_total_checks, {}));
                const key = normalizedStatePath(row.original_path);
                if (!key) continue;
                const analysis = row.threat_name === 'VirusTotal analysis requires review';
                const task: ShieldVirusTotalTask = {
                    filePath: row.original_path, queuedAt: Number(row.timestamp), sha256: row.sha256 || "",
                    uploadedHash: checks.resultsUploadedUnknownHash || "",
                    analysisId: checks.resultsUploadAnalysisId || "", forceCloudCheck: true,
                    blockedReason: analysis ? "analysis" : "file"
                };
                this.db.prepare("INSERT OR IGNORE INTO vt_shield_tasks VALUES (?, ?)").run(key, JSON.stringify(task));
                // Retain the complete old record for recovery/audit, outside findings.
                this.db.prepare("INSERT OR IGNORE INTO vt_shield_legacy_results VALUES (?, ?)").run(row.id, JSON.stringify(row));
                this.db.prepare("DELETE FROM scan_results WHERE id = ?").run(row.id);
            }
        });
    }
}
