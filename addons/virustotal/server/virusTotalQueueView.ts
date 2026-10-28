export type QueueRuntime = {
  enabled: boolean; configured: boolean; now?: number;
  activeResultsId?: string; activeScanId?: number;
  activeResultsPhase?: string;
  resultsNextAt?: number; shieldNextAt?: number; scanNextAt?: number; lookupNextAt?: number;
  resultsWaitReason?: string; shieldWaitReason?: string;
};

export function describeQueueItem(item: any, runtime: QueueRuntime) {
  const now = runtime.now ?? Date.now();
  const active = Boolean(item.active || (item.source === "results" && item.recordId === runtime.activeResultsId) || (item.source === "scan" && Number(item.recordId) === runtime.activeScanId));
  const phase = active && item.source === "results" ? runtime.activeResultsPhase || item.phase : item.phase;
  const nextAt = Math.max(Number(item.nextAttemptAt || 0), Number(item.source === "results" ? runtime.resultsNextAt : item.source === "shield" ? runtime.shieldNextAt : runtime.scanNextAt) || 0,
    phase === "pending" ? Number(runtime.lookupNextAt || 0) : 0);
  const waitReason = item.source === "results" ? runtime.resultsWaitReason : item.source === "shield" ? runtime.shieldWaitReason : item.message;
  const state = !runtime.enabled ? "Cloud checks disabled" : !runtime.configured ? "Waiting for API key"
    : item.paused ? "Paused" : item.requiresConfirmation ? "Waiting for confirmation" : !item.enumerated ? "Waiting for file collection"
    : phase === "blocked" ? "Action required" : phase === "upload_required" ? "Upload required"
    : active ? phase === "needs_upload" ? "Uploading file" : phase === "analysing" ? "Checking analysis" : "Checking hash"
    : phase === "analysing" ? "Awaiting analysis" : phase === "needs_upload" ? "Upload queued"
    : nextAt > now ? waitReason ? "Waiting to retry" : "Hash check scheduled" : "Hash lookup queued";
  const submission = phase === "blocked" ? "Open Results to retry or resolve this finding."
    : phase === "upload_required" ? "Hash checked: no report. Open Results to upload the file or quarantine it."
    : phase === "analysing" ? "File uploaded; ClamShield will monitor its analysis automatically."
    : phase === "needs_upload" ? "Hash checked: no report. File upload has not completed."
    : item.analysisId ? "An earlier file upload is recorded; a hash recheck is pending."
    : "Hash lookup only; no file upload is recorded for this task.";
  return { ...item, phase, active, state, submission, nextAttemptAt: active ? 0 : nextAt,
    message: item.message || (nextAt > now ? waitReason || "" : "") };
}

// Paginate in SQLite: full scans can contain millions of pending files.
export function getVirusTotalQueuePage(db: any, settings: any, shield: any[], runtime: QueueRuntime, options: any = {}) {
  const pageSize = 50;
  const source = ["results", "shield", "scan"].includes(options.source) ? options.source : "all";
  const search = String(options.search || "").trim().slice(0, 1000);
  const sql = `WITH queue AS (
    SELECT 'results:' || id AS id, id AS recordId, 'results' AS source, original_path AS filePath,
      CASE WHEN virus_total_refinement_status IN ('blocked', 'error') THEN 'blocked'
        WHEN virus_total_refinement_status = 'upload_required' THEN 'upload_required'
        WHEN virus_total_refinement_status = 'upload_queued' OR json_extract(virus_total_checks, '$.resultsPendingUploadHash') != '' THEN 'needs_upload'
        WHEN virus_total_refinement_status = 'awaiting_analysis' OR
          (virus_total_refinement_status = 'unknown' AND json_extract(virus_total_checks, '$.resultsUploadedUnknownHash') != '') THEN 'analysing'
        WHEN virus_total_refinement_status = 'unknown' THEN 'upload_required' ELSE 'pending' END AS phase,
      timestamp AS createdAt, COALESCE(json_extract(virus_total_checks, '$.resultsUploadCheckAfter'), 0) AS nextAttemptAt,
      '' AS jobId, 0 AS paused,
      0 AS requiresConfirmation, 1 AS enumerated,
      COALESCE(json_extract(virus_total_checks, '$.resultsQueueMessage'), '') AS message,
      COALESCE(json_extract(virus_total_checks, '$.resultsUploadAnalysisId'), '') AS analysisId, 0 AS active
    FROM scan_results
    WHERE ((CASE WHEN LOWER(source) = 'shield' THEN ?1 ELSE ?2 END) = 1 AND COALESCE(virus_total_refinement_status, '') = '') OR
        virus_total_refinement_status IN ('unknown', 'upload_required', 'upload_queued', 'awaiting_analysis', 'retry_pending', 'blocked', 'error') OR
        json_extract(virus_total_checks, '$.resultsUploadRequestedHash') != ''
    UNION ALL
    SELECT 'scan:' || f.id, CAST(f.id AS TEXT), 'scan', f.file_path, f.status, j.created_at,
      MAX(f.next_attempt_at, CASE WHEN f.status = 'pending' THEN j.lookup_after ELSE 0 END),
      f.job_id, j.status = 'paused', j.confirmation_required, j.enumerated, j.message,
      COALESCE((SELECT analysis_id FROM vt_scan_submissions s WHERE s.job_id = f.job_id AND s.sha256 = f.sha256 ORDER BY next_poll_at DESC LIMIT 1), ''), 0
    FROM vt_scan_files f JOIN vt_scan_jobs j ON j.job_id = f.job_id
    WHERE j.status IN ('active', 'paused') AND f.status NOT IN ('checked', 'skipped')
    UNION ALL
    SELECT json_extract(value, '$.id'), json_extract(value, '$.id'), 'shield', json_extract(value, '$.filePath'),
      json_extract(value, '$.phase'), json_extract(value, '$.createdAt'), COALESCE(json_extract(value, '$.nextAttemptAt'), 0),
      '', 0, 0, 1, COALESCE(json_extract(value, '$.message'), ''), COALESCE(json_extract(value, '$.analysisId'), ''), COALESCE(json_extract(value, '$.active'), 0)
    FROM json_each(?3)
  )`;
  const parameters = [Number(settings.virusTotalShieldBackgroundCheckEnabled === true), Number(settings.virusTotalAutoRefineEnabled === true), JSON.stringify(shield)];
  const counts: Record<string, number> = {
    results: Number(db.prepare(`${sql} SELECT COUNT(*) AS count FROM queue WHERE source = 'results'`).get(...parameters).count),
    shield: shield.length,
    scan: Number(db.prepare("SELECT COALESCE(SUM(MAX(0, total - checked - skipped)), 0) AS count FROM vt_scan_jobs WHERE status IN ('active', 'paused')").get().count),
  };
  const totalPending = Object.values(counts).reduce((a, b) => a + b, 0);
  if (options.summary) return { totalPending, counts };
  const where = "WHERE (? = 'all' OR source = ?) AND (? = '' OR INSTR(LOWER(COALESCE(filePath, '')), LOWER(?)) > 0)";
  const filters = [source, source, search, search];
  const total = search ? Number(db.prepare(`${sql} SELECT COUNT(*) AS count FROM queue ${where}`).get(...parameters, ...filters).count)
    : source === "all" ? totalPending : counts[source];
  const page = Math.max(1, Math.min(Math.ceil(total / pageSize) || 1, Math.floor(Number(options.page) || 1)));
  const items = db.prepare(`${sql} SELECT * FROM queue ${where} ORDER BY createdAt, id LIMIT ? OFFSET ?`).all(...parameters, ...filters, pageSize, (page - 1) * pageSize);
  return { items: items.map((item: any) => describeQueueItem(item, runtime)), total, totalPending, counts, page, pageSize,
    enabled: runtime.enabled, configured: runtime.configured };
}
