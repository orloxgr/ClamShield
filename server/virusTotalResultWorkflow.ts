import { isVirusTotalContentChange, virusTotalContentChangedMessage } from "../shared/virusTotalContent";

type Dependencies = {
  lookup: (hash: string) => Promise<any>;
  upload: (hash: string) => Promise<string>;
  analysis: (id: string, hash: string) => Promise<any | null>;
  eligibility: (explicit: boolean) => Promise<{ allowed: boolean; reason: string; message: string }>;
  classify: (report: any) => any;
  persist: () => Promise<void>;
  now?: () => number;
  progress?: (phase: string) => void;
};

const finalStatuses = ["likely_false_positive", "needs_review", "confirmed_suspicious", "confirmed_malicious"];
const stageLabels: Record<string, string> = { upload_required: "Upload required", upload_queued: "Upload queued",
  awaiting_analysis: "Awaiting analysis", retry_pending: "Waiting to retry", blocked: "Action required" };

// Resume older submissions too, including those stopped after five checks.
export function nextVirusTotalResultAttempt(item: any) {
  const c = item.virusTotalChecks || {}, status = item.virusTotalRefinement?.status;
  if (isVirusTotalContentChange(item)) return 0;
  if (finalStatuses.includes(status) || ["upload_required", "blocked"].includes(status)) return 0;
  const submitted = c.resultsUploadedUnknownHash && c.resultsUploadedUnknownHash === item.sha256 && !c.resultsAnalysisExpired;
  if (submitted || (c.resultsUploadRequestedHash && c.resultsUploadRequestedHash === item.sha256) || status === "retry_pending" || status === "upload_queued") {
    return Math.max(1, Number(c.resultsWorkflowRetryAt || c.resultsUploadCheckAfter || 1));
  }
  return 0;
}

export async function advanceVirusTotalResult(item: any, hash: string, deps: Dependencies, explicitUpload = false) {
  const now = deps.now || Date.now;
  const c = item.virusTotalChecks = { ...item.virusTotalChecks };
  const missing = () => ({ found: false, hash, url: `https://www.virustotal.com/gui/file/${hash}/detection` });
  const setStage = (status: string, message: string, retryAt = 0, report: any = missing()) => {
    c.resultsWorkflowRetryAt = retryAt;
    c.resultsUploadCheckAfter = retryAt;
    c.resultsQueueMessage = message;
    item.virusTotalRefinement = { status, label: stageLabels[status], severity: "neutral", checkedAt: now(), hash, message, report };
  };
  const finish = (report: any) => {
    c.resultsWorkflowRetryAt = 0; c.resultsUploadCheckAfter = 0; c.resultsUploadRequestedHash = "";
    c.resultsPendingUploadHash = ""; c.resultsQueueMessage = "";
    item.virusTotalRefinement = deps.classify(report);
  };
  let uploaded = false;
  // Repeating an old analysis cannot resolve a content mismatch. A fresh local scan is required.
  if (isVirusTotalContentChange(item)) {
    c.resultsBlockedReason = "content_changed";
    c.resultsUploadRequestedHash = ""; c.resultsPendingUploadHash = "";
    setStage("blocked", virusTotalContentChangedMessage);
    await deps.persist();
    return response();
  }
  try {
    if (explicitUpload) {
      c.resultsUploadRequestedHash = hash;
      await deps.persist();
    }
    const submitted = c.resultsUploadedUnknownHash === hash && !c.resultsAnalysisExpired;
    if (submitted && c.resultsUploadAnalysisId && !finalStatuses.includes(item.virusTotalRefinement?.status)) {
      deps.progress?.("analysing");
      let report: any;
      try { report = await deps.analysis(c.resultsUploadAnalysisId, hash); }
      catch (error: any) {
        if (!error.analysisMissing) throw error;
        // An expired analysis may still have a hash report. Never silently re-upload.
        c.resultsAnalysisExpired = true;
        c.resultsUploadRequestedHash = "";
        setStage("retry_pending", "The earlier analysis expired. Checking for a hash report next.", now() + 30_000);
        await deps.persist();
        return response();
      }
      if (report) finish(report);
      else setStage("awaiting_analysis", "VirusTotal is still analysing the uploaded file. ClamShield will check again automatically; you can quarantine it while waiting.", now() + 60_000);
    } else if ((item.virusTotalRefinement?.report?.found === false || c.resultsAnalysisExpired) &&
        (c.resultsUploadRequestedHash === hash || c.resultsPendingUploadHash === hash || item.virusTotalRefinement?.status === "upload_queued")) {
      const allowed = await deps.eligibility(c.resultsUploadRequestedHash === hash);
      if (!allowed.allowed) {
        c.resultsUploadRequestedHash = "";
        c.resultsPendingUploadHash = "";
        setStage("upload_required", allowed.message || "Automatic uploads are off. Choose Upload for analysis or quarantine the file.");
        item.virusTotalRefinement.report.uploadSkipReason = allowed.reason;
      } else {
        deps.progress?.("needs_upload");
        const id = await deps.upload(hash);
        c.resultsUploadedUnknownHash = hash; c.resultsUploadAnalysisId = id;
        c.resultsAnalysisExpired = false; c.resultsUploadRequestedHash = ""; c.resultsPendingUploadHash = "";
        c.resultsUploadedAt = now(); uploaded = true;
        setStage("awaiting_analysis", "File uploaded. VirusTotal analysis is pending; ClamShield will check it automatically. You can quarantine the file while waiting.", now() + 60_000);
        // Persist the accepted ID before any further network operation.
        await deps.persist();
      }
    } else {
      deps.progress?.("pending");
      const report = await deps.lookup(hash);
      c.cloud = now();
      if (report.found !== false) finish(report);
      else {
        const allowed = await deps.eligibility(c.resultsUploadRequestedHash === hash);
        if (submitted && c.resultsUploadAnalysisId) {
          setStage("awaiting_analysis", "No hash report was returned. ClamShield will retrieve the existing submitted analysis next.", now() + 1000, report);
        } else if (allowed.allowed && !c.resultsAnalysisExpired && !submitted) {
          c.resultsPendingUploadHash = hash;
          setStage("upload_queued", "Hash checked: no report. File upload is queued; ClamShield will follow its analysis automatically.", now() + 1000, report);
        } else {
          c.resultsUploadRequestedHash = "";
          setStage("upload_required", c.resultsAnalysisExpired || submitted
            ? "The earlier submission no longer has an accessible analysis or hash report. Choose Upload for analysis to submit it again, or quarantine the file."
            : allowed.message || "Hash checked: no report. Choose Upload for analysis or quarantine the file.", 0, report);
          item.virusTotalRefinement.report.uploadSkipReason = allowed.reason;
        }
      }
    }
  } catch (error: any) {
    const status = Number(error.status || error.response?.status || 0);
    const changed = isVirusTotalContentChange(error);
    const blocked = changed || error.fileError || [401, 403].includes(status) || ["ENOENT", "EACCES", "EPERM"].includes(error.code);
    const retryAt = blocked ? 0 : Math.max(now() + (status === 429 ? 15 * 60_000 : 60_000), Number(error.nextAllowedAt || 0));
    c.resultsBlockedReason = changed ? "content_changed" : [401, 403].includes(status) ? "api_key" : blocked ? "file" : "";
    if (changed) { c.resultsUploadRequestedHash = ""; c.resultsPendingUploadHash = ""; }
    setStage(blocked ? "blocked" : "retry_pending", changed ? virusTotalContentChangedMessage : `${error.message || String(error)} ${blocked
      ? c.resultsBlockedReason === "api_key" ? "Open Settings to fix the API key, then retry the check." : "Restore access to the original file and retry, or remove this finding if the file is already gone."
      : "ClamShield will retry automatically. You can also quarantine the file while waiting."}`, retryAt);
  }
  await deps.persist();
  return response();

  function response() {
    return { sha256: hash, uploaded, uploadAnalysisId: c.resultsUploadAnalysisId || "",
      report: item.virusTotalRefinement.report, refinement: item.virusTotalRefinement, checks: c };
  }
}
