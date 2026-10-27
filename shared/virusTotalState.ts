import { isVirusTotalContentChange, virusTotalContentChangedMessage } from "./virusTotalContent";

export function describeVirusTotalResult(item: any) {
  const refinement = item?.virusTotalRefinement || {};
  const report = refinement.report || {};
  const checks = item?.virusTotalChecks || {};
  const hash = item?.sha256 || refinement.hash || report.hash;
  // Opening an upload page is not proof that a sample was submitted.
  const uploaded = Boolean((hash && checks.resultsUploadedUnknownHash === hash) || (report.uploaded && report.analysisId));
  const nextCheckAt = Number(checks.resultsUploadCheckAfter || 0);
  const checkedAt = Number(refinement.checkedAt || 0);
  if (isVirusTotalContentChange(item)) return { state: "content_changed", label: "File changed",
    message: virusTotalContentChangedMessage, uploaded, checkedAt, nextCheckAt: 0, action: "rescan" };
  if (refinement.status === "blocked") return { state: "blocked", label: "Action required",
    message: refinement.message, uploaded, checkedAt, nextCheckAt: 0,
    action: checks.resultsBlockedReason === "api_key" ? "settings" : "check" };
  if (refinement.status === "retry_pending") return { state: "retry_pending", label: "Waiting to retry",
    message: refinement.message, uploaded, checkedAt, nextCheckAt, action: "queue" };
  if (refinement.status === "upload_queued") return { state: "upload_queued", label: "Upload queued",
    message: refinement.message, uploaded, checkedAt, nextCheckAt, action: "queue" };
  if (refinement.status === "error") return { state: "blocked", label: "Check needs attention",
    message: `${uploaded ? "An earlier file upload is recorded. " : ""}${refinement.message || "The VirusTotal check failed. No verdict is available."}`,
    uploaded, checkedAt, nextCheckAt: 0, action: "check" };
  if (refinement.status === "awaiting_analysis" || refinement.status === "upload_required" || refinement.status === "unknown" || report.found === false) {
    if (uploaded && !checks.resultsAnalysisExpired && refinement.status !== "upload_required") return {
      state: "awaiting_analysis", label: "Awaiting analysis",
      message: "File uploaded. ClamShield will check the submitted analysis automatically. You can quarantine the file while waiting.",
      uploaded, checkedAt, nextCheckAt, action: "queue",
    };
    const reason = report.uploadSkipReason === "disabled" ? "Automatic uploads are disabled for Results."
      : report.uploadSkipped ? String(report.message || "Upload was skipped.") : "";
    return { state: "upload_required", label: "Upload required", uploaded, checkedAt, nextCheckAt: 0, action: "upload",
      message: refinement.status === "upload_required" ? refinement.message : `Hash checked: no report. The file was not uploaded by ClamShield. Choose Upload for analysis or quarantine the file.${reason ? ` ${reason}` : ""}` };
  }
  if (!refinement.status) return { state: item?.virusTotalQueued ? "queued_hash" : "not_checked",
    label: item?.virusTotalQueued ? "Hash check queued" : "Not checked with VT",
    message: item?.virusTotalQueued ? "Hash check queued. View the queue for progress; you can quarantine the file while waiting." : "Check the hash with VirusTotal for a second opinion, or quarantine the file based on the local detection.",
    uploaded, checkedAt: 0, nextCheckAt: 0, action: item?.virusTotalQueued ? "queue" : "check" };
  return { state: "checked", label: refinement.label || "Needs review", message: `${refinement.message || "VirusTotal report available."} ${refinement.status === "likely_false_positive"
    ? "Review the detection before adding an exception; zero detections do not guarantee the file is safe."
    : refinement.status === "needs_review" ? "Review the engine results; quarantine the file if you cannot verify it." : "Quarantine is recommended."}`,
    uploaded, checkedAt, nextCheckAt: 0, action: "check" };
}
