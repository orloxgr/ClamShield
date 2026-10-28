import { englishText } from "../../../shared/localization/runtime";
import { isVirusTotalContentChange, virusTotalContentChangedMessage } from "./content";
export function describeVirusTotalResult(item: any) {
    const refinement = item?.virusTotalRefinement || {};
    const report = refinement.report || {};
    const checks = item?.virusTotalChecks || {};
    const hash = item?.sha256 || refinement.hash || report.hash;
    // Opening an upload page is not proof that a sample was submitted.
    const uploaded = Boolean((hash && checks.resultsUploadedUnknownHash === hash) || (report.uploaded && report.analysisId));
    const nextCheckAt = Number(checks.resultsUploadCheckAfter || 0);
    const checkedAt = Number(refinement.checkedAt || 0);
    if (isVirusTotalContentChange(item))
        return { state: "content_changed", label: englishText("backend.virustotal.file_changed"),
            message: virusTotalContentChangedMessage, uploaded, checkedAt, nextCheckAt: 0, action: "rescan" };
    if (refinement.status === "blocked")
        return { state: "blocked", label: englishText("results.action_required"),
            message: refinement.message, uploaded, checkedAt, nextCheckAt: 0,
            action: checks.resultsBlockedReason === "api_key" ? "settings" : "check" };
    if (refinement.status === "retry_pending")
        return { state: "retry_pending", label: englishText("results.waiting_to_retry"),
            message: refinement.message, uploaded, checkedAt, nextCheckAt, action: "queue" };
    if (refinement.status === "upload_queued")
        return { state: "upload_queued", label: englishText("results.upload_queued"),
            message: refinement.message, uploaded, checkedAt, nextCheckAt, action: "queue" };
    if (refinement.status === "error")
        return { state: "blocked", label: englishText("backend.virustotal.check_needs_attention"),
            message: `${uploaded ? englishText("backend.virustotal.an_earlier_file_upload_is_recorded") : ""}${refinement.message || englishText("backend.virustotal.the_virustotal_check_failed_no_verdict_is_available")}`,
            uploaded, checkedAt, nextCheckAt: 0, action: "check" };
    if (refinement.status === "awaiting_analysis" || refinement.status === "upload_required" || refinement.status === "unknown" || report.found === false) {
        if (uploaded && !checks.resultsAnalysisExpired && refinement.status !== "upload_required")
            return {
                state: "awaiting_analysis", label: englishText("results.awaiting_analysis"),
                message: englishText("backend.virustotal.file_uploaded_clamshield_will_check_the_submitted_analysis_automa"),
                uploaded, checkedAt, nextCheckAt, action: "queue",
            };
        const reason = report.uploadSkipReason === "disabled" ? "Automatic uploads are disabled for Results."
            : report.uploadSkipped ? String(report.message || "Upload was skipped.") : "";
        return { state: "upload_required", label: englishText("results.upload_required"), uploaded, checkedAt, nextCheckAt: 0, action: "upload",
            message: refinement.status === "upload_required" ? refinement.message : englishText("backend.virustotal.hash_checked_no_report_the_file_was_not_uploaded_by_clamshield_ch", {
                value1: String(reason ? ` ${reason}` : "")
            }) };
    }
    if (!refinement.status)
        return { state: item?.virusTotalQueued ? "queued_hash" : "not_checked",
            label: item?.virusTotalQueued ? englishText("backend.virustotal.hash_check_queued") : englishText("backend.virustotal.not_checked_with_vt"),
            message: item?.virusTotalQueued ? englishText("backend.virustotal.hash_check_queued_view_the_queue_for_progress_you_can_quarantine") : englishText("backend.virustotal.check_the_hash_with_virustotal_for_a_second_opinion_or_quarantine"),
            uploaded, checkedAt: 0, nextCheckAt: 0, action: item?.virusTotalQueued ? "queue" : "check" };
    return { state: "checked", label: refinement.label || englishText("results.needs_review"), message: `${refinement.message || englishText("backend.virustotal.virustotal_report_available")} ${refinement.status === "likely_false_positive"
            ? englishText("backend.virustotal.review_the_detection_before_adding_an_exception_zero_detections_d") : refinement.status === "needs_review" ? englishText("backend.virustotal.review_the_engine_results_quarantine_the_file_if_you_cannot_verif") : englishText("backend.virustotal.quarantine_is_recommended")}`,
        uploaded, checkedAt, nextCheckAt: 0, action: "check" };
}
