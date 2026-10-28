import { englishText } from "../../../shared/localization/runtime";
import { insertScanResultRow } from "../../../modules/results/server/rows";
import { mapScanResultRow, scanResultSelectSql } from "../../../modules/results/server/storage";
import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { asRecord } from "../../../server/core/database/values";
import { runtimeState } from "../../../server/core/runtimeState";
import { hashFile } from "../../../server/core/utils";
import { VirusTotalFileAnalysis } from "./virusTotalFileAnalysis";
import { advanceVirusTotalResult, nextVirusTotalResultAttempt } from "./virusTotalResultWorkflow";
import { assertVirusTotalQuotaAvailable, ensureScanResultHash, loadVirusTotalApiKey, recordVirusTotalLookupSafely, reserveVirusTotalLookupSlot, waitForVirusTotalLookupSlot } from "./account";
import { fetchVirusTotalFileReport, formatVirusTotalUploadSize, getVirusTotalResultsUploadMaxBytes, summarizeVirusTotalFileReport } from "./requests";
import { existsSync } from "fs";
import fs from "fs/promises";
export function classifyVirusTotalRefinement(report: any) {
    if (report?.found === false) {
        return {
            status: "upload_required",
            label: englishText("results.upload_required"),
            severity: "neutral",
            message: englishText("backend.virustotal.hash_checked_no_report_upload_the_file_for_analysis_or_quarantine")
        };
    }
    const stats = report?.stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const detections = malicious + suspicious;
    if (detections <= 0 && Number(stats.harmless || 0) + Number(stats.undetected || 0) === 0) {
        return { status: "needs_review", label: englishText("results.needs_review"), severity: "warning",
            message: englishText("backend.virustotal.virustotal_returned_a_report_with_no_completed_engine_verdicts_re") };
    }
    if (detections <= 0) {
        return {
            status: "likely_false_positive",
            label: englishText("results.likely_false_positive"),
            severity: "good",
            message: englishText("backend.virustotal.no_virustotal_engines_currently_flag_this_hash")
        };
    }
    if (detections <= 2) {
        return {
            status: "needs_review",
            label: englishText("results.needs_review"),
            severity: "warning",
            message: englishText("backend.virustotal.only_a_small_number_of_virustotal_engines_flag_this_hash")
        };
    }
    if (detections < 10) {
        return {
            status: "confirmed_suspicious",
            label: englishText("results.suspicious"),
            severity: "danger",
            message: englishText("backend.virustotal.several_virustotal_engines_flag_this_hash")
        };
    }
    return {
        status: "confirmed_malicious",
        label: englishText("results.malicious"),
        severity: "danger",
        message: englishText("backend.virustotal.many_virustotal_engines_flag_this_hash")
    };
}
export function buildVirusTotalRefinement(report: any) {
    const verdict = classifyVirusTotalRefinement(report);
    return {
        ...verdict,
        checkedAt: Date.now(),
        hash: report?.hash || "",
        stats: report?.stats || null,
        report
    };
}
export function getVirusTotalDetectionCount(report: any) {
    const stats = report?.stats || {};
    return Number(stats.malicious || 0) + Number(stats.suspicious || 0);
}
export function buildVirusTotalThreatName(report: any) {
    const detections = getVirusTotalDetectionCount(report);
    return `VirusTotal: ${detections} detection${detections === 1 ? "" : "s"}`;
}
export function getVirusTotalResultChecks(result: any) {
    return asRecord(result?.virusTotalChecks);
}
export function setVirusTotalResultChecks(result: any, patch: Record<string, any>) {
    result.virusTotalChecks = {
        ...getVirusTotalResultChecks(result),
        ...patch
    };
}
export function getVirusTotalRefinementStatus(result: any) {
    return String(result?.virusTotalRefinement?.status || "").trim().toLowerCase();
}
export function isVirusTotalResultUploadFollowupDue(result: any) {
    const at = nextVirusTotalResultAttempt(result);
    return at > 0 && Date.now() >= at;
}
export function getVirusTotalResultUploadFollowupAt(result: any) {
    return nextVirusTotalResultAttempt(result);
}
export async function getVirusTotalResultUploadEligibility(result: any, settings: any, explicit = false) {
    const fileStat = result.originalPath ? await fs.stat(result.originalPath).catch(() => null) : null;
    const maxBytes = getVirusTotalResultsUploadMaxBytes(settings);
    if (!explicit && settings.virusTotalResultsUploadUnknownEnabled !== true) {
        return { allowed: false, reason: englishText("backend.virustotal.disabled"), message: englishText("backend.virustotal.hash_checked_no_report_automatic_uploads_are_off_choose_upload_fo") };
    }
    if (!result.originalPath || !existsSync(result.originalPath) || !fileStat || !fileStat.isFile() || fileStat.size <= 0) {
        return { allowed: false, reason: englishText("backend.virustotal.unavailable"), message: englishText("backend.virustotal.the_original_file_is_unavailable_restore_it_to_upload_or_remove_t") };
    }
    if (fileStat.size > maxBytes) {
        return {
            allowed: false,
            reason: "too_large",
            message: englishText("backend.virustotal.file_exceeds_virustotal_upload_size_limit_is_adjust_the_upload_li", {
                value1: String(formatVirusTotalUploadSize(fileStat.size)),
                value2: String(formatVirusTotalUploadSize(maxBytes))
            })
        };
    }
    return { allowed: true, reason: "", message: "" };
}
export async function canUploadVirusTotalResultUnknown(result: any, settings: any) {
    return (await getVirusTotalResultUploadEligibility(result, settings)).allowed;
}
export const virusTotalFileAnalysis = new VirusTotalFileAnalysis({
    reserveSlot: async (wait) => {
        if (wait)
            await waitForVirusTotalLookupSlot();
        else
            reserveVirusTotalLookupSlot();
    },
    checkQuota: assertVirusTotalQuotaAvailable,
    recordRequest: recordVirusTotalLookupSafely
});
export const virusTotalResultChecksRunning = new Map<string, Promise<any>>();
// Network work must not restore a deleted/quarantined finding or overwrite other rows.
export async function persistVirusTotalResult(result: any) {
    await ensureAppStateReady();
    const db = getAppStateDb();
    const row = db.prepare(scanResultSelectSql() + " WHERE id = ?").get(result.id);
    if (!row)
        return;
    const current = mapScanResultRow(row);
    if (Number(current.timestamp) !== Number(result.timestamp))
        return;
    insertScanResultRow(db, { ...current, sha256: result.sha256,
        virusTotalChecks: result.virusTotalChecks, virusTotalRefinement: result.virusTotalRefinement });
}
export async function runVirusTotalResultCloudCheck(results: any[], result: any, settings: any, apiKey: string, onProgress: (phase: string) => void = () => { }, explicitUpload = false) {
    const running = virusTotalResultChecksRunning.get(result.id);
    if (running) {
        const response = await running;
        result.virusTotalRefinement = response.refinement;
        result.virusTotalChecks = response.checks;
        return response;
    }
    const task = (async () => {
        const sha256 = await ensureScanResultHash(results, result, "sha256");
        return advanceVirusTotalResult(result, sha256, {
            lookup: hash => fetchVirusTotalFileReport(apiKey, hash),
            upload: async (hash) => {
                if (await hashFile(result.originalPath, "sha256") !== hash) {
                    throw Object.assign(new Error(englishText("backend.virustotal.file_content_changed_since_the_detection_scan_it_again_before_sub")), { fileError: true, fileChanged: true });
                }
                return virusTotalFileAnalysis.upload(apiKey, result.originalPath, async () => {
                    const latest = runtimeState.currentVirusTotalSettings();
                    const current = getAppStateDb().prepare("SELECT timestamp FROM scan_results WHERE id = ?").get(result.id);
                    return current && Number(current.timestamp) === Number(result.timestamp) &&
                        latest.virusTotalCloudEnabled === true && await loadVirusTotalApiKey() === apiKey &&
                        (result.virusTotalChecks?.resultsUploadRequestedHash === hash || latest.virusTotalResultsUploadUnknownEnabled === true);
                });
            },
            analysis: async (id, hash) => {
                const payload = await virusTotalFileAnalysis.analysis(apiKey, id, hash);
                return payload ? summarizeVirusTotalFileReport(hash, payload) : null;
            },
            eligibility: explicit => getVirusTotalResultUploadEligibility(result, runtimeState.currentVirusTotalSettings(), explicit),
            classify: buildVirusTotalRefinement,
            persist: () => persistVirusTotalResult(result), progress: onProgress
        }, explicitUpload);
    })();
    virusTotalResultChecksRunning.set(result.id, task);
    try {
        return await task;
    }
    finally {
        virusTotalResultChecksRunning.delete(result.id);
    }
}
export function normalizeVirusTotalRefinementFilter(value: any) {
    const status = String(value || "all").trim().toLowerCase();
    if (["all", "unrefined", "likely_false_positive", "needs_review", "confirmed_suspicious", "confirmed_malicious", "upload_required", "awaiting_analysis", "upload_queued", "retry_pending", "blocked", "unknown", "error"].includes(status)) {
        return status;
    }
    return "all";
}
