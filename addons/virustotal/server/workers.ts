import { englishText } from "../../../shared/localization/runtime";
import { getExceptions, isExcluded } from "../../../modules/exceptions/server/service";
import { addHistory } from "../../../modules/history/server/storage";
import { addScanResult, getScanResults } from "../../../modules/results/server/storage";
import { ApplicationContext } from "../../../server/core/applicationContext";
import { normalizedStatePath } from "../../../server/core/database/values";
import { runtimeState } from "../../../server/core/runtimeState";
import { hashFile } from "../../../server/core/utils";
import { getFileFingerprint } from "../../../server/scanning/files";
import { shouldSkipBuiltInScanPath } from "../../../server/scanning/targets";
import { loadVirusTotalApiKey } from "./account";
import { virusTotalPublicApiLimits } from "./constants";
import { buildVirusTotalRefinement, buildVirusTotalThreatName, getVirusTotalDetectionCount, getVirusTotalRefinementStatus, getVirusTotalResultUploadFollowupAt, isVirusTotalResultUploadFollowupDue, persistVirusTotalResult, runVirusTotalResultCloudCheck, virusTotalFileAnalysis } from "./refinement";
import { createVirusTotalNoReport, fetchVirusTotalFileReport, formatVirusTotalUploadSize, getVirusTotalShieldUploadMaxBytes, summarizeVirusTotalFileReport } from "./requests";
import { isVirusTotalAutoRefinementCandidate } from "./status";
import { createHash } from "crypto";
import { existsSync } from "fs";
import fs from "fs/promises";
export function createScheduleVirusTotalRefinement(context: ApplicationContext) { return () => { }; }
export function createScheduleShieldVirusTotalCheck(context: ApplicationContext) { return () => { }; }
export function createProcessNextShieldVirusTotalCheck(context: Pick<ApplicationContext, "settings" | "virusTotalShieldQueue" | "scheduleShieldVirusTotalCheck" | "virusTotalShieldActiveItem" | "handleVirusTotalShieldDetection">) {
    return async () => {
        if (runtimeState.virusTotalShieldRunning)
            return;
        if (context.settings.virusTotalCloudEnabled !== true)
            return;
        if (context.settings.virusTotalShieldBackgroundCheckEnabled !== true && !Array.from(context.virusTotalShieldQueue.values()).some(item => item.forceCloudCheck || item.uploadedHash))
            return;
        const apiKey = await loadVirusTotalApiKey();
        if (!apiKey) {
            runtimeState.virusTotalShieldLastMessage = "VirusTotal API key is not configured.";
            return;
        }
        const now = Date.now();
        if (now < runtimeState.virusTotalShieldNextAllowedAt) {
            context.scheduleShieldVirusTotalCheck(runtimeState.virusTotalShieldNextAllowedAt - now);
            return;
        }
        const next = Array.from(context.virusTotalShieldQueue.entries())
            .find(([, queuedItem]) => Number(queuedItem.notBefore || 0) <= now);
        if (!next) {
            const nextAt = Math.min(...Array.from(context.virusTotalShieldQueue.values()).map(item => Number(item.notBefore || now)));
            if (Number.isFinite(nextAt))
                context.scheduleShieldVirusTotalCheck(Math.max(1000, nextAt - now));
            return;
        }
        const [normalizedPath, item] = next;
        context.virusTotalShieldQueue.delete(normalizedPath);
        runtimeState.virusTotalShieldRunning = true;
        context.virusTotalShieldActiveItem = { id: `shield:${normalizedPath}`, filePath: item.filePath, createdAt: item.queuedAt,
            phase: item.pendingUploadHash ? "needs_upload" : item.uploadedHash ? englishText("backend.virustotal.analysing") : englishText("backend.virustotal.pending"), active: true };
        try {
            if (!existsSync(item.filePath) && !item.uploadedHash) {
                runtimeState.virusTotalShieldLastMessage = `File unavailable. Restore it and scan again: ${item.filePath}`;
                return;
            }
            const sha256 = existsSync(item.filePath) ? await hashFile(item.filePath, "sha256") : item.uploadedHash!;
            if (item.pendingUploadHash === sha256) {
                const analysisId = await virusTotalFileAnalysis.upload(apiKey, item.filePath, async () => context.settings.virusTotalCloudEnabled === true && await loadVirusTotalApiKey() === apiKey);
                await addHistory({
                    type: "virustotal-shield-upload",
                    target: item.filePath,
                    result: 0,
                    threatsFound: 0,
                    scannedFiles: 1,
                    duration: 1,
                    actionTaken: englishText("backend.virustotal.uploaded_for_analysis", {
                        analysisId: String(analysisId)
                    })
                }).catch(() => { });
                context.virusTotalShieldQueue.set(normalizedPath, {
                    ...item,
                    queuedAt: Date.now(),
                    notBefore: Date.now() + 2 * 60 * 1000,
                    uploadedHash: sha256,
                    analysisId,
                    pendingUploadHash: ""
                });
                runtimeState.virusTotalShieldLastMessage = `VirusTotal analysis queued: ${item.filePath}`;
                runtimeState.virusTotalShieldWaitReason = "";
                runtimeState.virusTotalShieldNextAllowedAt = Date.now() + virusTotalPublicApiLimits.perLookupMs;
                return;
            }
            let report: any;
            if (item.uploadedHash === sha256 && item.analysisId) {
                let payload: any;
                try {
                    payload = await virusTotalFileAnalysis.analysis(apiKey, item.analysisId, sha256);
                }
                catch (error: any) {
                    if (!error.analysisMissing)
                        throw error;
                    // Keep an expired submission actionable in Results; never discard or re-upload it silently.
                    await addScanResult({ source: "shield", originalPath: item.filePath,
                        threatName: "VirusTotal analysis requires review", engine: "VirusTotal", sha256,
                        virusTotalRefinement: { ...buildVirusTotalRefinement(createVirusTotalNoReport(sha256)),
                            message: englishText("backend.virustotal.the_earlier_analysis_expired_recheck_the_hash_in_results_if_no_re") },
                        virusTotalChecks: { resultsUploadedUnknownHash: sha256, resultsUploadAnalysisId: item.analysisId, resultsAnalysisExpired: true } });
                    return;
                }
                if (!payload) {
                    context.virusTotalShieldQueue.set(normalizedPath, { ...item, notBefore: Date.now() + 60000 });
                    runtimeState.virusTotalShieldLastMessage = `Awaiting VirusTotal analysis; automatic follow-up scheduled: ${item.filePath}`;
                    return;
                }
                report = summarizeVirusTotalFileReport(sha256, payload);
            }
            else
                report = await fetchVirusTotalFileReport(apiKey, sha256);
            const detections = getVirusTotalDetectionCount(report);
            if (detections > 0) {
                const actionTaken = await context.handleVirusTotalShieldDetection(item.filePath, report);
                await addHistory({
                    type: "virustotal-shield-check",
                    target: item.filePath,
                    result: 1,
                    threatsFound: 1,
                    scannedFiles: 1,
                    duration: 1,
                    actionTaken
                }).catch(() => { });
                runtimeState.virusTotalShieldLastMessage = `${buildVirusTotalThreatName(report)}: ${item.filePath}`;
            }
            else if (report?.found === false) {
                const fileStat = await fs.stat(item.filePath).catch(() => null);
                const maxBytes = getVirusTotalShieldUploadMaxBytes(context.settings);
                const uploadEnabled = context.settings.virusTotalShieldUploadUnknownEnabled === true;
                const uploadSkipMessage = uploadEnabled && fileStat && fileStat.isFile() && fileStat.size > maxBytes
                    ? englishText("backend.virustotal.virustotal_upload_skipped_file_is_max_upload_size_is", {
                        value1: String(formatVirusTotalUploadSize(fileStat.size)),
                        value2: String(formatVirusTotalUploadSize(maxBytes))
                    }) : "";
                if (uploadEnabled &&
                    fileStat &&
                    fileStat.isFile() &&
                    fileStat.size > 0 &&
                    fileStat.size <= maxBytes &&
                    item.uploadedHash !== sha256) {
                    context.virusTotalShieldQueue.set(normalizedPath, {
                        ...item,
                        queuedAt: Date.now(),
                        notBefore: Math.max(Date.now() + 1000, runtimeState.virusTotalNextLookupAllowedAt),
                        pendingUploadHash: sha256
                    });
                    runtimeState.virusTotalShieldLastMessage = `VirusTotal upload queued: ${item.filePath}`;
                }
                else {
                    runtimeState.virusTotalShieldLastMessage = uploadSkipMessage || `Hash checked: no report. Enable file uploads in Settings to request analysis: ${item.filePath}`;
                }
            }
            else {
                runtimeState.virusTotalShieldLastMessage = `VirusTotal clean: ${item.filePath}`;
            }
            runtimeState.virusTotalShieldNextAllowedAt = Date.now() + virusTotalPublicApiLimits.perLookupMs;
            runtimeState.virusTotalShieldWaitReason = "";
        }
        catch (e: any) {
            const status = Number(e?.status || e?.response?.status || 0);
            const localDelayMs = Math.max(1000, Number(e?.nextAllowedAt || 0) - Date.now());
            const backoffMs = e?.localRateLimit || e?.localQuotaLimit
                ? localDelayMs
                : status === 429 ? 15 * 60 * 1000 : 60 * 1000;
            runtimeState.virusTotalShieldLastMessage = e?.message || String(e);
            runtimeState.virusTotalShieldWaitReason = runtimeState.virusTotalShieldLastMessage;
            runtimeState.virusTotalShieldNextAllowedAt = Date.now() + backoffMs;
            if (!e?.fileError) {
                context.virusTotalShieldQueue.set(normalizedPath, item);
            }
            else {
                await addScanResult({ source: "shield", originalPath: item.filePath,
                    threatName: "VirusTotal check requires review", engine: "VirusTotal",
                    sha256: item.uploadedHash || item.pendingUploadHash || "",
                    virusTotalRefinement: { status: "blocked", label: englishText("results.action_required"), severity: "neutral",
                        checkedAt: Date.now(), report: createVirusTotalNoReport(item.uploadedHash || item.pendingUploadHash || ""),
                        message: runtimeState.virusTotalShieldLastMessage + englishText("backend.virustotal.review_the_file_in_results_restore_access_and_retry_adjust_upload") },
                    virusTotalChecks: { resultsUploadedUnknownHash: item.uploadedHash || "", resultsUploadAnalysisId: item.analysisId || "", resultsBlockedReason: "file" } });
            }
            console.warn(englishText("backend.virustotal.virustotal_shield_check_paused"), runtimeState.virusTotalShieldLastMessage);
        }
        finally {
            runtimeState.virusTotalShieldRunning = false;
            context.virusTotalShieldActiveItem = null;
            if (context.virusTotalShieldQueue.size > 0)
                context.scheduleShieldVirusTotalCheck(Math.max(0, runtimeState.virusTotalShieldNextAllowedAt - Date.now()));
        }
    };
}
export function createEnqueueShieldVirusTotalCheck(context: Pick<ApplicationContext, "settings" | "virusTotalShieldQueue" | "scheduleShieldVirusTotalCheck">) {
    return (filePath: string) => {
        if (context.settings.virusTotalCloudEnabled !== true || context.settings.virusTotalShieldBackgroundCheckEnabled !== true)
            return;
        const normalizedPath = normalizedStatePath(filePath);
        if (!normalizedPath || context.virusTotalShieldQueue.has(normalizedPath))
            return;
        context.virusTotalShieldQueue.set(normalizedPath, { filePath, queuedAt: Date.now() });
        context.scheduleShieldVirusTotalCheck(Math.max(0, runtimeState.virusTotalShieldNextAllowedAt - Date.now()));
    };
}
export function createEnqueueContextMenuVirusTotalCheck(context: Pick<ApplicationContext, "settings" | "virusTotalShieldQueue" | "scheduleShieldVirusTotalCheck">) {
    return (filePath: string) => {
        if (context.settings.virusTotalCloudEnabled !== true)
            return;
        const normalizedPath = normalizedStatePath(filePath);
        if (!normalizedPath || context.virusTotalShieldQueue.has(normalizedPath))
            return;
        context.virusTotalShieldQueue.set(normalizedPath, { filePath, queuedAt: Date.now(), forceCloudCheck: true });
        context.scheduleShieldVirusTotalCheck(Math.max(0, runtimeState.virusTotalShieldNextAllowedAt - Date.now()));
    };
}
export function createScheduleVirusTotalScan(context: Pick<ApplicationContext, "virusTotalScanRunning" | "virusTotalScanTimer" | "processVirusTotalScanQueue">) {
    return (delayMs = 0) => {
        if (context.virusTotalScanRunning)
            return;
        if (context.virusTotalScanTimer)
            clearTimeout(context.virusTotalScanTimer);
        context.virusTotalScanTimer = setTimeout(() => {
            context.virusTotalScanTimer = null;
            context.processVirusTotalScanQueue().catch(e => console.warn(englishText("backend.virustotal.virustotal_scan_queue_failed"), e?.message || e));
        }, Math.max(20, Math.min(delayMs, 60 * 1000)));
        context.virusTotalScanTimer.unref?.();
    };
}
export function createProcessVirusTotalScanQueue(context: Pick<ApplicationContext, "virusTotalScanRunning" | "virusTotalScanQueue" | "virusTotalScanNextAllowedAt" | "settings" | "scheduleVirusTotalScan">) {
    return async () => {
        if (context.virusTotalScanRunning)
            return;
        const queuedItem = context.virusTotalScanQueue.next();
        if (!queuedItem) {
            const wakeAt = context.virusTotalScanQueue.nextWakeAt();
            context.virusTotalScanNextAllowedAt = wakeAt || 0;
            if (wakeAt !== null && context.settings.virusTotalCloudEnabled === true)
                context.scheduleVirusTotalScan(Math.max(0, wakeAt - Date.now()));
            return;
        }
        context.virusTotalScanRunning = true;
        let continueQueue = true;
        try {
            if (context.settings.virusTotalCloudEnabled !== true) {
                continueQueue = false;
                return;
            }
            const apiKey = await loadVirusTotalApiKey();
            if (!apiKey) {
                continueQueue = false;
                return;
            }
            if (runtimeState.virusTotalNextLookupAllowedAt > Date.now())
                return;
            runtimeState.virusTotalActiveScanId = Number(queuedItem.id);
            await context.virusTotalScanQueue.processNext({
                keyId: createHash("sha256").update(apiKey).digest("hex"),
                fingerprint: getFileFingerprint,
                hash: filePath => hashFile(filePath, "sha256"),
                lookup: hash => fetchVirusTotalFileReport(apiKey, hash),
                upload: (filePath, _hash, canContinue) => virusTotalFileAnalysis.upload(apiKey, filePath, async () => context.settings.virusTotalCloudEnabled === true && await loadVirusTotalApiKey() === apiKey && await canContinue()),
                analysis: async (id, hash) => {
                    const payload = await virusTotalFileAnalysis.analysis(apiKey, id, hash);
                    return payload ? summarizeVirusTotalFileReport(hash, payload) : null;
                },
                excluded: async (filePath) => shouldSkipBuiltInScanPath(context.settings, filePath) || isExcluded(filePath, await getExceptions()),
                detection: async (item, report) => {
                    await addScanResult({
                        source: "manual", scanType: item.scan_type, target: item.target,
                        originalPath: item.file_path, threatName: buildVirusTotalThreatName(report),
                        engine: "VirusTotal", sha256: report.hash,
                        virusTotalRefinement: buildVirusTotalRefinement(report)
                    });
                }
            }, queuedItem);
            context.virusTotalScanNextAllowedAt = 0;
        }
        catch (e: any) {
            const status = Number(e?.status || e?.response?.status || 0);
            context.virusTotalScanQueue.retry(queuedItem, e);
            if (status === 429 && !e?.localQuotaLimit) {
                runtimeState.virusTotalNextLookupAllowedAt = Math.max(runtimeState.virusTotalNextLookupAllowedAt, e?.nextAllowedAt || Date.now() + 15 * 60 * 1000);
            }
            if (status === 401 || status === 403)
                context.virusTotalScanQueue.setState(queuedItem.job_id, "paused");
            context.virusTotalScanQueue.message(queuedItem.job_id, e?.message || "Cloud check failed; waiting to retry.");
        }
        finally {
            context.virusTotalScanRunning = false;
            runtimeState.virusTotalActiveScanId = 0;
            const wakeAt = context.virusTotalScanQueue.nextWakeAt();
            context.virusTotalScanNextAllowedAt = wakeAt || 0;
            if (continueQueue && wakeAt !== null)
                context.scheduleVirusTotalScan(Math.max(0, Math.max(wakeAt, runtimeState.virusTotalNextLookupAllowedAt) - Date.now()));
        }
    };
}
export function createGetVirusTotalRefinementQueueItems(context: Pick<ApplicationContext, "settings">) {
    return async () => {
        if (context.settings.virusTotalCloudEnabled !== true)
            return [];
        if (!await loadVirusTotalApiKey())
            return [];
        const results = await getScanResults();
        return results.filter((result: any) => (isVirusTotalAutoRefinementCandidate(result, context.settings) && !getVirusTotalRefinementStatus(result)) ||
            getVirusTotalResultUploadFollowupAt(result) > 0);
    };
}
export function createGetVirusTotalRefinementQueueStatus(context: Pick<ApplicationContext, "getVirusTotalRefinementQueueItems" | "settings">) {
    return async () => {
        const queued = await context.getVirusTotalRefinementQueueItems().catch(() => []);
        return {
            enabled: context.settings.virusTotalCloudEnabled === true &&
                (context.settings.virusTotalAutoRefineEnabled === true || context.settings.virusTotalShieldBackgroundCheckEnabled === true),
            configured: Boolean(await loadVirusTotalApiKey()),
            running: runtimeState.virusTotalRefinementRunning,
            queued: queued.length,
            nextAllowedAt: runtimeState.virusTotalRefinementNextAllowedAt,
            lastMessage: runtimeState.virusTotalRefinementLastMessage
        };
    };
}
export function createProcessNextVirusTotalRefinement(context: Pick<ApplicationContext, "settings" | "scheduleVirusTotalRefinement" | "getVirusTotalRefinementQueueItems">) {
    return async () => {
        if (runtimeState.virusTotalRefinementRunning)
            return;
        if (context.settings.virusTotalCloudEnabled !== true)
            return;
        const apiKey = await loadVirusTotalApiKey();
        if (!apiKey) {
            runtimeState.virusTotalRefinementLastMessage = "VirusTotal API key is not configured.";
            return;
        }
        const now = Date.now();
        if (now < runtimeState.virusTotalRefinementNextAllowedAt) {
            context.scheduleVirusTotalRefinement(runtimeState.virusTotalRefinementNextAllowedAt - now);
            return;
        }
        runtimeState.virusTotalRefinementRunning = true;
        let activeResults: any[] = [];
        let activeResult: any = null;
        try {
            activeResults = await getScanResults();
            activeResult = activeResults.find(isVirusTotalResultUploadFollowupDue) || activeResults.find((item: any) => isVirusTotalAutoRefinementCandidate(item, context.settings) && !getVirusTotalRefinementStatus(item));
            if (!activeResult) {
                const nextFollowupAt = Math.min(...activeResults
                    .map(getVirusTotalResultUploadFollowupAt)
                    .filter((value: number) => value > Date.now()));
                if (Number.isFinite(nextFollowupAt)) {
                    runtimeState.virusTotalRefinementLastMessage = "Waiting for VirusTotal analysis results.";
                    context.scheduleVirusTotalRefinement(Math.max(1000, nextFollowupAt - Date.now()));
                }
                else {
                    runtimeState.virusTotalRefinementLastMessage = "No VirusTotal refinement items queued.";
                }
                return;
            }
            runtimeState.virusTotalActiveResultsId = String(activeResult.id);
            runtimeState.virusTotalResultsWaitReason = "";
            runtimeState.virusTotalActiveResultsPhase = "pending";
            const cloudCheck = await runVirusTotalResultCloudCheck(activeResults, activeResult, context.settings, apiKey, phase => { runtimeState.virusTotalActiveResultsPhase = phase; });
            await addHistory({
                type: cloudCheck.uploaded ? "virustotal-results-upload" : "virustotal-auto-refine",
                target: activeResult.originalPath || cloudCheck.sha256,
                result: 0,
                threatsFound: 0,
                scannedFiles: 1,
                duration: 1,
                actionTaken: cloudCheck.uploaded
                    ? cloudCheck.uploadAnalysisId ? englishText("backend.results.uploaded_for_analysis", {
                        uploadAnalysisId: String(cloudCheck.uploadAnalysisId)
                    }) : englishText("backend.results.uploaded_for_analysis_4990dae")
                    : activeResult.virusTotalRefinement.label || englishText("backend.results.checked")
            }).catch(() => { });
            runtimeState.virusTotalRefinementLastMessage = `${activeResult.virusTotalRefinement.label}: ${activeResult.originalPath || cloudCheck.sha256}`;
            runtimeState.virusTotalRefinementNextAllowedAt = Date.now() + virusTotalPublicApiLimits.perLookupMs;
        }
        catch (e: any) {
            const status = Number(e?.status || e?.response?.status || 0);
            const localDelayMs = Math.max(1000, Number(e?.nextAllowedAt || 0) - Date.now());
            const backoffMs = e?.localRateLimit || e?.localQuotaLimit
                ? localDelayMs
                : status === 429 ? 15 * 60 * 1000 : 60 * 1000;
            runtimeState.virusTotalRefinementLastMessage = e?.message || String(e);
            runtimeState.virusTotalResultsWaitReason = runtimeState.virusTotalRefinementLastMessage;
            runtimeState.virusTotalRefinementNextAllowedAt = Date.now() + backoffMs;
            if (activeResult && status !== 429 && status !== 401 && status !== 403) {
                activeResult.virusTotalRefinement = {
                    status: "error",
                    label: englishText("backend.virustotal.refinement_error"),
                    severity: "neutral",
                    checkedAt: Date.now(),
                    hash: String(activeResult.sha256 || ""),
                    stats: null,
                    message: englishText("backend.virustotal.retry_the_check_after_restoring_file_access_or_remove_the_finding", {
                        virusTotalRefinementLastMessage: String(runtimeState.virusTotalRefinementLastMessage)
                    })
                };
                await persistVirusTotalResult(activeResult).catch(() => { });
            }
            console.warn(englishText("backend.virustotal.virustotal_refinement_paused"), runtimeState.virusTotalRefinementLastMessage);
        }
        finally {
            runtimeState.virusTotalRefinementRunning = false;
            runtimeState.virusTotalActiveResultsId = "";
            runtimeState.virusTotalActiveResultsPhase = "pending";
        }
        const queued = await context.getVirusTotalRefinementQueueItems().catch(() => []);
        if (queued.length > 0)
            context.scheduleVirusTotalRefinement(Math.max(0, runtimeState.virusTotalRefinementNextAllowedAt - Date.now()));
    };
}
