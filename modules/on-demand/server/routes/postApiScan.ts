import { englishText } from "../../../../shared/localization/runtime";
import { loadVirusTotalApiKey } from "../../../../addons/virustotal/server/account";
import { buildClamFileListArgs, getClamScanChildTimeoutMs, isNoisyClamFileLine, parseClamOutputPath } from "../../../../engines/clamav/server/arguments";
import { flushPendingClamdDatabaseReload, manageClamd, stopClamdAfterScannerTimeout, waitForClamdReady } from "../../../../engines/clamav/server/daemon";
import { isImportantClamOutputLine, isLockedOrUnstableClamLine, uniqueFailedFilePathsFromClamLines } from "../../../../engines/clamav/server/output";
import { runYaraScanForTargets } from "../../../../engines/yara/server/scan";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { displayFileName, sleep } from "../../../../server/core/utils";
import { canResumeScanType, getFileFingerprint, getScanFileRecords, scanSessionRowToProgress } from "../../../../server/scanning/files";
import { applyScanProcessPriority, getPerWorkerBatchCap, getScanIntensityProfile } from "../../../../server/scanning/intensity";
import { chunkItems, createManualScanPathSkipper, createScanFileList, enumerateContextScanTargetFiles, enumerateScanTargetFiles, normalizeContextMenuAction, normalizeContextMenuTargets, resolveScanTarget } from "../../../../server/scanning/targets";
import { virusTotalLimitWarningsEnabled } from "../../../../addons/virustotal/server/virusTotalLimitWarning";
import { getExceptions, isExcluded } from "../../../exceptions/server/service";
import { getQuarantineMap } from "../../../quarantine/server/storage";
import { addHistory } from "../../../history/server/storage";
import { quarantineFile } from "../../../quarantine/server/files";
import { saveQuarantineMap } from "../../../quarantine/server/storage";
import { addScanFailedFiles } from "../../../results/server/rows";
import { addScanResult } from "../../../results/server/storage";
import { addTargetToShieldCache, normalizeCachePath } from "../../../shield/server/cache";
import { createInitialScanProgress } from "../sessions";
import { spawn } from "child_process";
import fs from "fs/promises";
import path from "path";
export function registerPostApiScan(app: any, context: Pick<ApplicationContext, "scanSessions" | "virusTotalScanQueue" | "settings" | "activeJobs" | "saveJobProgress" | "appendJobLogs" | "sendScanSummary" | "createScanHeartbeat" | "scheduleVirusTotalScan" | "enqueueContextMenuVirusTotalCheck" | "shieldScanCache">) {
    app.post("/api/scan", async (req, res) => {
        const { target, type, resumeJobId } = req.body;
        const contextMenuTargets = normalizeContextMenuTargets(req.body?.targets);
        const hasContextMenuTargets = !resumeJobId && contextMenuTargets.length > 0;
        const contextMenuAction = normalizeContextMenuAction(req.body?.contextAction);
        const contextMenuYaraEnabled = contextMenuAction !== "clamav";
        const contextMenuVirusTotalEnabled = contextMenuAction === "clamav-yara-vt";
        const scanSource = req.body?.source === "scheduled"
            ? "scheduled"
            : req.body?.source === "context-menu" || hasContextMenuTargets ? "context-menu" : "manual";
        const resumeSession = resumeJobId ? context.scanSessions.getSession(String(resumeJobId)) : null;
        if (resumeJobId && (!resumeSession || !canResumeScanType(resumeSession.type))) {
            return res.status(404).json({ error: englishText("backend.on_demand.no_resumable_scan_was_found") });
        }
        const isResume = !!resumeSession;
        const scanType = resumeSession?.type || (hasContextMenuTargets ? "context" : type);
        const scanTarget = resumeSession?.target || (hasContextMenuTargets
            ? (contextMenuTargets.length === 1 ? contextMenuTargets[0] : `${contextMenuTargets.length} selected items`)
            : (scanType === "memory" ? "Running process images" : (resolveScanTarget(scanType, target) || "C:\\")));
        const effectiveTarget = scanType === "memory" || hasContextMenuTargets ? undefined : resolveScanTarget(scanType, scanTarget);
        const jobId = resumeSession?.job_id || Date.now().toString();
        const savedCloudScan = resumeSession ? context.virusTotalScanQueue.get(jobId) : null;
        const virusTotalAllFiles = scanSource === "manual" &&
            (Boolean(savedCloudScan && savedCloudScan.status !== "cancelled") || req.body?.virusTotalAllFiles === true);
        if (virusTotalAllFiles && (context.settings.virusTotalCloudEnabled !== true || !await loadVirusTotalApiKey())) {
            return res.status(400).json({ error: englishText("backend.on_demand.enable_virustotal_and_configure_its_api_key_in_settings_before_ch") });
        }
        if (context.activeJobs[jobId]?.status === "running") {
            return res.json({ jobId, status: "started", resumed: isResume, progress: context.activeJobs[jobId].progress || null });
        }
        const conflictingScan = Object.entries(context.activeJobs).find(([activeJobId, job]) => activeJobId !== jobId &&
            job.status === "running" &&
            ["disk", "folder", "file", "memory", "context"].includes(job.progress?.type || ""));
        if (conflictingScan) {
            return res.status(409).json({ error: englishText("backend.on_demand.another_on_demand_or_scheduled_scan_is_already_running") });
        }
        if (runtimeState.isSimulated) {
            res.json({ jobId, status: "started", simulated: true });
            context.activeJobs[jobId] = {
                status: "running",
                kind: "scan",
                logs: ["Starting simulated scan..."],
                progress: createInitialScanProgress(jobId, scanType, scanTarget)
            };
            context.saveJobProgress(jobId, { totalFiles: 1240, phase: englishText("backend.on_demand.simulated_scan") });
            setTimeout(async () => {
                const isThreat = Math.random() < 0.5 && scanType !== "update";
                let threatsFound = 0;
                let actionTaken = "None";
                if (isThreat && scanSource !== "scheduled") {
                    threatsFound = 1;
                    const filePath = path.join(effectiveTarget || "C:\\TestPath", "eicar.com.txt");
                    await addScanResult({
                        source: scanSource,
                        scanType,
                        target: scanTarget,
                        originalPath: filePath,
                        threatName: "Eicar-Test-Signature (Simulated)"
                    });
                    context.appendJobLogs(jobId, [englishText("backend.on_demand.threat_found_sent_to_results", {
                            filePath: String(filePath)
                        })]);
                    actionTaken = "Sent to Results";
                }
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = isThreat ? 1 : 0;
                context.appendJobLogs(jobId, [englishText("backend.on_demand.scan_completed")]);
                context.saveJobProgress(jobId, {
                    status: "done",
                    phase: englishText("scan.complete"),
                    scannedFiles: 1240,
                    currentFile: englishText("scan.complete"),
                    completedAt: Date.now(),
                    threatsFound,
                    result: isThreat ? 1 : 0,
                    actionTaken
                });
                await addHistory({
                    type: scanSource === "scheduled" ? `scheduled-scan-${scanType}` : `scan-${scanType}`,
                    target: scanTarget,
                    result: isThreat ? 1 : 0,
                    threatsFound,
                    scannedFiles: 1240,
                    duration: 3,
                    actionTaken
                });
                if (isThreat) {
                    context.sendScanSummary({
                        title: scanSource === "scheduled" ? englishText("backend.on_demand.scheduled_scan_found_threats") : englishText("backend.on_demand.scan_found_threats"),
                        message: englishText("backend.on_demand.threat_found", {
                            threatsFound: String(threatsFound),
                            value2: String(threatsFound === 1 ? "" : englishText("dns.s"))
                        }),
                        detail: englishText("backend.on_demand.action", {
                            actionTaken: String(actionTaken)
                        }),
                        target: scanTarget,
                        action: actionTaken === "Quarantined" ? "quarantine" : "results"
                    });
                }
            }, 3000);
            return;
        }
        try {
            const dbFiles = await fs.readdir(context.settings.databaseDir);
            const hasDb = dbFiles.some(f => f.endsWith(".cvd") || f.endsWith(".cld"));
            if (!hasDb) {
                return res.status(400).json({ error: englishText("backend.on_demand.no_virus_database_found_please_go_to_updates_and_download_virus_d") });
            }
        }
        catch {
            return res.status(400).json({ error: "Failed to check virus database. Please update definitions." });
        }
        if (virusTotalAllFiles)
            context.virusTotalScanQueue.start(jobId, scanType, scanTarget);
        context.activeJobs[jobId] = {
            status: "running",
            kind: "scan",
            logs: [],
            analysisLogs: [],
            progress: isResume
                ? { ...createInitialScanProgress(jobId, scanType, scanTarget), ...(scanSessionRowToProgress(resumeSession) || {}), status: "running", phase: englishText("backend.on_demand.resuming"), virusTotalAllFiles }
                : { ...createInitialScanProgress(jobId, scanType, scanTarget), virusTotalAllFiles }
        };
        res.json({ jobId, status: "started", resumed: isResume, progress: context.activeJobs[jobId].progress || null });
        Promise.resolve().then(async () => {
            context.saveJobProgress(jobId, { phase: isResume ? englishText("backend.on_demand.loading_saved_scan") : englishText("backend.on_demand.enumerating_files") });
            const shouldSkipScanFile = createManualScanPathSkipper(context.settings, scanType);
            const resumableScan = canResumeScanType(scanType);
            let totalFiles = isResume
                ? Math.max(Number(resumeSession?.total_files || 0), context.scanSessions.countFiles(jobId))
                : 0;
            let scannedFiles = isResume ? context.scanSessions.countDoneFiles(jobId) : 0;
            const memoryYaraTargets: string[] = [];
            const contextVirusTotalTargets: string[] = [];
            if (scanType === "disk" && process.platform === "win32") {
                context.appendJobLogs(jobId, [
                    englishText("backend.on_demand.skipping_windows_locked_paging_system_files_that_cannot_be_opened"),
                    "C:\\pagefile.sys, C:\\swapfile.sys, C:\\hiberfil.sys, C:\\DumpStack.log.tmp"
                ]);
            }
            let isClamd = false;
            if (context.settings.offloadToMemory && context.settings.clamdscanPath) {
                try {
                    await fs.access(context.settings.clamdscanPath);
                    context.appendJobLogs(jobId, [englishText("backend.shield.offload_to_memory_is_enabled_preparing_clamd")]);
                    await manageClamd(context.settings);
                    const ready = await waitForClamdReady(context.settings, 45000, message => context.appendJobLogs(jobId, [message]));
                    if (ready.ready) {
                        isClamd = true;
                        context.appendJobLogs(jobId, [englishText("backend.on_demand.clamd_is_ready_using_clamdscan_workers")]);
                    }
                    else {
                        context.appendJobLogs(jobId, [
                            englishText("backend.shield.clamd_did_not_become_ready", {
                                reason: String(ready.reason)
                            }),
                            ...ready.details.map(line => `clamd detail: ${line}`),
                            englishText("backend.on_demand.falling_back_to_clamscan_for_this_scan")
                        ]);
                    }
                }
                catch (e: any) {
                    console.debug(englishText("backend.on_demand.scan_offload_requested_but_clamdscan_is_unavailable_falling_back"), e?.message || e);
                    context.appendJobLogs(jobId, [englishText("backend.shield.offload_requested_but_clamdscan_is_unavailable_falling_back_to_cl", {
                            value1: String(e?.message || e)
                        })]);
                }
            }
            const exePath = isClamd ? context.settings.clamdscanPath : context.settings.clamscanPath;
            let scanProfile = getScanIntensityProfile(context.settings, totalFiles, scanSource);
            const chunkSize = scanProfile.batchSize;
            let threatsFound = 0;
            let errorsFound = 0;
            let fatalScanErrors = 0;
            let scannerFailureBatches = 0;
            let failedFilesQueuedForRescan = 0;
            let ignoredDetections = 0;
            let ignoredExceptionDetections = 0;
            let ignoredProviderSafetyDetections = 0;
            let actionTaken = "None";
            const startedAt = Date.now();
            const heartbeat = context.createScanHeartbeat(jobId, "Scan");
            const exceptions = await getExceptions();
            context.appendJobLogs(jobId, [
                isResume ? englishText("backend.on_demand.resuming_interrupted_scan") : (scanType === "memory" ? englishText("backend.on_demand.scanning_running_programs") : englishText("backend.on_demand.scanning_selected_files")),
                isResume ? englishText("backend.on_demand.files_remaining", {
                    value1: String(Math.max(0, totalFiles - scannedFiles))
                }) : englishText("backend.on_demand.preparing_scan_queue")
            ]);
            const handleFoundLine = async (line: string) => {
                const match = line.match(/^(.*?):\s+(.*?)\s+FOUND$/);
                if (!match)
                    return;
                const originalPath = match[1];
                if (shouldSkipScanFile(originalPath)) {
                    ignoredDetections++;
                    ignoredProviderSafetyDetections++;
                    context.appendJobLogs(jobId, [
                        englishText("backend.on_demand.threat_found_f3f5927", {
                            value1: String(displayFileName(originalPath))
                        }),
                        englishText("backend.on_demand.action_ignored_because_this_path_is_excluded_from_provider_safety")
                    ]);
                    context.saveJobProgress(jobId, { actionTaken: englishText("backend.on_demand.ignored_by_exclusions") });
                    return;
                }
                if (isExcluded(originalPath, exceptions)) {
                    ignoredDetections++;
                    ignoredExceptionDetections++;
                    context.appendJobLogs(jobId, [
                        englishText("backend.on_demand.threat_found_f3f5927", {
                            value1: String(displayFileName(originalPath))
                        }),
                        englishText("backend.on_demand.action_ignored_because_it_is_in_exceptions")
                    ]);
                    context.saveJobProgress(jobId, { actionTaken: englishText("backend.on_demand.ignored_by_exceptions") });
                    return;
                }
                threatsFound++;
                const threatName = match[2];
                const action = context.settings.scanDetectionAction || "results";
                if (action === "quarantine") {
                    try {
                        const quarantined = await quarantineFile(originalPath, threatName, context.settings.quarantineDir);
                        const qMap = await getQuarantineMap();
                        qMap[quarantined.fileName] = quarantined.metadata;
                        await saveQuarantineMap(qMap);
                        context.appendJobLogs(jobId, [
                            englishText("backend.on_demand.threat_found_f3f5927", {
                                value1: String(displayFileName(originalPath))
                            }),
                            englishText("backend.on_demand.action_quarantined")
                        ]);
                        actionTaken = "Quarantined";
                    }
                    catch (e: any) {
                        context.appendJobLogs(jobId, [englishText("backend.on_demand.quarantine_failed_for", {
                                value1: String(displayFileName(originalPath)),
                                message: String(e.message)
                            })]);
                        actionTaken = "Quarantine Failed";
                    }
                }
                else {
                    await addScanResult({
                        source: scanSource,
                        scanType,
                        target: scanTarget,
                        originalPath,
                        threatName
                    });
                    context.appendJobLogs(jobId, [
                        englishText("backend.on_demand.threat_found_f3f5927", {
                            value1: String(displayFileName(originalPath))
                        }),
                        englishText("backend.on_demand.action_sent_to_results")
                    ]);
                    actionTaken = "Sent to Results";
                }
                context.saveJobProgress(jobId, { threatsFound, actionTaken });
            };
            const queueFailedFilesForRescan = async (pathsToQueue: string[], batchNumber: number, exitCode: number, reason: string) => {
                const seen = new Set<string>();
                const uniquePaths = pathsToQueue.filter(filePath => {
                    const normalizedPath = normalizeCachePath(filePath);
                    if (!filePath || !normalizedPath || seen.has(normalizedPath))
                        return false;
                    seen.add(normalizedPath);
                    return true;
                });
                if (uniquePaths.length === 0)
                    return 0;
                const timestamp = Date.now();
                const queued = await addScanFailedFiles(uniquePaths.map(filePath => ({
                    timestamp,
                    jobId,
                    source: scanSource,
                    scanType,
                    target: scanTarget,
                    batchNumber,
                    exitCode,
                    originalPath: filePath,
                    reason,
                    status: "pending"
                }))).catch((e: any) => {
                    context.appendJobLogs(jobId, [englishText("backend.on_demand.failed_to_queue_files_for_rescan", {
                            value1: String(e?.message || e)
                        })]);
                    return 0;
                });
                failedFilesQueuedForRescan += queued;
                return queued;
            };
            const scanChunk = async (chunk: string[], batchNumber: number, totalBatches?: number) => {
                const job = context.activeJobs[jobId];
                if (!job || job.status !== "running" || chunk.length === 0)
                    return false;
                const listPath = await createScanFileList(chunk);
                const args = buildClamFileListArgs(context.settings, isClamd, listPath);
                const chunkLines: string[] = [];
                context.saveJobProgress(jobId, {
                    phase: totalBatches ? englishText("backend.on_demand.clamav_batch", {
                        batchNumber: String(batchNumber),
                        totalBatches: String(totalBatches)
                    }) : englishText("backend.on_demand.clamav_batch_01baa00", {
                        batchNumber: String(batchNumber)
                    }),
                    currentFile: chunk[0] || "",
                    scannedFiles,
                    totalFiles
                });
                let childProcess: any = null;
                const code = await new Promise<number>((resolve) => {
                    let settled = false;
                    let timedOut = false;
                    let timeout: NodeJS.Timeout | null = null;
                    const finish = (resultCode: number) => {
                        if (settled)
                            return;
                        settled = true;
                        if (timeout)
                            clearTimeout(timeout);
                        resolve(resultCode);
                    };
                    const child = spawn(exePath, args, { windowsHide: true });
                    childProcess = child;
                    context.activeJobs[jobId].process = child;
                    if (!context.activeJobs[jobId].processes)
                        context.activeJobs[jobId].processes = new Set();
                    context.activeJobs[jobId].processes.add(child);
                    applyScanProcessPriority(child, context.settings, scanSource, isClamd ? "clamdscan" : "clamscan");
                    const timeoutMs = getClamScanChildTimeoutMs(context.settings, chunk.length);
                    timeout = setTimeout(() => {
                        timedOut = true;
                        context.appendJobLogs(jobId, [
                            englishText("backend.on_demand.scanner_timed_out_after_s_for_batch", {
                                value1: String(Math.round(timeoutMs / 1000)),
                                batchNumber: String(batchNumber)
                            }),
                            englishText("backend.on_demand.stopping_this_scanner_worker_and_queueing_the_file_batch_for_resc")
                        ]);
                        context.saveJobProgress(jobId, {
                            errorsFound: errorsFound + 1,
                            actionTaken: englishText("backend.on_demand.scanner_timeout")
                        });
                        try {
                            child.kill();
                        }
                        catch { }
                        if (isClamd) {
                            stopClamdAfterScannerTimeout(message => context.appendJobLogs(jobId, [message]));
                        }
                        setTimeout(() => finish(-2), 5000).unref?.();
                    }, timeoutMs);
                    timeout.unref?.();
                    let lastCurrentFileUpdateAt = 0;
                    const handleEngineLines = (lines: string[]) => {
                        chunkLines.push(...lines);
                        const visibleLines = lines.filter(isImportantClamOutputLine);
                        if (visibleLines.length)
                            context.appendJobLogs(jobId, visibleLines);
                        const now = Date.now();
                        if (now - lastCurrentFileUpdateAt > 250) {
                            const latestPath = [...lines].reverse().map(parseClamOutputPath).find(Boolean);
                            if (latestPath) {
                                lastCurrentFileUpdateAt = now;
                                context.saveJobProgress(jobId, { currentFile: latestPath });
                            }
                        }
                    };
                    child.stdout.on("data", data => {
                        const lines = data.toString().split("\n").map((line: string) => line.trim()).filter(Boolean);
                        handleEngineLines(lines);
                    });
                    child.stderr.on("data", data => {
                        const lines = data.toString().split("\n").map((line: string) => line.trim()).filter(Boolean);
                        handleEngineLines(lines);
                    });
                    child.on("error", error => {
                        context.appendJobLogs(jobId, [englishText("backend.on_demand.process_error", {
                                message: String(error.message)
                            })]);
                        finish(-1);
                    });
                    child.on("close", closeCode => finish(timedOut ? -2 : (closeCode ?? 0)));
                });
                await fs.unlink(listPath).catch(() => { });
                context.activeJobs[jobId]?.processes?.delete(childProcess);
                if (context.activeJobs[jobId]?.process === childProcess)
                    context.activeJobs[jobId].process = null;
                if (context.activeJobs[jobId]?.status !== "running") {
                    return false;
                }
                let scannerExitQueuedForRescan = false;
                if (code !== 0 && code !== 1) {
                    if (code === -1) {
                        fatalScanErrors++;
                        errorsFound++;
                        context.appendJobLogs(jobId, [
                            englishText("backend.on_demand.scanner_process_could_not_be_started"),
                            englishText("backend.on_demand.the_scan_was_stopped_because_the_scanner_process_itself_failed")
                        ]);
                        context.saveJobProgress(jobId, { errorsFound, result: -1, actionTaken: englishText("desktop.electron_main.scanner_error") });
                        return false;
                    }
                    scannerFailureBatches++;
                    errorsFound++;
                    const failedPaths = uniqueFailedFilePathsFromClamLines(chunkLines);
                    const queuedCount = await queueFailedFilesForRescan(failedPaths.length > 0 ? failedPaths : chunk, batchNumber, code, failedPaths.length > 0 ? "File access error during scan" : `Scanner exit code ${code}`);
                    context.appendJobLogs(jobId, [
                        englishText("backend.on_demand.scanner_process_returned_exit_code_for_batch", {
                            code: String(code),
                            batchNumber: String(batchNumber)
                        }),
                        englishText("backend.on_demand.file_queued_for_rescan_continuing_scan", {
                            value1: String(queuedCount.toLocaleString()),
                            value2: String(queuedCount === 1 ? "" : englishText("dns.s"))
                        })
                    ]);
                    actionTaken = "Queued files for rescan";
                    scannerExitQueuedForRescan = true;
                    context.saveJobProgress(jobId, { errorsFound, result: 0, actionTaken });
                }
                let suppressedCleanLines = 0;
                let suppressedFileWarningLines = 0;
                for (const line of chunkLines) {
                    if (line.includes(" FOUND"))
                        await handleFoundLine(line);
                    else if (isNoisyClamFileLine(line) || isLockedOrUnstableClamLine(line)) {
                        if (line.includes(" ERROR") || line.startsWith("ERROR:") || line.startsWith("WARNING:") || line.startsWith("LibClamAV Error:")) {
                            errorsFound++;
                            suppressedFileWarningLines++;
                        }
                        else {
                            suppressedCleanLines++;
                        }
                    }
                    else if (line.includes(" ERROR") || line.startsWith("WARNING:") || line.startsWith("ERROR:")) {
                        errorsFound++;
                    }
                }
                if (!scannerExitQueuedForRescan) {
                    const failedPaths = uniqueFailedFilePathsFromClamLines(chunkLines);
                    if (failedPaths.length > 0) {
                        const queuedCount = await queueFailedFilesForRescan(failedPaths, batchNumber, code, "File access error during scan");
                        if (queuedCount > 0) {
                            context.appendJobLogs(jobId, [
                                englishText("backend.on_demand.inaccessible_file_queued_for_rescan", {
                                    value1: String(queuedCount.toLocaleString()),
                                    value2: String(queuedCount === 1 ? "" : englishText("dns.s"))
                                })
                            ]);
                            actionTaken = "Queued files for rescan";
                        }
                    }
                }
                if (suppressedCleanLines > 0 || suppressedFileWarningLines > 0) {
                    context.appendJobLogs(jobId, [
                        scannerExitQueuedForRescan
                            ? (totalBatches ? englishText("backend.on_demand.batch_complete_with_inaccessible_files", {
                                batchNumber: String(batchNumber),
                                totalBatches: String(totalBatches)
                            }) : englishText("backend.on_demand.batch_complete_with_inaccessible_files_3e1cc32", {
                                batchNumber: String(batchNumber)
                            }))
                            : (totalBatches ? englishText("backend.on_demand.batch_complete", {
                                batchNumber: String(batchNumber),
                                totalBatches: String(totalBatches)
                            }) : englishText("backend.on_demand.batch_complete_c1f2144", {
                                batchNumber: String(batchNumber)
                            }))
                    ]);
                }
                if (resumableScan) {
                    context.scanSessions.markFilesDone(jobId, await getScanFileRecords(chunk));
                    scannedFiles = context.scanSessions.countDoneFiles(jobId);
                }
                else {
                    scannedFiles += chunk.length;
                }
                context.saveJobProgress(jobId, {
                    scannedFiles,
                    errorsFound,
                    currentFile: chunk[chunk.length - 1] || "",
                    phase: totalBatches ? englishText("backend.on_demand.clamav_batch", {
                        batchNumber: String(batchNumber),
                        totalBatches: String(totalBatches)
                    }) : englishText("backend.on_demand.clamav_batch_01baa00", {
                        batchNumber: String(batchNumber)
                    }),
                    result: threatsFound > 0 ? 1 : 0
                });
                return true;
            };
            if (!isResume) {
                if (resumableScan)
                    context.scanSessions.saveFiles(jobId, []);
                const enumerationBatchSize = Math.max(chunkSize, 1000);
                let pendingRecords: Array<{
                    filePath: string;
                    size: number;
                    mtimeMs: number;
                }> = [];
                let firstFile = "";
                const fileSource = hasContextMenuTargets
                    ? enumerateContextScanTargetFiles(context.settings, contextMenuTargets)
                    : enumerateScanTargetFiles(context.settings, scanType, scanTarget);
                for await (const filePath of fileSource) {
                    const fingerprint = await getFileFingerprint(filePath);
                    const record = {
                        filePath,
                        size: fingerprint?.size || 0,
                        mtimeMs: fingerprint?.mtimeMs || 0
                    };
                    pendingRecords.push(record);
                    if (!firstFile)
                        firstFile = filePath;
                    if (scanType === "memory" || scanType === "context")
                        memoryYaraTargets.push(filePath);
                    if (hasContextMenuTargets && contextMenuVirusTotalEnabled && fingerprint?.size)
                        contextVirusTotalTargets.push(filePath);
                    if (pendingRecords.length >= enumerationBatchSize) {
                        if (resumableScan)
                            context.scanSessions.appendFiles(jobId, pendingRecords, totalFiles);
                        if (virusTotalAllFiles)
                            context.virusTotalScanQueue.addFiles(jobId, pendingRecords);
                        totalFiles += pendingRecords.length;
                        context.saveJobProgress(jobId, {
                            phase: englishText("backend.on_demand.enumerating_files"),
                            totalFiles,
                            currentFile: filePath
                        });
                        pendingRecords = [];
                        await sleep(1);
                    }
                }
                if (pendingRecords.length > 0) {
                    if (resumableScan)
                        context.scanSessions.appendFiles(jobId, pendingRecords, totalFiles);
                    if (virusTotalAllFiles)
                        context.virusTotalScanQueue.addFiles(jobId, pendingRecords);
                    totalFiles += pendingRecords.length;
                    context.saveJobProgress(jobId, {
                        phase: englishText("backend.on_demand.enumerating_files"),
                        totalFiles,
                        currentFile: pendingRecords[pendingRecords.length - 1].filePath
                    });
                }
                if (!resumableScan && (scanType === "memory" || scanType === "context")) {
                    totalFiles = memoryYaraTargets.length;
                }
                if (scanType === "memory" && process.platform === "win32") {
                    context.appendJobLogs(jobId, [englishText("backend.on_demand.running_programs_found", {
                            totalFiles: String(totalFiles)
                        })]);
                }
                if (totalFiles === 0) {
                    if (virusTotalAllFiles)
                        context.virusTotalScanQueue.finishEnumeration(jobId, virusTotalLimitWarningsEnabled(context.settings.virusTotalShowLimitWarnings));
                    context.appendJobLogs(jobId, [englishText("backend.on_demand.no_readable_files_found_for_this_scan_target")]);
                    context.activeJobs[jobId].status = "done";
                    context.activeJobs[jobId].result = 0;
                    context.saveJobProgress(jobId, {
                        status: "done",
                        phase: englishText("backend.on_demand.no_readable_files"),
                        currentFile: englishText("scan.complete"),
                        completedAt: Date.now(),
                        result: 0
                    });
                    await flushPendingClamdDatabaseReload(context.settings).catch(e => console.warn(englishText("backend.shield.deferred_clamd_reload_failed"), e.message));
                    return;
                }
                context.saveJobProgress(jobId, {
                    phase: englishText("backend.on_demand.queued"),
                    totalFiles,
                    scannedFiles: 0,
                    currentFile: firstFile || englishText("backend.on_demand.preparing_final_checks")
                });
                scanProfile = getScanIntensityProfile(context.settings, totalFiles, scanSource);
            }
            else if (totalFiles === 0) {
                if (virusTotalAllFiles)
                    context.virusTotalScanQueue.finishEnumeration(jobId, virusTotalLimitWarningsEnabled(context.settings.virusTotalShowLimitWarnings));
                context.appendJobLogs(jobId, [englishText("backend.on_demand.no_saved_files_were_found_for_this_resumable_scan")]);
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = 0;
                context.saveJobProgress(jobId, {
                    status: "done",
                    phase: englishText("backend.on_demand.no_saved_files"),
                    currentFile: englishText("scan.complete"),
                    completedAt: Date.now(),
                    result: 0
                });
                await flushPendingClamdDatabaseReload(context.settings).catch(e => console.warn(englishText("backend.shield.deferred_clamd_reload_failed"), e.message));
                return;
            }
            if (virusTotalAllFiles) {
                if (isResume) {
                    let afterIndex = -1;
                    for (;;) {
                        const page = context.scanSessions.getFilesPage(jobId, afterIndex);
                        if (!page.length)
                            break;
                        context.virusTotalScanQueue.addFiles(jobId, page.map((file: any) => ({
                            filePath: file.file_path, size: Number(file.size), mtimeMs: Number(file.mtime_ms)
                        })));
                        afterIndex = Number(page[page.length - 1].file_index);
                        await sleep(1);
                    }
                }
                context.virusTotalScanQueue.finishEnumeration(jobId, virusTotalLimitWarningsEnabled(context.settings.virusTotalShowLimitWarnings));
                context.scheduleVirusTotalScan();
                context.appendJobLogs(jobId, [englishText("backend.on_demand.virustotal_files_queued_for_independent_hash_checks_cloud_checks", {
                        value1: String(context.virusTotalScanQueue.get(jobId)?.pending.toLocaleString())
                    })]);
            }
            scanProfile = getScanIntensityProfile(context.settings, totalFiles, scanSource);
            const workerCount = scanProfile.workers;
            const uncappedWorkerBatchSize = Math.max(1, Math.ceil(Math.min(scanProfile.batchSize, Math.max(1, totalFiles)) / workerCount));
            const perWorkerBatchCap = getPerWorkerBatchCap(scanProfile.intensity, isClamd);
            const workerBatchSize = Math.max(1, Math.min(uncappedWorkerBatchSize, perWorkerBatchCap));
            const effectiveBatchWindow = workerBatchSize * workerCount;
            let batchNumber = 0;
            context.appendJobLogs(jobId, [
                englishText("backend.on_demand.intensity_100_worker_priority_file_effective_batch_window_files_p", {
                    label: String(scanProfile.label),
                    intensity: String(scanProfile.intensity),
                    workerCount: String(workerCount),
                    value4: String(workerCount === 1 ? "" : englishText("dns.s")),
                    priorityClass: String(scanProfile.priorityClass),
                    value6: String(effectiveBatchWindow.toLocaleString()),
                    value7: String(workerBatchSize.toLocaleString()),
                    value8: String(scanProfile.delayMs ? englishText("backend.on_demand.ms_pause", {
                        delayMs: String(scanProfile.delayMs)
                    }) : "")
                })
            ]);
            if (resumableScan) {
                context.scanSessions.resetInProgress(jobId);
                scannedFiles = context.scanSessions.countDoneFiles(jobId);
                context.saveJobProgress(jobId, { scannedFiles, totalFiles });
                const runWorker = async () => {
                    while (context.activeJobs[jobId]?.status === "running") {
                        const pendingPage = context.scanSessions.claimPendingFilesPage(jobId, workerBatchSize);
                        if (pendingPage.length === 0)
                            break;
                        const skipped = pendingPage.filter((file: any) => shouldSkipScanFile(file.filePath));
                        if (skipped.length > 0) {
                            context.scanSessions.markFilesDone(jobId, skipped);
                            scannedFiles = context.scanSessions.countDoneFiles(jobId);
                            context.saveJobProgress(jobId, { scannedFiles, totalFiles });
                        }
                        const chunk = pendingPage
                            .filter((file: any) => !shouldSkipScanFile(file.filePath))
                            .map((file: any) => file.filePath);
                        if (chunk.length === 0)
                            continue;
                        const currentBatchNumber = ++batchNumber;
                        const scanned = await scanChunk(chunk, currentBatchNumber);
                        if (!scanned)
                            break;
                        if (scanProfile.delayMs > 0)
                            await sleep(scanProfile.delayMs);
                    }
                };
                await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
            }
            else {
                const chunks = chunkItems(memoryYaraTargets, workerBatchSize);
                let nextChunkIndex = 0;
                const runWorker = async () => {
                    while (context.activeJobs[jobId]?.status === "running") {
                        const chunkIndex = nextChunkIndex++;
                        if (chunkIndex >= chunks.length)
                            break;
                        const scanned = await scanChunk(chunks[chunkIndex], chunkIndex + 1, chunks.length);
                        if (!scanned)
                            break;
                        if (scanProfile.delayMs > 0 && chunkIndex < chunks.length - 1)
                            await sleep(scanProfile.delayMs);
                    }
                };
                await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
            }
            clearInterval(heartbeat);
            if (context.activeJobs[jobId]?.status !== "running") {
                return;
            }
            if (context.activeJobs[jobId]?.status === "running" && (!hasContextMenuTargets || contextMenuYaraEnabled)) {
                context.saveJobProgress(jobId, { phase: englishText("backend.on_demand.yara_scan"), currentFile: "" });
                const yaraTargets = scanType === "memory"
                    ? memoryYaraTargets
                    : hasContextMenuTargets ? contextMenuTargets : (effectiveTarget ? [effectiveTarget] : []);
                const yaraResult = await runYaraScanForTargets(context.settings, yaraTargets, {
                    activeJobs: context.activeJobs,
                    appendJobLogs: context.appendJobLogs,
                    jobId,
                    source: scanSource,
                    scanType,
                    target: scanTarget,
                    action: context.settings.scanDetectionAction || "results"
                });
                if (yaraResult.matches > 0) {
                    threatsFound += yaraResult.matches;
                    actionTaken = yaraResult.actionTaken;
                    context.saveJobProgress(jobId, { threatsFound, actionTaken });
                }
                if (Number(yaraResult.ignoredMatches || 0) > 0) {
                    ignoredDetections += Number(yaraResult.ignoredMatches || 0);
                    context.saveJobProgress(jobId, {
                        actionTaken: threatsFound > 0 ? actionTaken : englishText("backend.on_demand.ignored_by_exclusions")
                    });
                }
            }
            if (context.activeJobs[jobId]?.status === "running" && hasContextMenuTargets && !contextMenuYaraEnabled) {
                context.appendJobLogs(jobId, [englishText("backend.on_demand.yara_skipped_clamav_only_context_menu_scan")]);
            }
            if (context.activeJobs[jobId]?.status === "running" && hasContextMenuTargets && contextMenuVirusTotalEnabled) {
                if (context.settings.virusTotalCloudEnabled === true && await loadVirusTotalApiKey()) {
                    const vtTargets = contextVirusTotalTargets.slice(0, 100);
                    vtTargets.forEach(context.enqueueContextMenuVirusTotalCheck);
                    context.appendJobLogs(jobId, [
                        englishText("backend.on_demand.virustotal_cloud_checks_queued", {
                            length: String(vtTargets.length),
                            value2: String(contextVirusTotalTargets.length > vtTargets.length ? englishText("backend.on_demand.of_eligible_files", {
                                length: String(contextVirusTotalTargets.length)
                            }) : "")
                        })
                    ]);
                }
                else {
                    context.appendJobLogs(jobId, [englishText("backend.on_demand.virustotal_skipped_cloud_check_is_disabled_or_the_api_key_is_not")]);
                }
            }
            const isThreat = threatsFound > 0;
            const scanFailed = fatalScanErrors > 0;
            const hasRescanQueue = failedFilesQueuedForRescan > 0;
            const duration = Math.max(1, Math.round((Date.now() - startedAt) / 1000));
            const rescanAction = hasRescanQueue
                ? `${failedFilesQueuedForRescan.toLocaleString()} file${failedFilesQueuedForRescan === 1 ? "" : "s"} queued for rescan`
                : "";
            const finalActionTaken = scanFailed
                ? "Scanner error"
                : hasRescanQueue
                    ? (isThreat && actionTaken !== "None" ? `${actionTaken}; ${rescanAction}` : rescanAction)
                    : isThreat
                        ? actionTaken
                        : ignoredDetections > 0
                            ? [
                                ignoredExceptionDetections > 0 ? `${ignoredExceptionDetections.toLocaleString()} ignored by Exceptions` : "",
                                ignoredProviderSafetyDetections > 0 ? `${ignoredProviderSafetyDetections.toLocaleString()} ignored by provider-safety exclusions` : ""
                            ].filter(Boolean).join("; ") || `${ignoredDetections.toLocaleString()} ignored by exclusions`
                            : "None";
            context.appendJobLogs(jobId, [
                scanFailed
                    ? englishText("backend.on_demand.scan_stopped_with_scanner_errors") : hasRescanQueue
                    ? englishText("backend.on_demand.scan_complete", {
                        rescanAction: String(rescanAction)
                    }) : isThreat
                    ? englishText("backend.on_demand.scan_complete_detections_found") : ignoredDetections > 0
                    ? englishText("backend.on_demand.scan_complete_no_active_threats_found_detection_ignored_by_exclus", {
                        value1: String(ignoredDetections.toLocaleString()),
                        value2: String(ignoredDetections === 1 ? "" : englishText("dns.s"))
                    }) : englishText("backend.on_demand.scan_complete_no_active_threats_found")
            ]);
            await addHistory({
                type: scanSource === "scheduled" ? `scheduled-scan-${scanType}` : `scan-${scanType}`,
                target: scanTarget,
                result: scanFailed ? -1 : isThreat ? 1 : 0,
                threatsFound,
                scannedFiles,
                duration,
                actionTaken: finalActionTaken
            });
            if (isThreat && scanSource !== "scheduled") {
                context.sendScanSummary({
                    title: englishText("backend.on_demand.scan_found_threats"),
                    message: englishText("backend.on_demand.threat_found", {
                        threatsFound: String(threatsFound),
                        value2: String(threatsFound === 1 ? "" : englishText("dns.s"))
                    }),
                    detail: englishText("backend.on_demand.action_c3f9fc4", {
                        finalActionTaken: String(finalActionTaken)
                    }),
                    target: scanTarget,
                    action: actionTaken === "Quarantined" ? "quarantine" : "results"
                });
            }
            if ((scanType === "disk" || scanType === "folder" || scanType === "file") && effectiveTarget) {
                context.saveJobProgress(jobId, { phase: englishText("backend.on_demand.building_shield_cache"), currentFile: "" });
                context.appendJobLogs(jobId, [englishText("backend.on_demand.updating_real_time_protection_cache")]);
                try {
                    const cachedCount = await addTargetToShieldCache(context.shieldScanCache, effectiveTarget, context.settings, (count) => {
                        console.debug(englishText("backend.on_demand.shield_cache_indexed_files", {
                            count: String(count)
                        }));
                    });
                    context.appendJobLogs(jobId, [englishText("backend.on_demand.protection_cache_updated_files", {
                            cachedCount: String(cachedCount)
                        })]);
                }
                catch (e: any) {
                    context.appendJobLogs(jobId, [`Protection cache update failed: ${e.message}`]);
                }
            }
            context.activeJobs[jobId].status = "done";
            context.activeJobs[jobId].result = scanFailed ? -1 : isThreat ? 1 : 0;
            context.activeJobs[jobId].process = null;
            context.saveJobProgress(jobId, {
                status: "done",
                phase: scanFailed ? englishText("desktop.electron_main.scanner_error") : hasRescanQueue ? englishText("backend.on_demand.complete_with_rescan_queue") : englishText("scan.complete"),
                currentFile: scanFailed ? englishText("desktop.electron_main.scanner_error") : englishText("scan.complete"),
                completedAt: Date.now(),
                result: scanFailed ? -1 : isThreat ? 1 : 0,
                scannedFiles,
                threatsFound,
                errorsFound,
                actionTaken: finalActionTaken
            });
            context.scanSessions.compactCompletedFileLists();
            await flushPendingClamdDatabaseReload(context.settings).catch(e => console.warn(englishText("backend.shield.deferred_clamd_reload_failed"), e.message));
        }).catch(e => {
            const job = context.activeJobs[jobId];
            if (!job)
                return;
            if (virusTotalAllFiles && !context.virusTotalScanQueue.get(jobId)?.enumerated) {
                context.virusTotalScanQueue.setState(jobId, "paused");
                context.virusTotalScanQueue.message(jobId, "File collection was interrupted. Resume the local scan to continue.");
            }
            context.appendJobLogs(jobId, [englishText("updates.error", {
                    message: String(e.message)
                })]);
            const resumable = canResumeScanType(scanType);
            if (resumable)
                context.scanSessions.resetInProgress(jobId);
            job.status = "done";
            job.result = -1;
            job.process = null;
            context.saveJobProgress(jobId, {
                status: resumable ? "error" : "done",
                phase: resumable ? englishText("backend.on_demand.interrupted_by_error") : englishText("desktop.diagnostics.error"),
                currentFile: englishText("desktop.diagnostics.error"),
                completedAt: resumable ? undefined : Date.now(),
                result: -1
            });
            flushPendingClamdDatabaseReload(context.settings).catch((reloadError: any) => console.warn(englishText("backend.shield.deferred_clamd_reload_failed"), reloadError.message));
        });
    });
}
