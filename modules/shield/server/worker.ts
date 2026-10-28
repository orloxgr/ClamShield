import { englishText } from "../../../shared/localization/runtime";
import { buildClamScanArgs, getClamScanChildTimeoutMs } from "../../../engines/clamav/server/arguments";
import { flushPendingClamdDatabaseReload, manageClamd, stopClamdAfterScannerTimeout, waitForClamdReady } from "../../../engines/clamav/server/daemon";
import { isLockedOrUnstableClamLine } from "../../../engines/clamav/server/output";
import { runYaraScanForTargets } from "../../../engines/yara/server/scan";
import { ApplicationContext } from "../../../server/core/applicationContext";
import { runtimeState } from "../../../server/core/runtimeState";
import { displayFileName } from "../../../server/core/utils";
import { existingUniqueDirs, getResolvedSystemPaths } from "../../../server/platform/paths";
import { applyShieldLowImpactPriority } from "../../../server/platform/processes";
import { cacheEntryMatches, getFileFingerprint } from "../../../server/scanning/files";
import { getScanIntensityProfile } from "../../../server/scanning/intensity";
import { createBuiltInScanPathSkipper } from "../../../server/scanning/targets";
import { getExceptions, isExcluded } from "../../exceptions/server/service";
import { getQuarantineMap } from "../../quarantine/server/storage";
import { addHistory } from "../../history/server/storage";
import { quarantineFile } from "../../quarantine/server/files";
import { saveQuarantineMap } from "../../quarantine/server/storage";
import { addScanResult } from "../../results/server/storage";
import { normalizePositiveNumber } from "../../settings/server/validation";
import { normalizeShieldDetectionAction, shieldActionKind, shieldActionNotifies } from "./actions";
import { spawn } from "child_process";
import chokidar from "chokidar";
import fs from "fs/promises";
import path from "path";
export function createQueuePendingThreat(context: Pick<ApplicationContext, "pendingThreatStore">) {
    return async (threat: any) => {
        const fingerprint = await getFileFingerprint(threat.originalPath);
        // Keep unavailable-file detections visible, but ignore late reports for
        // a file whose decision has already been completed.
        const pending = context.pendingThreatStore.register(threat, fingerprint);
        if (pending && runtimeState.pendingThreatHandler)
            runtimeState.pendingThreatHandler(pending);
    };
}
export function createStartShield(context: Pick<ApplicationContext, "shieldWatcher" | "pendingThreatStore" | "shieldScanCache" | "activeJobs" | "appendJobLogs" | "createScanHeartbeat" | "sendApiEvent" | "queuePendingThreat" | "pendingThreats" | "enqueueShieldVirusTotalCheck" | "settings">) {
    return async function (currentSettings: any) {
        if (context.shieldWatcher) {
            await context.shieldWatcher.close();
            context.shieldWatcher = null;
        }
        if (!currentSettings.shieldEnabled) {
            console.log(englishText("backend.shield.shield_is_disabled_in_settings"));
            return;
        }
        const watchPaths: string[] = [];
        const resolvedPaths = await getResolvedSystemPaths();
        if (currentSettings.monitorDownloads)
            watchPaths.push(resolvedPaths.Downloads);
        if (currentSettings.monitorDesktop)
            watchPaths.push(resolvedPaths.Desktop);
        if (currentSettings.monitorDocuments)
            watchPaths.push(resolvedPaths.Documents);
        if (currentSettings.autoDetectBrowserDownloads !== false && Array.isArray(resolvedPaths.BrowserDownloads)) {
            watchPaths.push(...resolvedPaths.BrowserDownloads.map((item: any) => item.path));
        }
        if (Array.isArray(currentSettings.customWatchedFolders)) {
            watchPaths.push(...currentSettings.customWatchedFolders);
        }
        const existingWatchPaths = await existingUniqueDirs(watchPaths);
        console.log(englishText("backend.shield.shield_watch_paths"), existingWatchPaths);
        if (existingWatchPaths.length === 0)
            return;
        const shouldSkipShieldPath = createBuiltInScanPathSkipper(currentSettings);
        context.shieldWatcher = chokidar.watch(existingWatchPaths, {
            ignored: (candidatePath: string) => /(^|[\/\\])\./.test(candidatePath) ||
                shouldSkipShieldPath(candidatePath),
            persistent: true,
            ignoreInitial: true,
            depth: normalizePositiveNumber(currentSettings.shieldDepth, 1, 0, 20),
            ignorePermissionErrors: true,
            awaitWriteFinish: {
                stabilityThreshold: currentSettings.shieldStabilityThreshold || 2000,
                pollInterval: currentSettings.shieldPollInterval || 1000
            }
        });
        context.shieldWatcher.on('error', error => console.error(englishText("backend.shield.shield_watcher_error", {
            error: String(error)
        })));
        const filesBeingScanned = new Set<string>();
        const pendingShieldScans = new Map<string, {
            filePath: string;
            reason: "add" | "change";
        }>();
        const lockedFileBackoff = new Map<string, number>();
        let activeShieldScans = 0;
        const shieldProfile = getScanIntensityProfile(currentSettings, 0, "shield");
        const maxShieldScans = shieldProfile.workers;
        const processShieldQueue = () => {
            while (activeShieldScans < maxShieldScans && pendingShieldScans.size > 0) {
                const next = Array.from(pendingShieldScans.entries()).find(([normalizedPath]) => !filesBeingScanned.has(normalizedPath)) as [
                    string,
                    {
                        filePath: string;
                        reason: "add" | "change";
                    }
                ] | undefined;
                if (!next)
                    return;
                const [normalizedPath, item] = next;
                pendingShieldScans.delete(normalizedPath);
                activeShieldScans++;
                scanShieldFile(item.filePath, item.reason)
                    .catch(err => console.error(englishText("backend.shield.shield_queued_scan_failed"), err))
                    .finally(() => {
                    activeShieldScans--;
                    processShieldQueue();
                });
            }
        };
        const enqueueShieldFile = (filePath: string, reason: "add" | "change") => {
            if (shouldSkipShieldPath(filePath))
                return;
            if (reason === "add")
                context.pendingThreatStore.fileAdded(filePath);
            const normalizedPath = path.resolve(filePath).toLowerCase();
            pendingShieldScans.set(normalizedPath, { filePath, reason });
            processShieldQueue();
        };
        const scanShieldFile = async (filePath: string, reason: "add" | "change") => {
            const normalizedPath = path.resolve(filePath).toLowerCase();
            if (shouldSkipShieldPath(filePath))
                return;
            if (filesBeingScanned.has(normalizedPath))
                return;
            const lockedUntil = lockedFileBackoff.get(normalizedPath) || 0;
            if (lockedUntil > Date.now()) {
                console.debug(englishText("backend.shield.shield_skipping_locked_unstable_file_until", {
                    value1: String(new Date(lockedUntil).toISOString()),
                    filePath: String(filePath)
                }));
                return;
            }
            lockedFileBackoff.delete(normalizedPath);
            filesBeingScanned.add(normalizedPath);
            console.log(englishText("backend.shield.shield_file", {
                value1: String(reason === "add" ? englishText("backend.shield.detected") : englishText("backend.shield.changed")),
                filePath: String(filePath)
            }));
            const fingerprint = await getFileFingerprint(filePath);
            if (!fingerprint || (reason !== "add" && cacheEntryMatches(fingerprint, context.shieldScanCache.get(normalizedPath))) || runtimeState.isSimulated) {
                filesBeingScanned.delete(normalizedPath);
                return;
            }
            const maxFileSizeBytes = normalizePositiveNumber(currentSettings.maxFileSize, 50, 1, 4096) * 1024 * 1024;
            if (fingerprint.size > maxFileSizeBytes) {
                context.shieldScanCache.set(normalizedPath, fingerprint);
                filesBeingScanned.delete(normalizedPath);
                return;
            }
            const jobId = "shield-" + Date.now() + Math.random().toString(36).substring(7);
            context.activeJobs[jobId] = { status: "running", kind: "shield-scan", logs: [], analysisLogs: [] };
            context.appendJobLogs(jobId, [
                englishText("backend.shield.real_time_protection_is_checking", {
                    value1: String(displayFileName(filePath))
                })
            ]);
            let isClamd = false;
            if (currentSettings.offloadToMemory && currentSettings.clamdscanPath) {
                try {
                    await fs.access(currentSettings.clamdscanPath);
                    context.appendJobLogs(jobId, [englishText("backend.shield.offload_to_memory_is_enabled_preparing_clamd")]);
                    await manageClamd(currentSettings);
                    const ready = await waitForClamdReady(currentSettings, 45000, message => context.appendJobLogs(jobId, [message]));
                    if (ready.ready) {
                        isClamd = true;
                        context.appendJobLogs(jobId, [englishText("backend.shield.clamd_is_ready_using_clamdscan")]);
                    }
                    else {
                        context.appendJobLogs(jobId, [
                            englishText("backend.shield.clamd_did_not_become_ready", {
                                reason: String(ready.reason)
                            }),
                            ...ready.details.map(line => `clamd detail: ${line}`),
                            englishText("backend.shield.falling_back_to_clamscan_for_this_shield_scan")
                        ]);
                    }
                }
                catch (e: any) {
                    console.debug(englishText("backend.shield.shield_offload_requested_but_clamdscan_is_unavailable_falling_bac"), e?.message || e);
                    context.appendJobLogs(jobId, [englishText("backend.shield.offload_requested_but_clamdscan_is_unavailable_falling_back_to_cl", {
                            value1: String(e?.message || e)
                        })]);
                }
            }
            let exePath = isClamd ? currentSettings.clamdscanPath : currentSettings.clamscanPath;
            let args = buildClamScanArgs(currentSettings, isClamd, "file", filePath);
            console.debug(englishText("backend.shield.shield_scan_engine", {
                value1: String(isClamd ? englishText("backend.shield.clamdscan_offload_to_ram") : "clamscan/direct")
            }));
            console.debug(englishText("backend.shield.shield_scan_executable", {
                exePath: String(exePath)
            }));
            console.debug(englishText("backend.shield.shield_scan_arguments", {
                value1: String(args.join(" "))
            }));
            try {
                const heartbeat = context.createScanHeartbeat(jobId, "Shield scan");
                const child = spawn(exePath, args, { windowsHide: true });
                context.activeJobs[jobId].process = child;
                applyShieldLowImpactPriority(child, currentSettings, isClamd ? "clamdscan" : "clamscan");
                if (isClamd && runtimeState.clamdProcess) {
                    applyShieldLowImpactPriority(runtimeState.clamdProcess, currentSettings, "clamd");
                }
                child.stdout.on("data", (data) => {
                    const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                    context.appendJobLogs(jobId, lines);
                });
                child.stderr.on("data", (data) => {
                    const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                    context.appendJobLogs(jobId, lines);
                });
                await new Promise<void>((resolve) => {
                    let settled = false;
                    let timedOut = false;
                    const timeoutMs = getClamScanChildTimeoutMs(currentSettings, 1);
                    const timeout = setTimeout(() => {
                        timedOut = true;
                        context.appendJobLogs(jobId, [
                            englishText("backend.shield.shield_scanner_timed_out_after_s", {
                                value1: String(Math.round(timeoutMs / 1000))
                            }),
                            englishText("backend.shield.stopping_this_shield_scanner_worker_this_file_was_not_treated_as")
                        ]);
                        try {
                            child.kill();
                        }
                        catch { }
                        if (isClamd) {
                            stopClamdAfterScannerTimeout(message => context.appendJobLogs(jobId, [message]));
                        }
                        setTimeout(() => {
                            if (context.activeJobs[jobId]) {
                                context.activeJobs[jobId].status = "done";
                                context.activeJobs[jobId].result = -1;
                                context.activeJobs[jobId].process = null;
                                filesBeingScanned.delete(normalizedPath);
                            }
                            settle();
                        }, 5000).unref?.();
                    }, timeoutMs);
                    timeout.unref?.();
                    const settle = () => {
                        if (settled)
                            return;
                        settled = true;
                        clearTimeout(timeout);
                        clearInterval(heartbeat);
                        resolve();
                    };
                    child.on("error", (err: any) => {
                        clearInterval(heartbeat);
                        console.error(englishText("backend.shield.failed_to_start_shield_scan_process"), err.message);
                        if (context.activeJobs[jobId]) {
                            context.activeJobs[jobId].status = "error";
                            context.appendJobLogs(jobId, [englishText("backend.shield.process_error") + err.message]);
                            filesBeingScanned.delete(normalizedPath);
                        }
                        settle();
                    });
                    child.on("close", async (code) => {
                        try {
                            if (!context.activeJobs[jobId])
                                return;
                            const effectiveCode = timedOut ? -2 : code;
                            if (effectiveCode !== 0 && effectiveCode !== 1) {
                                context.appendJobLogs(jobId, [
                                    englishText("backend.shield.shield_scanner_process_failed_with_exit_code", {
                                        value1: String(effectiveCode ?? englishText("exceptions.unknown_b23a6a8"))
                                    }),
                                    englishText("backend.shield.this_file_was_not_treated_as_clean")
                                ]);
                                context.activeJobs[jobId].status = "done";
                                context.activeJobs[jobId].result = -1;
                                context.activeJobs[jobId].process = null;
                                filesBeingScanned.delete(normalizedPath);
                                return;
                            }
                            let threatsFound = 0;
                            let scannedFiles = 0;
                            let duration = 0;
                            const qMap = await getQuarantineMap();
                            const exceptions = await getExceptions();
                            let quarantineMapChanged = false;
                            let actionTaken = "None";
                            for (const line of context.activeJobs[jobId].analysisLogs || []) {
                                if (line.includes(" FOUND")) {
                                    const match = line.match(/^(.*?):\s+(.*?)\s+FOUND$/);
                                    if (match) {
                                        const originalPath = match[1];
                                        if (shouldSkipShieldPath(originalPath)) {
                                            context.appendJobLogs(jobId, [englishText("backend.shield.ignored_provider_safety_exclusion", {
                                                    originalPath: String(originalPath)
                                                })]);
                                            continue;
                                        }
                                        if (isExcluded(originalPath, exceptions)) {
                                            context.appendJobLogs(jobId, [englishText("backend.shield.ignored_exception", {
                                                    originalPath: String(originalPath)
                                                })]);
                                            continue;
                                        }
                                        threatsFound++;
                                        const threatName = match[2];
                                        const action = normalizeShieldDetectionAction(currentSettings.actionOnDetection || (currentSettings.autoQuarantine ? "quarantine_silent" : "ask"));
                                        const actionKind = shieldActionKind(action);
                                        if (actionKind === "quarantine") {
                                            try {
                                                const quarantined = await quarantineFile(originalPath, threatName, currentSettings.quarantineDir);
                                                qMap[quarantined.fileName] = quarantined.metadata;
                                                quarantineMapChanged = true;
                                                context.appendJobLogs(jobId, [englishText("backend.shield.quarantined", {
                                                        originalPath: String(originalPath),
                                                        destPath: String(quarantined.destPath)
                                                    })]);
                                                actionTaken = "Quarantined";
                                                if (shieldActionNotifies(action)) {
                                                    context.sendApiEvent("threat", {
                                                        id: Date.now().toString() + Math.random().toString(36).substring(7),
                                                        originalPath,
                                                        threatName,
                                                        mode: "notice",
                                                        title: englishText("backend.core.threat_quarantined"),
                                                        subtitle: englishText("backend.core.clamshield_shield_quarantined_this_file"),
                                                        timestamp: Date.now()
                                                    });
                                                }
                                            }
                                            catch (e: any) {
                                                context.appendJobLogs(jobId, [englishText("backend.shield.failed_to_quarantine", {
                                                        originalPath: String(originalPath),
                                                        message: String(e.message)
                                                    })]);
                                                actionTaken = "Quarantine Failed";
                                            }
                                        }
                                        else if (actionKind === "ask") {
                                            const pendingThreat = {
                                                id: Date.now().toString() + Math.random().toString(36).substring(7),
                                                originalPath,
                                                threatName,
                                                timestamp: Date.now()
                                            };
                                            await context.queuePendingThreat(pendingThreat);
                                            context.appendJobLogs(jobId, [englishText("backend.shield.threat_found_waiting_for_user_action", {
                                                    originalPath: String(originalPath)
                                                })]);
                                            actionTaken = "Pending";
                                        }
                                        else {
                                            await addScanResult({
                                                source: "shield",
                                                scanType: "shield",
                                                target: filePath,
                                                originalPath,
                                                threatName
                                            });
                                            context.appendJobLogs(jobId, [englishText("backend.shield.threat_found_sent_silently_to_results", {
                                                    originalPath: String(originalPath)
                                                })]);
                                            actionTaken = "Sent to Results";
                                            if (shieldActionNotifies(action)) {
                                                context.sendApiEvent("threat", {
                                                    id: Date.now().toString() + Math.random().toString(36).substring(7),
                                                    originalPath,
                                                    threatName,
                                                    mode: "notice",
                                                    title: englishText("backend.core.threat_sent_to_results"),
                                                    subtitle: englishText("backend.core.clamshield_shield_saved_this_detection_for_review"),
                                                    timestamp: Date.now()
                                                });
                                            }
                                        }
                                    }
                                }
                                if (line.startsWith("Scanned files:")) {
                                    const m = line.match(/\d+/);
                                    if (m)
                                        scannedFiles = parseInt(m[0], 10);
                                }
                                if (line.startsWith("Infected files:")) {
                                    continue;
                                }
                                if (line.startsWith("Time:")) {
                                    const m = line.match(/(\d+\.\d+) sec/);
                                    if (m)
                                        duration = Math.round(parseFloat(m[1]));
                                }
                            }
                            if (quarantineMapChanged) {
                                await saveQuarantineMap(qMap);
                            }
                            const yaraResult = await runYaraScanForTargets(currentSettings, [filePath], {
                                activeJobs: context.activeJobs,
                                appendJobLogs: context.appendJobLogs,
                                jobId,
                                source: "shield",
                                scanType: "shield",
                                target: filePath,
                                action: normalizeShieldDetectionAction(currentSettings.actionOnDetection || (currentSettings.autoQuarantine ? "quarantine_silent" : "ask")),
                                pendingThreats: context.pendingThreats,
                                queuePendingThreat: context.queuePendingThreat,
                                notifyThreat: (threat: any) => context.sendApiEvent("threat", threat)
                            });
                            if (yaraResult.matches > 0) {
                                threatsFound += yaraResult.matches;
                                actionTaken = yaraResult.actionTaken;
                            }
                            context.enqueueShieldVirusTotalCheck(filePath);
                            const isThreat = threatsFound > 0;
                            context.appendJobLogs(jobId, [englishText("backend.shield.shield_scan_finished_with_exit_code", {
                                    value1: String(effectiveCode ?? englishText("exceptions.unknown_b23a6a8"))
                                })]);
                            if (isThreat) {
                                console.log(englishText("backend.shield.shield_threat_found_in", {
                                    filePath: String(filePath)
                                }));
                            }
                            const lockedOrUnstable = !isThreat && (context.activeJobs[jobId].logs || []).some(isLockedOrUnstableClamLine);
                            if (lockedOrUnstable) {
                                const cooldownMs = 10 * 60 * 1000;
                                lockedFileBackoff.set(normalizedPath, Date.now() + cooldownMs);
                                console.debug(englishText("backend.shield.shield_locked_unstable_scan_backoff_applied_for_minutes", {
                                    value1: String(Math.round(cooldownMs / 60000)),
                                    filePath: String(filePath)
                                }));
                            }
                            const latestFingerprint = await getFileFingerprint(filePath);
                            if (latestFingerprint) {
                                context.shieldScanCache.set(normalizedPath, latestFingerprint);
                            }
                            else {
                                context.shieldScanCache.delete(normalizedPath);
                            }
                            await addHistory({
                                type: "scan-shield",
                                target: filePath,
                                result: isThreat ? 1 : 0,
                                threatsFound,
                                scannedFiles,
                                duration,
                                actionTaken: isThreat ? actionTaken : englishText("backend.yara.none")
                            });
                            delete context.activeJobs[jobId];
                            filesBeingScanned.delete(normalizedPath);
                            await flushPendingClamdDatabaseReload(context.settings).catch(e => console.warn(englishText("backend.shield.deferred_clamd_reload_failed"), e.message));
                        }
                        finally {
                            settle();
                        }
                    });
                });
            }
            catch (err) {
                console.error(englishText("backend.shield.shield_scan_failed"), err);
                filesBeingScanned.delete(normalizedPath);
                if (context.activeJobs[jobId])
                    delete context.activeJobs[jobId];
                await flushPendingClamdDatabaseReload(context.settings).catch((e: any) => console.warn(englishText("backend.shield.deferred_clamd_reload_failed"), e.message));
            }
        };
        context.shieldWatcher.on('add', (filePath) => enqueueShieldFile(filePath, "add"));
        context.shieldWatcher.on('change', (filePath) => enqueueShieldFile(filePath, "change"));
    };
}
