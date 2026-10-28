import { englishText } from "../../../../shared/localization/runtime";
import { buildClamScanArgs } from "../../../../engines/clamav/server/arguments";
import { flushPendingClamdDatabaseReload } from "../../../../engines/clamav/server/daemon";
import { runYaraScanForTargets } from "../../../../engines/yara/server/scan";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { createManualScanPathSkipper, createScanFileList, getRunningProcessImagePaths, resolveScanTarget } from "../../../../server/scanning/targets";
import { getExceptions, isExcluded } from "../../../exceptions/server/service";
import { getQuarantineMap } from "../../../quarantine/server/storage";
import { addHistory } from "../../../history/server/storage";
import { quarantineFile } from "../../../quarantine/server/files";
import { saveQuarantineMap } from "../../../quarantine/server/storage";
import { addScanResult } from "../../../results/server/storage";
import { addTargetToShieldCache } from "../../../shield/server/cache";
import { spawn } from "child_process";
import fs from "fs/promises";
import path from "path";
export function registerPostApiScanLegacy(app: any, context: Pick<ApplicationContext, "settings" | "activeJobs" | "appendJobLogs" | "broadcastJobEvent" | "createScanHeartbeat" | "shieldScanCache">) {
    app.post("/api/scan-legacy", async (req, res) => {
        const { target, type } = req.body;
        const effectiveTarget = resolveScanTarget(type, target);
        const jobId = Date.now().toString();
        const shouldSkipLegacyScanFile = createManualScanPathSkipper(context.settings, type);
        // type could be 'file', 'folder', 'disk', 'memory'
        if (runtimeState.isSimulated) {
            // Simulated scan
            res.json({ jobId, status: "started", simulated: true });
            context.activeJobs[jobId] = { status: "running", kind: "scan", logs: [] };
            context.appendJobLogs(jobId, [englishText("backend.on_demand.starting_simulated_scan")]);
            // Simulate run
            setTimeout(async () => {
                const isThreat = Math.random() < 0.5 && type !== 'update';
                let threatsFound = 0;
                let actionTaken = "None";
                if (isThreat) {
                    threatsFound = 1;
                    const testPath = effectiveTarget || "C:\\TestPath";
                    const filePath = path.join(testPath, "eicar.com.txt");
                    context.appendJobLogs(jobId, [englishText("backend.on_demand.found_eicar_test_signature", {
                            filePath: String(filePath)
                        })]);
                    const action = context.settings.scanDetectionAction || "results";
                    if (action === "quarantine") {
                        context.appendJobLogs(jobId, [englishText("backend.on_demand.quarantined", {
                                filePath: String(filePath)
                            })]);
                        actionTaken = "Quarantined";
                    }
                    else {
                        await addScanResult({
                            source: "manual",
                            scanType: type,
                            target: effectiveTarget || "C:\\",
                            originalPath: filePath,
                            threatName: "Eicar-Test-Signature (Simulated)"
                        });
                        context.appendJobLogs(jobId, [englishText("backend.on_demand.threat_found_sent_to_results", {
                                filePath: String(filePath)
                            })]);
                        actionTaken = "Sent to Results";
                    }
                }
                context.appendJobLogs(jobId, [englishText("backend.on_demand.scan_completed")]);
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = isThreat ? 1 : 0;
                context.broadcastJobEvent(jobId);
                await addHistory({
                    type: `scan-${type}`,
                    target: effectiveTarget || "C:\\",
                    result: isThreat ? 1 : 0,
                    threatsFound,
                    scannedFiles: Math.floor(Math.random() * 1000) + 10,
                    duration: Math.floor(Math.random() * 10) + 1,
                    actionTaken
                });
            }, 3000);
            return;
        }
        // Real ClamAV Scan
        try {
            const dbFiles = await fs.readdir(context.settings.databaseDir);
            const hasDb = dbFiles.some(f => f.endsWith('.cvd') || f.endsWith('.cld'));
            if (!hasDb) {
                return res.status(400).json({ error: englishText("backend.on_demand.no_virus_database_found_please_go_to_updates_and_download_virus_d") });
            }
        }
        catch (e) {
            return res.status(400).json({ error: "Failed to check virus database. Please update definitions." });
        }
        let memoryFileListPath: string | null = null;
        let memoryProcessCount = 0;
        let memoryYaraTargets: string[] = [];
        let scanTarget = effectiveTarget;
        if (type === "memory" && process.platform === "win32") {
            const processPaths = (await getRunningProcessImagePaths())
                .filter(filePath => !shouldSkipLegacyScanFile(filePath));
            memoryProcessCount = processPaths.length;
            memoryYaraTargets = processPaths;
            if (processPaths.length === 0) {
                return res.status(400).json({ error: englishText("backend.on_demand.no_readable_running_process_executable_paths_were_found") });
            }
            memoryFileListPath = await createScanFileList(processPaths);
            scanTarget = memoryFileListPath;
        }
        let isClamd = false;
        if (type !== "memory" && context.settings.offloadToMemory && context.settings.clamdscanPath) {
            try {
                await fs.access(context.settings.clamdscanPath);
                isClamd = true;
            }
            catch (e: any) {
                console.debug(englishText("backend.on_demand.legacy_scan_offload_requested_but_clamdscan_is_unavailable_fallin"), e?.message || e);
            }
        }
        let exePath = isClamd ? context.settings.clamdscanPath : context.settings.clamscanPath;
        let args = buildClamScanArgs(context.settings, isClamd, type, scanTarget);
        try {
            context.activeJobs[jobId] = { status: "running", kind: "scan", logs: [], analysisLogs: [] };
            if (type === "disk" && process.platform === "win32") {
                context.appendJobLogs(jobId, [
                    englishText("backend.on_demand.skipping_windows_locked_paging_system_files_that_cannot_be_opened"),
                    "C:\\pagefile.sys, C:\\swapfile.sys, C:\\hiberfil.sys, C:\\DumpStack.log.tmp"
                ]);
            }
            if (type === "memory" && process.platform === "win32") {
                context.appendJobLogs(jobId, [
                    englishText("backend.on_demand.running_programs_found_d15c46b", {
                        memoryProcessCount: String(memoryProcessCount)
                    }),
                    englishText("backend.on_demand.scanning_running_programs")
                ]);
            }
            context.appendJobLogs(jobId, [
                type === "memory" ? englishText("backend.on_demand.checking_running_programs") : englishText("backend.on_demand.checking_selected_files")
            ]);
            console.debug(englishText("backend.on_demand.legacy_scan_target", {
                value1: String(type === "memory" ? englishText("backend.on_demand.running_process_images") : (effectiveTarget || scanTarget || englishText("backend.on_demand.default_target")))
            }));
            console.debug(englishText("backend.on_demand.legacy_scan_engine", {
                value1: String(isClamd ? englishText("backend.shield.clamdscan_offload_to_ram") : "clamscan/direct")
            }));
            console.debug(englishText("backend.on_demand.legacy_scan_executable", {
                exePath: String(exePath)
            }));
            console.debug(englishText("backend.on_demand.legacy_scan_arguments", {
                value1: String(args.join(" "))
            }));
            const heartbeat = context.createScanHeartbeat(jobId, "Scan");
            const child = spawn(exePath, args, { windowsHide: true });
            context.activeJobs[jobId].process = child;
            child.on("error", (err: any) => {
                clearInterval(heartbeat);
                console.error(englishText("backend.on_demand.failed_to_start_manual_scan_process"), err.message);
                if (memoryFileListPath) {
                    fs.unlink(memoryFileListPath).catch(() => { });
                }
                if (context.activeJobs[jobId]) {
                    context.activeJobs[jobId].status = "error";
                    context.appendJobLogs(jobId, [englishText("backend.shield.process_error") + err.message]);
                }
            });
            child.stdout.on("data", (data) => {
                const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                context.appendJobLogs(jobId, lines);
            });
            child.stderr.on("data", (data) => {
                const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                context.appendJobLogs(jobId, lines);
            });
            child.on("close", async (code) => {
                clearInterval(heartbeat);
                if (!context.activeJobs[jobId])
                    return;
                let scannedFiles = 0;
                let threatsFound = 0;
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
                            if (shouldSkipLegacyScanFile(originalPath)) {
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
                            const action = context.settings.scanDetectionAction || "results";
                            if (action === "quarantine") {
                                try {
                                    const quarantined = await quarantineFile(originalPath, threatName, context.settings.quarantineDir);
                                    qMap[quarantined.fileName] = quarantined.metadata;
                                    quarantineMapChanged = true;
                                    context.appendJobLogs(jobId, [englishText("backend.shield.quarantined", {
                                            originalPath: String(originalPath),
                                            destPath: String(quarantined.destPath)
                                        })]);
                                    actionTaken = "Quarantined";
                                }
                                catch (e: any) {
                                    context.appendJobLogs(jobId, [englishText("backend.shield.failed_to_quarantine", {
                                            originalPath: String(originalPath),
                                            message: String(e.message)
                                        })]);
                                    actionTaken = "Quarantine Failed";
                                }
                            }
                            else {
                                await addScanResult({
                                    source: "manual",
                                    scanType: type,
                                    target: type === "memory" ? "Running process images" : (effectiveTarget || "C:\\"),
                                    originalPath,
                                    threatName
                                });
                                context.appendJobLogs(jobId, [englishText("backend.on_demand.threat_found_sent_to_results_bb2baec", {
                                        originalPath: String(originalPath)
                                    })]);
                                actionTaken = "Sent to Results";
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
                if (memoryFileListPath) {
                    await fs.unlink(memoryFileListPath).catch(() => { });
                }
                const yaraTargets = type === "memory"
                    ? memoryYaraTargets
                    : (effectiveTarget ? [effectiveTarget] : []);
                const yaraResult = await runYaraScanForTargets(context.settings, yaraTargets, {
                    activeJobs: context.activeJobs,
                    appendJobLogs: context.appendJobLogs,
                    jobId,
                    source: "manual",
                    scanType: type,
                    target: type === "memory" ? "Running process images" : (effectiveTarget || "C:\\"),
                    action: context.settings.scanDetectionAction || "results"
                });
                if (yaraResult.matches > 0) {
                    threatsFound += yaraResult.matches;
                    actionTaken = yaraResult.actionTaken;
                }
                const isThreat = threatsFound > 0;
                const exitSummary = code === 1 && !isThreat
                    ? englishText("backend.on_demand.scan_finished_with_exit_code_1_but_all_detections_were_ignored_by") : code === 1
                    ? englishText("backend.on_demand.scan_finished_with_exit_code_1_active_threats_were_found") : englishText("backend.on_demand.scan_finished_with_exit_code", {
                    value1: String(code ?? englishText("exceptions.unknown_b23a6a8"))
                });
                context.appendJobLogs(jobId, [exitSummary]);
                await addHistory({
                    type: `scan-${type}`,
                    target: type === "memory" ? "Running process images" : (effectiveTarget || "C:\\"),
                    result: isThreat ? 1 : 0,
                    threatsFound,
                    scannedFiles: type === "memory" && scannedFiles === 0 ? memoryProcessCount : scannedFiles,
                    duration,
                    actionTaken: isThreat ? actionTaken : englishText("backend.yara.none")
                });
                if ((type === "disk" || type === "folder" || type === "file") && effectiveTarget) {
                    context.appendJobLogs(jobId, [englishText("backend.on_demand.building_real_time_shield_cache_for_this_scan_target")]);
                    try {
                        const cachedCount = await addTargetToShieldCache(context.shieldScanCache, effectiveTarget, context.settings, (count) => {
                            context.appendJobLogs(jobId, [englishText("backend.on_demand.shield_cache_indexed_files", {
                                    count: String(count)
                                })]);
                        });
                        context.appendJobLogs(jobId, [englishText("backend.on_demand.shield_cache_updated_files_indexed", {
                                cachedCount: String(cachedCount)
                            })]);
                    }
                    catch (e: any) {
                        context.appendJobLogs(jobId, [`Shield cache update failed: ${e.message}`]);
                    }
                }
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = isThreat ? 1 : 0;
                context.activeJobs[jobId].process = null;
                await flushPendingClamdDatabaseReload(context.settings).catch(e => console.warn(englishText("backend.shield.deferred_clamd_reload_failed"), e.message));
            });
            child.on("error", (err) => {
                clearInterval(heartbeat);
                if (!context.activeJobs[jobId])
                    return;
                if (memoryFileListPath) {
                    fs.unlink(memoryFileListPath).catch(() => { });
                }
                context.appendJobLogs(jobId, [englishText("updates.error", {
                        message: String(err.message)
                    })]);
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = -1;
                context.activeJobs[jobId].process = null;
                flushPendingClamdDatabaseReload(context.settings).catch((reloadError: any) => console.warn(englishText("backend.shield.deferred_clamd_reload_failed"), reloadError.message));
            });
            res.json({ jobId, status: "started" });
        }
        catch (e: any) {
            if (memoryFileListPath) {
                await fs.unlink(memoryFileListPath).catch(() => { });
            }
            res.status(500).json({ error: e.message });
        }
    });
}
