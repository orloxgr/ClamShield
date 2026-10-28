import { englishText } from "../../../shared/localization/runtime";
import { downloadAndInstallSaneSecurityDatabases } from "../../../addons/sanesecurity/server/install";
import { getConfiguredSecuriteInfoDatabaseNames, redactSecuriteInfoSecret } from "../../../addons/securiteinfo/server/service";
import { freshclamRunTimeoutMs } from "../../../engines/clamav/server/constants";
import { reloadClamdDatabases } from "../../../engines/clamav/server/daemon";
import { prepareFreshclamConfig, runFreshclamWithConfig } from "../../../engines/clamav/server/freshclam";
import { updateYaraForgeRules } from "../../../engines/yara/server/install";
import { normalizeYaraRuleset } from "../../../engines/yara/server/rules";
import { ApplicationContext } from "../../../server/core/applicationContext";
import { runtimeState } from "../../../server/core/runtimeState";
import { pathExists } from "../../../server/scanning/files";
import { addHistory, getLatestHistoryByType, getLatestSuccessfulClamAVUpdateHistory } from "../../history/server/storage";
import { saveConfig } from "../../settings/server/service";
import { normalizePositiveNumber } from "../../settings/server/validation";
import { downloadAndLaunchClamShieldInstaller, getLatestClamShieldRelease } from "./service";
export function createScheduleAppExitForUpdate(context: Pick<ApplicationContext, "appUpdateExitScheduled" | "activeJobs">) {
    return () => {
        if (context.appUpdateExitScheduled)
            return;
        context.appUpdateExitScheduled = true;
        for (const job of Object.values(context.activeJobs)) {
            try {
                job.process?.kill?.();
                if (job.processes) {
                    for (const child of Array.from(job.processes))
                        child?.kill?.();
                    job.processes.clear();
                }
            }
            catch {
                // Best-effort cleanup before the installer replaces files.
            }
        }
        try {
            runtimeState.clamdProcess?.kill?.();
            runtimeState.clamdProcess = null;
        }
        catch {
            // Best-effort cleanup before the installer replaces files.
        }
        const timer = setTimeout(() => process.exit(0), 2000);
        timer.unref?.();
    };
}
export function createStartSaneSecurityUpdate(context: Pick<ApplicationContext, "settings" | "activeJobs" | "appendJobLogs" | "broadcastJobEvent">) {
    return async (source: "manual" | "automatic" = "manual") => {
        if (!context.settings.saneSecurityEnabled) {
            throw new Error(englishText("backend.updates.sanesecurity_signatures_are_not_enabled_install_them_from_dashboa"));
        }
        if (runtimeState.saneSecurityUpdateInProgress) {
            throw new Error("A SaneSecurity signature update is already running.");
        }
        if (!await pathExists(context.settings.clamscanPath)) {
            throw new Error(englishText("backend.updates.clamscan_was_not_found_at_install_the_clamav_engine_first", {
                clamscanPath: String(context.settings.clamscanPath)
            }));
        }
        const jobId = `sanesecurity-update-${Date.now()}`;
        const startedAt = Date.now();
        runtimeState.saneSecurityUpdateInProgress = true;
        runtimeState.saneSecurityUpdateJobId = jobId;
        context.activeJobs[jobId] = { status: "running", logs: [] };
        context.appendJobLogs(jobId, [
            source === "automatic"
                ? "Starting automatic SaneSecurity signature update..."
                : "Starting SaneSecurity signature update..."
        ]);
        void Promise.resolve().then(async () => {
            try {
                const installedDatabases = await downloadAndInstallSaneSecurityDatabases(context.settings, line => {
                    if (context.activeJobs[jobId])
                        context.appendJobLogs(jobId, [line]);
                });
                context.settings = {
                    ...context.settings,
                    lastSaneSecurityUpdate: new Date().toISOString(),
                    lastSaneSecurityUpdateResult: "Updated"
                };
                await saveConfig(context.settings);
                await reloadClamdDatabases(context.settings);
                context.appendJobLogs(jobId, [
                    `SaneSecurity update complete: ${installedDatabases.length} signed databases installed.`
                ]);
                if (context.activeJobs[jobId]) {
                    context.activeJobs[jobId].status = "done";
                    context.activeJobs[jobId].result = 0;
                    context.broadcastJobEvent(jobId);
                }
                await addHistory({
                    type: "update-sanesecurity",
                    target: source === "automatic" ? "SaneSecurity (Auto)" : "SaneSecurity",
                    result: 0,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                    actionTaken: englishText("backend.updates.updated_databases", {
                        length: String(installedDatabases.length)
                    })
                });
            }
            catch (e: any) {
                const message = e?.message || String(e);
                context.settings = {
                    ...context.settings,
                    lastSaneSecurityUpdateResult: `Update failed: ${message}`.slice(0, 500)
                };
                await saveConfig(context.settings).catch(() => { });
                if (context.activeJobs[jobId]) {
                    context.appendJobLogs(jobId, [englishText("updates.error", {
                            message: String(message)
                        })]);
                    context.activeJobs[jobId].status = "done";
                    context.activeJobs[jobId].result = 1;
                    context.broadcastJobEvent(jobId);
                }
                await addHistory({
                    type: "update-sanesecurity",
                    target: source === "automatic" ? "SaneSecurity (Auto)" : "SaneSecurity",
                    result: 1,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                    actionTaken: englishText("common.update_job_progress.failed")
                }).catch(() => { });
                console.error("SaneSecurity update failed:", message);
            }
            finally {
                runtimeState.saneSecurityUpdateInProgress = false;
                runtimeState.saneSecurityUpdateJobId = null;
            }
        });
        return jobId;
    };
}
export function createScheduleNextUpdate(context: Pick<ApplicationContext, "autoUpdateTimer" | "settings" | "scheduleNextUpdate" | "startSaneSecurityUpdate">) {
    return () => {
        if (context.autoUpdateTimer)
            clearTimeout(context.autoUpdateTimer);
        if (!context.settings.autoUpdateEnabled)
            return;
        // 1 minute poll
        context.autoUpdateTimer = setTimeout(async () => {
            try {
                if (!runtimeState.isSimulated && context.settings.autoUpdateEnabled) {
                    const now = Date.now();
                    const lastClamAVHistory = await getLatestSuccessfulClamAVUpdateHistory();
                    const lastClamAVTime = context.settings.lastClamAVUpdate
                        ? new Date(context.settings.lastClamAVUpdate).getTime()
                        : (lastClamAVHistory ? new Date(lastClamAVHistory.date).getTime() : 0);
                    const clamavIntervalMs = Math.max(24, normalizePositiveNumber(context.settings.clamavUpdateIntervalHours || context.settings.updateIntervalHours, 24, 24, 720)) * 60 * 60 * 1000;
                    const securiteIntervalMs = normalizePositiveNumber(context.settings.securiteInfoUpdateIntervalHours, 1, 1, 24) * 60 * 60 * 1000;
                    const lastSecuriteTime = context.settings.lastSecuriteInfoUpdate ? new Date(context.settings.lastSecuriteInfoUpdate).getTime() : 0;
                    const updateTarget = !lastClamAVTime || now - lastClamAVTime > clamavIntervalMs
                        ? "clamav"
                        : context.settings.securiteInfoEnabled === true && (!lastSecuriteTime || now - lastSecuriteTime > securiteIntervalMs)
                            ? "securiteinfo"
                            : "";
                    const saneIntervalMs = normalizePositiveNumber(context.settings.saneSecurityUpdateIntervalHours, 1, 1, 24) * 60 * 60 * 1000;
                    const lastSaneTime = context.settings.lastSaneSecurityUpdate ? new Date(context.settings.lastSaneSecurityUpdate).getTime() : 0;
                    const saneDue = context.settings.saneSecurityEnabled && !runtimeState.saneSecurityUpdateInProgress && (!lastSaneTime || now - lastSaneTime > saneIntervalMs);
                    if (updateTarget) {
                        if (runtimeState.freshclamUpdateInProgress) {
                            console.log("Skipping automatic signature update because FreshClam is already running.");
                            context.scheduleNextUpdate();
                            return;
                        }
                        console.log(`Triggering automatic ${updateTarget} signature update...`);
                        if (updateTarget === "securiteinfo") {
                            runtimeState.freshclamUpdateInProgress = true;
                            const startedAt = Date.now();
                            let resultCode = 1;
                            let actionTaken = "Failed";
                            let preparedConfig: Awaited<ReturnType<typeof prepareFreshclamConfig>> | null = null;
                            const databaseCount = getConfiguredSecuriteInfoDatabaseNames(context.settings).length;
                            try {
                                preparedConfig = await prepareFreshclamConfig(context.settings, {
                                    includeOfficial: false,
                                    includeSecuriteInfo: true
                                });
                                const code = await runFreshclamWithConfig(context.settings, preparedConfig, {
                                    onLine: line => console.log(`SecuriteInfo auto-update: ${line}`)
                                });
                                if (code !== 0) {
                                    throw new Error(englishText("backend.updates.freshclam_failed_with_exit_code", {
                                        code: String(code)
                                    }));
                                }
                                await reloadClamdDatabases(context.settings);
                                context.settings = {
                                    ...context.settings,
                                    lastSecuriteInfoUpdate: new Date().toISOString(),
                                    lastSecuriteInfoUpdateResult: `FreshClam updated ${databaseCount} configured databases`
                                };
                                resultCode = 0;
                                actionTaken = `FreshClam updated ${databaseCount} configured databases`;
                            }
                            catch (e: any) {
                                const message = redactSecuriteInfoSecret(e?.message || String(e));
                                context.settings = {
                                    ...context.settings,
                                    lastSecuriteInfoUpdateResult: `Update failed: ${message}`.slice(0, 500)
                                };
                                console.error("Automatic SecuriteInfo update failed:", message);
                            }
                            finally {
                                await preparedConfig?.cleanup().catch(() => { });
                                runtimeState.freshclamUpdateInProgress = false;
                                await saveConfig(context.settings).catch(() => { });
                                await addHistory({
                                    type: "update",
                                    target: "SecuriteInfo (Auto)",
                                    result: resultCode,
                                    threatsFound: 0,
                                    scannedFiles: databaseCount,
                                    duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                                    actionTaken
                                }).catch(() => { });
                            }
                            if (saneDue) {
                                try {
                                    await context.startSaneSecurityUpdate("automatic");
                                }
                                catch (e: any) {
                                    console.error("Could not start automatic SaneSecurity update:", e?.message || e);
                                }
                            }
                            context.scheduleNextUpdate();
                            return;
                        }
                        const preparedConfig = await prepareFreshclamConfig(context.settings, {
                            includeOfficial: true,
                            includeSecuriteInfo: false
                        });
                        // Run through runFreshclamWithConfig like the manual update does. FreshClam on Windows
                        // writes its progress bar to stdout even when piped (about 3.5 MB per full update);
                        // left unread, the pipe fills and FreshClam blocks forever on the write.
                        runtimeState.freshclamUpdateInProgress = true;
                        let code = 1;
                        try {
                            code = await runFreshclamWithConfig(context.settings, preparedConfig, {
                                onLine: line => {
                                    if (/^Time:\s/.test(line))
                                        return; // progress bar redraws
                                    console.log(`ClamAV auto-update: ${line}`);
                                },
                                timeoutMs: freshclamRunTimeoutMs
                            });
                        }
                        catch (e: any) {
                            console.error("Auto-update process error:", preparedConfig.redact(e?.message || String(e)));
                        }
                        finally {
                            runtimeState.freshclamUpdateInProgress = false;
                            await preparedConfig.cleanup().catch(() => { });
                        }
                        if (code === 0)
                            await reloadClamdDatabases(context.settings);
                        context.settings = {
                            ...context.settings,
                            lastClamAVUpdate: code === 0 ? new Date().toISOString() : context.settings.lastClamAVUpdate,
                            lastClamAVUpdateResult: code === 0 ? "Updated" : "Update failed"
                        };
                        await saveConfig(context.settings);
                        await addHistory({
                            type: "update",
                            target: "ClamAV (Auto)",
                            result: code === 0 ? 0 : 1,
                            threatsFound: 0,
                            scannedFiles: 0,
                            duration: 1,
                            actionTaken: code === 0 ? englishText("backend.yara.updated") : englishText("common.update_job_progress.failed")
                        });
                        if (saneDue) {
                            try {
                                await context.startSaneSecurityUpdate("automatic");
                            }
                            catch (e: any) {
                                console.error("Could not start automatic SaneSecurity update:", e?.message || e);
                            }
                        }
                        console.log(`Auto-update finished with code ${code}`);
                    }
                    else if (saneDue) {
                        try {
                            await context.startSaneSecurityUpdate("automatic");
                        }
                        catch (e: any) {
                            console.error("Could not start automatic SaneSecurity update:", e?.message || e);
                        }
                    }
                }
            }
            catch (e) {
                console.error("Auto-update check failed:", e);
            }
            context.scheduleNextUpdate();
        }, 60000); // Check every minute
    };
}
export function createScheduleNextYaraUpdate(context: Pick<ApplicationContext, "yaraAutoUpdateTimer" | "settings" | "isRunningClamdScanJob" | "scheduleNextYaraUpdate">) {
    return () => {
        if (context.yaraAutoUpdateTimer)
            clearTimeout(context.yaraAutoUpdateTimer);
        if (!context.settings.yaraEnabled || !context.settings.yaraAutoUpdateEnabled)
            return;
        context.yaraAutoUpdateTimer = setTimeout(async () => {
            try {
                const lastAttempt = await getLatestHistoryByType("yara-update");
                const intervalMs = normalizePositiveNumber(context.settings.yaraUpdateIntervalHours, 168, 1, 8760) * 60 * 60 * 1000;
                const shouldUpdate = !lastAttempt || Date.now() - new Date(lastAttempt.date).getTime() > intervalMs;
                if (shouldUpdate) {
                    if (context.isRunningClamdScanJob()) {
                        console.log("YARA Forge auto-update deferred because a scan is running.");
                        context.scheduleNextYaraUpdate();
                        return;
                    }
                    console.log("Triggering YARA Forge auto-update...");
                    await updateYaraForgeRules(context.settings, message => console.log(`YARA auto-update: ${message}`));
                    await addHistory({
                        type: "yara-update",
                        target: `YARA Forge ${normalizeYaraRuleset(context.settings.yaraRuleset)}`,
                        result: 0,
                        threatsFound: 0,
                        scannedFiles: 0,
                        duration: 1,
                        actionTaken: englishText("backend.yara.updated")
                    });
                }
            }
            catch (e: any) {
                console.error("YARA auto-update failed:", e.message);
                await addHistory({
                    type: "yara-update",
                    target: `YARA Forge ${normalizeYaraRuleset(context.settings.yaraRuleset)}`,
                    result: 1,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: 1,
                    actionTaken: englishText("common.update_job_progress.failed")
                });
            }
            context.scheduleNextYaraUpdate();
        }, 60000);
    };
}
export function createScheduleNextAppUpdateCheck(context: Pick<ApplicationContext, "appUpdateTimer" | "settings" | "isRunningClamdScanJob" | "scheduleAppExitForUpdate" | "scheduleNextAppUpdateCheck">) {
    return () => {
        if (context.appUpdateTimer)
            clearTimeout(context.appUpdateTimer);
        if (!context.settings.appUpdateCheckEnabled)
            return;
        context.appUpdateTimer = setTimeout(async () => {
            try {
                const lastAttempt = await getLatestHistoryByType("app-update-check");
                const intervalMs = normalizePositiveNumber(context.settings.appUpdateIntervalHours, 168, 1, 8760) * 60 * 60 * 1000;
                const shouldCheck = !lastAttempt || Date.now() - new Date(lastAttempt.date).getTime() > intervalMs;
                if (shouldCheck) {
                    console.log("Checking for ClamShield app update...");
                    const update = await getLatestClamShieldRelease(context.settings);
                    let actionTaken = update.updateAvailable ? `Available ${update.latestVersion}` : "No update";
                    let shouldExitForUpdate = false;
                    if (update.updateAvailable && context.settings.appSilentAutoInstall === true) {
                        if (context.isRunningClamdScanJob()) {
                            actionTaken = `Available ${update.latestVersion}; install deferred because a scan is running`;
                        }
                        else {
                            const result = await downloadAndLaunchClamShieldInstaller(context.settings, message => console.log(`ClamShield update: ${message}`));
                            actionTaken = result.handoffReady ? `Installer queued ${update.latestVersion}` : "No update";
                            shouldExitForUpdate = result.handoffReady;
                        }
                    }
                    await addHistory({
                        type: "app-update-check",
                        target: "ClamShield",
                        result: 0,
                        threatsFound: 0,
                        scannedFiles: 0,
                        duration: 1,
                        actionTaken
                    });
                    if (shouldExitForUpdate)
                        context.scheduleAppExitForUpdate();
                }
            }
            catch (e: any) {
                console.error("ClamShield app update check failed:", e.message);
                await addHistory({
                    type: "app-update-check",
                    target: "ClamShield",
                    result: 1,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: 1,
                    actionTaken: englishText("common.update_job_progress.failed")
                });
            }
            context.scheduleNextAppUpdateCheck();
        }, 60000);
    };
}
