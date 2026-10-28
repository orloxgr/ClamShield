import { englishText } from "../../../../shared/localization/runtime";
import { getConfiguredSecuriteInfoDatabaseNames, normalizeSecuriteInfoPlan, redactSecuriteInfoSecret } from "../../../../addons/securiteinfo/server/service";
import { freshclamRunTimeoutMs } from "../../../../engines/clamav/server/constants";
import { reloadClamdDatabases } from "../../../../engines/clamav/server/daemon";
import { prepareFreshclamConfig, runFreshclamWithConfig } from "../../../../engines/clamav/server/freshclam";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { pathExists } from "../../../../server/scanning/files";
import { addHistory } from "../../../history/server/storage";
import { saveConfig } from "../../../settings/server/service";
import { spawn } from "child_process";
export function registerPostApiUpdate(app: any, context: Pick<ApplicationContext, "activeJobs" | "settings" | "appendJobLogs" | "broadcastJobEvent">) {
    app.post("/api/update", async (req, res) => {
        const jobId = Date.now().toString();
        let preparedConfig: Awaited<ReturnType<typeof prepareFreshclamConfig>> | null = null;
        const requestedTarget = req.body?.target === "securiteinfo" ? "securiteinfo" : "clamav";
        if (runtimeState.freshclamUpdateInProgress) {
            if (runtimeState.freshclamUpdateTarget === requestedTarget && runtimeState.freshclamUpdateJobId && context.activeJobs[runtimeState.freshclamUpdateJobId]?.status === "running") {
                return res.json({ jobId: runtimeState.freshclamUpdateJobId, status: "already_running" });
            }
            return res.status(409).json({ error: "A signature update is already running." });
        }
        if (requestedTarget === "securiteinfo" && context.settings.securiteInfoEnabled !== true) {
            return res.status(400).json({ error: englishText("backend.updates.securiteinfo_signatures_are_not_enabled") });
        }
        if (runtimeState.isSimulated) {
            setTimeout(async () => {
                await addHistory({
                    type: "update",
                    target: "Databases",
                    result: 0,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: 2,
                    actionTaken: englishText("backend.yara.updated")
                });
            }, 2000);
            return res.json({ jobId, status: "started", simulated: true });
        }
        try {
            runtimeState.freshclamUpdateInProgress = true;
            runtimeState.freshclamUpdateJobId = jobId;
            runtimeState.freshclamUpdateTarget = requestedTarget;
            context.activeJobs[jobId] = { status: "running", logs: [] };
            if (requestedTarget === "securiteinfo") {
                res.json({ jobId, status: "started" });
                (async () => {
                    const startedAt = Date.now();
                    const databaseCount = getConfiguredSecuriteInfoDatabaseNames(context.settings).length;
                    try {
                        context.appendJobLogs(jobId, [
                            englishText("backend.updates.updating_securiteinfo_databases_with_freshclam", {
                                value1: String(normalizeSecuriteInfoPlan(context.settings.securiteInfoPlan) === "paid" ? englishText("backend.updates.paid") : englishText("updates.basic"))
                            })
                        ]);
                        preparedConfig = await prepareFreshclamConfig(context.settings, {
                            includeOfficial: false,
                            includeSecuriteInfo: true
                        });
                        const code = await runFreshclamWithConfig(context.settings, preparedConfig, {
                            onLine: line => {
                                if (context.activeJobs[jobId])
                                    context.appendJobLogs(jobId, [line]);
                            },
                            onProcess: child => {
                                if (context.activeJobs[jobId])
                                    context.activeJobs[jobId].process = child;
                            }
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
                        await saveConfig(context.settings);
                        if (!context.activeJobs[jobId])
                            return;
                        context.appendJobLogs(jobId, [`SecuriteInfo FreshClam update complete for ${databaseCount} configured databases.`]);
                        context.activeJobs[jobId].status = "done";
                        context.activeJobs[jobId].result = 0;
                        context.activeJobs[jobId].process = null;
                        context.broadcastJobEvent(jobId);
                        await addHistory({
                            type: "update",
                            target: "SecuriteInfo",
                            result: 0,
                            threatsFound: 0,
                            scannedFiles: databaseCount,
                            duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                            actionTaken: englishText("backend.updates.freshclam_updated_configured_databases", {
                                databaseCount: String(databaseCount)
                            })
                        });
                    }
                    catch (e: any) {
                        const message = redactSecuriteInfoSecret(e?.message || String(e));
                        context.settings = {
                            ...context.settings,
                            lastSecuriteInfoUpdateResult: `Update failed: ${message}`.slice(0, 500)
                        };
                        await saveConfig(context.settings).catch(() => { });
                        if (context.activeJobs[jobId]) {
                            context.appendJobLogs(jobId, [englishText("updates.error", {
                                    message: String(message)
                                })]);
                            context.activeJobs[jobId].status = "done";
                            context.activeJobs[jobId].result = 1;
                            context.activeJobs[jobId].process = null;
                            context.broadcastJobEvent(jobId);
                        }
                        await addHistory({
                            type: "update",
                            target: "SecuriteInfo",
                            result: 1,
                            threatsFound: 0,
                            scannedFiles: 0,
                            duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                            actionTaken: englishText("common.update_job_progress.failed")
                        }).catch(() => { });
                    }
                    finally {
                        await preparedConfig?.cleanup().catch(() => { });
                        if (runtimeState.freshclamUpdateJobId === jobId) {
                            runtimeState.freshclamUpdateInProgress = false;
                            runtimeState.freshclamUpdateJobId = null;
                            runtimeState.freshclamUpdateTarget = null;
                        }
                    }
                })();
                return;
            }
            if (!await pathExists(context.settings.freshclamPath)) {
                throw new Error(englishText("backend.clamav.freshclam_executable_was_not_found_at_reinstall_the_clamav_engine", {
                    freshclamPath: String(context.settings.freshclamPath)
                }));
            }
            context.appendJobLogs(jobId, [englishText("backend.updates.preparing_freshclam_configuration")]);
            preparedConfig = await prepareFreshclamConfig(context.settings, {
                includeOfficial: true,
                includeSecuriteInfo: false
            });
            await saveConfig(context.settings);
            const args = ["--config-file=" + preparedConfig.configPath, "--datadir=" + context.settings.databaseDir];
            context.appendJobLogs(jobId, [englishText("backend.updates.downloading_official_clamav_virus_definitions")]);
            const child = spawn(context.settings.freshclamPath, args, { windowsHide: true });
            context.activeJobs[jobId].process = child;
            let processStartFailed = false;
            let timedOut = false;
            const runTimer = setTimeout(() => {
                timedOut = true;
                context.appendJobLogs(jobId, [englishText("backend.updates.freshclam_did_not_finish_within_minutes_and_was_stopped", {
                        value1: String(Math.round(freshclamRunTimeoutMs / 60000))
                    })]);
                try {
                    child.kill();
                }
                catch { }
            }, freshclamRunTimeoutMs);
            child.on("error", (err: any) => {
                clearTimeout(runTimer);
                processStartFailed = true;
                if (runtimeState.freshclamUpdateJobId === jobId) {
                    runtimeState.freshclamUpdateInProgress = false;
                    runtimeState.freshclamUpdateJobId = null;
                    runtimeState.freshclamUpdateTarget = null;
                }
                const safeMessage = preparedConfig?.redact(err.message) || err.message;
                console.error(englishText("backend.updates.failed_to_start_freshclam_process"), safeMessage);
                preparedConfig?.cleanup().catch(() => { });
                if (context.activeJobs[jobId]) {
                    context.activeJobs[jobId].status = "done";
                    context.activeJobs[jobId].result = -1;
                    context.activeJobs[jobId].process = null;
                    context.appendJobLogs(jobId, [englishText("backend.shield.process_error") + safeMessage]);
                    context.broadcastJobEvent(jobId);
                }
            });
            child.stdout.on("data", (data) => {
                const lines = data.toString()
                    .split('\n')
                    .map((line: string) => preparedConfig?.redact(line.trim()) || line.trim())
                    .filter(Boolean);
                if (lines.length)
                    context.appendJobLogs(jobId, lines);
            });
            child.stderr.on("data", (data) => {
                const lines = data.toString()
                    .split('\n')
                    .map((line: string) => preparedConfig?.redact(line.trim()) || line.trim())
                    .filter(Boolean);
                if (lines.length)
                    context.appendJobLogs(jobId, lines);
            });
            child.on("close", async (exitCode) => {
                clearTimeout(runTimer);
                const code = timedOut ? -2 : exitCode;
                if (runtimeState.freshclamUpdateJobId === jobId) {
                    runtimeState.freshclamUpdateInProgress = false;
                    runtimeState.freshclamUpdateJobId = null;
                    runtimeState.freshclamUpdateTarget = null;
                }
                await preparedConfig?.cleanup();
                if (!context.activeJobs[jobId])
                    return;
                if (processStartFailed)
                    return;
                if (code === 0) {
                    context.appendJobLogs(jobId, [englishText("backend.updates.virus_definitions_updated_successfully")]);
                }
                else {
                    context.appendJobLogs(jobId, [
                        englishText("backend.updates.freshclam_failed_with_exit_code_7e1c81e", {
                            value1: String(code ?? englishText("exceptions.unknown_b23a6a8"))
                        }),
                        englishText("backend.updates.check_your_internet_connection_firewall_proxy_or_clamav_mirror_ac")
                    ]);
                }
                context.settings = {
                    ...context.settings,
                    lastClamAVUpdate: code === 0 ? new Date().toISOString() : context.settings.lastClamAVUpdate,
                    lastClamAVUpdateResult: code === 0 ? "Updated" : "Update failed"
                };
                await saveConfig(context.settings);
                if (code === 0)
                    await reloadClamdDatabases(context.settings);
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = code ?? 0;
                context.activeJobs[jobId].process = null;
                context.broadcastJobEvent(jobId);
                await addHistory({
                    type: "update",
                    target: "ClamAV",
                    result: code === 0 ? 0 : 1,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: 1,
                    actionTaken: code === 0 ? englishText("backend.yara.updated") : englishText("common.update_job_progress.failed")
                });
            });
            res.json({ jobId, status: "started" });
        }
        catch (e: any) {
            if (runtimeState.freshclamUpdateJobId === jobId) {
                runtimeState.freshclamUpdateInProgress = false;
                runtimeState.freshclamUpdateJobId = null;
                runtimeState.freshclamUpdateTarget = null;
            }
            await preparedConfig?.cleanup();
            const safeMessage = preparedConfig?.redact(e.message) || redactSecuriteInfoSecret(e.message);
            if (context.activeJobs[jobId]) {
                context.appendJobLogs(jobId, [englishText("backend.updates.error_079c55a", {
                        safeMessage: String(safeMessage)
                    })]);
                context.activeJobs[jobId].status = "done";
                context.activeJobs[jobId].result = -1;
                context.broadcastJobEvent(jobId);
            }
            res.status(500).json({ error: safeMessage });
        }
    });
}
