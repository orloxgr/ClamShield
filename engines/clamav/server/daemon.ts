import { englishText } from "../../../shared/localization/runtime";
import { saveConfig } from "../../../modules/settings/server/service";
import { adoptClamavEngineFolder, findExtractedClamavDir } from "../../../server/core/files";
import { defaultLogsDir, engineBaseDir, execAsync } from "../../../server/core/paths";
import { runtimeState } from "../../../server/core/runtimeState";
import { sleep } from "../../../server/core/utils";
import { applyShieldLowImpactPriority } from "../../../server/platform/processes";
import { pathExists } from "../../../server/scanning/files";
import { ensureClamdConfContent, getClamdConfSignature } from "./arguments";
import { ensureFreshclamConfig } from "./freshclam";
import { spawn } from "child_process";
import fs from "fs/promises";
import { createConnection } from "net";
import path from "path";
export const clamdOutputSuppression = new Map<string, {
    count: number;
    lastLoggedAt: number;
}>();
export function stopClamdAfterScannerTimeout(log?: (message: string) => void) {
    if (!runtimeState.clamdProcess)
        return;
    log?.("Stopping clamd because a clamdscan worker timed out.");
    try {
        runtimeState.clamdProcess.kill();
    }
    catch { }
    runtimeState.clamdProcess = null;
    runtimeState.clamdConfSignature = "";
}
export function getNoisyClamdOutputKey(line: string) {
    if (/^LibClamAV Warning: cl_scanfile_callback: scanned_out exceeds UINT32_MAX/i.test(line)) {
        return "scanned_out exceeds UINT32_MAX";
    }
    return "";
}
export function logClamdOutput(line: string, level: "log" | "warn") {
    const key = getNoisyClamdOutputKey(line);
    if (!key) {
        console[level](`clamd: ${line}`);
        return;
    }
    const now = Date.now();
    const state = clamdOutputSuppression.get(key) || { count: 0, lastLoggedAt: 0 };
    state.count++;
    if (state.count === 1 || now - state.lastLoggedAt >= 60000) {
        const repeats = state.count - 1;
        console[level](`clamd: ${line}${repeats > 0 ? ` (suppressed ${repeats} repeat${repeats === 1 ? "" : "s"})` : ""}`);
        state.count = 1;
        state.lastLoggedAt = now;
    }
    clamdOutputSuppression.set(key, state);
}
export function filterClamdStartupOutput(lines: string[]) {
    return lines.filter(line => !getNoisyClamdOutputKey(line));
}
export function recordClamdOutput(lines: string[]) {
    if (!lines.length)
        return;
    runtimeState.clamdStartupOutput.push(...lines);
    if (runtimeState.clamdStartupOutput.length > 80)
        runtimeState.clamdStartupOutput.splice(0, runtimeState.clamdStartupOutput.length - 80);
}
export async function pingClamd(timeoutMs = 1500) {
    return await new Promise<{
        ok: boolean;
        error?: string;
    }>((resolve) => {
        const socket = createConnection({ host: "127.0.0.1", port: 3310 });
        let settled = false;
        let buffer = "";
        const finish = (result: {
            ok: boolean;
            error?: string;
        }) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            socket.destroy();
            resolve(result);
        };
        const timer = setTimeout(() => finish({ ok: false, error: englishText("backend.clamav.timed_out_waiting_for_clamd_pong") }), timeoutMs);
        socket.on("connect", () => {
            socket.write("PING\n");
        });
        socket.on("data", chunk => {
            buffer += chunk.toString();
            if (/PONG/i.test(buffer))
                finish({ ok: true });
            else if (buffer.length > 1000)
                finish({ ok: false, error: englishText("backend.clamav.unexpected_clamd_response", {
                        value1: String(buffer.slice(0, 200))
                    }) });
        });
        socket.on("error", error => finish({ ok: false, error: error.message }));
        socket.on("end", () => {
            if (!/PONG/i.test(buffer))
                finish({ ok: false, error: buffer ? englishText("backend.clamav.unexpected_clamd_response", {
                        value1: String(buffer.slice(0, 200))
                    }) : englishText("backend.clamav.clamd_closed_the_connection") });
        });
    });
}
export async function readClamdLogTail(settings: any) {
    const logPath = path.join(settings.logsDir || defaultLogsDir, "clamd.log");
    try {
        const handle = await fs.open(logPath, "r");
        try {
            const stat = await handle.stat();
            const length = Math.min(stat.size, 65536);
            const buffer = Buffer.alloc(length);
            await handle.read(buffer, 0, length, Math.max(0, stat.size - length));
            const content = buffer.toString("utf8");
            return content.split(/\r?\n/).filter(Boolean).slice(-12);
        }
        finally {
            await handle.close();
        }
    }
    catch {
        return [];
    }
}
export async function waitForClamdReady(settings: any, timeoutMs = 45000, onProgress?: (message: string) => void) {
    const startedAt = Date.now();
    let lastError = "";
    let announced = false;
    while (Date.now() - startedAt < timeoutMs) {
        if (!runtimeState.clamdProcess) {
            const logTail = await readClamdLogTail(settings);
            return {
                ready: false,
                reason: englishText("backend.clamav.clamd_is_not_running"),
                details: [...runtimeState.clamdStartupOutput.slice(-12), ...logTail]
            };
        }
        const ping = await pingClamd();
        if (ping.ok)
            return { ready: true, reason: englishText("backend.clamav.clamd_is_ready"), details: [] };
        lastError = ping.error || "clamd did not answer PING.";
        if (!announced) {
            onProgress?.(englishText("backend.clamav.waiting_for_clamd_to_finish_loading_databases"));
            announced = true;
        }
        await sleep(500);
    }
    const logTail = await readClamdLogTail(settings);
    return {
        ready: false,
        reason: lastError || englishText("backend.clamav.clamd_did_not_become_ready_before_the_timeout"),
        details: [...runtimeState.clamdStartupOutput.slice(-12), ...logTail]
    };
}
let clamdManagement: Promise<void> = Promise.resolve();
export function manageClamd(settings: any) {
    const requestedSettings = { ...settings };
    const next = clamdManagement.then(() => applyClamdSettings(requestedSettings));
    clamdManagement = next.catch(() => {});
    return next;
}
async function applyClamdSettings(settings: any) {
    if (runtimeState.isSimulated || !settings.clamdPath)
        return;
    if (settings.offloadToMemory) {
        const nextClamdConfSignature = getClamdConfSignature(settings);
        await ensureClamdConfContent(settings);
        if (runtimeState.clamdProcess && runtimeState.clamdConfSignature && runtimeState.clamdConfSignature !== nextClamdConfSignature) {
            console.log(englishText("backend.clamav.restarting_clamd_because_managed_clamd_conf_changed"));
            runtimeState.clamdProcess.kill();
            runtimeState.clamdProcess = null;
            await sleep(500);
        }
        if (!runtimeState.clamdProcess) {
            console.log(englishText("backend.clamav.starting_clamd_process"));
            try {
                runtimeState.clamdStartupOutput = [];
                const child = spawn(settings.clamdPath, ["--config-file=" + settings.clamdConf], { windowsHide: true });
                runtimeState.clamdProcess = child;
                runtimeState.clamdConfSignature = nextClamdConfSignature;
                applyShieldLowImpactPriority(runtimeState.clamdProcess, settings, "clamd");
                child.stdout?.on("data", (data: Buffer) => {
                    const lines = data.toString().split(/\r?\n/).map(line => line.trim()).filter(Boolean);
                    recordClamdOutput(filterClamdStartupOutput(lines));
                    lines.forEach(line => logClamdOutput(line, "log"));
                });
                child.stderr?.on("data", (data: Buffer) => {
                    const lines = data.toString().split(/\r?\n/).map(line => line.trim()).filter(Boolean);
                    recordClamdOutput(filterClamdStartupOutput(lines));
                    lines.forEach(line => logClamdOutput(line, "warn"));
                });
                child.on("error", (err: any) => {
                    console.error(englishText("backend.clamav.failed_to_start_clamd"), err.message);
                    recordClamdOutput([`Failed to start clamd: ${err.message}`]);
                    if (runtimeState.clamdProcess === child) {
                        runtimeState.clamdProcess = null;
                        runtimeState.clamdConfSignature = "";
                    }
                });
                child.on("close", (code: number | null) => {
                    console.log(englishText("backend.clamav.clamd_process_closed"));
                    recordClamdOutput([`clamd process closed${code === null ? "" : ` with exit code ${code}`}.`]);
                    if (runtimeState.clamdProcess === child) {
                        runtimeState.clamdProcess = null;
                        runtimeState.clamdConfSignature = "";
                    }
                });
            }
            catch (e: any) {
                console.error(englishText("backend.clamav.failed_to_start_clamd"), e.message);
                recordClamdOutput([`Failed to start clamd: ${e.message}`]);
            }
        }
        else {
            applyShieldLowImpactPriority(runtimeState.clamdProcess, settings, "clamd");
        }
    }
    else {
        if (runtimeState.clamdProcess) {
            console.log(englishText("backend.clamav.stopping_clamd_process"));
            runtimeState.clamdProcess.kill();
            runtimeState.clamdProcess = null;
            runtimeState.clamdConfSignature = "";
        }
    }
}
export async function performClamdDatabaseReload(settings: any) {
    if (!settings.offloadToMemory || !runtimeState.clamdProcess)
        return;
    if (runtimeState.clamdDatabaseReloadInProgress) {
        runtimeState.clamdDatabaseReloadPending = true;
        return;
    }
    runtimeState.clamdDatabaseReloadInProgress = true;
    console.log("Reloading clamd after database update.");
    try {
        runtimeState.clamdProcess.kill();
        runtimeState.clamdProcess = null;
        runtimeState.clamdConfSignature = "";
        await sleep(500);
        await manageClamd(settings);
    }
    finally {
        runtimeState.clamdDatabaseReloadInProgress = false;
    }
}
export async function reloadClamdDatabases(settings: any) {
    if (!settings.offloadToMemory || !runtimeState.clamdProcess)
        return;
    if (runtimeState.shouldDeferClamdDatabaseReload?.()) {
        runtimeState.clamdDatabaseReloadPending = true;
        console.log(englishText("backend.clamav.deferring_clamd_reload_until_active_scans_finish"));
        return;
    }
    runtimeState.clamdDatabaseReloadPending = false;
    await performClamdDatabaseReload(settings);
}
export async function flushPendingClamdDatabaseReload(settings: any) {
    if (!runtimeState.clamdDatabaseReloadPending || runtimeState.shouldDeferClamdDatabaseReload?.())
        return;
    runtimeState.clamdDatabaseReloadPending = false;
    await performClamdDatabaseReload(settings);
}
export async function checkIsAdmin() {
    if (process.platform !== "win32")
        return false;
    try {
        await execAsync("net session");
        return true;
    }
    catch {
        return false;
    }
}
export async function checkClamAV(settings: any) {
    if (process.platform !== "win32") {
        runtimeState.isSimulated = true;
    }
    else {
        runtimeState.isSimulated = false;
        // Auto-fix paths if old clamav-* folder exists
        try {
            await fs.mkdir(engineBaseDir, { recursive: true });
            const extractedClamDir = await findExtractedClamavDir();
            const managedClamDir = path.join(engineBaseDir, "clamav");
            const managedEngineExists = await pathExists(path.join(managedClamDir, "clamscan.exe")) && await pathExists(path.join(managedClamDir, "freshclam.exe"));
            if (!managedEngineExists && extractedClamDir) {
                console.log(englishText("backend.clamav.adopting_extracted_clamav_engine_into_managed_folder"));
                settings.clamavDir = await adoptClamavEngineFolder(extractedClamDir);
                settings.clamscanPath = path.join(settings.clamavDir, "clamscan.exe");
                settings.freshclamPath = path.join(settings.clamavDir, "freshclam.exe");
                settings.clamdPath = path.join(settings.clamavDir, "clamd.exe");
                settings.clamdscanPath = path.join(settings.clamavDir, "clamdscan.exe");
                settings.freshclamConf = path.join(settings.clamavDir, "freshclam.conf");
                settings.clamdConf = path.join(settings.clamavDir, "clamd.conf");
                await saveConfig(settings);
            }
        }
        catch (e: any) {
            console.error(englishText("backend.clamav.error_during_checkclamav_auto_fix"), e.message);
        }
        // Ensure configuration files exist
        if (settings.freshclamConf) {
            try {
                await ensureFreshclamConfig(settings);
            }
            catch (e) {
                console.error(englishText("backend.clamav.failed_to_ensure_freshclam_conf"), e);
            }
        }
        if (settings.clamdConf) {
            await ensureClamdConfContent(settings);
        }
    }
}
