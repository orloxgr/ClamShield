import { englishText } from "../../shared/localization/runtime";
import { appTempDir } from "../core/paths";
import { getScanIntensityProfile } from "../scanning/intensity";
import { spawn } from "child_process";
import { randomBytes } from "crypto";
import fs from "fs/promises";
import path from "path";
export async function ensureAppTempDir() {
    await fs.mkdir(appTempDir, { recursive: true });
    return appTempDir;
}
export async function runPowerShellFile(script: string) {
    const scriptPath = path.join(await ensureAppTempDir(), `clamshield-${Date.now()}-${randomBytes(6).toString("hex")}.ps1`);
    await fs.writeFile(scriptPath, script, "utf8");
    try {
        return await new Promise<{
            stdout: string;
            stderr: string;
        }>((resolve, reject) => {
            let settled = false;
            const child = spawn("powershell", [
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", scriptPath
            ], {
                windowsHide: true
            });
            let stdout = "";
            let stderr = "";
            child.stdout.on("data", data => stdout += data.toString());
            child.stderr.on("data", data => stderr += data.toString());
            const timeout = setTimeout(() => {
                if (settled)
                    return;
                settled = true;
                child.kill();
                reject(new Error(englishText("backend.platform.powershell_operation_timed_out")));
            }, 45000);
            child.on("error", error => {
                if (settled)
                    return;
                settled = true;
                clearTimeout(timeout);
                reject(error);
            });
            child.on("close", code => {
                if (settled)
                    return;
                settled = true;
                clearTimeout(timeout);
                if (code === 0) {
                    resolve({ stdout, stderr });
                }
                else {
                    const message = (stderr || stdout || `PowerShell exited with code ${code}`).trim();
                    reject(new Error(message));
                }
            });
        });
    }
    finally {
        fs.unlink(scriptPath).catch(() => { });
    }
}
export async function runPowerShellJson(script: string) {
    const { stdout, stderr } = await runPowerShellFile(script);
    const output = `${stdout}\n${stderr}`;
    const match = output.match(/CLAMSHIELD_JSON_START\s*([\s\S]*?)\s*CLAMSHIELD_JSON_END/);
    if (!match) {
        throw new Error((stderr || stdout || "PowerShell did not return JSON.").trim());
    }
    return JSON.parse(match[1]);
}
export type ProcessRunOptions = {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    timeoutMs?: number;
    onLine?: (line: string) => void;
};
export async function runHiddenProcess(executable: string, args: string[], options: ProcessRunOptions = {}) {
    return await new Promise<{
        code: number;
        stdout: string;
        stderr: string;
    }>((resolve, reject) => {
        let settled = false;
        let stdout = "";
        let stderr = "";
        let stdoutRemainder = "";
        let stderrRemainder = "";
        const child = spawn(executable, args, {
            cwd: options.cwd,
            env: options.env,
            windowsHide: true
        });
        const emitLines = (text: string, stream: "stdout" | "stderr") => {
            const combined = (stream === "stdout" ? stdoutRemainder : stderrRemainder) + text;
            const lines = combined.split(/\r\n|\n|\r/g);
            const remainder = lines.pop() || "";
            if (stream === "stdout")
                stdoutRemainder = remainder;
            else
                stderrRemainder = remainder;
            for (const line of lines.map(item => item.trim()).filter(Boolean)) {
                options.onLine?.(line);
            }
        };
        child.stdout?.on("data", data => {
            const text = data.toString();
            stdout += text;
            emitLines(text, "stdout");
        });
        child.stderr?.on("data", data => {
            const text = data.toString();
            stderr += text;
            emitLines(text, "stderr");
        });
        const timeout = setTimeout(() => {
            if (settled)
                return;
            settled = true;
            child.kill();
            reject(new Error(englishText("backend.platform.timed_out", {
                value1: String(path.basename(executable))
            })));
        }, options.timeoutMs || 300000);
        timeout.unref?.();
        child.on("error", error => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timeout);
            reject(error);
        });
        child.on("close", code => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timeout);
            if (stdoutRemainder.trim())
                options.onLine?.(stdoutRemainder.trim());
            if (stderrRemainder.trim())
                options.onLine?.(stderrRemainder.trim());
            resolve({ code: code ?? -1, stdout, stderr });
        });
    });
}
export function normalizeWindowsPriority(value: any, fallback = "BelowNormal") {
    const normalized = String(value || fallback).toLowerCase();
    const priorityMap: Record<string, string> = {
        idle: "Idle",
        belownormal: "BelowNormal",
        "below-normal": "BelowNormal",
        below_normal: "BelowNormal",
        normal: "Normal"
    };
    return priorityMap[normalized] || fallback;
}
export async function setWindowsProcessPriority(pid: any, priority: any) {
    if (process.platform !== "win32")
        return;
    const normalizedPid = Number(pid);
    if (!Number.isInteger(normalizedPid) || normalizedPid <= 0)
        return;
    const priorityClass = normalizeWindowsPriority(priority);
    const script = [
        "$ErrorActionPreference = 'SilentlyContinue'",
        `$p = Get-Process -Id ${normalizedPid} -ErrorAction SilentlyContinue`,
        `if ($p) { $p.PriorityClass = '${priorityClass}' }`
    ].join("\n");
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    await new Promise<void>((resolve) => {
        let settled = false;
        const done = () => {
            if (!settled) {
                settled = true;
                resolve();
            }
        };
        const child = spawn("powershell", ["-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", encoded], { windowsHide: true });
        child.on("error", done);
        child.on("close", done);
    });
}
export function applyShieldLowImpactPriority(child: any, settings: any, label: string) {
    const profile = getScanIntensityProfile(settings, 0, "shield");
    const priorityClass = normalizeWindowsPriority(profile.priorityClass, profile.priorityClass);
    void setWindowsProcessPriority(child?.pid, priorityClass)
        .then(() => {
        if (process.platform === "win32" && child?.pid) {
            console.log(englishText("backend.platform.shield_low_impact_mode_pid_priority_set_to", {
                label: String(label),
                pid: String(child.pid),
                priorityClass: String(priorityClass)
            }));
        }
    })
        .catch((err: any) => console.warn(englishText("backend.platform.shield_low_impact_mode_could_not_set_priority", {
        label: String(label)
    }), err?.message || err));
}
