import express from "express";
import fs from "fs/promises";
import { appendFileSync, createWriteStream, createReadStream, existsSync, mkdirSync } from "fs";
import path from "path";
import os from "os";
import { exec, spawn } from "child_process";
import { promisify } from "util";
import { createHash, randomBytes } from "crypto";
import { createRequire } from "module";
import axios from "axios";
import unzipper from "unzipper";
import chokidar from "chokidar";

const runtimeFileName = typeof __filename === "string" ? __filename : path.resolve(process.argv[1] || ".");
const runtimeDir = typeof __dirname === "string" ? __dirname : path.dirname(runtimeFileName);
const nodeRequire = createRequire(runtimeFileName);

const execAsync = promisify(exec);

// Path logic to handle default paths or user configurations
// Note: process.platform === "win32" is Node.js's identifier for ALL Windows systems, including 64-bit.
const programDataDir = process.platform === "win32" 
    ? path.join(process.env.PROGRAMDATA || "C:\\ProgramData", "ClamShield") 
    : path.join(process.cwd(), "data", "ClamShield");

const engineBaseDir = path.join(programDataDir, "engine");
const defaultLogsDir = path.join(programDataDir, "logs");
const yaraBaseDir = path.join(programDataDir, "yara");
const yaraForgeRulesDir = path.join(yaraBaseDir, "rules", "forge");
const yaraCustomRulesDir = path.join(yaraBaseDir, "rules", "custom");
const yaraCacheDir = path.join(yaraBaseDir, "cache");
let debugLoggingEnabled = false;
let currentLogsDir = defaultLogsDir;

function logArgToString(arg: any) {
    if (arg instanceof Error) return arg.stack || arg.message;
    if (typeof arg === "string") return arg;
    try {
        return JSON.stringify(arg);
    } catch {
        return String(arg);
    }
}

function writeAppLog(fileName: string, level: string, args: any[]) {
    try {
        mkdirSync(currentLogsDir, { recursive: true });
        const line = `[${new Date().toISOString()}] [${level.toUpperCase()}] ${args.map(logArgToString).join(" ")}\n`;
        appendFileSync(path.join(currentLogsDir, fileName), line, "utf8");
    } catch {
        // Logging must never break protection or scans.
    }
}

const originalConsole = {
    log: console.log.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
    debug: console.debug.bind(console)
};

console.log = (...args: any[]) => {
    originalConsole.log(...args);
    if (debugLoggingEnabled) writeAppLog("server.log", "info", args);
};
console.debug = (...args: any[]) => {
    originalConsole.debug(...args);
    if (debugLoggingEnabled) writeAppLog("server.log", "debug", args);
};
console.warn = (...args: any[]) => {
    originalConsole.warn(...args);
    if (debugLoggingEnabled) writeAppLog("server.log", "warn", args);
};
console.error = (...args: any[]) => {
    originalConsole.error(...args);
    if (debugLoggingEnabled) writeAppLog("server.log", "error", args);
};

process.on("uncaughtException", error => {
    writeAppLog("server.log", "fatal", ["Uncaught exception", error]);
    originalConsole.error("Uncaught exception:", error);
});

process.on("unhandledRejection", reason => {
    writeAppLog("server.log", "fatal", ["Unhandled rejection", reason]);
    originalConsole.error("Unhandled rejection:", reason);
});

const defaultSettings = {
    // Relying on 64-bit Program Files by default, but we'll try to use a local bundled path if possible
    clamavDir: process.platform === "win32" ? path.join(engineBaseDir, "clamav") : "/usr/bin",
    clamscanPath: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "clamscan.exe") : "/usr/bin/clamscan",
    freshclamPath: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "freshclam.exe") : "/usr/bin/freshclam",
    freshclamConf: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "freshclam.conf") : "/etc/clamav/freshclam.conf",
    clamdPath: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "clamd.exe") : "/usr/sbin/clamd",
    clamdscanPath: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "clamdscan.exe") : "/usr/bin/clamdscan",
    clamdConf: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "clamd.conf") : "/etc/clamav/clamd.conf",
    yaraDir: process.platform === "win32" ? path.join(engineBaseDir, "yara") : "/usr/bin",
    yaraPath: process.platform === "win32" ? path.join(engineBaseDir, "yara", "yara64.exe") : "/usr/bin/yara",
    yaraRulesDir: yaraForgeRulesDir,
    yaraCustomRulesDir,
    yaraCacheDir,
    databaseDir: path.join(programDataDir, "db"),
    quarantineDir: path.join(programDataDir, "quarantine"),
    logsDir: defaultLogsDir,
    defaultAction: "ask",
    actionOnDetection: "ask",
    scanDetectionAction: "results",
    autoQuarantine: false,
    autoUpdateEnabled: true,
    updateIntervalHours: 24,
    yaraEnabled: true,
    yaraRuleset: "core",
    yaraAutoUpdateEnabled: true,
    yaraUpdateIntervalHours: 168,
    yaraTimeoutSeconds: 15,
    yaraMaxFileSize: 50,
    scanBatchSize: 250,
    scanBatchDelayMs: 0,
    appUpdateCheckEnabled: true,
    appUpdateIntervalHours: 168,
    appSilentAutoInstall: false,
    skippedAppVersion: "",
    offloadToMemory: false,
    maxFileSize: 50, // MB
    scanArchives: true,
    recursive: true,
    followSymlinks: false,
    shieldEnabled: true,
    shieldShowPopup: true,
    shieldMaxConcurrentScans: 1,
    autoDetectBrowserDownloads: true,
    monitorDownloads: true,
    monitorDesktop: true,
    monitorDocuments: true,
    customWatchedFolders: [],
    exclusions: [],
    shieldDepth: 1,
    shieldPollInterval: 1000,
    shieldStabilityThreshold: 2000,
    shieldLowImpactMode: true,
    shieldProcessPriority: "belowNormal",
    runOnStartup: true,
    startMinimized: false,
    eulaAccepted: false,
    playSoundOnAlert: false,
    enableDebugLog: false,
    logRetentionDays: 7,
    autoDisableDefender: true,
    defenderEnforceIntervalMinutes: 5
};

const apiSessionToken = process.env.CLAMSHIELD_API_TOKEN || randomBytes(32).toString("hex");
const apiCookieName = "clamshield_session";
const apiHeaderName = "x-clamshield-session";
let pendingThreatHandler: ((threat: any) => void) | null = null;
let scanResultsChangedHandler: (() => void | Promise<void>) | null = null;

// Simulate mode if not on Windows or clamscan not found
let isSimulated = false;
async function runPowerShellFile(script: string) {
    const scriptPath = path.join(os.tmpdir(), `clamshield-${Date.now()}-${randomBytes(6).toString("hex")}.ps1`);
    await fs.writeFile(scriptPath, script, "utf8");
    try {
        return await new Promise<{ stdout: string, stderr: string }>((resolve, reject) => {
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
                if (settled) return;
                settled = true;
                child.kill();
                reject(new Error("PowerShell operation timed out."));
            }, 45000);
            child.on("error", error => {
                if (settled) return;
                settled = true;
                clearTimeout(timeout);
                reject(error);
            });
            child.on("close", code => {
                if (settled) return;
                settled = true;
                clearTimeout(timeout);
                if (code === 0) {
                    resolve({ stdout, stderr });
                } else {
                    const message = (stderr || stdout || `PowerShell exited with code ${code}`).trim();
                    reject(new Error(message));
                }
            });
        });
    } finally {
        fs.unlink(scriptPath).catch(() => {});
    }
}

async function runPowerShellJson(script: string) {
    const { stdout, stderr } = await runPowerShellFile(script);
    const output = `${stdout}\n${stderr}`;
    const match = output.match(/CLAMSHIELD_JSON_START\s*([\s\S]*?)\s*CLAMSHIELD_JSON_END/);
    if (!match) {
        throw new Error((stderr || stdout || "PowerShell did not return JSON.").trim());
    }
    return JSON.parse(match[1]);
}

function defenderStatusScript() {
    return `
$ErrorActionPreference = 'Continue'
$status = $null
$prefs = $null
$errorText = $null
try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $errorText = $_.Exception.Message }
try { $prefs = Get-MpPreference -ErrorAction Stop } catch {}
$result = [ordered]@{
    Supported = $true
    Error = $errorText
    AMServiceEnabled = if ($status) { $status.AMServiceEnabled } else { $null }
    AntivirusEnabled = if ($status) { $status.AntivirusEnabled } else { $null }
    RealTimeProtectionEnabled = if ($status) { $status.RealTimeProtectionEnabled } else { $null }
    BehaviorMonitorEnabled = if ($status) { $status.BehaviorMonitorEnabled } else { $null }
    IoavProtectionEnabled = if ($status) { $status.IoavProtectionEnabled } else { $null }
    OnAccessProtectionEnabled = if ($status) { $status.OnAccessProtectionEnabled } else { $null }
    IsTamperProtected = if ($status -and ($status.PSObject.Properties.Name -contains 'IsTamperProtected')) { $status.IsTamperProtected } else { $null }
    DisableRealtimeMonitoring = if ($prefs) { $prefs.DisableRealtimeMonitoring } else { $null }
    DisableBehaviorMonitoring = if ($prefs) { $prefs.DisableBehaviorMonitoring } else { $null }
    DisableIOAVProtection = if ($prefs) { $prefs.DisableIOAVProtection } else { $null }
    DisableScriptScanning = if ($prefs) { $prefs.DisableScriptScanning } else { $null }
}
'CLAMSHIELD_JSON_START'
$result | ConvertTo-Json -Compress
'CLAMSHIELD_JSON_END'
`;
}

function defenderDisableScript() {
    return `
$ErrorActionPreference = 'Continue'
$operations = [ordered]@{}
function Set-ClamShieldMpPreference($Name, $Value) {
    try {
        $params = @{}
        $params[$Name] = $Value
        Set-MpPreference @params -ErrorAction Stop
        $operations[$Name] = 'ok'
    } catch {
        $operations[$Name] = $_.Exception.Message
    }
}
Set-ClamShieldMpPreference 'DisableRealtimeMonitoring' $true
Set-ClamShieldMpPreference 'DisableBehaviorMonitoring' $true
Set-ClamShieldMpPreference 'DisableIOAVProtection' $true
Set-ClamShieldMpPreference 'DisableScriptScanning' $true
try {
    New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    $operations['SecurityAndMaintenanceNotifications'] = 'ok'
} catch {
    $operations['SecurityAndMaintenanceNotifications'] = $_.Exception.Message
}
try {
    $WMI = [wmiclass]"root\\SecurityCenter2:AntiVirusProduct"
    $New = $WMI.CreateInstance()
    $New.displayName = "ClamShield Antivirus"
    $New.instanceGuid = "{F6DB11CF-FA62-4C3D-AA9F-44F4FD9D77AA}"
    $New.pathToSignedProductExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $New.pathToSignedReportingExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $New.productState = 397568
    $New.Put() | Out-Null
    $operations['SecurityCenterRegistration'] = 'ok'
} catch {
    $operations['SecurityCenterRegistration'] = $_.Exception.Message
}
Start-Sleep -Milliseconds 800
$status = $null
$prefs = $null
$errorText = $null
try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $errorText = $_.Exception.Message }
try { $prefs = Get-MpPreference -ErrorAction Stop } catch {}
$realTimeEnabled = if ($status) { [bool]$status.RealTimeProtectionEnabled } else { $null }
$success = ($realTimeEnabled -eq $false)
$result = [ordered]@{
    Supported = $true
    Success = $success
    Error = $errorText
    Operations = $operations
    RealTimeProtectionEnabled = $realTimeEnabled
    BehaviorMonitorEnabled = if ($status) { $status.BehaviorMonitorEnabled } else { $null }
    IoavProtectionEnabled = if ($status) { $status.IoavProtectionEnabled } else { $null }
    OnAccessProtectionEnabled = if ($status) { $status.OnAccessProtectionEnabled } else { $null }
    IsTamperProtected = if ($status -and ($status.PSObject.Properties.Name -contains 'IsTamperProtected')) { $status.IsTamperProtected } else { $null }
    DisableRealtimeMonitoring = if ($prefs) { $prefs.DisableRealtimeMonitoring } else { $null }
    DisableBehaviorMonitoring = if ($prefs) { $prefs.DisableBehaviorMonitoring } else { $null }
    DisableIOAVProtection = if ($prefs) { $prefs.DisableIOAVProtection } else { $null }
    DisableScriptScanning = if ($prefs) { $prefs.DisableScriptScanning } else { $null }
    NeedsManualAction = (-not $success)
    Message = if ($success) { 'Microsoft Defender real-time protection is paused.' } else { 'Microsoft Defender did not remain paused. Windows Tamper Protection, policy, or Security Center registration may be preventing programmatic disable.' }
}
'CLAMSHIELD_JSON_START'
$result | ConvertTo-Json -Depth 5 -Compress
'CLAMSHIELD_JSON_END'
`;
}

function defenderRestoreScript() {
    return `
$ErrorActionPreference = 'Continue'
$operations = [ordered]@{}
function Set-ClamShieldMpPreference($Name, $Value) {
    try {
        $params = @{}
        $params[$Name] = $Value
        Set-MpPreference @params -ErrorAction Stop
        $operations[$Name] = 'ok'
    } catch {
        $operations[$Name] = $_.Exception.Message
    }
}
Set-ClamShieldMpPreference 'DisableRealtimeMonitoring' $false
Set-ClamShieldMpPreference 'DisableBehaviorMonitoring' $false
Set-ClamShieldMpPreference 'DisableIOAVProtection' $false
Set-ClamShieldMpPreference 'DisableScriptScanning' $false
try {
    Remove-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Force -ErrorAction SilentlyContinue
    $operations['SecurityAndMaintenanceNotifications'] = 'ok'
} catch {
    $operations['SecurityAndMaintenanceNotifications'] = $_.Exception.Message
}
Start-Sleep -Milliseconds 800
$status = $null
$prefs = $null
$errorText = $null
try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $errorText = $_.Exception.Message }
try { $prefs = Get-MpPreference -ErrorAction Stop } catch {}
$result = [ordered]@{
    Supported = $true
    Success = $true
    Error = $errorText
    Operations = $operations
    RealTimeProtectionEnabled = if ($status) { $status.RealTimeProtectionEnabled } else { $null }
    BehaviorMonitorEnabled = if ($status) { $status.BehaviorMonitorEnabled } else { $null }
    IoavProtectionEnabled = if ($status) { $status.IoavProtectionEnabled } else { $null }
    OnAccessProtectionEnabled = if ($status) { $status.OnAccessProtectionEnabled } else { $null }
    IsTamperProtected = if ($status -and ($status.PSObject.Properties.Name -contains 'IsTamperProtected')) { $status.IsTamperProtected } else { $null }
    DisableRealtimeMonitoring = if ($prefs) { $prefs.DisableRealtimeMonitoring } else { $null }
    DisableBehaviorMonitoring = if ($prefs) { $prefs.DisableBehaviorMonitoring } else { $null }
    DisableIOAVProtection = if ($prefs) { $prefs.DisableIOAVProtection } else { $null }
    DisableScriptScanning = if ($prefs) { $prefs.DisableScriptScanning } else { $null }
    Message = 'Microsoft Defender preferences were restored where Windows allowed it.'
}
'CLAMSHIELD_JSON_START'
$result | ConvertTo-Json -Depth 5 -Compress
'CLAMSHIELD_JSON_END'
`;
}

async function getDefenderStatus() {
    if (process.platform !== "win32") return { Supported: false, Error: "Only supported on Windows." };
    return runPowerShellJson(defenderStatusScript());
}

function defenderTamperProtectedResult(status: any) {
    return {
        Supported: true,
        Success: false,
        SideBySideMode: true,
        NeedsManualAction: true,
        IsTamperProtected: true,
        RealTimeProtectionEnabled: status?.RealTimeProtectionEnabled ?? null,
        BehaviorMonitorEnabled: status?.BehaviorMonitorEnabled ?? null,
        IoavProtectionEnabled: status?.IoavProtectionEnabled ?? null,
        OnAccessProtectionEnabled: status?.OnAccessProtectionEnabled ?? null,
        DisableRealtimeMonitoring: status?.DisableRealtimeMonitoring ?? null,
        DisableBehaviorMonitoring: status?.DisableBehaviorMonitoring ?? null,
        DisableIOAVProtection: status?.DisableIOAVProtection ?? null,
        DisableScriptScanning: status?.DisableScriptScanning ?? null,
        Message: "Windows Tamper Protection is ON. Defender cannot be paused automatically. ClamShield will keep running side-by-side."
    };
}

async function requestDefenderPause() {
    if (process.platform !== "win32") return { Supported: false, Success: false, Error: "Only supported on Windows." };
    const status = await getDefenderStatus();
    if (status?.IsTamperProtected === true) {
        return defenderTamperProtectedResult(status);
    }
    return runPowerShellJson(defenderDisableScript());
}

async function restoreDefenderPreferences() {
    if (process.platform !== "win32") return { Supported: false, Success: false, Error: "Only supported on Windows." };
    return runPowerShellJson(defenderRestoreScript());
}

async function openWindowsSecurity() {
    if (process.platform !== "win32") return { success: false, error: "Only supported on Windows." };
    const attempts = [
        { command: "explorer.exe", args: ["windowsdefender://threatsettings/"] },
        { command: "cmd.exe", args: ["/c", "start", "", "windowsdefender://threatsettings/"] },
        { command: "explorer.exe", args: ["windowsdefender:"] },
        { command: "explorer.exe", args: ["ms-settings:windowsdefender"] },
        { command: "cmd.exe", args: ["/c", "start", "", "windowsdefender:"] },
        { command: "cmd.exe", args: ["/c", "start", "", "ms-settings:windowsdefender"] }
    ];
    const errors: string[] = [];
    for (const attempt of attempts) {
        const result = await new Promise<{ success: boolean, error?: string }>((resolve) => {
            let settled = false;
            const done = (success: boolean, error?: string) => {
                if (!settled) {
                    settled = true;
                    resolve({ success, error });
                }
            };
            try {
                const child = spawn(attempt.command, attempt.args, {
                    detached: true,
                    stdio: "ignore",
                    windowsHide: true
                });
                child.on("error", (err: any) => done(false, err?.message || String(err)));
                child.on("spawn", () => {
                    child.unref();
                    done(true);
                });
                setTimeout(() => done(true), 1200).unref?.();
            } catch (e: any) {
                done(false, e?.message || String(e));
            }
        });
        if (result.success) {
            return { success: true, command: attempt.command, args: attempt.args };
        }
        if (result.error) errors.push(`${attempt.command}: ${result.error}`);
    }
    return { success: false, error: errors.join("; ") || "Windows Security could not be opened." };
}

async function autoDisableDefender() {
    try {
        const result = await requestDefenderPause();
        if (!result.Success && !result.SideBySideMode) {
            console.warn("Defender pause was not fully applied:", result.Message || result.Error || result);
        }
        return result;
    } catch (e: any) {
        console.warn("Defender pause failed:", e.message);
        return { Supported: process.platform === "win32", Success: false, Error: e.message };
    }
}

function readCookie(req: express.Request, name: string) {
    const cookieHeader = req.headers.cookie || "";
    const cookies = cookieHeader.split(";").map(part => part.trim());
    const prefix = `${name}=`;
    const match = cookies.find(cookie => cookie.startsWith(prefix));
    return match ? decodeURIComponent(match.slice(prefix.length)) : "";
}

function requireLocalApiSession(req: express.Request, res: express.Response, next: express.NextFunction) {
    if (!req.path.startsWith("/api")) return next();
    if (readCookie(req, apiCookieName) === apiSessionToken) return next();
    if (req.header(apiHeaderName) === apiSessionToken) return next();
    res.status(403).json({ error: "Invalid local API session." });
}

function normalizePositiveNumber(value: any, fallback: number, min: number, max: number) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
}

function formatDuration(totalSeconds: number) {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (hours > 0) {
        return `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
    }
    return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function normalizeWindowsPriority(value: any, fallback = "BelowNormal") {
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

async function setWindowsProcessPriority(pid: any, priority: any) {
    if (process.platform !== "win32") return;
    const normalizedPid = Number(pid);
    if (!Number.isInteger(normalizedPid) || normalizedPid <= 0) return;

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

function applyShieldLowImpactPriority(child: any, settings: any, label: string) {
    if (settings?.shieldLowImpactMode === false) return;
    const priorityClass = normalizeWindowsPriority(settings?.shieldProcessPriority, "BelowNormal");
    void setWindowsProcessPriority(child?.pid, priorityClass)
        .then(() => {
            if (process.platform === "win32" && child?.pid) {
                console.log(`Shield low impact mode: ${label} PID ${child.pid} priority set to ${priorityClass}.`);
            }
        })
        .catch((err: any) => console.warn(`Shield low impact mode could not set ${label} priority:`, err?.message || err));
}

async function isDirectory(dirPath: string) {
    try {
        const stat = await fs.stat(dirPath);
        return stat.isDirectory();
    } catch {
        return false;
    }
}

function dedupePaths(paths: string[]) {
    const seen = new Set<string>();
    return paths.filter(folderPath => {
        const normalized = path.resolve(folderPath).toLowerCase();
        if (seen.has(normalized)) return false;
        seen.add(normalized);
        return true;
    });
}

async function existingUniqueDirs(paths: string[]) {
    const unique = dedupePaths(paths.filter(Boolean));
    const result: string[] = [];
    for (const dirPath of unique) {
        if (await isDirectory(dirPath)) result.push(dirPath);
    }
    return result;
}

async function existingUniqueFiles(paths: string[]) {
    const unique = dedupePaths(paths.filter(Boolean));
    const result: string[] = [];
    for (const filePath of unique) {
        try {
            const stat = await fs.stat(filePath);
            if (stat.isFile()) result.push(filePath);
        } catch {}
    }
    return result;
}

async function getWindowsKnownFolders() {
    if (process.platform !== "win32") {
        const homeDir = os.homedir();
        return {
            Desktop: path.join(homeDir, "Desktop"),
            Documents: path.join(homeDir, "Documents"),
            Downloads: path.join(homeDir, "Downloads")
        };
    }

    const fallbackHome = os.homedir();
    const fallback = {
        Desktop: path.join(fallbackHome, "Desktop"),
        Documents: path.join(fallbackHome, "Documents"),
        Downloads: path.join(fallbackHome, "Downloads")
    };

    const script = `
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders'
$props = Get-ItemProperty -Path $key
$out = [ordered]@{}
if ($props.Desktop) { $out.Desktop = [Environment]::ExpandEnvironmentVariables($props.Desktop) }
if ($props.Personal) { $out.Documents = [Environment]::ExpandEnvironmentVariables($props.Personal) }
$downloads = $props.'{374DE290-123F-4565-9164-39C4925E467B}'
if ($downloads) { $out.Downloads = [Environment]::ExpandEnvironmentVariables($downloads) }
$out | ConvertTo-Json -Compress
`;

    try {
        const encoded = Buffer.from(script, "utf16le").toString("base64");
        const { stdout } = await execAsync(`powershell -NoProfile -EncodedCommand ${encoded}`);
        const parsed = JSON.parse(stdout.trim() || "{}");
        return {
            Desktop: parsed.Desktop || fallback.Desktop,
            Documents: parsed.Documents || fallback.Documents,
            Downloads: parsed.Downloads || fallback.Downloads
        };
    } catch {
        return fallback;
    }
}

async function readJsonFile(filePath: string) {
    try {
        return JSON.parse(await fs.readFile(filePath, "utf8"));
    } catch {
        return null;
    }
}

async function detectChromiumDownloadFolders(browser: string, rootDir: string, directProfile = false) {
    const folders: { browser: string, path: string, profile: string }[] = [];
    const candidatePrefs: { filePath: string, profile: string }[] = [];

    if (directProfile) {
        candidatePrefs.push({ filePath: path.join(rootDir, "Preferences"), profile: "Default" });
    } else {
        try {
            const entries = await fs.readdir(rootDir, { withFileTypes: true });
            for (const entry of entries) {
                if (!entry.isDirectory()) continue;
                candidatePrefs.push({
                    filePath: path.join(rootDir, entry.name, "Preferences"),
                    profile: entry.name
                });
            }
        } catch {
            return folders;
        }
    }

    for (const candidate of candidatePrefs) {
        const prefs = await readJsonFile(candidate.filePath);
        const downloadDir = prefs?.download?.default_directory;
        if (typeof downloadDir === "string" && await isDirectory(downloadDir)) {
            folders.push({ browser, path: downloadDir, profile: candidate.profile });
        }
    }

    return folders;
}

function unescapeFirefoxPrefPath(prefPath: string) {
    return prefPath.replace(/\\\\/g, "\\").replace(/\\"/g, '"');
}

async function detectFirefoxDownloadFolders(rootDir: string) {
    const folders: { browser: string, path: string, profile: string }[] = [];
    let profilesIni = "";
    try {
        profilesIni = await fs.readFile(path.join(rootDir, "profiles.ini"), "utf8");
    } catch {
        return folders;
    }

    const sections = profilesIni.split(/\r?\n\s*\r?\n/);
    for (const section of sections) {
        const pathMatch = section.match(/^Path=(.+)$/m);
        if (!pathMatch) continue;
        const isRelative = /^IsRelative=1$/m.test(section);
        const profilePath = isRelative ? path.join(rootDir, pathMatch[1]) : pathMatch[1];
        const prefsPath = path.join(profilePath, "prefs.js");
        let prefs = "";
        try {
            prefs = await fs.readFile(prefsPath, "utf8");
        } catch {
            continue;
        }

        const customPathMatch = prefs.match(/user_pref\("browser\.download\.dir",\s*"((?:\\.|[^"])*)"\);/);
        if (!customPathMatch) continue;
        const downloadDir = unescapeFirefoxPrefPath(customPathMatch[1]);
        if (await isDirectory(downloadDir)) {
            folders.push({ browser: "Firefox", path: downloadDir, profile: path.basename(profilePath) });
        }
    }

    return folders;
}

async function detectBrowserDownloadFolders() {
    if (process.platform !== "win32") return [];

    const localAppData = process.env.LOCALAPPDATA || "";
    const appData = process.env.APPDATA || "";
    const chromiumBrowsers = [
        { browser: "Google Chrome", root: path.join(localAppData, "Google", "Chrome", "User Data") },
        { browser: "Microsoft Edge", root: path.join(localAppData, "Microsoft", "Edge", "User Data") },
        { browser: "Brave", root: path.join(localAppData, "BraveSoftware", "Brave-Browser", "User Data") },
        { browser: "Vivaldi", root: path.join(localAppData, "Vivaldi", "User Data") },
        { browser: "Opera", root: path.join(appData, "Opera Software", "Opera Stable"), directProfile: true },
        { browser: "Opera GX", root: path.join(appData, "Opera Software", "Opera GX Stable"), directProfile: true },
        { browser: "Chromium", root: path.join(localAppData, "Chromium", "User Data") }
    ];

    const detected: { browser: string, path: string, profile: string }[] = [];
    for (const item of chromiumBrowsers) {
        if (!await isDirectory(item.root)) continue;
        detected.push(...await detectChromiumDownloadFolders(item.browser, item.root, !!item.directProfile));
    }

    const firefoxRoot = path.join(appData, "Mozilla", "Firefox");
    if (await isDirectory(firefoxRoot)) {
        detected.push(...await detectFirefoxDownloadFolders(firefoxRoot));
    }

    const seen = new Set<string>();
    return detected.filter(item => {
        const key = path.resolve(item.path).toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

async function getResolvedSystemPaths() {
    const known = await getWindowsKnownFolders();
    const browserDownloads = await detectBrowserDownloadFolders();
    return {
        ...known,
        BrowserDownloads: browserDownloads
    };
}

async function getRunningProcessImagePaths() {
    if (process.platform !== "win32") return [];
    const script = `
$ErrorActionPreference = 'SilentlyContinue'
$paths = Get-CimInstance Win32_Process |
    Where-Object { $_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath -PathType Leaf) } |
    Select-Object -ExpandProperty ExecutablePath -Unique
'CLAMSHIELD_JSON_START'
@($paths) | ConvertTo-Json -Compress
'CLAMSHIELD_JSON_END'
`;
    try {
        const result = await runPowerShellJson(script);
        return existingUniqueFiles(Array.isArray(result) ? result : [result].filter(Boolean));
    } catch (e: any) {
        console.warn("Failed to enumerate process executable paths:", e.message);
        return [];
    }
}

async function createScanFileList(paths: string[]) {
    const listPath = path.join(os.tmpdir(), `clamshield-scan-list-${Date.now()}-${randomBytes(6).toString("hex")}.txt`);
    await fs.writeFile(listPath, paths.join(os.EOL), "utf8");
    return listPath;
}

class ScanSessionStore {
    private db: any;
    private upsertStmt: any;
    private insertFileStmt: any;
    private markFileDoneStmt: any;
    private markFilePendingStmt: any;

    constructor(dbPath: string) {
        mkdirSync(path.dirname(dbPath), { recursive: true });
        const { DatabaseSync } = nodeRequire("node:sqlite");
        this.db = new DatabaseSync(dbPath);
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS scan_sessions (
                job_id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                total_files INTEGER NOT NULL,
                scanned_files INTEGER NOT NULL,
                current_file TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                completed_at INTEGER,
                threats_found INTEGER NOT NULL,
                errors_found INTEGER NOT NULL,
                result INTEGER,
                action_taken TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_session_files (
                job_id TEXT NOT NULL,
                file_index INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                normalized_path TEXT NOT NULL,
                status TEXT NOT NULL,
                size INTEGER NOT NULL DEFAULT 0,
                mtime_ms INTEGER NOT NULL DEFAULT 0,
                scanned_at INTEGER,
                PRIMARY KEY (job_id, normalized_path)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_sessions_updated_at ON scan_sessions(updated_at);
            CREATE INDEX IF NOT EXISTS idx_scan_session_files_status ON scan_session_files(job_id, status, file_index);
        `);
        this.upsertStmt = this.db.prepare(`
            INSERT INTO scan_sessions (
                job_id, type, target, status, phase, total_files, scanned_files,
                current_file, started_at, updated_at, completed_at, threats_found,
                errors_found, result, action_taken
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                type = excluded.type,
                target = excluded.target,
                status = excluded.status,
                phase = excluded.phase,
                total_files = excluded.total_files,
                scanned_files = excluded.scanned_files,
                current_file = excluded.current_file,
                updated_at = excluded.updated_at,
                completed_at = excluded.completed_at,
                threats_found = excluded.threats_found,
                errors_found = excluded.errors_found,
                result = excluded.result,
                action_taken = excluded.action_taken
        `);
        this.insertFileStmt = this.db.prepare(`
            INSERT INTO scan_session_files (
                job_id, file_index, file_path, normalized_path, status, size, mtime_ms, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id, normalized_path) DO UPDATE SET
                file_index = excluded.file_index,
                file_path = excluded.file_path,
                status = excluded.status,
                size = excluded.size,
                mtime_ms = excluded.mtime_ms,
                scanned_at = excluded.scanned_at
        `);
        this.markFileDoneStmt = this.db.prepare(`
            UPDATE scan_session_files
            SET status = 'done', size = ?, mtime_ms = ?, scanned_at = ?
            WHERE job_id = ? AND normalized_path = ?
        `);
        this.markFilePendingStmt = this.db.prepare(`
            UPDATE scan_session_files
            SET status = 'pending', size = ?, mtime_ms = ?, scanned_at = NULL
            WHERE job_id = ? AND normalized_path = ?
        `);
    }

    save(progress: ScanProgress) {
        this.upsertStmt.run(
            progress.jobId,
            progress.type,
            progress.target,
            progress.status,
            progress.phase,
            progress.totalFiles,
            progress.scannedFiles,
            progress.currentFile || "",
            progress.startedAt,
            progress.updatedAt,
            progress.completedAt || null,
            progress.threatsFound,
            progress.errorsFound,
            progress.result ?? null,
            progress.actionTaken || "None"
        );
    }

    saveFiles(jobId: string, files: Array<{ filePath: string, size: number, mtimeMs: number }>) {
        this.db.exec("BEGIN");
        try {
            this.db.prepare("DELETE FROM scan_session_files WHERE job_id = ?").run(jobId);
            files.forEach((file, index) => {
                this.insertFileStmt.run(
                    jobId,
                    index,
                    file.filePath,
                    normalizeCachePath(file.filePath),
                    "pending",
                    file.size,
                    file.mtimeMs,
                    null
                );
            });
            this.db.exec("COMMIT");
        } catch (e) {
            this.db.exec("ROLLBACK");
            throw e;
        }
    }

    getLatestResumable() {
        return this.db.prepare(`
            SELECT *
            FROM scan_sessions
            WHERE status IN ('running', 'paused', 'error')
              AND type IN ('disk', 'folder', 'file')
            ORDER BY updated_at DESC
            LIMIT 1
        `).get();
    }

    getSession(jobId: string) {
        return this.db.prepare("SELECT * FROM scan_sessions WHERE job_id = ?").get(jobId);
    }

    getFiles(jobId: string) {
        return this.db.prepare(`
            SELECT *
            FROM scan_session_files
            WHERE job_id = ?
            ORDER BY file_index ASC
        `).all(jobId);
    }

    markFilesDone(jobId: string, files: Array<{ filePath: string, size: number, mtimeMs: number }>) {
        this.db.exec("BEGIN");
        try {
            const scannedAt = Date.now();
            for (const file of files) {
                this.markFileDoneStmt.run(file.size, file.mtimeMs, scannedAt, jobId, normalizeCachePath(file.filePath));
            }
            this.db.exec("COMMIT");
        } catch (e) {
            this.db.exec("ROLLBACK");
            throw e;
        }
    }

    markFilePending(jobId: string, filePath: string, size: number, mtimeMs: number) {
        this.markFilePendingStmt.run(size, mtimeMs, jobId, normalizeCachePath(filePath));
    }

    discard(jobId: string) {
        this.db.prepare("UPDATE scan_sessions SET status = 'discarded', phase = 'Discarded', updated_at = ? WHERE job_id = ?")
            .run(Date.now(), jobId);
        this.db.prepare("DELETE FROM scan_session_files WHERE job_id = ?").run(jobId);
    }
}

function createInitialScanProgress(jobId: string, type: string, target: string): ScanProgress {
    const now = Date.now();
    return {
        jobId,
        type,
        target,
        status: "running",
        phase: "Starting",
        totalFiles: 0,
        scannedFiles: 0,
        currentFile: "",
        startedAt: now,
        updatedAt: now,
        threatsFound: 0,
        errorsFound: 0,
        actionTaken: "None",
        elapsedSeconds: 0,
        quietSeconds: 0
    };
}

const windowsLockedScanExclusions = [
    String.raw`^[A-Z]:\\pagefile\.sys$`,
    String.raw`^[A-Z]:\\swapfile\.sys$`,
    String.raw`^[A-Z]:\\hiberfil\.sys$`,
    String.raw`^[A-Z]:\\DumpStack\.log(?:\.tmp)?$`,
    String.raw`^[A-Z]:\\System Volume Information(\\|$)`,
    String.raw`^[A-Z]:\\\$Recycle\.Bin(\\|$)`
];

function escapeRegex(value: string) {
    return value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

function pathToClamExcludePattern(folderPath: string) {
    const normalized = path.resolve(folderPath).replace(/[\\/]+$/, "");
    return `^${escapeRegex(normalized)}(?:[\\\\/]|$)`;
}

function getClamShieldScanExclusionPaths(settings: any) {
    return [
        settings.yaraCacheDir,
        settings.yaraRulesDir,
        settings.yaraCustomRulesDir,
        settings.quarantineDir,
        path.join(programDataDir, "updates")
    ].filter(Boolean);
}

function buildClamdConfContent(settings: any) {
    const lines = [
        `DatabaseDirectory ${settings.databaseDir}`,
        "TCPAddr 127.0.0.1",
        "TCPSocket 3310"
    ];
    if (settings.enableDebugLog === true) {
        lines.push(`LogFile ${path.join(settings.logsDir, "clamd.log")}`);
        lines.push("LogTime yes");
        lines.push("LogVerbose yes");
    }
    getClamShieldScanExclusionPaths(settings)
        .forEach((folderPath: string) => lines.push(`ExcludePath ${pathToClamExcludePattern(folderPath)}`));
    return `${lines.join("\n")}\n`;
}

function getClamdConfSignature(settings: any) {
    return createHash("sha256").update(buildClamdConfContent(settings)).digest("hex");
}

async function ensureClamdConfContent(settings: any) {
    if (!settings.clamdConf) return false;
    try {
        await fs.mkdir(path.dirname(settings.clamdConf), { recursive: true });
        let content = "";
        try {
            content = await fs.readFile(settings.clamdConf, "utf8");
        } catch (e: any) {
            console.debug("clamd.conf could not be read; writing managed config:", e?.message || e);
        }
        const desired = buildClamdConfContent(settings);
        if (content !== desired) {
            await fs.writeFile(settings.clamdConf, desired);
            console.debug("clamd.conf updated to match ClamShield managed settings.");
            return true;
        }
        return false;
    } catch (e: any) {
        console.warn("Failed to ensure clamd managed config:", e?.message || e);
        return false;
    }
}

function buildClamScanArgs(scanSettings: any, isClamd: boolean, type: string, target?: string) {
    const args = isClamd
        ? ["--config-file=" + scanSettings.clamdConf]
        : ["--database=" + scanSettings.databaseDir];

    if (scanSettings.recursive && type !== "file") {
        args.push(isClamd ? "--multiscan" : "--recursive");
    }

    if (!isClamd) {
        const maxFileSize = normalizePositiveNumber(scanSettings.maxFileSize, 50, 1, 4096);
        args.push(`--max-filesize=${maxFileSize}M`);
        args.push(`--max-scansize=${Math.max(maxFileSize, maxFileSize * 2)}M`);
        args.push(`--scan-archive=${scanSettings.scanArchives === false ? "no" : "yes"}`);
        args.push(`--follow-dir-symlinks=${scanSettings.followSymlinks ? "1" : "0"}`);
        args.push(`--follow-file-symlinks=${scanSettings.followSymlinks ? "1" : "0"}`);
        getClamShieldScanExclusionPaths(scanSettings).forEach((folderPath: string) => {
            args.push(`--exclude=${pathToClamExcludePattern(folderPath)}`);
        });
        if (process.platform === "win32" && type === "disk") {
            windowsLockedScanExclusions.forEach(pattern => args.push(`--exclude=${pattern}`));
        }
        if (type === "memory") {
            if (target && process.platform === "win32") {
                args.push(`--file-list=${target}`);
            } else {
                args.push("--memory");
            }
        }
    }

    if (target && !(type === "memory" && process.platform === "win32")) args.push(target);
    return args;
}

function buildClamFileListArgs(scanSettings: any, isClamd: boolean, listPath: string) {
    const args = isClamd
        ? ["--config-file=" + scanSettings.clamdConf]
        : ["--database=" + scanSettings.databaseDir];

    if (isClamd) {
        args.push("--multiscan");
    } else {
        const maxFileSize = normalizePositiveNumber(scanSettings.maxFileSize, 50, 1, 4096);
        args.push(`--max-filesize=${maxFileSize}M`);
        args.push(`--max-scansize=${Math.max(maxFileSize, maxFileSize * 2)}M`);
        args.push(`--scan-archive=${scanSettings.scanArchives === false ? "no" : "yes"}`);
        args.push(`--follow-dir-symlinks=${scanSettings.followSymlinks ? "1" : "0"}`);
        args.push(`--follow-file-symlinks=${scanSettings.followSymlinks ? "1" : "0"}`);
        getClamShieldScanExclusionPaths(scanSettings).forEach((folderPath: string) => {
            args.push(`--exclude=${pathToClamExcludePattern(folderPath)}`);
        });
    }

    args.push(`--file-list=${listPath}`);
    return args;
}

function parseClamOutputPath(line: string) {
    const match = line.match(/^(.+?):\s+(.+)$/);
    return match ? match[1] : "";
}

function isNoisyClamFileLine(line: string) {
    return /:\s+(OK|Empty file|Symbolic link|Excluded)(?:\.| ERROR)?$/i.test(line) ||
        /^WARNING: File path check failure for:/i.test(line);
}

function isLockedOrUnstableClamLine(line: string) {
    return /File path check failure|Can't get file status|Can't open file or directory|Access denied/i.test(line);
}

function isImportantClamOutputLine(line: string) {
    if (!line) return false;
    if (/^-{3,}\s*SCAN SUMMARY\s*-{3,}$/i.test(line)) return true;
    if (/^(Scanned files|Infected files|Total errors|Time):/i.test(line)) return true;
    if (/^(ERROR|LibClamAV Error|Process error):/i.test(line)) return true;
    if (isLockedOrUnstableClamLine(line)) return true;
    if (line.includes(" ERROR") && !isNoisyClamFileLine(line)) return true;
    return false;
}

function displayFileName(filePath: string) {
    return path.basename(filePath || "").trim() || "Unknown file";
}

function titleCase(value: string) {
    const normalized = String(value || "").trim();
    return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1).toLowerCase() : "";
}

async function hashFile(filePath: string) {
    const hash = createHash("sha256");
    await new Promise<void>((resolve, reject) => {
        const stream = createReadStream(filePath);
        stream.on("data", chunk => hash.update(chunk));
        stream.on("error", reject);
        stream.on("end", resolve);
    });
    return hash.digest("hex");
}

const yaraForgePackages: Record<string, { label: string, url: string, fileName: string }> = {
    core: {
        label: "Core",
        url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
        fileName: "yara-rules-core.yar"
    },
    extended: {
        label: "Extended",
        url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
        fileName: "yara-rules-extended.yar"
    },
    full: {
        label: "Full",
        url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip",
        fileName: "yara-rules-full.yar"
    }
};

function normalizeYaraRuleset(value: any) {
    return Object.prototype.hasOwnProperty.call(yaraForgePackages, value) ? value : "core";
}

function getYaraRulesFile(settings: any) {
    const ruleset = normalizeYaraRuleset(settings.yaraRuleset);
    return path.join(settings.yaraRulesDir || yaraForgeRulesDir, yaraForgePackages[ruleset].fileName);
}

async function downloadToFile(url: string, destination: string, onProgress?: (message: string) => void) {
    await fs.mkdir(path.dirname(destination), { recursive: true });
    const response = await axios({
        url,
        method: "GET",
        responseType: "stream",
        headers: { "User-Agent": "ClamShield" }
    });
    const total = Number(response.headers["content-length"] || 0);
    let downloaded = 0;
    let lastProgress = 0;
    response.data.on("data", (chunk: Buffer) => {
        downloaded += chunk.length;
        if (total > 0) {
            const percent = Math.floor((downloaded / total) * 100);
            if (percent >= lastProgress + 10) {
                lastProgress = percent;
                onProgress?.(`Downloaded ${percent}%`);
            }
        }
    });
    const writer = createWriteStream(destination);
    response.data.pipe(writer);
    await new Promise<void>((resolve, reject) => {
        writer.on("finish", resolve);
        writer.on("error", reject);
        response.data.on("error", reject);
    });
}

async function extractZip(zipPath: string, destination: string) {
    await fs.mkdir(destination, { recursive: true });
    const extractStream = createReadStream(zipPath).pipe(unzipper.Extract({ path: destination }));
    await new Promise<void>((resolve, reject) => {
        extractStream.on("close", resolve);
        extractStream.on("error", reject);
    });
}

async function findFileByName(rootPath: string, fileName: string): Promise<string | null> {
    for await (const filePath of walkFiles(rootPath)) {
        if (path.basename(filePath).toLowerCase() === fileName.toLowerCase()) {
            return filePath;
        }
    }
    return null;
}

async function findLargestYaraFile(rootPath: string): Promise<string | null> {
    let best: { filePath: string, size: number } | null = null;
    for await (const filePath of walkFiles(rootPath)) {
        const ext = path.extname(filePath).toLowerCase();
        if (ext !== ".yar" && ext !== ".yara") continue;
        try {
            const stat = await fs.stat(filePath);
            if (!best || stat.size > best.size) {
                best = { filePath, size: stat.size };
            }
        } catch (e: any) {
            console.debug("Unable to inspect candidate YARA rules file:", filePath, e?.message || e);
        }
    }
    return best?.filePath || null;
}

async function countYaraRules(filePath: string) {
    try {
        const content = await fs.readFile(filePath, "utf8");
        return (content.match(/^\s*(?:private\s+|global\s+)*rule\s+[A-Za-z0-9_]+/gm) || []).length;
    } catch {
        return 0;
    }
}

function normalizeVersion(value: any) {
    return String(value || "0.0.0").trim().replace(/^v/i, "");
}

function compareVersions(a: string, b: string) {
    const left = normalizeVersion(a).split(".").map(part => parseInt(part, 10) || 0);
    const right = normalizeVersion(b).split(".").map(part => parseInt(part, 10) || 0);
    const length = Math.max(left.length, right.length);
    for (let i = 0; i < length; i++) {
        const delta = (left[i] || 0) - (right[i] || 0);
        if (delta !== 0) return delta;
    }
    return 0;
}

async function getCurrentAppVersion() {
    let pkgVersion = process.env.npm_package_version || "1.0.14";
    try {
        const pkgPath = path.join(runtimeDir, process.env.NODE_ENV === "production" ? ".." : "", "package.json");
        const pkgData = await fs.readFile(pkgPath, "utf8");
        pkgVersion = JSON.parse(pkgData).version || pkgVersion;
    } catch (e: any) {
        console.debug("Unable to read package.json for app version; using fallback version:", e?.message || e);
    }
    return normalizeVersion(pkgVersion);
}

async function getLatestClamShieldRelease(settings: any) {
    const currentVersion = await getCurrentAppVersion();
    const releaseRes = await axios.get("https://api.github.com/repos/orloxgr/ClamShield/releases/latest", {
        headers: { "User-Agent": "ClamShield" }
    });
    const release = releaseRes.data;
    const latestVersion = normalizeVersion(release.tag_name || release.name);
    const skipped = normalizeVersion(settings.skippedAppVersion) === latestVersion;
    const asset = (release.assets || []).find((item: any) => {
        const name = String(item.name || "").toLowerCase();
        return name.endsWith(".exe") && (name.includes("setup") || name.includes("clamshield"));
    }) || (release.assets || []).find((item: any) => String(item.name || "").toLowerCase().endsWith(".exe"));

    return {
        currentVersion,
        latestVersion,
        updateAvailable: compareVersions(latestVersion, currentVersion) > 0 && !skipped,
        skipped,
        releaseUrl: release.html_url,
        publishedAt: release.published_at,
        assetName: asset?.name || "",
        downloadUrl: asset?.browser_download_url || ""
    };
}

async function downloadAndLaunchClamShieldInstaller(settings: any, log?: (message: string) => void) {
    const update = await getLatestClamShieldRelease(settings);
    if (!update.updateAvailable) return { ...update, launched: false };
    if (!update.downloadUrl) throw new Error("Latest ClamShield release does not include a Windows installer asset.");

    const updatesDir = path.join(programDataDir, "updates");
    const safeName = update.assetName.replace(/[<>:"/\\|?*]/g, "_") || `ClamShield-Setup-${update.latestVersion}.exe`;
    const installerPath = path.join(updatesDir, safeName);
    log?.(`Downloading ClamShield ${update.latestVersion} installer...`);
    await downloadToFile(update.downloadUrl, installerPath, log);

    const args = ["/S"];
    log?.(`Launching installer: ${installerPath}`);
    const child = spawn(installerPath, args, {
        detached: true,
        stdio: "ignore",
        windowsHide: true
    });
    child.unref();
    return { ...update, launched: true, installerPath };
}

async function ensureYaraEngine(settings: any, log?: (message: string) => void) {
    if (settings.yaraPath && existsSync(settings.yaraPath)) {
        log?.(`YARA engine found: ${settings.yaraPath}`);
        return settings.yaraPath;
    }
    if (process.platform !== "win32") {
        throw new Error("YARA engine was not found. Install YARA and set the yaraPath setting.");
    }

    log?.("Finding latest YARA Windows release...");
    const releaseRes = await axios.get("https://api.github.com/repos/VirusTotal/yara/releases/latest", {
        headers: { "User-Agent": "ClamShield" }
    });
    const asset = releaseRes.data.assets.find((item: any) =>
        item.name.toLowerCase().includes("win64") &&
        item.name.toLowerCase().endsWith(".zip")
    );
    if (!asset) {
        throw new Error("Could not find a Windows x64 YARA release asset.");
    }

    await fs.mkdir(settings.yaraDir || path.dirname(settings.yaraPath), { recursive: true });
    const zipPath = path.join(settings.yaraCacheDir || yaraCacheDir, asset.name);
    log?.(`Downloading ${asset.name}...`);
    await downloadToFile(asset.browser_download_url, zipPath, log);

    const tempDir = path.join(settings.yaraCacheDir || yaraCacheDir, `engine-${Date.now()}`);
    await fs.rm(tempDir, { recursive: true, force: true });
    await extractZip(zipPath, tempDir);
    const yaraExe = await findFileByName(tempDir, "yara64.exe") || await findFileByName(tempDir, "yara.exe");
    const yaracExe = await findFileByName(tempDir, "yarac64.exe") || await findFileByName(tempDir, "yarac.exe");
    if (!yaraExe) {
        throw new Error("Downloaded YARA package did not contain yara64.exe.");
    }

    const finalYaraPath = path.join(settings.yaraDir || path.dirname(settings.yaraPath), "yara64.exe");
    await fs.copyFile(yaraExe, finalYaraPath);
    if (yaracExe) {
        await fs.copyFile(yaracExe, path.join(settings.yaraDir || path.dirname(settings.yaraPath), "yarac64.exe"));
    }
    await fs.rm(tempDir, { recursive: true, force: true });
    await fs.unlink(zipPath).catch(() => {});
    settings.yaraPath = finalYaraPath;
    log?.(`YARA engine ready: ${finalYaraPath}`);
    return finalYaraPath;
}

async function updateYaraForgeRules(settings: any, log?: (message: string) => void) {
    const ruleset = normalizeYaraRuleset(settings.yaraRuleset);
    const pack = yaraForgePackages[ruleset];
    await ensureYaraEngine(settings, log);

    await fs.mkdir(settings.yaraCacheDir || yaraCacheDir, { recursive: true });
    await fs.rm(settings.yaraRulesDir || yaraForgeRulesDir, { recursive: true, force: true });
    await fs.mkdir(settings.yaraRulesDir || yaraForgeRulesDir, { recursive: true });

    const zipPath = path.join(settings.yaraCacheDir || yaraCacheDir, `yara-forge-rules-${ruleset}.zip`);
    log?.(`Downloading YARA Forge ${pack.label} rules...`);
    await downloadToFile(pack.url, zipPath, log);
    await extractZip(zipPath, settings.yaraRulesDir || yaraForgeRulesDir);

    const expected = await findFileByName(settings.yaraRulesDir || yaraForgeRulesDir, pack.fileName);
    const anyRulesFile = expected || await findLargestYaraFile(settings.yaraRulesDir || yaraForgeRulesDir);
    if (!anyRulesFile) {
        throw new Error(`YARA Forge ${pack.label} package did not contain a .yar rules file.`);
    }

    const finalRulesFile = getYaraRulesFile(settings);
    if (path.resolve(anyRulesFile).toLowerCase() !== path.resolve(finalRulesFile).toLowerCase()) {
        await fs.copyFile(anyRulesFile, finalRulesFile);
    }
    const ruleCount = await countYaraRules(finalRulesFile);
    await fs.unlink(zipPath).catch(() => {});
    settings.lastYaraUpdate = new Date().toISOString();
    settings.lastYaraRuleset = ruleset;
    settings.lastYaraRuleCount = ruleCount;
    await saveConfig(settings);
    log?.(`YARA Forge ${pack.label} rules ready (${ruleCount} rules).`);
    return { ruleset, ruleCount, rulesFile: finalRulesFile };
}

async function quarantineFile(originalPath: string, threatName: string, quarantineDir: string) {
    await fs.mkdir(quarantineDir, { recursive: true });
    const baseName = path.basename(originalPath);
    const timestampedName = `${Date.now()}_${randomBytes(4).toString("hex")}_${baseName}`;
    const destPath = path.join(quarantineDir, timestampedName);
    const sha256 = await hashFile(originalPath).catch(() => null);

    try {
        await fs.rename(originalPath, destPath);
    } catch {
        await fs.copyFile(originalPath, destPath);
        await fs.unlink(originalPath);
    }

    if (process.platform !== "win32") {
        await fs.chmod(destPath, 0o600).catch(() => {});
    }

    return {
        fileName: timestampedName,
        destPath,
        metadata: {
            originalPath,
            threatName,
            sha256,
            timestamp: Date.now()
        }
    };
}

type ShieldCacheEntry = {
    size: number;
    mtimeMs: number;
    scannedAt: number;
};

type ScanProgress = {
    jobId: string;
    type: string;
    target: string;
    status: string;
    phase: string;
    totalFiles: number;
    scannedFiles: number;
    currentFile: string;
    startedAt: number;
    updatedAt: number;
    completedAt?: number;
    threatsFound: number;
    errorsFound: number;
    result?: number;
    actionTaken: string;
    elapsedSeconds?: number;
    quietSeconds?: number;
};

type ShieldScanCache = {
    version: number;
    files: Record<string, ShieldCacheEntry>;
};

function getShieldCachePath() {
    return path.join(programDataDir, "shield_scan_cache.json");
}

function getShieldCacheDbPath() {
    return path.join(programDataDir, "shield_scan_cache.sqlite");
}

function getScanSessionsDbPath() {
    return path.join(programDataDir, "scan_sessions.sqlite");
}

function normalizeCachePath(filePath: string) {
    return path.resolve(filePath).toLowerCase();
}

interface ShieldScanCacheStore {
    type: "sqlite" | "json";
    get(normalizedPath: string): ShieldCacheEntry | undefined;
    set(normalizedPath: string, entry: ShieldCacheEntry): void;
    delete(normalizedPath: string): void;
    clear(): void;
    count(): number;
    compact?(): void;
}

async function loadLegacyShieldScanCache(): Promise<ShieldScanCache> {
    const cachePath = getShieldCachePath();
    try {
        const stat = await fs.stat(cachePath);
        if (stat.size > 50 * 1024 * 1024) {
            console.warn("Shield scan cache is too large; starting with a fresh cache.");
            await saveLegacyShieldScanCache({ version: 1, files: {} }).catch(() => {});
            return { version: 1, files: {} };
        }
        const data = await fs.readFile(cachePath, "utf8");
        const parsed = JSON.parse(data);
        if (parsed && parsed.version === 1 && parsed.files && typeof parsed.files === "object") {
            return parsed;
        }
    } catch (e: any) {
        console.debug("Legacy shield scan cache could not be loaded; starting with an empty cache:", e?.message || e);
    }
    return { version: 1, files: {} };
}

async function saveLegacyShieldScanCache(cache: ShieldScanCache) {
    await fs.writeFile(getShieldCachePath(), JSON.stringify(cache));
}

class JsonShieldScanCacheStore implements ShieldScanCacheStore {
    type: "json" = "json";
    private cache: ShieldScanCache;

    constructor(cache: ShieldScanCache) {
        this.cache = cache;
    }

    get(normalizedPath: string) {
        return this.cache.files[normalizedPath];
    }

    set(normalizedPath: string, entry: ShieldCacheEntry) {
        this.cache.files[normalizedPath] = entry;
        saveLegacyShieldScanCache(this.cache).catch(e => console.error("Failed to save shield JSON cache:", e));
    }

    delete(normalizedPath: string) {
        delete this.cache.files[normalizedPath];
        saveLegacyShieldScanCache(this.cache).catch(e => console.error("Failed to save shield JSON cache:", e));
    }

    clear() {
        this.cache = { version: 1, files: {} };
        saveLegacyShieldScanCache(this.cache).catch(e => console.error("Failed to save shield JSON cache:", e));
    }

    count() {
        return Object.keys(this.cache.files).length;
    }
}

class SqliteShieldScanCacheStore implements ShieldScanCacheStore {
    type: "sqlite" = "sqlite";
    private db: any;
    private getStmt: any;
    private setStmt: any;
    private deleteStmt: any;
    private countStmt: any;

    constructor(dbPath: string) {
        const { DatabaseSync } = nodeRequire("node:sqlite");
        this.db = new DatabaseSync(dbPath);
        this.db.exec(`
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS shield_scan_cache (
                path TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                mtime_ms INTEGER NOT NULL,
                scanned_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_shield_scan_cache_scanned_at ON shield_scan_cache(scanned_at);
        `);
        this.getStmt = this.db.prepare("SELECT size, mtime_ms as mtimeMs, scanned_at as scannedAt FROM shield_scan_cache WHERE path = ?");
        this.setStmt = this.db.prepare(`
            INSERT INTO shield_scan_cache(path, size, mtime_ms, scanned_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                size = excluded.size,
                mtime_ms = excluded.mtime_ms,
                scanned_at = excluded.scanned_at
        `);
        this.deleteStmt = this.db.prepare("DELETE FROM shield_scan_cache WHERE path = ?");
        this.countStmt = this.db.prepare("SELECT COUNT(*) as count FROM shield_scan_cache");
    }

    get(normalizedPath: string) {
        const row = this.getStmt.get(normalizedPath);
        if (!row) return undefined;
        return {
            size: Number(row.size),
            mtimeMs: Number(row.mtimeMs),
            scannedAt: Number(row.scannedAt)
        };
    }

    set(normalizedPath: string, entry: ShieldCacheEntry) {
        this.setStmt.run(normalizedPath, entry.size, entry.mtimeMs, entry.scannedAt);
    }

    delete(normalizedPath: string) {
        this.deleteStmt.run(normalizedPath);
    }

    clear() {
        this.db.exec("DELETE FROM shield_scan_cache; PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");
    }

    count() {
        const row = this.countStmt.get();
        return Number(row?.count || 0);
    }

    compact() {
        this.db.exec("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");
    }

    importLegacy(cache: ShieldScanCache) {
        const entries = Object.entries(cache.files || {});
        if (entries.length === 0) return 0;
        this.db.exec("BEGIN IMMEDIATE");
        try {
            for (const [normalizedPath, entry] of entries) {
                if (!entry || typeof entry.size !== "number" || typeof entry.mtimeMs !== "number") continue;
                this.set(normalizedPath, entry);
            }
            this.db.exec("COMMIT");
        } catch (e) {
            this.db.exec("ROLLBACK");
            throw e;
        }
        return entries.length;
    }
}

async function loadShieldScanCacheStore(): Promise<ShieldScanCacheStore> {
    try {
        const store = new SqliteShieldScanCacheStore(getShieldCacheDbPath());
        const legacyCache = await loadLegacyShieldScanCache();
        const legacyCount = Object.keys(legacyCache.files).length;
        if (legacyCount > 0) {
            const importedCount = store.importLegacy(legacyCache);
            await saveLegacyShieldScanCache({ version: 1, files: {} });
            console.log(`Migrated ${importedCount} shield cache entries to SQLite.`);
        }
        return store;
    } catch (e) {
        console.warn("SQLite shield cache unavailable; using JSON fallback.", e);
        return new JsonShieldScanCacheStore(await loadLegacyShieldScanCache());
    }
}

async function getFileFingerprint(filePath: string): Promise<ShieldCacheEntry | null> {
    try {
        const stat = await fs.stat(filePath);
        if (!stat.isFile()) return null;
        return {
            size: stat.size,
            mtimeMs: Math.trunc(stat.mtimeMs),
            scannedAt: Date.now()
        };
    } catch {
        return null;
    }
}

async function getScanFileRecords(filePaths: string[]) {
    const records: Array<{ filePath: string, size: number, mtimeMs: number }> = [];
    for (const filePath of filePaths) {
        const fingerprint = await getFileFingerprint(filePath);
        records.push({
            filePath,
            size: fingerprint?.size || 0,
            mtimeMs: fingerprint?.mtimeMs || 0
        });
    }
    return records;
}

function scanSessionRowToProgress(row: any): ScanProgress | null {
    if (!row) return null;
    return {
        jobId: row.job_id,
        type: row.type,
        target: row.target,
        status: row.status,
        phase: row.phase,
        totalFiles: Number(row.total_files || 0),
        scannedFiles: Number(row.scanned_files || 0),
        currentFile: row.current_file || "",
        startedAt: Number(row.started_at || Date.now()),
        updatedAt: Number(row.updated_at || Date.now()),
        completedAt: row.completed_at ? Number(row.completed_at) : undefined,
        threatsFound: Number(row.threats_found || 0),
        errorsFound: Number(row.errors_found || 0),
        result: row.result === null || row.result === undefined ? undefined : Number(row.result),
        actionTaken: row.action_taken || "None",
        elapsedSeconds: Math.max(0, Math.floor((Date.now() - Number(row.started_at || Date.now())) / 1000)),
        quietSeconds: Math.max(0, Math.floor((Date.now() - Number(row.updated_at || Date.now())) / 1000))
    };
}

function canResumeScanType(type: string) {
    return type === "disk" || type === "folder" || type === "file";
}

function fileRecordMatches(row: any, fingerprint: ShieldCacheEntry | null) {
    return !!fingerprint &&
        Number(row.size || 0) === fingerprint.size &&
        Number(row.mtime_ms || 0) === fingerprint.mtimeMs;
}

function cacheEntryMatches(current: ShieldCacheEntry | null, cached?: ShieldCacheEntry) {
    return !!current && !!cached && current.size === cached.size && current.mtimeMs === cached.mtimeMs;
}

async function pathExists(filePath?: string) {
    if (!filePath) return false;
    try {
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}

async function ensureFreshclamConfig(settings: any) {
    await fs.mkdir(settings.databaseDir, { recursive: true });
    await fs.mkdir(settings.logsDir || defaultLogsDir, { recursive: true });
    if (!settings.freshclamConf) {
        settings.freshclamConf = path.join(settings.clamavDir || path.join(engineBaseDir, "clamav"), "freshclam.conf");
    }
    await fs.mkdir(path.dirname(settings.freshclamConf), { recursive: true });
    const confContent = `DatabaseDirectory ${settings.databaseDir}\nUpdateLogFile ${path.join(settings.logsDir || defaultLogsDir, 'freshclam.log')}\nDatabaseMirror database.clamav.net\n`;
    await fs.writeFile(settings.freshclamConf, confContent);
}

async function retryRemovePath(targetPath: string, attempts = 5) {
    for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
            await fs.rm(targetPath, { recursive: true, force: true });
            return;
        } catch (e: any) {
            if (attempt === attempts) throw e;
            await sleep(500 * attempt);
        }
    }
}

async function retryCopyDirectory(sourcePath: string, targetPath: string, attempts = 3) {
    for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
            await fs.cp(sourcePath, targetPath, { recursive: true, force: true });
            return;
        } catch (e: any) {
            if (attempt === attempts) throw e;
            await sleep(500 * attempt);
        }
    }
}

async function findExtractedClamavDir() {
    const entries = await fs.readdir(engineBaseDir, { withFileTypes: true });
    const candidates = entries
        .filter(entry => entry.isDirectory() && entry.name.toLowerCase().startsWith("clamav") && entry.name.toLowerCase() !== "clamav")
        .map(entry => path.join(engineBaseDir, entry.name));
    for (const candidate of candidates) {
        if (await pathExists(path.join(candidate, "clamscan.exe")) && await pathExists(path.join(candidate, "freshclam.exe"))) {
            return candidate;
        }
    }
    return "";
}

async function adoptClamavEngineFolder(sourceDir: string) {
    const finalClamDir = path.join(engineBaseDir, "clamav");
    const stagingDir = path.join(engineBaseDir, `clamav-staging-${Date.now()}`);
    try {
        await retryRemovePath(stagingDir);
        await retryCopyDirectory(sourceDir, stagingDir);
        await retryRemovePath(finalClamDir);
        await fs.rename(stagingDir, finalClamDir);
        if (path.resolve(sourceDir).toLowerCase() !== path.resolve(finalClamDir).toLowerCase()) {
            await retryRemovePath(sourceDir).catch(e => console.debug("ClamAV extracted folder cleanup failed:", e?.message || e));
        }
        return finalClamDir;
    } catch (e: any) {
        await retryRemovePath(stagingDir).catch(() => {});
        if (e?.code === "EPERM" || e?.code === "EBUSY" || e?.code === "EACCES") {
            throw new Error(`Windows blocked replacing the ClamAV engine folder (${e.code}). Close ClamShield and any antivirus scan touching C:\\ProgramData\\ClamShield, then try again.`);
        }
        throw e;
    }
}

function resolveScanTarget(type: string, target?: string) {
    if (target) return target;
    if (type === "disk") return process.platform === "win32" ? "C:\\" : "/";
    return target;
}

async function* walkFiles(rootPath: string): AsyncGenerator<string> {
    const stack = [rootPath];
    while (stack.length) {
        const current = stack.pop()!;
        let stat;
        try {
            stat = await fs.stat(current);
        } catch {
            continue;
        }

        if (stat.isFile()) {
            yield current;
            continue;
        }

        if (!stat.isDirectory()) continue;

        let entries;
        try {
            entries = await fs.readdir(current, { withFileTypes: true });
        } catch {
            continue;
        }

        for (const entry of entries) {
            if (entry.name === "." || entry.name === "..") continue;
            const childPath = path.join(current, entry.name);
            if (entry.isDirectory()) stack.push(childPath);
            else if (entry.isFile()) yield childPath;
        }
    }
}

function isWindowsLockedScanPath(filePath: string) {
    if (process.platform !== "win32") return false;
    return windowsLockedScanExclusions.some(pattern => new RegExp(pattern, "i").test(filePath));
}

function shouldSkipManualScanFile(settings: any, type: string, filePath: string) {
    if (type === "disk" && isWindowsLockedScanPath(filePath)) return true;
    return getClamShieldScanExclusionPaths(settings).some((excludedPath: string) => isPathInside(filePath, excludedPath));
}

async function enumerateScanTargets(settings: any, type: string, target: string) {
    if (type === "memory" && process.platform === "win32") {
        return getRunningProcessImagePaths();
    }

    const files: string[] = [];
    let stat;
    try {
        stat = await fs.stat(target);
    } catch {
        return files;
    }

    if (stat.isFile()) {
        if (!shouldSkipManualScanFile(settings, type, target)) files.push(target);
        return files;
    }

    if (!stat.isDirectory()) return files;
    for await (const filePath of walkFiles(target)) {
        if (shouldSkipManualScanFile(settings, type, filePath)) continue;
        files.push(filePath);
        if (files.length % 5000 === 0) await sleep(1);
    }
    return files;
}

function chunkItems<T>(items: T[], chunkSize: number) {
    const chunks: T[][] = [];
    for (let i = 0; i < items.length; i += chunkSize) {
        chunks.push(items.slice(i, i + chunkSize));
    }
    return chunks;
}

function getAdaptiveScanBatchSize(totalFiles: number) {
    if (totalFiles <= 100) return 1;
    if (totalFiles <= 500) return 3;
    if (totalFiles <= 1000) return 10;
    return 100;
}

async function addTargetToShieldCache(cache: ShieldScanCacheStore, targetPath: string, onProgress?: (count: number) => void) {
    let count = 0;
    for await (const filePath of walkFiles(targetPath)) {
        const fingerprint = await getFileFingerprint(filePath);
        if (!fingerprint) continue;
        cache.set(normalizeCachePath(filePath), fingerprint);
        count++;
        if (count % 5000 === 0) onProgress?.(count);
        if (count % 200 === 0) await sleep(1);
    }
    cache.compact?.();
    onProgress?.(count);
    return count;
}

let isInstalling = false;
let installProgress = "";
let cachedIsAdmin = false;
let clamdProcess: any = null;
let clamdConfSignature = "";

async function manageClamd(settings: any) {
    if (isSimulated || !settings.clamdPath) return;

    if (settings.offloadToMemory) {
        const nextClamdConfSignature = getClamdConfSignature(settings);
        await ensureClamdConfContent(settings);
        if (clamdProcess && clamdConfSignature && clamdConfSignature !== nextClamdConfSignature) {
            console.log("Restarting clamd because managed clamd.conf changed.");
            clamdProcess.kill();
            clamdProcess = null;
            await sleep(500);
        }
        if (!clamdProcess) {
            console.log("Starting clamd process...");
            try {
                clamdProcess = spawn(settings.clamdPath, ["--config-file=" + settings.clamdConf], { windowsHide: true });
                clamdConfSignature = nextClamdConfSignature;
                applyShieldLowImpactPriority(clamdProcess, settings, "clamd");
                clamdProcess.on("error", (err: any) => {
                    console.error("Failed to start clamd:", err.message);
                    clamdProcess = null;
                    clamdConfSignature = "";
                });
                clamdProcess.on("close", () => {
                    console.log("clamd process closed.");
                    clamdProcess = null;
                    clamdConfSignature = "";
                });
            } catch (e: any) {
                console.error("Failed to start clamd:", e.message);
            }
        } else {
            if (settings.shieldLowImpactMode === false) {
                void setWindowsProcessPriority(clamdProcess?.pid, "Normal")
                    .then(() => {
                        if (process.platform === "win32" && clamdProcess?.pid) {
                            console.log(`Shield low impact mode: clamd PID ${clamdProcess.pid} priority restored to Normal.`);
                        }
                    });
            } else {
                applyShieldLowImpactPriority(clamdProcess, settings, "clamd");
            }
        }
    } else {
        if (clamdProcess) {
            console.log("Stopping clamd process...");
            clamdProcess.kill();
            clamdProcess = null;
            clamdConfSignature = "";
        }
    }
}

async function checkIsAdmin() {
    if (process.platform !== "win32") return false;
    try {
        await execAsync("net session");
        return true;
    } catch {
        return false;
    }
}

async function checkClamAV(settings: any) {
    if (process.platform !== "win32") {
        isSimulated = true;
    } else {
        isSimulated = false;
        
        // Auto-fix paths if old clamav-* folder exists
        try {
            await fs.mkdir(engineBaseDir, { recursive: true });
            const extractedClamDir = await findExtractedClamavDir();
            const managedClamDir = path.join(engineBaseDir, "clamav");
            const managedEngineExists = await pathExists(path.join(managedClamDir, "clamscan.exe")) && await pathExists(path.join(managedClamDir, "freshclam.exe"));

            if (!managedEngineExists && extractedClamDir) {
                console.log("Adopting extracted ClamAV engine into managed folder.");
                settings.clamavDir = await adoptClamavEngineFolder(extractedClamDir);
                settings.clamscanPath = path.join(settings.clamavDir, "clamscan.exe");
                settings.freshclamPath = path.join(settings.clamavDir, "freshclam.exe");
                settings.clamdPath = path.join(settings.clamavDir, "clamd.exe");
                settings.clamdscanPath = path.join(settings.clamavDir, "clamdscan.exe");
                settings.freshclamConf = path.join(settings.clamavDir, "freshclam.conf");
                settings.clamdConf = path.join(settings.clamavDir, "clamd.conf");
                await saveConfig(settings);
            }
        } catch (e: any) {
            console.error("Error during checkClamAV auto-fix:", e.message);
        }

        // Ensure configuration files exist
        if (settings.freshclamConf) {
            try {
                await ensureFreshclamConfig(settings);
            } catch (e) {
                console.error("Failed to ensure freshclam.conf:", e);
            }
        }

        if (settings.clamdConf) {
            await ensureClamdConfContent(settings);
        }
    }
}

// Ensure directories exist
async function ensureDirs(settings: any) {
    const dirs = [
        programDataDir,
        settings.databaseDir,
        settings.quarantineDir,
        settings.logsDir,
        settings.yaraDir,
        settings.yaraRulesDir,
        settings.yaraCustomRulesDir,
        settings.yaraCacheDir
    ];
    for (const dir of dirs) {
        try {
            await fs.mkdir(dir, { recursive: true });
        } catch (e) {
            console.error(`Failed to create dir: ${dir}`, e);
        }
    }
}

// Load configurations
async function loadConfig() {
    const configPath = path.join(programDataDir, "settings.json");
    try {
        const data = await fs.readFile(configPath, "utf8");
        const parsed = JSON.parse(data);
        const actionOnDetection = parsed.actionOnDetection === "warn" ? "ask" : (parsed.actionOnDetection || defaultSettings.actionOnDetection);
        const scanDetectionAction = parsed.scanDetectionAction || (parsed.actionOnDetection === "quarantine" || parsed.autoQuarantine ? "quarantine" : defaultSettings.scanDetectionAction);
        const loadedSettings = {
            ...defaultSettings,
            ...parsed,
            actionOnDetection,
            scanDetectionAction,
            eulaAccepted: parsed.eulaAccepted !== false
        };
        currentLogsDir = loadedSettings.logsDir || defaultLogsDir;
        debugLoggingEnabled = loadedSettings.enableDebugLog === true;
        return loadedSettings;
    } catch {
        currentLogsDir = defaultLogsDir;
        debugLoggingEnabled = defaultSettings.enableDebugLog;
        return defaultSettings;
    }
}

async function saveConfig(settings: any) {
    const configPath = path.join(programDataDir, "settings.json");
    currentLogsDir = settings.logsDir || defaultLogsDir;
    debugLoggingEnabled = settings.enableDebugLog === true;
    await fs.writeFile(configPath, JSON.stringify(settings, null, 2));
}

async function cleanupOldLogs(settings: any) {
    const retentionDays = normalizePositiveNumber(settings.logRetentionDays, 7, 1, 365);
    const logsDir = settings.logsDir || defaultLogsDir;
    const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
    try {
        await fs.mkdir(logsDir, { recursive: true });
        const entries = await fs.readdir(logsDir, { withFileTypes: true });
        await Promise.all(entries
            .filter(entry => entry.isFile() && entry.name.toLowerCase().endsWith(".log"))
            .map(async entry => {
                const logPath = path.join(logsDir, entry.name);
                try {
                    const stat = await fs.stat(logPath);
                    if (stat.mtimeMs < cutoff) {
                        await fs.unlink(logPath);
                    }
                } catch (e) {
                    console.warn("Failed to apply log retention for", logPath, e);
                }
            }));
    } catch (e) {
        console.warn("Failed to clean old logs:", e);
    }
}

async function manageStartup(settings: any) {
    if (process.platform !== "win32") return;
    try {
        let command = `"${process.argv[0]}"`;
        if (process.argv.length > 1 && !process.argv[0].endsWith("ClamShield.exe") && !process.argv[0].endsWith("clamshield.exe") ) {
             command += ` "${process.argv[1]}"`;
        }
        
        let targetCommand = (process.argv[0].endsWith("ClamShield.exe") || process.argv[0].endsWith("clamshield.exe")) ? process.execPath : command.replace(/"/g, '\\"');

        const taskName = "ClamShield";

        if (settings.runOnStartup) {
            const startupArgs = settings.startMinimized ? " --minimized" : "";
            const schtasksCmd = `schtasks /create /tn "${taskName}" /tr "\\"${targetCommand}\\"${startupArgs}" /sc onlogon /rl highest /f`;
            await execAsync(schtasksCmd).catch(() => {});
        } else {
            await execAsync(`schtasks /delete /tn "${taskName}" /f`).catch(() => {});
        }
    } catch (e: any) {
        console.error("Failed to set startup task:", e.message);
    }
}

// Simple JSON DB for history
async function getHistory() {
    const historyPath = path.join(programDataDir, "history.json");
    try {
        return JSON.parse(await fs.readFile(historyPath, "utf8"));
    } catch {
        return [];
    }
}

async function getExceptions() {
    const excPath = path.join(programDataDir, "exceptions.json");
    try {
        return JSON.parse(await fs.readFile(excPath, "utf8"));
    } catch {
        return [];
    }
}

async function saveExceptions(list: string[]) {
    const excPath = path.join(programDataDir, "exceptions.json");
    await fs.writeFile(excPath, JSON.stringify(list, null, 2));
}

function isExcluded(filePath: string, exceptions: string[]) {
    // Normalize paths to avoid slash differences
    const normFile = path.resolve(filePath).toLowerCase();
    return exceptions.some(exc => {
        const normExc = path.resolve(exc).toLowerCase();
        return normFile === normExc || normFile.startsWith(normExc + path.sep);
    });
}

async function getQuarantineMap() {
    const mapPath = path.join(programDataDir, "quarantine_map.json");
    try {
        return JSON.parse(await fs.readFile(mapPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveQuarantineMap(map: Record<string, any>) {
    const mapPath = path.join(programDataDir, "quarantine_map.json");
    await fs.writeFile(mapPath, JSON.stringify(map, null, 2));
}

async function getQuarantineItems(quarantineDir: string) {
    try {
        const files = await fs.readdir(quarantineDir);
        const qMap = await getQuarantineMap();
        const items = await Promise.all(files.map(async file => {
            const stat = await fs.stat(path.join(quarantineDir, file));
            let meta = qMap[file];
            if (!meta) {
                const baseMatch = file.match(/^(.*?)(?:\.\d{3})?$/);
                if (baseMatch && qMap[baseMatch[1]]) {
                    meta = qMap[baseMatch[1]];
                }
            }
            const timestamp = Number(meta?.timestamp) || stat.mtimeMs;

            return {
                id: file,
                fileName: file,
                threatName: meta ? meta.threatName : "Unknown Threat",
                originalPath: meta ? meta.originalPath : "Unknown",
                size: stat.size,
                timestamp,
                date: new Date(timestamp).toISOString()
            };
        }));
        return items.sort((a, b) => b.timestamp - a.timestamp);
    } catch {
        return [];
    }
}

async function restoreQuarantinedFileAndAddException(settings: any, fileName: string) {
    const safeName = path.basename(fileName);
    if (safeName !== fileName) {
        throw new Error("Invalid quarantine item.");
    }

    const qMap = await getQuarantineMap();
    const metadata = qMap[safeName];
    const originalPath = metadata?.originalPath;
    if (!originalPath || originalPath === "Unknown") {
        throw new Error("Original file location is unknown.");
    }

    const quarantinePath = path.join(settings.quarantineDir, safeName);
    await fs.access(quarantinePath);
    if (existsSync(originalPath)) {
        throw new Error("A file already exists at the original location. Restore manually from the quarantine folder.");
    }

    await fs.mkdir(path.dirname(originalPath), { recursive: true });
    try {
        await fs.rename(quarantinePath, originalPath);
    } catch {
        await fs.copyFile(quarantinePath, originalPath);
        await fs.unlink(quarantinePath);
    }

    const exceptions = await getExceptions();
    if (!exceptions.includes(originalPath)) {
        exceptions.push(originalPath);
        await saveExceptions(exceptions);
    }

    delete qMap[safeName];
    await saveQuarantineMap(qMap);

    await addHistory({
        type: "quarantine-restore",
        target: originalPath,
        result: 0,
        threatsFound: 0,
        scannedFiles: 0,
        duration: 0,
        actionTaken: "Restored and added to exceptions"
    });

    return { restoredPath: originalPath };
}

function getScanResultsPath() {
    return path.join(programDataDir, "scan_results.json");
}

function getResultsReminderPath() {
    return path.join(programDataDir, "results_reminder.json");
}

async function getScanResults() {
    try {
        const data = JSON.parse(await fs.readFile(getScanResultsPath(), "utf8"));
        return Array.isArray(data)
            ? data.sort((a: any, b: any) => Number(b.timestamp || 0) - Number(a.timestamp || 0))
            : [];
    } catch {
        return [];
    }
}

async function saveScanResults(results: any[]) {
    await fs.writeFile(getScanResultsPath(), JSON.stringify(results.sort((a: any, b: any) => Number(b.timestamp || 0) - Number(a.timestamp || 0)), null, 2));
    if (scanResultsChangedHandler) {
        Promise.resolve(scanResultsChangedHandler()).catch(e => console.warn("Failed to notify scan results change:", e));
    }
}

async function getResultsReminderState() {
    try {
        return JSON.parse(await fs.readFile(getResultsReminderPath(), "utf8"));
    } catch {
        return { remindUntil: 0, forgottenUntil: 0 };
    }
}

async function saveResultsReminderState(state: any) {
    await fs.writeFile(getResultsReminderPath(), JSON.stringify(state, null, 2));
    if (scanResultsChangedHandler) {
        Promise.resolve(scanResultsChangedHandler()).catch(e => console.warn("Failed to notify results reminder change:", e));
    }
}

async function addScanResult(result: any) {
    const results = await getScanResults();
    const originalPath = path.resolve(result.originalPath);
    const existing = results.find((item: any) =>
        item.originalPath && path.resolve(item.originalPath).toLowerCase() === originalPath.toLowerCase()
    );
    if (existing) {
        Object.assign(existing, {
            ...result,
            originalPath,
            timestamp: Date.now()
        });
    } else {
        results.unshift({
            id: Date.now().toString() + randomBytes(4).toString("hex"),
            timestamp: Date.now(),
            originalPath,
            ...result
        });
    }
    await saveScanResults(results.sort((a: any, b: any) => Number(b.timestamp) - Number(a.timestamp)));
}

async function removeScanResult(resultId: string) {
    const results = await getScanResults();
    const index = results.findIndex((item: any) => item.id === resultId);
    if (index === -1) {
        throw new Error("Result not found.");
    }
    const [item] = results.splice(index, 1);
    await saveScanResults(results);
    return item;
}

async function quarantineResultItem(settings: any, result: any) {
    if (!result.originalPath || !existsSync(result.originalPath)) {
        throw new Error("Original file is no longer available.");
    }
    const qMap = await getQuarantineMap();
    const quarantined = await quarantineFile(result.originalPath, result.threatName || "Unknown Threat", settings.quarantineDir);
    qMap[quarantined.fileName] = quarantined.metadata;
    await saveQuarantineMap(qMap);
    return quarantined;
}

async function addHistory(entry: any) {
    const historyPath = path.join(programDataDir, "history.json");
    const history = await getHistory();
    history.unshift({ id: Date.now().toString(), date: new Date().toISOString(), ...entry });
    await fs.writeFile(historyPath, JSON.stringify(history, null, 2));
}

function isPathInside(childPath: string, parentPath: string) {
    const child = path.resolve(childPath).toLowerCase();
    const parent = path.resolve(parentPath).replace(/[\\/]+$/, "").toLowerCase();
    return child === parent || child.startsWith(parent + path.sep.toLowerCase()) || child.startsWith(parent + "/");
}

function shouldSkipYaraTarget(settings: any, filePath: string, fingerprint: ShieldCacheEntry | null) {
    if (!fingerprint) return true;
    const maxBytes = normalizePositiveNumber(settings.yaraMaxFileSize, 50, 1, 4096) * 1024 * 1024;
    if (fingerprint.size > maxBytes) return true;
    const ownYaraPaths = [
        settings.yaraDir,
        settings.yaraRulesDir,
        settings.yaraCustomRulesDir,
        settings.yaraCacheDir
    ].filter(Boolean);
    return ownYaraPaths.some((ownPath: string) => isPathInside(filePath, ownPath));
}

async function createYaraTargetList(settings: any, targets: string[], onProgress?: (count: number) => void) {
    const listPath = path.join(os.tmpdir(), `clamshield-yara-list-${Date.now()}-${randomBytes(6).toString("hex")}.txt`);
    const writer = createWriteStream(listPath, { encoding: "utf16le" });
    let count = 0;
    let unreadablePathCount = 0;
    try {
        for (const target of targets.filter(Boolean)) {
            let stat;
            try {
                stat = await fs.stat(target);
            } catch {
                unreadablePathCount++;
                continue;
            }
            if (stat.isFile()) {
                const fingerprint = await getFileFingerprint(target);
                if (!shouldSkipYaraTarget(settings, target, fingerprint)) {
                    writer.write(`${target}${os.EOL}`);
                    count++;
                }
                continue;
            }
            if (!stat.isDirectory()) continue;
            for await (const filePath of walkFiles(target)) {
                const fingerprint = await getFileFingerprint(filePath);
                if (shouldSkipYaraTarget(settings, filePath, fingerprint)) continue;
                writer.write(`${filePath}${os.EOL}`);
                count++;
                if (count % 5000 === 0) onProgress?.(count);
                if (count % 200 === 0) await sleep(1);
            }
        }
    } finally {
        await new Promise<void>((resolve, reject) => {
            writer.end(() => resolve());
            writer.on("error", reject);
        });
    }
    onProgress?.(count);
    return { listPath, count, unreadablePathCount };
}

function parseYaraMatchLine(line: string) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.toLowerCase().startsWith("error:") || trimmed.includes(": error:")) return null;
    const match = trimmed.match(/^([A-Za-z0-9_.@$-]+)(?:\s+\[[^\]]+\])?\s+(.+)$/);
    if (!match) return null;
    const originalPath = match[2].trim();
    if (!originalPath || originalPath.startsWith("[")) return null;
    return {
        ruleName: match[1],
        originalPath
    };
}

async function handleYaraDetection(settings: any, detection: any, options: any) {
    const exceptions = await getExceptions();
    if (isExcluded(detection.originalPath, exceptions)) {
        options.appendJobLogs(options.jobId, [
            `YARA threat found: ${displayFileName(detection.originalPath)}`,
            "Action: Ignored because it is in Exceptions"
        ]);
        return "Ignored";
    }

    const threatName = `YARA: ${detection.ruleNames.join(", ")}`;
    if (options.action === "quarantine") {
        try {
            const quarantined = await quarantineFile(detection.originalPath, threatName, settings.quarantineDir);
            const qMap = await getQuarantineMap();
            qMap[quarantined.fileName] = quarantined.metadata;
            await saveQuarantineMap(qMap);
            options.appendJobLogs(options.jobId, [
                `YARA threat found: ${displayFileName(detection.originalPath)}`,
                "Action: Quarantined"
            ]);
            return "Quarantined";
        } catch (e: any) {
            options.appendJobLogs(options.jobId, [`YARA quarantine failed for ${displayFileName(detection.originalPath)}: ${e.message}`]);
            return "Quarantine Failed";
        }
    }

    if (options.action === "ask" && Array.isArray(options.pendingThreats)) {
        const pendingThreat = {
            id: Date.now().toString() + Math.random().toString(36).substring(7),
            originalPath: detection.originalPath,
            threatName,
            engine: "YARA",
            timestamp: Date.now()
        };
        options.pendingThreats.push(pendingThreat);
        if (pendingThreatHandler) pendingThreatHandler(pendingThreat);
        options.appendJobLogs(options.jobId, [
            `YARA threat found: ${displayFileName(detection.originalPath)}`,
            "Action: Waiting for your decision"
        ]);
        return "Pending";
    }

    await addScanResult({
        source: options.source,
        scanType: options.scanType,
        target: options.target,
        originalPath: detection.originalPath,
        threatName,
        engine: "YARA",
        yaraRuleset: normalizeYaraRuleset(settings.yaraRuleset)
    });
    options.appendJobLogs(options.jobId, [
        `YARA threat found: ${displayFileName(detection.originalPath)}`,
        "Action: Sent to Results"
    ]);
    return "Sent to Results";
}

async function runYaraScanForTargets(settings: any, targets: string[], options: any) {
    if (settings.yaraEnabled === false) return { matches: 0, actionTaken: "None" };
    const job = options.activeJobs[options.jobId];
    if (!job) return { matches: 0, actionTaken: "None" };

    const rulesFile = getYaraRulesFile(settings);
    if (!existsSync(rulesFile)) {
        options.appendJobLogs(options.jobId, [
            `YARA skipped: ${path.basename(rulesFile)} is missing. Use Updates -> Update YARA Rules.`
        ]);
        return { matches: 0, actionTaken: "None" };
    }

    let yaraPath: string;
    try {
        yaraPath = await ensureYaraEngine(settings, message => console.debug(`YARA: ${message}`));
    } catch (e: any) {
        options.appendJobLogs(options.jobId, [`YARA skipped: ${e.message}`]);
        return { matches: 0, actionTaken: "None" };
    }

    const { listPath, count, unreadablePathCount } = await createYaraTargetList(settings, targets, (indexed) => {
        console.debug(`YARA target list indexed: ${indexed} files`);
    });
    if (unreadablePathCount > 0) {
        options.appendJobLogs(options.jobId, [
            `YARA skipped ${unreadablePathCount} unreadable target path${unreadablePathCount === 1 ? "" : "s"}.`
        ]);
    }
    if (count === 0) {
        await fs.unlink(listPath).catch(() => {});
        options.appendJobLogs(options.jobId, ["YARA skipped: no eligible files after exclusions and size limits."]);
        return { matches: 0, actionTaken: "None" };
    }

    const maxBytes = normalizePositiveNumber(settings.yaraMaxFileSize, 50, 1, 4096) * 1024 * 1024;
    const timeoutSeconds = normalizePositiveNumber(settings.yaraTimeoutSeconds, 15, 1, 3600);
    const args = [
        "--no-warnings",
        "--fast-scan",
        `--timeout=${timeoutSeconds}`,
        `--skip-larger=${maxBytes}`,
        "--scan-list",
        rulesFile,
        listPath
    ];
    options.appendJobLogs(options.jobId, [
        "YARA scan started",
        `YARA ruleset: ${titleCase(normalizeYaraRuleset(settings.yaraRuleset))}`,
        `YARA scanned files: ${count}`
    ]);

    const stdoutLines: string[] = [];
    const child = spawn(yaraPath, args, { windowsHide: true });
    job.process = child;
    let openErrorCount = 0;
    const exitCode = await new Promise<number>((resolve) => {
        child.stdout.on("data", data => {
            const lines = data.toString().split("\n").map((line: string) => line.trim()).filter(Boolean);
            stdoutLines.push(...lines);
            if (lines.length) console.debug("YARA output:", lines);
        });
        child.stderr.on("data", data => {
            const lines = data.toString().split("\n").map((line: string) => line.trim()).filter(Boolean);
            const visibleLines: string[] = [];
            for (const line of lines) {
                if (/error scanning .*could not open file/i.test(line)) {
                    openErrorCount++;
                } else {
                    visibleLines.push(line);
                }
            }
            if (visibleLines.length) console.debug("YARA stderr:", visibleLines);
        });
        child.on("error", error => {
            options.appendJobLogs(options.jobId, [`YARA process error: ${error.message}`]);
            resolve(-1);
        });
        child.on("close", code => resolve(code ?? 0));
    });
    await fs.unlink(listPath).catch(() => {});
    if (job.process === child) job.process = null;
    if (openErrorCount > 0) {
        options.appendJobLogs(options.jobId, [
            `YARA skipped ${openErrorCount} file${openErrorCount === 1 ? "" : "s"} it could not open. ClamAV scan results are still valid.`
        ]);
    }

    const detectionsByPath = new Map<string, { originalPath: string, ruleNames: Set<string> }>();
    for (const line of stdoutLines) {
        const match = parseYaraMatchLine(line);
        if (!match) continue;
        const normalizedPath = path.resolve(match.originalPath).toLowerCase();
        if (!detectionsByPath.has(normalizedPath)) {
            detectionsByPath.set(normalizedPath, { originalPath: match.originalPath, ruleNames: new Set() });
        }
        detectionsByPath.get(normalizedPath)!.ruleNames.add(match.ruleName);
    }

    let actionTaken = "None";
    for (const detection of detectionsByPath.values()) {
        const result = await handleYaraDetection(settings, {
            originalPath: detection.originalPath,
            ruleNames: Array.from(detection.ruleNames).slice(0, 8)
        }, options);
        if (result !== "Ignored") actionTaken = result;
    }

    options.appendJobLogs(options.jobId, [`YARA matches: ${detectionsByPath.size}`]);
    return { matches: detectionsByPath.size, actionTaken };
}

async function startServer() {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
        const hasValidSession = readCookie(req, apiCookieName) === apiSessionToken || req.header(apiHeaderName) === apiSessionToken;
        if (hasValidSession) {
            res.cookie(apiCookieName, apiSessionToken, {
                httpOnly: true,
                sameSite: "strict",
                secure: false,
                path: "/"
            });
        }
        next();
    });
    app.use(requireLocalApiSession);
    
    let settings = await loadConfig();
    await ensureDirs(settings);
    await cleanupOldLogs(settings);
    console.log("ClamShield service starting", {
        version: process.env.npm_package_version,
        logsDir: settings.logsDir,
        debugLoggingEnabled: settings.enableDebugLog === true
    });
    let defenderTimer: NodeJS.Timeout | null = null;
    const scheduleDefenderEnforcement = async (runNow = true) => {
        if (defenderTimer) clearInterval(defenderTimer);
        if (!settings.autoDisableDefender) return;

        if (runNow) {
            autoDisableDefender().catch(e => console.warn("Initial Defender pause failed:", e.message));
        }
        const intervalMinutes = normalizePositiveNumber(settings.defenderEnforceIntervalMinutes, 5, 1, 1440);
        defenderTimer = setInterval(() => {
            autoDisableDefender().catch(e => console.warn("Scheduled Defender pause failed:", e.message));
        }, intervalMinutes * 60 * 1000);
        defenderTimer.unref?.();
    };

    await scheduleDefenderEnforcement(true);
    await checkClamAV(settings);
    await manageStartup(settings);
    cachedIsAdmin = await checkIsAdmin();

    const scanSessions = new ScanSessionStore(getScanSessionsDbPath());
    const activeJobs: Record<string, { status: string, logs: string[], analysisLogs?: string[], result?: number, process?: any, lastOutputAt?: number, progress?: ScanProgress }> = {};
    let pendingThreats: any[] = [];
    const eventClients = new Set<express.Response>();
    const sendApiEventToClient = (client: express.Response, event: string, data: any) => {
        client.write(`event: ${event}\n`);
        client.write(`data: ${JSON.stringify(data)}\n\n`);
    };
    const sendApiEvent = (event: string, data: any) => {
        for (const client of Array.from(eventClients)) {
            try {
                sendApiEventToClient(client, event, data);
            } catch {
                eventClients.delete(client);
            }
        }
    };
    const jobEventClients = new Map<string, Set<express.Response>>();
    const sendJobEventToClient = (client: express.Response, data: any) => {
        client.write(`event: job\n`);
        client.write(`data: ${JSON.stringify(data)}\n\n`);
    };
    const broadcastJobEvent = (jobId: string, logs: string[] = []) => {
        const clients = jobEventClients.get(jobId);
        if (!clients || clients.size === 0) return;
        const job = activeJobs[jobId];
        if (!job) {
            for (const client of Array.from(clients)) {
                try {
                    sendJobEventToClient(client, { status: "missing", logs: [], progress: null });
                } catch {}
            }
            return;
        }
        const payload = {
            status: job.status,
            logs,
            progress: job.progress || null,
            result: job.result
        };
        for (const client of Array.from(clients)) {
            try {
                sendJobEventToClient(client, payload);
            } catch {
                clients.delete(client);
            }
        }
    };
    const getResultsReminderPayload = async () => {
        const results = await getScanResults();
        if (results.length === 0) {
            return { show: false, count: 0, latestTimestamp: 0 };
        }
        const latestTimestamp = Math.max(...results.map((item: any) => Number(item.timestamp || 0)));
        const state = await getResultsReminderState();
        const now = Date.now();
        const show = now >= Number(state.remindUntil || 0) && latestTimestamp > Number(state.forgottenUntil || 0);
        return { show, count: results.length, latestTimestamp };
    };
    const broadcastResultsReminder = async () => {
        sendApiEvent("results-reminder", await getResultsReminderPayload());
    };
    pendingThreatHandler = threat => sendApiEvent("threat", threat);
    scanResultsChangedHandler = broadcastResultsReminder;
    const shieldScanCache = await loadShieldScanCacheStore();
    console.log(`Shield cache backend: ${shieldScanCache.type}`);
    const saveJobProgress = (jobId: string, patch: Partial<ScanProgress>) => {
        const job = activeJobs[jobId];
        if (!job?.progress) return;
        job.progress = {
            ...job.progress,
            ...patch,
            updatedAt: Date.now()
        };
        job.progress.elapsedSeconds = Math.floor((Date.now() - job.progress.startedAt) / 1000);
        const lastOutputAt = job.lastOutputAt || job.progress.startedAt;
        job.progress.quietSeconds = Math.floor((Date.now() - lastOutputAt) / 1000);
        try {
            scanSessions.save(job.progress);
        } catch (e) {
            console.warn("Failed to save scan progress:", e);
        }
        broadcastJobEvent(jobId);
    };
    const appendJobLogs = (jobId: string, lines: string[]) => {
        const job = activeJobs[jobId];
        if (!job || lines.length === 0) return;
        job.logs.push(...lines);
        job.lastOutputAt = Date.now();
        if (job.logs.length > 1000) job.logs.splice(0, job.logs.length - 1000);
        const analysisLines = lines.filter(line =>
            line.includes(" FOUND") ||
            line.startsWith("Scanned files:") ||
            line.startsWith("Infected files:") ||
            line.startsWith("Time:")
        );
        if (analysisLines.length) {
            if (!job.analysisLogs) job.analysisLogs = [];
            job.analysisLogs.push(...analysisLines);
            if (job.analysisLogs.length > 5000) job.analysisLogs.splice(0, job.analysisLogs.length - 5000);
        }
        broadcastJobEvent(jobId, lines);
    };

    app.post("/api/client-log", (req, res) => {
        const level = typeof req.body?.level === "string" ? req.body.level : "error";
        const message = req.body?.message || "Renderer log";
        if (debugLoggingEnabled || level === "fatal") {
            writeAppLog("renderer.log", level, [message, req.body?.details || {}]);
        }
        res.json({ success: true });
    });

    app.get("/api/events", async (req, res) => {
        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache, no-transform");
        res.setHeader("Connection", "keep-alive");
        res.flushHeaders?.();
        eventClients.add(res);
        sendApiEventToClient(res, "connected", { ok: true });
        for (const threat of pendingThreats) {
            sendApiEventToClient(res, "threat", threat);
        }
        try {
            sendApiEventToClient(res, "results-reminder", await getResultsReminderPayload());
        } catch (e) {
            console.warn("Failed to send initial results reminder event:", e);
        }
        const keepAlive = setInterval(() => {
            try {
                res.write(":keepalive\n\n");
            } catch {
                clearInterval(keepAlive);
                eventClients.delete(res);
            }
        }, 25000);
        keepAlive.unref?.();
        req.on("close", () => {
            clearInterval(keepAlive);
            eventClients.delete(res);
        });
    });

    const createScanHeartbeat = (jobId: string, label: string) => {
        const startedAt = Date.now();
        const timer = setInterval(() => {
            const job = activeJobs[jobId];
            if (!job || job.status !== "running") {
                clearInterval(timer);
                return;
            }
            const now = Date.now();
            const elapsedSeconds = Math.floor((now - startedAt) / 1000);
            const lastOutputAt = job.lastOutputAt || startedAt;
            const quietSeconds = Math.floor((now - lastOutputAt) / 1000);
            saveJobProgress(jobId, {
                phase: job.progress?.phase || label,
                elapsedSeconds,
                quietSeconds
            });
        }, 5000);
        timer.unref?.();
        return timer;
    };

    let shieldWatcher: any = null;
    async function startShield(currentSettings: any) {
        if (shieldWatcher) {
            await shieldWatcher.close();
            shieldWatcher = null;
        }

        if (!currentSettings.shieldEnabled) {
            console.log("Shield is disabled in settings.");
            return;
        }

        const watchPaths: string[] = [];
        const resolvedPaths = await getResolvedSystemPaths();
        if (currentSettings.monitorDownloads) watchPaths.push(resolvedPaths.Downloads);
        if (currentSettings.monitorDesktop) watchPaths.push(resolvedPaths.Desktop);
        if (currentSettings.monitorDocuments) watchPaths.push(resolvedPaths.Documents);
        if (currentSettings.autoDetectBrowserDownloads !== false && Array.isArray(resolvedPaths.BrowserDownloads)) {
            watchPaths.push(...resolvedPaths.BrowserDownloads.map((item: any) => item.path));
        }
        if (Array.isArray(currentSettings.customWatchedFolders)) {
            watchPaths.push(...currentSettings.customWatchedFolders);
        }

        const existingWatchPaths = await existingUniqueDirs(watchPaths);
        console.log("Shield watch paths:", existingWatchPaths);

        if (existingWatchPaths.length === 0) return;

        shieldWatcher = chokidar.watch(existingWatchPaths, {
            ignored: /(^|[\/\\])\../, 
            persistent: true,
            ignoreInitial: true,
            depth: normalizePositiveNumber(currentSettings.shieldDepth, 1, 0, 20),
            ignorePermissionErrors: true,
            awaitWriteFinish: {
                stabilityThreshold: currentSettings.shieldStabilityThreshold || 2000,
                pollInterval: currentSettings.shieldPollInterval || 1000
            }
        });

        shieldWatcher.on('error', error => console.error(`Shield watcher error: ${error}`));

        const filesBeingScanned = new Set<string>();
        const pendingShieldScans = new Map<string, { filePath: string, reason: "add" | "change" }>();
        const lockedFileBackoff = new Map<string, number>();
        let activeShieldScans = 0;
        const maxShieldScans = Math.floor(normalizePositiveNumber(currentSettings.shieldMaxConcurrentScans, 1, 1, 4));

        const processShieldQueue = () => {
            while (activeShieldScans < maxShieldScans && pendingShieldScans.size > 0) {
                const next = Array.from(pendingShieldScans.entries()).find(([normalizedPath]) => !filesBeingScanned.has(normalizedPath)) as [string, { filePath: string, reason: "add" | "change" }] | undefined;
                if (!next) return;
                const [normalizedPath, item] = next;
                pendingShieldScans.delete(normalizedPath);

                activeShieldScans++;
                scanShieldFile(item.filePath, item.reason)
                    .catch(err => console.error("Shield queued scan failed:", err))
                    .finally(() => {
                        activeShieldScans--;
                        processShieldQueue();
                    });
            }
        };

        const enqueueShieldFile = (filePath: string, reason: "add" | "change") => {
            const normalizedPath = path.resolve(filePath).toLowerCase();
            pendingShieldScans.set(normalizedPath, { filePath, reason });
            processShieldQueue();
        };

        const scanShieldFile = async (filePath: string, reason: "add" | "change") => {
            const normalizedPath = path.resolve(filePath).toLowerCase();
            if (filesBeingScanned.has(normalizedPath)) return;
            const lockedUntil = lockedFileBackoff.get(normalizedPath) || 0;
            if (lockedUntil > Date.now()) {
                console.debug(`Shield: skipping locked/unstable file until ${new Date(lockedUntil).toISOString()} -> ${filePath}`);
                return;
            }
            lockedFileBackoff.delete(normalizedPath);
            filesBeingScanned.add(normalizedPath);
            console.log(`Shield: File ${reason === "add" ? "detected" : "changed"} -> ${filePath}`);
            const fingerprint = await getFileFingerprint(filePath);
            if (!fingerprint || cacheEntryMatches(fingerprint, shieldScanCache.get(normalizedPath)) || isSimulated) {
                filesBeingScanned.delete(normalizedPath);
                return;
            }
            const maxFileSizeBytes = normalizePositiveNumber(currentSettings.maxFileSize, 50, 1, 4096) * 1024 * 1024;
            if (fingerprint.size > maxFileSizeBytes) {
                shieldScanCache.set(normalizedPath, fingerprint);
                filesBeingScanned.delete(normalizedPath);
                return;
            }

            let isClamd = false;
            if (currentSettings.offloadToMemory && currentSettings.clamdscanPath) {
                try {
                    await fs.access(currentSettings.clamdscanPath);
                    isClamd = true;
                } catch (e: any) {
                    console.debug("Shield offload requested, but clamdscan is unavailable; falling back to clamscan:", e?.message || e);
                }
            }
            let exePath = isClamd ? currentSettings.clamdscanPath : currentSettings.clamscanPath;
            let args = buildClamScanArgs(currentSettings, isClamd, "file", filePath);

            const jobId = "shield-" + Date.now() + Math.random().toString(36).substring(7);
            activeJobs[jobId] = { status: "running", logs: [], analysisLogs: [] };
            appendJobLogs(jobId, [
                `Real-time protection is checking: ${displayFileName(filePath)}`,
                `Low impact mode: ${currentSettings.shieldLowImpactMode === false ? "off" : "on"}`
            ]);
            console.debug(`Shield scan engine: ${isClamd ? "clamdscan/offload to RAM" : "clamscan/direct"}`);
            console.debug(`Shield scan executable: ${exePath}`);
            console.debug(`Shield scan arguments: ${args.join(" ")}`);
            
            try {
                const heartbeat = createScanHeartbeat(jobId, "Shield scan");
                const child = spawn(exePath, args, { windowsHide: true });
                activeJobs[jobId].process = child;
                applyShieldLowImpactPriority(child, currentSettings, isClamd ? "clamdscan" : "clamscan");
                if (isClamd && clamdProcess) {
                    applyShieldLowImpactPriority(clamdProcess, currentSettings, "clamd");
                }
                
                child.on("error", (err: any) => {
                    clearInterval(heartbeat);
                    console.error("Failed to start shield scan process:", err.message);
                    if (activeJobs[jobId]) {
                        activeJobs[jobId].status = "error";
                        appendJobLogs(jobId, ["Process error: " + err.message]);
                        filesBeingScanned.delete(normalizedPath);
                    }
                });

                child.stdout.on("data", (data) => {
                    const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                    appendJobLogs(jobId, lines);
                });
                child.stderr.on("data", (data) => {
                    const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                    appendJobLogs(jobId, lines);
                });

                child.on("close", async (code) => {
                    clearInterval(heartbeat);
                    if (!activeJobs[jobId]) return;
                    let threatsFound = 0;
                    let scannedFiles = 0;
                    let duration = 0;
                    
                    const qMap = await getQuarantineMap();
                    const exceptions = await getExceptions();
                    let quarantineMapChanged = false;
                    let actionTaken = "None";

                    for (const line of activeJobs[jobId].analysisLogs || []) {
                        if (line.includes(" FOUND")) {
                            const match = line.match(/^(.*?):\s+(.*?)\s+FOUND$/);
                            if (match) {
                                const originalPath = match[1];
                                if (isExcluded(originalPath, exceptions)) {
                                    appendJobLogs(jobId, [`Ignored (Exception): ${originalPath}`]);
                                    continue;
                                }
                                const threatName = match[2];
                                const action = currentSettings.actionOnDetection || (currentSettings.autoQuarantine ? "quarantine" : "ask");
                                if (action === "quarantine") {
                                    try {
                                        const quarantined = await quarantineFile(originalPath, threatName, currentSettings.quarantineDir);
                                        qMap[quarantined.fileName] = quarantined.metadata;
                                        quarantineMapChanged = true;
                                        appendJobLogs(jobId, [`Quarantined: ${originalPath} -> ${quarantined.destPath}`]);
                                        actionTaken = "Quarantined";
                                    } catch (e: any) {
                                        appendJobLogs(jobId, [`Failed to quarantine ${originalPath}: ${e.message}`]);
                                        actionTaken = "Quarantine Failed";
                                    }
                                } else if (action === "ask") {
                                    const pendingThreat = {
                                        id: Date.now().toString() + Math.random().toString(36).substring(7),
                                        originalPath,
                                        threatName,
                                        timestamp: Date.now()
                                    };
                                    pendingThreats.push(pendingThreat);
                                    if (pendingThreatHandler) pendingThreatHandler(pendingThreat);
                                    appendJobLogs(jobId, [`Threat found, waiting for user action: ${originalPath}`]);
                                    actionTaken = "Pending";
                                } else {
                                    await addScanResult({
                                        source: "shield",
                                        scanType: "shield",
                                        target: filePath,
                                        originalPath,
                                        threatName
                                    });
                                    appendJobLogs(jobId, [`Threat found, sent silently to Results: ${originalPath}`]);
                                    actionTaken = "Sent to Results";
                                }
                            }
                        }
                        if (line.startsWith("Scanned files:")) {
                            const m = line.match(/\d+/);
                            if (m) scannedFiles = parseInt(m[0], 10);
                        }
                        if (line.startsWith("Infected files:")) {
                            const m = line.match(/\d+/);
                            if (m) threatsFound = parseInt(m[0], 10);
                        }
                        if (line.startsWith("Time:")) {
                            const m = line.match(/(\d+\.\d+) sec/);
                            if (m) duration = Math.round(parseFloat(m[1]));
                        }
                    }

                    if (quarantineMapChanged) {
                        await saveQuarantineMap(qMap);
                    }

                    const yaraResult = await runYaraScanForTargets(currentSettings, [filePath], {
                        activeJobs,
                        appendJobLogs,
                        jobId,
                        source: "shield",
                        scanType: "shield",
                        target: filePath,
                        action: currentSettings.actionOnDetection || (currentSettings.autoQuarantine ? "quarantine" : "ask"),
                        pendingThreats
                    });
                    if (yaraResult.matches > 0) {
                        threatsFound += yaraResult.matches;
                        actionTaken = yaraResult.actionTaken;
                    }

                    const isThreat = code === 1 || threatsFound > 0;
                    appendJobLogs(jobId, [`Shield scan finished with exit code ${code ?? "unknown"}.`]);
                    if (isThreat) {
                        console.log(`Shield: Threat found in ${filePath}`);
                    }

                    const lockedOrUnstable = !isThreat && (activeJobs[jobId].logs || []).some(isLockedOrUnstableClamLine);
                    if (lockedOrUnstable) {
                        const cooldownMs = 10 * 60 * 1000;
                        lockedFileBackoff.set(normalizedPath, Date.now() + cooldownMs);
                        console.debug(`Shield: locked/unstable scan backoff applied for ${Math.round(cooldownMs / 60000)} minutes -> ${filePath}`);
                    }

                    const latestFingerprint = await getFileFingerprint(filePath);
                    if (latestFingerprint) {
                        shieldScanCache.set(normalizedPath, latestFingerprint);
                    } else {
                        shieldScanCache.delete(normalizedPath);
                    }
                    
                    await addHistory({
                        type: "scan-shield",
                        target: filePath,
                        result: isThreat ? 1 : 0,
                        threatsFound,
                        scannedFiles,
                        duration,
                        actionTaken: isThreat ? actionTaken : "None"
                    });
                    
                    delete activeJobs[jobId];
                    filesBeingScanned.delete(normalizedPath);
                });
            } catch (err) {
                console.error("Shield scan failed", err);
                filesBeingScanned.delete(normalizedPath);
            }
        };

        shieldWatcher.on('add', (filePath) => enqueueShieldFile(filePath, "add"));
        shieldWatcher.on('change', (filePath) => enqueueShieldFile(filePath, "change"));
    }

    startShield(settings);
    await manageClamd(settings);

    // API Routes

    app.get("/api/status", async (req, res) => {
        const history = await getHistory();
        const lastScan = history.find((h: any) => h.type.startsWith("scan")) || null;
        const lastUpdate = history.find((h: any) => h.type === "update") || null;
        const lastThreat = history.find((h: any) => h.threatsFound > 0) || null;

        let hasEngine = false;
        let hasDb = false;
        let hasYaraEngine = false;
        let hasYaraRules = false;
        const quarantineItems = await getQuarantineItems(settings.quarantineDir);
        try {
            hasEngine = await pathExists(settings.clamscanPath) && await pathExists(settings.freshclamPath);
            const dbFiles = await fs.readdir(settings.databaseDir);
            hasDb = dbFiles.some(f => f.endsWith('.cvd') || f.endsWith('.cld'));
        } catch { }
        hasYaraEngine = Boolean(settings.yaraPath && existsSync(settings.yaraPath));
        hasYaraRules = existsSync(getYaraRulesFile(settings));

        const pkgVersion = await getCurrentAppVersion();
        res.json({
            appVersion: pkgVersion,
            isSimulated,
            isInstalling,
            installProgress,
            platform: process.platform,
            isAdmin: cachedIsAdmin,
            settings,
            hasEngine,
            hasDb,
            hasYaraEngine,
            hasYaraRules,
            stats: {
                engineVersion: isSimulated ? "ClamAV (Simulated)" : "ClamAV (Installed)",
                yaraRuleset: normalizeYaraRuleset(settings.yaraRuleset),
                yaraRuleCount: settings.lastYaraRuleCount || 0,
                lastYaraUpdate: settings.lastYaraUpdate || null,
                lastScan: lastScan ? lastScan.date : null,
                lastUpdate: lastUpdate ? lastUpdate.date : null,
                lastThreat: lastThreat ? lastThreat.date : null,
                quarantineCount: quarantineItems.length,
                shieldCacheCount: shieldScanCache.count(),
                shieldCacheBackend: shieldScanCache.type
            }
        });
    });

    app.post("/api/install-engine", async (req, res) => {
        if (process.platform !== "win32") {
            return res.status(400).json({ error: "Auto-install is only supported on Windows 64-bit." });
        }
        if (isInstalling) {
            return res.json({ status: "already_installing" });
        }

        isInstalling = true;
        installProgress = "Starting download...";
        res.json({ status: "started" });

        try {
            installProgress = "Finding latest ClamAV release...";
            const releaseRes = await axios.get("https://api.github.com/repos/Cisco-Talos/clamav/releases/latest");
            const releaseData = releaseRes.data;
            
            const winAsset = releaseData.assets.find((a: any) => 
                a.name.toLowerCase().includes("win") && 
                a.name.toLowerCase().includes("x64") && 
                a.name.toLowerCase().endsWith(".zip") &&
                !a.name.toLowerCase().includes("symbol")
            );

            if (!winAsset) {
                throw new Error("Could not find a Windows x64 zip asset in the latest release.");
            }
            
            const zipUrl = winAsset.browser_download_url;
            
            await fs.mkdir(engineBaseDir, { recursive: true });
            const zipPath = path.join(engineBaseDir, "clamav.zip");
            
            installProgress = `Downloading ${winAsset.name} (this may take a minute)...`;
            
            const response = await axios({ url: zipUrl, method: 'GET', responseType: 'stream' });
            const writer = createWriteStream(zipPath);
            response.data.pipe(writer);
            
            await new Promise<void>((resolve, reject) => {
                writer.on('finish', () => resolve());
                writer.on('error', reject);
            });
            
            installProgress = "Extracting ClamAV engine...";
            const extractStream = createReadStream(zipPath).pipe(unzipper.Extract({ path: engineBaseDir }));
            await new Promise<void>((resolve, reject) => {
                extractStream.on('close', () => resolve());
                extractStream.on('error', reject);
            });
            
            installProgress = "Configuring engine & signatures...";
            const extractedClamDir = await findExtractedClamavDir();
            if (!extractedClamDir) {
                throw new Error("ClamAV archive was extracted, but clamscan.exe and freshclam.exe were not found.");
            }
            installProgress = "Copying ClamAV engine into managed folder...";
            const finalClamDir = await adoptClamavEngineFolder(extractedClamDir);

            const confPath = path.join(finalClamDir, "freshclam.conf");
            const clamdConfPath = path.join(finalClamDir, "clamd.conf");
            await fs.mkdir(settings.databaseDir, { recursive: true });
            
            settings.clamavDir = finalClamDir;
            settings.clamscanPath = path.join(settings.clamavDir, "clamscan.exe");
            settings.freshclamPath = path.join(settings.clamavDir, "freshclam.exe");
            settings.clamdPath = path.join(settings.clamavDir, "clamd.exe");
            settings.clamdscanPath = path.join(settings.clamavDir, "clamdscan.exe");
            settings.freshclamConf = confPath;
            settings.clamdConf = clamdConfPath;

            await ensureFreshclamConfig(settings);

            const clamdConfContent = buildClamdConfContent(settings);
            await fs.writeFile(clamdConfPath, clamdConfContent);
            
            await saveConfig(settings);
            await autoDisableDefender();

            // Clean up zip
            try {
                await fs.unlink(zipPath);
            } catch (e: any) {
                console.debug("ClamAV installer zip cleanup failed:", e?.message || e);
            }
            
            await checkClamAV(settings); // Verify
            isInstalling = false;
            installProgress = "Complete";
        } catch (e: any) {
            console.error("Install failed: ", e);
            isInstalling = false;
            installProgress = "Error: " + e.message;
        }
    });

    // Add automatic update task
    let autoUpdateTimer: NodeJS.Timeout | null = null;
    
    const scheduleNextUpdate = () => {
        if (autoUpdateTimer) clearTimeout(autoUpdateTimer);
        if (!settings.autoUpdateEnabled) return;
        
        // 1 minute poll
        autoUpdateTimer = setTimeout(async () => {
            try {
                if (!isSimulated && settings.autoUpdateEnabled) {
                    const history = await getHistory();
                    const lastUpdate = history.find((h: any) => h.type === "update" && h.result === 0);
                    let shouldUpdate = false;
                    
                    if (!lastUpdate) {
                        shouldUpdate = true;
                    } else {
                        const lastDate = new Date(lastUpdate.date).getTime();
                        const now = Date.now();
                        const intervalMs = (settings.updateIntervalHours || 24) * 60 * 60 * 1000;
                        if (now - lastDate > intervalMs) {
                            shouldUpdate = true;
                        }
                    }
                    
                    if (shouldUpdate) {
                        console.log("Triggering auto-update...");
                        const args = ["--config-file=" + settings.freshclamConf, "--datadir=" + settings.databaseDir];
                        const child = spawn(settings.freshclamPath, args, { windowsHide: true });
                        
                        child.on("error", (err: any) => {
                            console.error("Auto-update process error:", err.message);
                        });

                        child.on("close", async (code) => {
                            await addHistory({
                                type: "update",
                                target: "Databases (Auto)",
                                result: code === 0 ? 0 : 1,
                                threatsFound: 0,
                                scannedFiles: 0,
                                duration: 1, 
                                actionTaken: code === 0 ? "Updated" : "Failed"
                            });
                            console.log(`Auto-update finished with code ${code}`);
                        });
                    }
                }
            } catch (e) {
                console.error("Auto-update check failed:", e);
            }
            scheduleNextUpdate();
        }, 60000); // Check every minute
    };

    let yaraAutoUpdateTimer: NodeJS.Timeout | null = null;
    const scheduleNextYaraUpdate = () => {
        if (yaraAutoUpdateTimer) clearTimeout(yaraAutoUpdateTimer);
        if (!settings.yaraEnabled || !settings.yaraAutoUpdateEnabled) return;

        yaraAutoUpdateTimer = setTimeout(async () => {
            try {
                const history = await getHistory();
                const lastAttempt = history.find((h: any) => h.type === "yara-update");
                const intervalMs = normalizePositiveNumber(settings.yaraUpdateIntervalHours, 168, 1, 8760) * 60 * 60 * 1000;
                const shouldUpdate = !lastAttempt || Date.now() - new Date(lastAttempt.date).getTime() > intervalMs;
                if (shouldUpdate) {
                    console.log("Triggering YARA Forge auto-update...");
                    await updateYaraForgeRules(settings, message => console.log(`YARA auto-update: ${message}`));
                    await addHistory({
                        type: "yara-update",
                        target: `YARA Forge ${normalizeYaraRuleset(settings.yaraRuleset)}`,
                        result: 0,
                        threatsFound: 0,
                        scannedFiles: 0,
                        duration: 1,
                        actionTaken: "Updated"
                    });
                }
            } catch (e: any) {
                console.error("YARA auto-update failed:", e.message);
                await addHistory({
                    type: "yara-update",
                    target: `YARA Forge ${normalizeYaraRuleset(settings.yaraRuleset)}`,
                    result: 1,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: 1,
                    actionTaken: "Failed"
                });
            }
            scheduleNextYaraUpdate();
        }, 60000);
    };

    let appUpdateTimer: NodeJS.Timeout | null = null;
    const scheduleNextAppUpdateCheck = () => {
        if (appUpdateTimer) clearTimeout(appUpdateTimer);
        if (!settings.appUpdateCheckEnabled) return;

        appUpdateTimer = setTimeout(async () => {
            try {
                const history = await getHistory();
                const lastAttempt = history.find((h: any) => h.type === "app-update-check");
                const intervalMs = normalizePositiveNumber(settings.appUpdateIntervalHours, 168, 1, 8760) * 60 * 60 * 1000;
                const shouldCheck = !lastAttempt || Date.now() - new Date(lastAttempt.date).getTime() > intervalMs;
                if (shouldCheck) {
                    console.log("Checking for ClamShield app update...");
                    const update = await getLatestClamShieldRelease(settings);
                    let actionTaken = update.updateAvailable ? `Available ${update.latestVersion}` : "No update";
                    if (update.updateAvailable && settings.appSilentAutoInstall === true) {
                        await downloadAndLaunchClamShieldInstaller(settings, message => console.log(`ClamShield update: ${message}`));
                        actionTaken = `Installer launched ${update.latestVersion}`;
                        const timer = setTimeout(() => process.exit(0), 1500);
                        timer.unref?.();
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
                }
            } catch (e: any) {
                console.error("ClamShield app update check failed:", e.message);
                await addHistory({
                    type: "app-update-check",
                    target: "ClamShield",
                    result: 1,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: 1,
                    actionTaken: "Failed"
                });
            }
            scheduleNextAppUpdateCheck();
        }, 60000);
    };

    // Initial trigger
    scheduleNextUpdate();
    scheduleNextYaraUpdate();
    scheduleNextAppUpdateCheck();

    app.post("/api/settings", async (req, res) => {
        settings = { ...settings, ...req.body };
        await saveConfig(settings);
        await ensureDirs(settings);
        await cleanupOldLogs(settings);
        res.json({ success: true, settings });
        Promise.resolve()
            .then(async () => {
                await checkClamAV(settings);
                await startShield(settings);
                await manageClamd(settings);
                await manageStartup(settings);
                await scheduleDefenderEnforcement(false);
                scheduleNextUpdate();
                scheduleNextYaraUpdate();
                scheduleNextAppUpdateCheck();
            })
            .catch(e => console.error("Failed to apply settings side effects:", e));
    });

    app.post("/api/shield-cache/clear", async (req, res) => {
        shieldScanCache.clear();
        res.json({ success: true, shieldCacheCount: 0 });
    });

    app.post("/api/accept-eula", async (req, res) => {
        settings = { ...settings, eulaAccepted: true };
        await saveConfig(settings);
        res.json({ success: true, settings });
    });

    app.get("/api/system-paths", async (req, res) => {
        try {
            res.json(await getResolvedSystemPaths());
        } catch (e: any) {
            res.status(500).json({ error: e.message || "Failed to resolve system paths." });
        }
    });

    app.get("/api/defender-status", async (req, res) => {
        try {
            res.json(await getDefenderStatus());
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.post("/api/alert-defender", async (req, res) => {
        try {
            const result = await requestDefenderPause();
            res.status(result.Success ? 200 : 409).json({ success: result.Success, ...result });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.post("/api/stop-defender", async (req, res) => {
        try {
            const result = await requestDefenderPause();
            res.status(result.Success ? 200 : 409).json({ success: result.Success, ...result });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.post("/api/restore-defender", async (req, res) => {
        try {
            const result = await restoreDefenderPreferences();
            res.json({ success: result.Success, ...result });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.post("/api/open-windows-security", async (req, res) => {
        try {
            const result = await openWindowsSecurity();
            res.status(result.success ? 200 : 500).json(result);
        } catch (e: any) {
            res.status(500).json({ success: false, error: e.message });
        }
    });

    app.get("/api/history", async (req, res) => {
        res.json(await getHistory());
    });

    app.get("/api/select-folder", async (req, res) => {
        if (process.platform === "win32") {
            const script = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.windows.forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = "Select a Folder (Navigate into the folder and click Open)"
$dialog.ValidateNames = $false
$dialog.CheckFileExists = $false
$dialog.CheckPathExists = $true
$dialog.FileName = "Folder Selection."
$dialog.Filter = "Folders|*.none_such_extension"
if ($dialog.ShowDialog() -eq 'OK') {
    $path = [System.IO.Path]::GetDirectoryName($dialog.FileName)
    if (Test-Path -Path $path -PathType Container) {
        Write-Output $path
    } else {
        Write-Output "Error: Not a folder"
    }
}
`;
            try {
                const encoded = Buffer.from(script, "utf16le").toString("base64");
                const child = spawn("powershell", ["-STA", "-NoProfile", "-EncodedCommand", encoded], { windowsHide: true });
                let output = "";
                let errorOutput = "";
                child.stdout.on("data", data => output += data.toString());
                child.stderr.on("data", data => errorOutput += data.toString());
                child.on("close", () => {
                    const pathStr = output.trim();
                    if (pathStr && path.isAbsolute(pathStr) && !pathStr.startsWith("Error")) {
                        res.json({ path: pathStr });
                    } else {
                        res.status(400).json({ error: pathStr || errorOutput || "No folder selected." });
                    }
                });
            } catch (e: any) {
                res.status(500).json({ error: e.message });
            }
        } else {
            res.json({ path: "" });
        }
    });

    app.get("/api/select-file", async (req, res) => {
        if (process.platform === "win32") {
            const script = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.windows.forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = "Select a File"
$dialog.Filter = "All Files|*.*"
if ($dialog.ShowDialog() -eq 'OK') {
    Write-Output $dialog.FileName
}
`;
            try {
                const encoded = Buffer.from(script, "utf16le").toString("base64");
                const child = spawn("powershell", ["-STA", "-NoProfile", "-EncodedCommand", encoded], { windowsHide: true });
                let output = "";
                let errorOutput = "";
                child.stdout.on("data", data => output += data.toString());
                child.stderr.on("data", data => errorOutput += data.toString());
                child.on("close", () => {
                    const pathStr = output.trim();
                    if (pathStr && path.isAbsolute(pathStr) && !pathStr.startsWith("Error")) {
                        res.json({ path: pathStr });
                    } else {
                        res.status(400).json({ error: pathStr || errorOutput || "No file selected." });
                    }
                });
            } catch (e: any) {
                res.status(500).json({ error: e.message });
            }
        } else {
            res.json({ path: "" });
        }
    });

    app.post("/api/scan", async (req, res) => {
        const { target, type, resumeJobId } = req.body;
        const resumeSession = resumeJobId ? scanSessions.getSession(String(resumeJobId)) : null;
        if (resumeJobId && (!resumeSession || !canResumeScanType(resumeSession.type))) {
            return res.status(404).json({ error: "No resumable scan was found." });
        }
        const isResume = !!resumeSession;
        const scanType = resumeSession?.type || type;
        const scanTarget = resumeSession?.target || (scanType === "memory" ? "Running process images" : (resolveScanTarget(scanType, target) || "C:\\"));
        const effectiveTarget = scanType === "memory" ? undefined : resolveScanTarget(scanType, scanTarget);
        const jobId = resumeSession?.job_id || Date.now().toString();

        if (activeJobs[jobId]?.status === "running") {
            return res.json({ jobId, status: "started", resumed: isResume, progress: activeJobs[jobId].progress || null });
        }

        if (isSimulated) {
            res.json({ jobId, status: "started", simulated: true });
            activeJobs[jobId] = {
                status: "running",
                logs: ["Starting simulated scan..."],
                progress: createInitialScanProgress(jobId, scanType, scanTarget)
            };
            saveJobProgress(jobId, { totalFiles: 1240, phase: "Simulated scan" });
            setTimeout(async () => {
                const isThreat = Math.random() < 0.5 && scanType !== "update";
                let threatsFound = 0;
                let actionTaken = "None";
                if (isThreat) {
                    threatsFound = 1;
                    const filePath = path.join(effectiveTarget || "C:\\TestPath", "eicar.com.txt");
                    await addScanResult({
                        source: "manual",
                        scanType,
                        target: scanTarget,
                        originalPath: filePath,
                        threatName: "Eicar-Test-Signature (Simulated)"
                    });
                    appendJobLogs(jobId, [`Threat found, sent to Results: ${filePath}`]);
                    actionTaken = "Sent to Results";
                }
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = isThreat ? 1 : 0;
                appendJobLogs(jobId, ["Scan completed."]);
                saveJobProgress(jobId, {
                    status: "done",
                    phase: "Complete",
                    scannedFiles: 1240,
                    currentFile: "Complete",
                    completedAt: Date.now(),
                    threatsFound,
                    result: isThreat ? 1 : 0,
                    actionTaken
                });
                await addHistory({
                    type: `scan-${scanType}`,
                    target: scanTarget,
                    result: isThreat ? 1 : 0,
                    threatsFound,
                    scannedFiles: 1240,
                    duration: 3,
                    actionTaken
                });
            }, 3000);
            return;
        }

        try {
            const dbFiles = await fs.readdir(settings.databaseDir);
            const hasDb = dbFiles.some(f => f.endsWith(".cvd") || f.endsWith(".cld"));
            if (!hasDb) {
                return res.status(400).json({ error: "No virus database found. Please go to Updates and download virus definitions first." });
            }
        } catch {
            return res.status(400).json({ error: "Failed to check virus database. Please update definitions." });
        }

        activeJobs[jobId] = {
            status: "running",
            logs: [],
            analysisLogs: [],
            progress: isResume
                ? { ...createInitialScanProgress(jobId, scanType, scanTarget), ...(scanSessionRowToProgress(resumeSession) || {}), status: "running", phase: "Resuming" }
                : createInitialScanProgress(jobId, scanType, scanTarget)
        };
        res.json({ jobId, status: "started", resumed: isResume, progress: activeJobs[jobId].progress || null });

        Promise.resolve().then(async () => {
            saveJobProgress(jobId, { phase: isResume ? "Loading saved scan" : "Enumerating files" });
            let allScanFiles: string[] = [];
            let scanFiles: string[] = [];
            let scannedFiles = 0;

            if (isResume) {
                const fileRows = scanSessions.getFiles(jobId);
                for (const row of fileRows) {
                    allScanFiles.push(row.file_path);
                    const fingerprint = await getFileFingerprint(row.file_path);
                    if (row.status === "done" && fileRecordMatches(row, fingerprint)) {
                        scannedFiles++;
                    } else {
                        scanFiles.push(row.file_path);
                        scanSessions.markFilePending(jobId, row.file_path, fingerprint?.size || 0, fingerprint?.mtimeMs || 0);
                    }
                }
            } else {
                allScanFiles = await enumerateScanTargets(settings, scanType, scanTarget);
                scanFiles = allScanFiles;
                if (canResumeScanType(scanType)) {
                    scanSessions.saveFiles(jobId, await getScanFileRecords(allScanFiles));
                }
            }

            if (allScanFiles.length === 0) {
                appendJobLogs(jobId, ["No readable files found for this scan target."]);
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = 0;
                saveJobProgress(jobId, {
                    status: "done",
                    phase: "No readable files",
                    currentFile: "Complete",
                    completedAt: Date.now(),
                    result: 0
                });
                return;
            }

            saveJobProgress(jobId, {
                phase: isResume ? "Resuming" : "Queued",
                totalFiles: allScanFiles.length,
                scannedFiles,
                currentFile: scanFiles[0] || "Preparing final checks"
            });

            if (scanType === "disk" && process.platform === "win32") {
                appendJobLogs(jobId, [
                    "Skipping Windows locked paging/system files that cannot be opened while Windows is running:",
                    "C:\\pagefile.sys, C:\\swapfile.sys, C:\\hiberfil.sys, C:\\DumpStack.log.tmp"
                ]);
            }
            if (scanType === "memory" && process.platform === "win32") {
                appendJobLogs(jobId, [
                    `Running programs found: ${scanFiles.length}`
                ]);
            }

            let isClamd = false;
            if (settings.offloadToMemory && settings.clamdscanPath) {
                try {
                    await fs.access(settings.clamdscanPath);
                    isClamd = true;
                } catch (e: any) {
                    console.debug("Scan offload requested, but clamdscan is unavailable; falling back to clamscan:", e?.message || e);
                }
            }
            const exePath = isClamd ? settings.clamdscanPath : settings.clamscanPath;
            const chunkSize = getAdaptiveScanBatchSize(scanFiles.length);
            const chunkDelayMs = Math.round(normalizePositiveNumber(settings.scanBatchDelayMs, 0, 0, 60000));
            const chunks = chunkItems(scanFiles, chunkSize);
            let threatsFound = 0;
            let errorsFound = 0;
            let actionTaken = "None";
            const startedAt = Date.now();
            const heartbeat = createScanHeartbeat(jobId, "Scan");
            const exceptions = await getExceptions();

            appendJobLogs(jobId, [
                isResume ? "Resuming interrupted scan..." : (scanType === "memory" ? "Scanning running programs..." : "Scanning selected files..."),
                isResume ? `Files remaining: ${scanFiles.length}` : `Files to scan: ${scanFiles.length}`
            ]);

            const handleFoundLine = async (line: string) => {
                const match = line.match(/^(.*?):\s+(.*?)\s+FOUND$/);
                if (!match) return;
                const originalPath = match[1];
                if (isExcluded(originalPath, exceptions)) {
                    appendJobLogs(jobId, [
                        `Threat found: ${displayFileName(originalPath)}`,
                        "Action: Ignored because it is in Exceptions"
                    ]);
                    return;
                }
                threatsFound++;
                const threatName = match[2];
                const action = settings.scanDetectionAction || "results";
                if (action === "quarantine") {
                    try {
                        const quarantined = await quarantineFile(originalPath, threatName, settings.quarantineDir);
                        const qMap = await getQuarantineMap();
                        qMap[quarantined.fileName] = quarantined.metadata;
                        await saveQuarantineMap(qMap);
                        appendJobLogs(jobId, [
                            `Threat found: ${displayFileName(originalPath)}`,
                            "Action: Quarantined"
                        ]);
                        actionTaken = "Quarantined";
                    } catch (e: any) {
                        appendJobLogs(jobId, [`Quarantine failed for ${displayFileName(originalPath)}: ${e.message}`]);
                        actionTaken = "Quarantine Failed";
                    }
                } else {
                    await addScanResult({
                        source: "manual",
                        scanType,
                        target: scanTarget,
                        originalPath,
                        threatName
                    });
                    appendJobLogs(jobId, [
                        `Threat found: ${displayFileName(originalPath)}`,
                        "Action: Sent to Results"
                    ]);
                    actionTaken = "Sent to Results";
                }
                saveJobProgress(jobId, { threatsFound, actionTaken });
            };

            for (let i = 0; i < chunks.length; i++) {
                const job = activeJobs[jobId];
                if (!job || job.status !== "running") break;
                const chunk = chunks[i];
                const listPath = await createScanFileList(chunk);
                const args = buildClamFileListArgs(settings, isClamd, listPath);
                const chunkLines: string[] = [];
                saveJobProgress(jobId, {
                    phase: `ClamAV batch ${i + 1}/${chunks.length}`,
                    currentFile: chunk[0] || "",
                    scannedFiles,
                    totalFiles: allScanFiles.length
                });
                const code = await new Promise<number>((resolve) => {
                    const child = spawn(exePath, args, { windowsHide: true });
                    activeJobs[jobId].process = child;
                    let lastCurrentFileUpdateAt = 0;
                    const handleEngineLines = (lines: string[]) => {
                        chunkLines.push(...lines);
                        const visibleLines = lines.filter(isImportantClamOutputLine);
                        if (visibleLines.length) appendJobLogs(jobId, visibleLines);
                        const now = Date.now();
                        if (now - lastCurrentFileUpdateAt > 250) {
                            const latestPath = [...lines].reverse().map(parseClamOutputPath).find(Boolean);
                            if (latestPath) {
                                lastCurrentFileUpdateAt = now;
                                saveJobProgress(jobId, { currentFile: latestPath });
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
                        appendJobLogs(jobId, [`Process error: ${error.message}`]);
                        resolve(-1);
                    });
                    child.on("close", closeCode => resolve(closeCode ?? 0));
                });
                await fs.unlink(listPath).catch(() => {});
                if (activeJobs[jobId]?.process) activeJobs[jobId].process = null;
                if (activeJobs[jobId]?.status !== "running") {
                    break;
                }

                let suppressedCleanLines = 0;
                let suppressedFileWarningLines = 0;
                for (const line of chunkLines) {
                    if (line.includes(" FOUND")) await handleFoundLine(line);
                    else if (isNoisyClamFileLine(line)) {
                        if (line.includes(" ERROR") || line.startsWith("WARNING:")) {
                            errorsFound++;
                            suppressedFileWarningLines++;
                        } else {
                            suppressedCleanLines++;
                        }
                    } else if (line.includes(" ERROR") || line.startsWith("WARNING:")) {
                        errorsFound++;
                    }
                }
                if (suppressedCleanLines > 0 || suppressedFileWarningLines > 0) {
                    appendJobLogs(jobId, [
                        `Batch ${i + 1}/${chunks.length} complete.`
                    ]);
                }
                if (canResumeScanType(scanType)) {
                    scanSessions.markFilesDone(jobId, await getScanFileRecords(chunk));
                }
                scannedFiles += chunk.length;
                saveJobProgress(jobId, {
                    scannedFiles,
                    errorsFound,
                    currentFile: chunk[chunk.length - 1] || "",
                    phase: `ClamAV batch ${i + 1}/${chunks.length}`,
                    result: code
                });
                if (chunkDelayMs > 0 && i < chunks.length - 1) await sleep(chunkDelayMs);
            }
            clearInterval(heartbeat);
            if (activeJobs[jobId]?.status !== "running") {
                return;
            }

            if (activeJobs[jobId]?.status === "running") {
                saveJobProgress(jobId, { phase: "YARA scan", currentFile: "" });
                const yaraTargets = scanType === "memory" ? scanFiles : (effectiveTarget ? [effectiveTarget] : []);
                const yaraResult = await runYaraScanForTargets(settings, yaraTargets, {
                    activeJobs,
                    appendJobLogs,
                    jobId,
                    source: "manual",
                    scanType,
                    target: scanTarget,
                    action: settings.scanDetectionAction || "results"
                });
                if (yaraResult.matches > 0) {
                    threatsFound += yaraResult.matches;
                    actionTaken = yaraResult.actionTaken;
                    saveJobProgress(jobId, { threatsFound, actionTaken });
                }
            }

            const isThreat = threatsFound > 0;
            const duration = Math.max(1, Math.round((Date.now() - startedAt) / 1000));
            appendJobLogs(jobId, [isThreat ? "Scan complete: detections found" : "Scan complete: no active threats found"]);
            await addHistory({
                type: `scan-${scanType}`,
                target: scanTarget,
                result: isThreat ? 1 : 0,
                threatsFound,
                scannedFiles,
                duration,
                actionTaken: isThreat ? actionTaken : "None"
            });

            if ((scanType === "disk" || scanType === "folder" || scanType === "file") && effectiveTarget) {
                saveJobProgress(jobId, { phase: "Building shield cache", currentFile: "" });
                appendJobLogs(jobId, ["Updating real-time protection cache..."]);
                try {
                    const cachedCount = await addTargetToShieldCache(shieldScanCache, effectiveTarget, (count) => {
                        console.debug(`Shield cache indexed: ${count} files`);
                    });
                    appendJobLogs(jobId, [`Protection cache updated: ${cachedCount} files`]);
                } catch (e: any) {
                    appendJobLogs(jobId, [`Protection cache update failed: ${e.message}`]);
                }
            }

            activeJobs[jobId].status = "done";
            activeJobs[jobId].result = isThreat ? 1 : 0;
            activeJobs[jobId].process = null;
            saveJobProgress(jobId, {
                status: "done",
                phase: "Complete",
                currentFile: "Complete",
                completedAt: Date.now(),
                result: isThreat ? 1 : 0,
                scannedFiles,
                threatsFound,
                errorsFound,
                actionTaken: isThreat ? actionTaken : "None"
            });
        }).catch(e => {
            const job = activeJobs[jobId];
            if (!job) return;
            appendJobLogs(jobId, [`Error: ${e.message}`]);
            const resumable = canResumeScanType(scanType);
            job.status = "done";
            job.result = -1;
            job.process = null;
            saveJobProgress(jobId, {
                status: resumable ? "error" : "done",
                phase: resumable ? "Interrupted by error" : "Error",
                currentFile: "Error",
                completedAt: resumable ? undefined : Date.now(),
                result: -1
            });
        });
    });

    app.post("/api/scan-legacy", async (req, res) => {
        const { target, type } = req.body;
        const effectiveTarget = resolveScanTarget(type, target);
        const jobId = Date.now().toString();
        // type could be 'file', 'folder', 'disk', 'memory'
        
        if (isSimulated) {
            // Simulated scan
            res.json({ jobId, status: "started", simulated: true });
            
            activeJobs[jobId] = { status: "running", logs: [] };
            appendJobLogs(jobId, ["Starting simulated scan..."]);
            
            // Simulate run
            setTimeout(async () => {
                const isThreat = Math.random() < 0.5 && type !== 'update';
                let threatsFound = 0;
                let actionTaken = "None";
                
                if (isThreat) {
                    threatsFound = 1;
                    const testPath = effectiveTarget || "C:\\TestPath";
                    const filePath = path.join(testPath, "eicar.com.txt");
                    appendJobLogs(jobId, [`FOUND: ${filePath}: Eicar-Test-Signature`]);
                    
                    const action = settings.scanDetectionAction || "results";
                    if (action === "quarantine") {
                        appendJobLogs(jobId, [`Quarantined: ${filePath}`]);
                        actionTaken = "Quarantined";
                    } else {
                        await addScanResult({
                            source: "manual",
                            scanType: type,
                            target: effectiveTarget || "C:\\",
                            originalPath: filePath,
                            threatName: "Eicar-Test-Signature (Simulated)"
                        });
                        appendJobLogs(jobId, [`Threat found, sent to Results: ${filePath}`]);
                        actionTaken = "Sent to Results";
                    }
                }
                
                appendJobLogs(jobId, ["Scan completed."]);
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = isThreat ? 1 : 0;
                broadcastJobEvent(jobId);
                
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
            const dbFiles = await fs.readdir(settings.databaseDir);
            const hasDb = dbFiles.some(f => f.endsWith('.cvd') || f.endsWith('.cld'));
            if (!hasDb) {
                return res.status(400).json({ error: "No virus database found. Please go to Updates and download virus definitions first." });
            }
        } catch (e) {
            return res.status(400).json({ error: "Failed to check virus database. Please update definitions." });
        }

        let memoryFileListPath: string | null = null;
        let memoryProcessCount = 0;
        let memoryYaraTargets: string[] = [];
        let scanTarget = effectiveTarget;
        if (type === "memory" && process.platform === "win32") {
            const processPaths = await getRunningProcessImagePaths();
            memoryProcessCount = processPaths.length;
            memoryYaraTargets = processPaths;
            if (processPaths.length === 0) {
                return res.status(400).json({ error: "No readable running process executable paths were found." });
            }
            memoryFileListPath = await createScanFileList(processPaths);
            scanTarget = memoryFileListPath;
        }

        let isClamd = false;
        if (type !== "memory" && settings.offloadToMemory && settings.clamdscanPath) {
            try {
                await fs.access(settings.clamdscanPath);
                isClamd = true;
            } catch (e: any) {
                console.debug("Legacy scan offload requested, but clamdscan is unavailable; falling back to clamscan:", e?.message || e);
            }
        }
        let exePath = isClamd ? settings.clamdscanPath : settings.clamscanPath;
        let args = buildClamScanArgs(settings, isClamd, type, scanTarget);
        
        try {
            activeJobs[jobId] = { status: "running", logs: [], analysisLogs: [] };
            if (type === "disk" && process.platform === "win32") {
                appendJobLogs(jobId, [
                    "Skipping Windows locked paging/system files that cannot be opened while Windows is running:",
                    "C:\\pagefile.sys, C:\\swapfile.sys, C:\\hiberfil.sys, C:\\DumpStack.log.tmp"
                ]);
            }
            if (type === "memory" && process.platform === "win32") {
                appendJobLogs(jobId, [
                    `Running programs found: ${memoryProcessCount}`,
                    "Scanning running programs..."
                ]);
            }
            appendJobLogs(jobId, [
                type === "memory" ? "Checking running programs..." : "Checking selected files..."
            ]);
            console.debug(`Legacy scan target: ${type === "memory" ? "Running process images" : (effectiveTarget || scanTarget || "Default target")}`);
            console.debug(`Legacy scan engine: ${isClamd ? "clamdscan/offload to RAM" : "clamscan/direct"}`);
            console.debug(`Legacy scan executable: ${exePath}`);
            console.debug(`Legacy scan arguments: ${args.join(" ")}`);
            const heartbeat = createScanHeartbeat(jobId, "Scan");
            const child = spawn(exePath, args, { windowsHide: true });
            activeJobs[jobId].process = child;
            
            child.on("error", (err: any) => {
                clearInterval(heartbeat);
                console.error("Failed to start manual scan process:", err.message);
                    if (memoryFileListPath) {
                        fs.unlink(memoryFileListPath).catch(() => {});
                    }
                    if (activeJobs[jobId]) {
                        activeJobs[jobId].status = "error";
                        appendJobLogs(jobId, ["Process error: " + err.message]);
                    }
                });

                child.stdout.on("data", (data) => {
                    const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                    appendJobLogs(jobId, lines);
                });
                
                child.stderr.on("data", (data) => {
                    const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                    appendJobLogs(jobId, lines);
                });
            
            child.on("close", async (code) => {
                clearInterval(heartbeat);
                if (!activeJobs[jobId]) return;
                
                let scannedFiles = 0;
                let threatsFound = 0;
                let duration = 0;
                
                const qMap = await getQuarantineMap();
                const exceptions = await getExceptions();
                let quarantineMapChanged = false;
                let actionTaken = "None";

                for (const line of activeJobs[jobId].analysisLogs || []) {
                    if (line.includes(" FOUND")) {
                        const match = line.match(/^(.*?):\s+(.*?)\s+FOUND$/);
                        if (match) {
                            const originalPath = match[1];
                            if (isExcluded(originalPath, exceptions)) {
                                appendJobLogs(jobId, [`Ignored (Exception): ${originalPath}`]);
                                continue;
                            }
                            const threatName = match[2];
                            const action = settings.scanDetectionAction || "results";
                            if (action === "quarantine") {
                                try {
                                    const quarantined = await quarantineFile(originalPath, threatName, settings.quarantineDir);
                                    qMap[quarantined.fileName] = quarantined.metadata;
                                    quarantineMapChanged = true;
                                    appendJobLogs(jobId, [`Quarantined: ${originalPath} -> ${quarantined.destPath}`]);
                                    actionTaken = "Quarantined";
                                } catch (e: any) {
                                    appendJobLogs(jobId, [`Failed to quarantine ${originalPath}: ${e.message}`]);
                                    actionTaken = "Quarantine Failed";
                                }
                            } else {
                                await addScanResult({
                                    source: "manual",
                                    scanType: type,
                                    target: type === "memory" ? "Running process images" : (effectiveTarget || "C:\\"),
                                    originalPath,
                                    threatName
                                });
                                appendJobLogs(jobId, [`Threat found, sent to Results: ${originalPath}`]);
                                actionTaken = "Sent to Results";
                            }
                        }
                    }
                    if (line.startsWith("Scanned files:")) {
                        const m = line.match(/\d+/);
                        if (m) scannedFiles = parseInt(m[0], 10);
                    }
                    if (line.startsWith("Infected files:")) {
                        const m = line.match(/\d+/);
                        if (m) threatsFound = parseInt(m[0], 10);
                    }
                    if (line.startsWith("Time:")) {
                        const m = line.match(/(\d+\.\d+) sec/);
                        if (m) duration = Math.round(parseFloat(m[1]));
                    }
                }
                
                if (quarantineMapChanged) {
                    await saveQuarantineMap(qMap);
                }
                if (memoryFileListPath) {
                    await fs.unlink(memoryFileListPath).catch(() => {});
                }

                const yaraTargets = type === "memory"
                    ? memoryYaraTargets
                    : (effectiveTarget ? [effectiveTarget] : []);
                const yaraResult = await runYaraScanForTargets(settings, yaraTargets, {
                    activeJobs,
                    appendJobLogs,
                    jobId,
                    source: "manual",
                    scanType: type,
                    target: type === "memory" ? "Running process images" : (effectiveTarget || "C:\\"),
                    action: settings.scanDetectionAction || "results"
                });
                if (yaraResult.matches > 0) {
                    threatsFound += yaraResult.matches;
                    actionTaken = yaraResult.actionTaken;
                }

                const isThreat = code === 1 || threatsFound > 0;
                const exitSummary = code === 1
                    ? "Scan finished with exit code 1 (threats were found)."
                    : `Scan finished with exit code ${code ?? "unknown"}.`;
                appendJobLogs(jobId, [exitSummary]);
                await addHistory({
                    type: `scan-${type}`,
                    target: type === "memory" ? "Running process images" : (effectiveTarget || "C:\\"),
                    result: isThreat ? 1 : 0,
                    threatsFound,
                    scannedFiles: type === "memory" && scannedFiles === 0 ? memoryProcessCount : scannedFiles, 
                    duration,
                    actionTaken: isThreat ? actionTaken : "None"
                });

                if ((type === "disk" || type === "folder" || type === "file") && effectiveTarget) {
                    appendJobLogs(jobId, ["Building real-time shield cache for this scan target..."]);
                    try {
                        const cachedCount = await addTargetToShieldCache(shieldScanCache, effectiveTarget, (count) => {
                            appendJobLogs(jobId, [`Shield cache indexed: ${count} files`]);
                        });
                        appendJobLogs(jobId, [`Shield cache updated: ${cachedCount} files indexed`]);
                    } catch (e: any) {
                        appendJobLogs(jobId, [`Shield cache update failed: ${e.message}`]);
                    }
                }

                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = code ?? 0;
                activeJobs[jobId].process = null;
            });

            child.on("error", (err) => {
                clearInterval(heartbeat);
                if (!activeJobs[jobId]) return;
                if (memoryFileListPath) {
                    fs.unlink(memoryFileListPath).catch(() => {});
                }
                appendJobLogs(jobId, [`Error: ${err.message}`]);
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = -1;
                activeJobs[jobId].process = null;
            });
            
            res.json({ jobId, status: "started" });
        } catch (e: any) {
            if (memoryFileListPath) {
                await fs.unlink(memoryFileListPath).catch(() => {});
            }
            res.status(500).json({ error: e.message });
        }
    });

    app.get("/api/scan/resumable", (req, res) => {
        try {
            const row = scanSessions.getLatestResumable();
            const progress = scanSessionRowToProgress(row);
            res.json({ available: !!progress, progress });
        } catch (e: any) {
            res.status(500).json({ error: e.message || "Failed to load resumable scan." });
        }
    });

    app.post("/api/scan/:jobId/discard", (req, res) => {
        try {
            const job = activeJobs[req.params.jobId];
            if (job?.process) job.process.kill();
            if (job) job.status = "done";
            scanSessions.discard(req.params.jobId);
            broadcastJobEvent(req.params.jobId, ["Interrupted scan discarded."]);
            res.json({ success: true });
        } catch (e: any) {
            res.status(500).json({ error: e.message || "Failed to discard scan." });
        }
    });

    app.get("/api/scan/:jobId/events", (req, res) => {
        const jobId = req.params.jobId;
        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache, no-transform");
        res.setHeader("Connection", "keep-alive");
        res.flushHeaders?.();
        let clients = jobEventClients.get(jobId);
        if (!clients) {
            clients = new Set<express.Response>();
            jobEventClients.set(jobId, clients);
        }
        clients.add(res);
        const job = activeJobs[jobId];
        sendJobEventToClient(res, {
            status: job?.status || "missing",
            logs: job?.logs || [],
            progress: job?.progress || null,
            result: job?.result
        });
        const keepAlive = setInterval(() => {
            try {
                res.write(":keepalive\n\n");
            } catch {
                clearInterval(keepAlive);
                clients?.delete(res);
            }
        }, 25000);
        keepAlive.unref?.();
        req.on("close", () => {
            clearInterval(keepAlive);
            clients?.delete(res);
            if (clients && clients.size === 0) jobEventClients.delete(jobId);
        });
    });

    app.get("/api/scan/:jobId", (req, res) => {
        const job = activeJobs[req.params.jobId];
        if (!job) {
            return res.status(404).json({ error: "Job not found" });
        }
        res.json({
            status: job.status,
            logs: job.logs,
            result: job.result,
            progress: job.progress || null
        });
        // Clear logs after sending them so we don't accumulate too much
        job.logs = [];
    });

    app.post("/api/scan/:jobId/cancel", (req, res) => {
        const job = activeJobs[req.params.jobId];
        if (job) {
            const resumable = canResumeScanType(job.progress?.type || "");
            if (job.process) {
                job.process.kill();
            }
            job.status = "done";
            saveJobProgress(req.params.jobId, {
                status: resumable ? "paused" : "done",
                phase: resumable ? "Paused" : "Cancelled",
                currentFile: resumable ? "Paused" : "Cancelled",
                completedAt: resumable ? undefined : Date.now(),
                result: -1,
                actionTaken: resumable ? "Paused" : "Cancelled"
            });
            appendJobLogs(req.params.jobId, [resumable ? "Scan paused. You can resume it later." : "Scan cancelled by user."]);
            broadcastJobEvent(req.params.jobId);
            res.json({ status: resumable ? "paused" : "cancelled" });
        } else {
            res.status(404).json({ error: "Job not found" });
        }
    });

    app.post("/api/update", async (req, res) => {
        const jobId = Date.now().toString();
        if (isSimulated) {
            setTimeout(async () => {
                await addHistory({
                    type: "update",
                    target: "Databases",
                    result: 0,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: 2,
                    actionTaken: "Updated"
                });
            }, 2000);
            return res.json({ jobId, status: "started", simulated: true });
        }

        try {
            activeJobs[jobId] = { status: "running", logs: [] };
            if (!await pathExists(settings.freshclamPath)) {
                throw new Error(`FreshClam executable was not found at ${settings.freshclamPath}. Reinstall the ClamAV engine from the setup wizard.`);
            }
            appendJobLogs(jobId, ["Preparing FreshClam configuration..."]);
            await ensureFreshclamConfig(settings);
            await saveConfig(settings);

            const args = ["--config-file=" + settings.freshclamConf, "--datadir=" + settings.databaseDir];
            appendJobLogs(jobId, ["Downloading ClamAV virus definitions..."]);
            const child = spawn(settings.freshclamPath, args, { windowsHide: true });
            activeJobs[jobId].process = child;
            let processStartFailed = false;
            
            child.on("error", (err: any) => {
                processStartFailed = true;
                console.error("Failed to start freshclam process:", err.message);
                if (activeJobs[jobId]) {
                    activeJobs[jobId].status = "done";
                    activeJobs[jobId].result = -1;
                    activeJobs[jobId].process = null;
                    appendJobLogs(jobId, ["Process error: " + err.message]);
                    broadcastJobEvent(jobId);
                }
            });

            child.stdout.on("data", (data) => {
                const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                if (lines.length) appendJobLogs(jobId, lines);
            });
            
            child.stderr.on("data", (data) => {
                const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                if (lines.length) appendJobLogs(jobId, lines);
            });
            
            child.on("close", async (code) => {
                if (!activeJobs[jobId]) return;
                if (processStartFailed) return;
                if (code === 0) {
                    appendJobLogs(jobId, ["Virus definitions updated successfully."]);
                } else {
                    appendJobLogs(jobId, [
                        `FreshClam failed with exit code ${code ?? "unknown"}.`,
                        "Check your internet connection, firewall, proxy, or ClamAV mirror access."
                    ]);
                }
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = code ?? 0;
                activeJobs[jobId].process = null;
                broadcastJobEvent(jobId);
                
                await addHistory({
                    type: "update",
                    target: "Databases",
                    result: code === 0 ? 0 : 1,
                    threatsFound: 0,
                    scannedFiles: 0,
                    duration: 1, 
                    actionTaken: code === 0 ? "Updated" : "Failed"
                });
            });

            res.json({ jobId, status: "started" });
        } catch(e: any) {
            if (activeJobs[jobId]) {
                appendJobLogs(jobId, [`Error: ${e.message}`]);
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = -1;
                broadcastJobEvent(jobId);
            }
            res.status(500).json({ error: e.message });
        }
    });

    app.post("/api/update-yara", async (req, res) => {
        const jobId = "yara-update-" + Date.now().toString();
        const requestedRuleset = normalizeYaraRuleset(req.body?.ruleset || settings.yaraRuleset);
        if (requestedRuleset !== settings.yaraRuleset) {
            settings = { ...settings, yaraRuleset: requestedRuleset };
            await saveConfig(settings);
        }
        activeJobs[jobId] = { status: "running", logs: [] };
        res.json({ jobId, status: "started" });

        const startedAt = Date.now();
        try {
            appendJobLogs(jobId, [`Updating YARA Forge ${normalizeYaraRuleset(settings.yaraRuleset)} rules...`]);
            const result = await updateYaraForgeRules(settings, message => {
                if (activeJobs[jobId]) appendJobLogs(jobId, [message]);
            });
            if (!activeJobs[jobId]) return;
            appendJobLogs(jobId, [`YARA update complete: ${result.ruleCount} rules loaded.`]);
            activeJobs[jobId].status = "done";
            activeJobs[jobId].result = 0;
            broadcastJobEvent(jobId);
            await addHistory({
                type: "yara-update",
                target: `YARA Forge ${result.ruleset}`,
                result: 0,
                threatsFound: 0,
                scannedFiles: result.ruleCount,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: "Updated"
            });
        } catch (e: any) {
            console.error("YARA update failed:", e.message);
            if (activeJobs[jobId]) {
                appendJobLogs(jobId, [`Error: ${e.message}`]);
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = 1;
                broadcastJobEvent(jobId);
            }
            await addHistory({
                type: "yara-update",
                target: `YARA Forge ${normalizeYaraRuleset(settings.yaraRuleset)}`,
                result: 1,
                threatsFound: 0,
                scannedFiles: 0,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: "Failed"
            });
        }
    });

    app.get("/api/app-update", async (req, res) => {
        try {
            res.json(await getLatestClamShieldRelease(settings));
        } catch (e: any) {
            res.status(500).json({ error: e.message || "Failed to check for ClamShield updates." });
        }
    });

    app.post("/api/app-update/skip", async (req, res) => {
        try {
            const version = normalizeVersion(req.body?.version || "");
            if (!version || version === "0.0.0") {
                return res.status(400).json({ error: "Missing version to skip." });
            }
            settings = { ...settings, skippedAppVersion: version };
            await saveConfig(settings);
            res.json({ success: true, skippedAppVersion: version });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.post("/api/app-update/disable", async (req, res) => {
        try {
            settings = { ...settings, appUpdateCheckEnabled: false };
            await saveConfig(settings);
            scheduleNextAppUpdateCheck();
            res.json({ success: true, settings });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.post("/api/app-update/install", async (req, res) => {
        const jobId = "app-update-" + Date.now().toString();
        activeJobs[jobId] = { status: "running", logs: [] };
        res.json({ jobId, status: "started" });

        const startedAt = Date.now();
        try {
            const result = await downloadAndLaunchClamShieldInstaller(settings, message => {
                if (activeJobs[jobId]) appendJobLogs(jobId, [message]);
            });
            if (!activeJobs[jobId]) return;
            appendJobLogs(jobId, [result.launched
                ? "ClamShield installer launched. The app will close so the update can replace files."
                : "No newer ClamShield version is available."]);
            activeJobs[jobId].status = "done";
            activeJobs[jobId].result = 0;
            broadcastJobEvent(jobId);
            await addHistory({
                type: "app-update-install",
                target: `ClamShield ${result.latestVersion || ""}`.trim(),
                result: 0,
                threatsFound: 0,
                scannedFiles: 0,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: result.launched ? "Installer launched" : "No update"
            });
            if (result.launched) {
                const timer = setTimeout(() => process.exit(0), 1500);
                timer.unref?.();
            }
        } catch (e: any) {
            console.error("ClamShield app update install failed:", e.message);
            if (activeJobs[jobId]) {
                appendJobLogs(jobId, [`Error: ${e.message}`]);
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = 1;
                broadcastJobEvent(jobId);
            }
            await addHistory({
                type: "app-update-install",
                target: "ClamShield",
                result: 1,
                threatsFound: 0,
                scannedFiles: 0,
                duration: Math.max(1, Math.round((Date.now() - startedAt) / 1000)),
                actionTaken: "Failed"
            });
        }
    });

    app.get("/api/results", async (req, res) => {
        const results = await getScanResults();
        res.json(results.map((result: any) => ({
            ...result,
            available: Boolean(result.originalPath && existsSync(result.originalPath))
        })));
    });

    app.post("/api/results/quarantine-all", async (req, res) => {
        const results = await getScanResults();
        const remaining: any[] = [];
        const errors: any[] = [];
        let quarantinedCount = 0;
        let removedUnavailableCount = 0;

        for (const result of results) {
            if (!result.originalPath || !existsSync(result.originalPath)) {
                removedUnavailableCount++;
                continue;
            }
            try {
                await quarantineResultItem(settings, result);
                quarantinedCount++;
            } catch (e: any) {
                remaining.push(result);
                errors.push({ id: result.id, path: result.originalPath, error: e.message });
            }
        }

        await saveScanResults(remaining);
        await addHistory({
            type: "results-quarantine-all",
            target: "Scan Results",
            result: errors.length === 0 ? 0 : 1,
            threatsFound: quarantinedCount,
            scannedFiles: results.length,
            duration: 0,
            actionTaken: `Quarantined ${quarantinedCount} result${quarantinedCount === 1 ? "" : "s"}`
        });
        res.status(errors.length === 0 ? 200 : 207).json({
            success: errors.length === 0,
            quarantinedCount,
            removedUnavailableCount,
            errors
        });
    });

    app.post("/api/results/clear-missing", async (req, res) => {
        const results = await getScanResults();
        const remaining = results.filter((result: any) => result.originalPath && existsSync(result.originalPath));
        const removedCount = results.length - remaining.length;
        await saveScanResults(remaining);
        res.json({ success: true, removedCount });
    });

    app.get("/api/results-reminder", async (req, res) => {
        res.json(await getResultsReminderPayload());
    });

    app.post("/api/results-reminder/action", async (req, res) => {
        const action = req.body.action;
        const results = await getScanResults();
        const latestTimestamp = results.length ? Math.max(...results.map((item: any) => Number(item.timestamp || 0))) : 0;
        const state = await getResultsReminderState();
        if (action === "remind-10") {
            state.remindUntil = Date.now() + 10 * 60 * 1000;
        } else if (action === "remind-60") {
            state.remindUntil = Date.now() + 60 * 60 * 1000;
        } else if (action === "forget") {
            state.forgottenUntil = latestTimestamp;
            state.remindUntil = 0;
        } else if (action === "open") {
            state.remindUntil = Date.now() + 10 * 60 * 1000;
        } else {
            return res.status(400).json({ success: false, error: "Invalid reminder action." });
        }
        await saveResultsReminderState(state);
        res.json({ success: true, openResults: action === "open" });
    });

    app.post("/api/results/:id/action", async (req, res) => {
        try {
            const action = req.body.action;
            if (action !== "quarantine" && action !== "exception") {
                return res.status(400).json({ success: false, error: "Invalid action." });
            }

            const results = await getScanResults();
            const result = results.find((item: any) => item.id === req.params.id);
            if (!result) {
                throw new Error("Result not found.");
            }
            if (action === "quarantine") {
                const quarantined = await quarantineResultItem(settings, result);
                await saveScanResults(results.filter((item: any) => item.id !== req.params.id));
                await addHistory({
                    type: "results-quarantine",
                    target: result.originalPath,
                    result: 0,
                    threatsFound: 1,
                    scannedFiles: 1,
                    duration: 0,
                    actionTaken: "Quarantined from Results"
                });
                return res.json({ success: true, quarantined });
            }

            const exceptions = await getExceptions();
            if (!exceptions.includes(result.originalPath)) {
                exceptions.push(result.originalPath);
                await saveExceptions(exceptions);
            }
            await saveScanResults(results.filter((item: any) => item.id !== req.params.id));
            await addHistory({
                type: "results-exception",
                target: result.originalPath,
                result: 0,
                threatsFound: 0,
                scannedFiles: 1,
                duration: 0,
                actionTaken: "Added to exceptions from Results"
            });
            res.json({ success: true });
        } catch (e: any) {
            res.status(400).json({ success: false, error: e.message });
        }
    });

    app.get("/api/pending-threats", (req, res) => {
        res.json(pendingThreats);
    });

    app.post("/api/simulate-threat", (req, res) => {
        const pendingThreat = {
            id: Date.now().toString() + Math.random().toString(36).substring(7),
            originalPath: "C:\\TestPath\\fake-virus.exe",
            threatName: "Win32.Test.SimulatedThreat.A",
            timestamp: Date.now()
        };
        pendingThreats.push(pendingThreat);
        if (pendingThreatHandler) pendingThreatHandler(pendingThreat);
        res.json({ success: true });
    });

    app.post("/api/pending-threats/:id/action", async (req, res) => {
        const threatId = req.params.id;
        const action = req.body.action; // "quarantine" | "ignore"
        const index = pendingThreats.findIndex(t => t.id === threatId);
        
        if (index === -1) {
            return res.json({ success: false, error: "Threat not found" });
        }
        
        const threat = pendingThreats[index];
        pendingThreats.splice(index, 1);
        
        if (action === "quarantine") {
            try {
                const quarantined = await quarantineFile(threat.originalPath, threat.threatName, settings.quarantineDir);
                const qMap = await getQuarantineMap();
                qMap[quarantined.fileName] = quarantined.metadata;
                await saveQuarantineMap(qMap);
            } catch (e: any) {
                console.error("Failed to quarantine from pending:", e.message);
            }
        } else if (action === "exception") {
            const exceptions = await getExceptions();
            if (!exceptions.includes(threat.originalPath)) {
                exceptions.push(threat.originalPath);
                await saveExceptions(exceptions);
            }
        } else if (action === "results") {
            await addScanResult({
                source: "shield",
                scanType: "shield",
                target: threat.originalPath,
                originalPath: threat.originalPath,
                threatName: threat.threatName,
                engine: threat.engine || (String(threat.threatName || "").startsWith("YARA:") ? "YARA" : "ClamAV"),
                yaraRuleset: threat.engine === "YARA" ? normalizeYaraRuleset(settings.yaraRuleset) : undefined
            });
        }
        res.json({ success: true });
    });

    app.post("/api/empty-quarantine", async (req, res) => {
        try {
            const files = await fs.readdir(settings.quarantineDir);
            for (const file of files) {
                try {
                    await fs.unlink(path.join(settings.quarantineDir, file));
                } catch (e) {
                    console.error("Cannot delete quarantine file:", file);
                }
            }
            await saveQuarantineMap({});
            res.json({ success: true });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.get("/api/exceptions", async (req, res) => {
        try {
            res.json(await getExceptions());
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.post("/api/exceptions", async (req, res) => {
        try {
            const list = req.body.exceptions;
            if (Array.isArray(list)) {
                await saveExceptions(list);
                res.json({ success: true });
            } else {
                res.status(400).json({ error: "Invalid array" });
            }
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.get("/api/quarantine", async (req, res) => {
        try {
            res.json(await getQuarantineItems(settings.quarantineDir));
        } catch (e: any) {
            console.error("Error reading quarantine dir:", e);
            res.status(500).json({ error: e.message, items: [] });
        }
    });

    app.post("/api/quarantine/:fileName/restore-exception", async (req, res) => {
        try {
            const result = await restoreQuarantinedFileAndAddException(settings, req.params.fileName);
            res.json({ success: true, ...result });
        } catch (e: any) {
            res.status(400).json({ success: false, error: e.message });
        }
    });

    app.get("/api/open-quarantine", async (req, res) => {
        try {
            if (process.platform === 'win32') {
                exec(`explorer "${settings.quarantineDir}"`);
            } else if (process.platform === 'darwin') {
                exec(`open "${settings.quarantineDir}"`);
            } else {
                exec(`xdg-open "${settings.quarantineDir}"`);
            }
            res.json({ success: true });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.get('/alert.html', (req, res) => {
        const isProd = process.env.NODE_ENV === "production";
        const alertPath = isProd 
            ? path.join(runtimeDir, "..", "public", "alert.html") 
            : path.join(runtimeDir, "public", "alert.html");
            
        if (existsSync(alertPath)) {
            res.sendFile(alertPath);
        } else {
            res.status(404).send("Alert not found");
        }
    });

    app.get('/results-reminder.html', (req, res) => {
        const isProd = process.env.NODE_ENV === "production";
        const reminderPath = isProd
            ? path.join(runtimeDir, "..", "public", "results-reminder.html")
            : path.join(runtimeDir, "public", "results-reminder.html");

        if (existsSync(reminderPath)) {
            res.sendFile(reminderPath);
        } else {
            res.status(404).send("Reminder not found");
        }
    });

    // Vite Middleware for Frontend
    if (process.env.NODE_ENV !== "production") {
        const { createServer: createViteServer } = await import("vite");
        const vite = await createViteServer({
            server: { middlewareMode: true },
            appType: "spa"
        });
        app.use(vite.middlewares);
    } else {
        const distPath = path.join(runtimeDir);
        app.use(express.static(distPath));
        app.get("*", (req, res) => res.sendFile(path.join(distPath, "index.html")));
    }

    const PORT = process.env.PORT || 3000;
    app.listen(Number(PORT), "127.0.0.1", () => {
        console.log(`Server running on http://127.0.0.1:${PORT} (Simulated: ${isSimulated})`);
    });
}

startServer();
