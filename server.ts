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
    writeAppLog("server.log", "warn", args);
};
console.error = (...args: any[]) => {
    originalConsole.error(...args);
    writeAppLog("server.log", "error", args);
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
    runOnStartup: true,
    startMinimized: false,
    eulaAccepted: false,
    playSoundOnAlert: false,
    enableDebugLog: false,
    logRetentionDays: 7,
    autoDisableDefender: true,
    defenderEnforceIntervalMinutes: 5
};

const apiSessionToken = randomBytes(32).toString("hex");
const apiCookieName = "clamshield_session";

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

async function requestDefenderPause() {
    if (process.platform !== "win32") return { Supported: false, Success: false, Error: "Only supported on Windows." };
    return runPowerShellJson(defenderDisableScript());
}

async function restoreDefenderPreferences() {
    if (process.platform !== "win32") return { Supported: false, Success: false, Error: "Only supported on Windows." };
    return runPowerShellJson(defenderRestoreScript());
}

async function autoDisableDefender() {
    try {
        const result = await requestDefenderPause();
        if (!result.Success) {
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
    if (!req.path.startsWith("/api") || req.method === "GET") return next();
    if (readCookie(req, apiCookieName) === apiSessionToken) return next();
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

function buildClamdConfContent(settings: any) {
    const lines = [
        `DatabaseDirectory ${settings.databaseDir}`,
        "TCPAddr 127.0.0.1",
        "TCPSocket 3310",
        `LogFile ${path.join(settings.logsDir, "clamd.log")}`
    ];
    [settings.yaraCacheDir, settings.yaraRulesDir, settings.yaraCustomRulesDir]
        .filter(Boolean)
        .forEach((folderPath: string) => lines.push(`ExcludePath ${pathToClamExcludePattern(folderPath)}`));
    return `${lines.join("\n")}\n`;
}

async function ensureClamdConfExclusions(settings: any) {
    if (!settings.clamdConf) return;
    try {
        let content = "";
        try {
            content = await fs.readFile(settings.clamdConf, "utf8");
        } catch {
            await fs.writeFile(settings.clamdConf, buildClamdConfContent(settings));
            return;
        }
        const missing = [settings.yaraCacheDir, settings.yaraRulesDir, settings.yaraCustomRulesDir]
            .filter(Boolean)
            .map((folderPath: string) => `ExcludePath ${pathToClamExcludePattern(folderPath)}`)
            .filter((line: string) => !content.includes(line));
        if (missing.length > 0) {
            await fs.appendFile(settings.clamdConf, `\n${missing.join("\n")}\n`);
        }
    } catch (e) {
        console.warn("Failed to ensure clamd YARA exclusions:", e);
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
        if (scanSettings.yaraCacheDir) args.push(`--exclude=${pathToClamExcludePattern(scanSettings.yaraCacheDir)}`);
        if (scanSettings.yaraRulesDir) args.push(`--exclude=${pathToClamExcludePattern(scanSettings.yaraRulesDir)}`);
        if (scanSettings.yaraCustomRulesDir) args.push(`--exclude=${pathToClamExcludePattern(scanSettings.yaraCustomRulesDir)}`);
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
        fileName: "yara-forge-rules-core.yar"
    },
    extended: {
        label: "Extended",
        url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
        fileName: "yara-forge-rules-extended.yar"
    },
    full: {
        label: "Full",
        url: "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip",
        fileName: "yara-forge-rules-full.yar"
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

async function countYaraRules(filePath: string) {
    try {
        const content = await fs.readFile(filePath, "utf8");
        return (content.match(/^\s*(?:private\s+|global\s+)*rule\s+[A-Za-z0-9_]+/gm) || []).length;
    } catch {
        return 0;
    }
}

async function ensureYaraEngine(settings: any, log?: (message: string) => void) {
    if (settings.yaraPath && existsSync(settings.yaraPath)) {
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
    const anyRulesFile = expected || await findFileByName(settings.yaraRulesDir || yaraForgeRulesDir, `yara-forge-rules-${ruleset}.yar`);
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
    } catch {}
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

function cacheEntryMatches(current: ShieldCacheEntry | null, cached?: ShieldCacheEntry) {
    return !!current && !!cached && current.size === cached.size && current.mtimeMs === cached.mtimeMs;
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

async function manageClamd(settings: any) {
    if (isSimulated || !settings.clamdPath) return;

    if (settings.offloadToMemory) {
        if (!clamdProcess) {
            console.log("Starting clamd process...");
            try {
                // Ensure clamd.conf exists, create if missing
                try {
                    await fs.access(settings.clamdConf);
                } catch (e) {
                    const clamdConfContent = buildClamdConfContent(settings);
                    await fs.writeFile(settings.clamdConf, clamdConfContent);
                    console.log("Created missing clamd.conf");
                }
                await ensureClamdConfExclusions(settings);
                
                clamdProcess = spawn(settings.clamdPath, ["--config-file=" + settings.clamdConf]);
                clamdProcess.on("error", (err: any) => {
                    console.error("Failed to start clamd:", err.message);
                    clamdProcess = null;
                });
                clamdProcess.on("close", () => {
                    console.log("clamd process closed.");
                    clamdProcess = null;
                });
            } catch (e: any) {
                console.error("Failed to start clamd:", e.message);
            }
        }
    } else {
        if (clamdProcess) {
            console.log("Stopping clamd process...");
            clamdProcess.kill();
            clamdProcess = null;
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
            const entries = await fs.readdir(engineBaseDir, { withFileTypes: true });
            const clamDir = entries.find(e => e.isDirectory() && e.name.toLowerCase().startsWith("clamav") && e.name !== "clamav");
            
            if (clamDir) {
                // Rename the old extracted folder to 'clamav'
                await fs.rename(path.join(engineBaseDir, clamDir.name), path.join(engineBaseDir, "clamav"));
                
                settings.clamavDir = path.join(engineBaseDir, "clamav");
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
                await fs.access(settings.freshclamConf);
            } catch (e) {
                const confContent = `DatabaseDirectory ${settings.databaseDir}\nUpdateLogFile ${path.join(settings.logsDir, 'freshclam.log')}\nDatabaseMirror database.clamav.net\n`;
                await fs.writeFile(settings.freshclamConf, confContent).catch(console.error);
                console.log("Created missing freshclam.conf");
            }
        }

        if (settings.clamdConf) {
            try {
                await fs.access(settings.clamdConf);
            } catch (e) {
                    const clamdConfContent = buildClamdConfContent(settings);
                    await fs.writeFile(settings.clamdConf, clamdConfContent).catch(console.error);
                    console.log("Created missing clamd.conf on startup");
                }
                await ensureClamdConfExclusions(settings);
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
    const writer = createWriteStream(listPath, { encoding: "utf8" });
    let count = 0;
    try {
        for (const target of targets.filter(Boolean)) {
            let stat;
            try {
                stat = await fs.stat(target);
            } catch {
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
    return { listPath, count };
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
        options.appendJobLogs(options.jobId, [`YARA ignored (Exception): ${detection.originalPath}`]);
        return "Ignored";
    }

    const threatName = `YARA: ${detection.ruleNames.join(", ")}`;
    if (options.action === "quarantine") {
        try {
            const quarantined = await quarantineFile(detection.originalPath, threatName, settings.quarantineDir);
            const qMap = await getQuarantineMap();
            qMap[quarantined.fileName] = quarantined.metadata;
            await saveQuarantineMap(qMap);
            options.appendJobLogs(options.jobId, [`YARA quarantined: ${detection.originalPath} -> ${quarantined.destPath}`]);
            return "Quarantined";
        } catch (e: any) {
            options.appendJobLogs(options.jobId, [`YARA failed to quarantine ${detection.originalPath}: ${e.message}`]);
            return "Quarantine Failed";
        }
    }

    if (options.action === "ask" && Array.isArray(options.pendingThreats)) {
        options.pendingThreats.push({
            id: Date.now().toString() + Math.random().toString(36).substring(7),
            originalPath: detection.originalPath,
            threatName,
            engine: "YARA",
            timestamp: Date.now()
        });
        options.appendJobLogs(options.jobId, [`YARA match waiting for user action: ${detection.originalPath}`]);
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
    options.appendJobLogs(options.jobId, [`YARA match sent to Results: ${detection.originalPath}`]);
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
        yaraPath = await ensureYaraEngine(settings, message => options.appendJobLogs(options.jobId, [`YARA: ${message}`]));
    } catch (e: any) {
        options.appendJobLogs(options.jobId, [`YARA skipped: ${e.message}`]);
        return { matches: 0, actionTaken: "None" };
    }

    const { listPath, count } = await createYaraTargetList(settings, targets, (indexed) => {
        options.appendJobLogs(options.jobId, [`YARA target list indexed: ${indexed} files`]);
    });
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
        `YARA ruleset: ${normalizeYaraRuleset(settings.yaraRuleset)} (${rulesFile})`,
        `YARA executable: ${yaraPath}`,
        `YARA arguments: ${args.join(" ")}`
    ]);

    const stdoutLines: string[] = [];
    const child = spawn(yaraPath, args);
    job.process = child;
    const exitCode = await new Promise<number>((resolve) => {
        child.stdout.on("data", data => {
            const lines = data.toString().split("\n").map((line: string) => line.trim()).filter(Boolean);
            stdoutLines.push(...lines);
            if (lines.length) options.appendJobLogs(options.jobId, lines.map((line: string) => `YARA: ${line}`));
        });
        child.stderr.on("data", data => {
            const lines = data.toString().split("\n").map((line: string) => line.trim()).filter(Boolean);
            if (lines.length) options.appendJobLogs(options.jobId, lines.map((line: string) => `YARA: ${line}`));
        });
        child.on("error", error => {
            options.appendJobLogs(options.jobId, [`YARA process error: ${error.message}`]);
            resolve(-1);
        });
        child.on("close", code => resolve(code ?? 0));
    });
    await fs.unlink(listPath).catch(() => {});
    if (job.process === child) job.process = null;

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

    options.appendJobLogs(options.jobId, [`YARA finished with exit code ${exitCode}. Matches: ${detectionsByPath.size}.`]);
    return { matches: detectionsByPath.size, actionTaken };
}

async function startServer() {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
        res.cookie(apiCookieName, apiSessionToken, {
            httpOnly: true,
            sameSite: "strict",
            secure: false,
            path: "/"
        });
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

    const activeJobs: Record<string, { status: string, logs: string[], analysisLogs?: string[], result?: number, process?: any, lastOutputAt?: number }> = {};
    let pendingThreats: any[] = [];
    const shieldScanCache = await loadShieldScanCacheStore();
    console.log(`Shield cache backend: ${shieldScanCache.type}`);
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
    };

    app.post("/api/client-log", (req, res) => {
        const level = typeof req.body?.level === "string" ? req.body.level : "error";
        const message = req.body?.message || "Renderer log";
        writeAppLog("renderer.log", level, [message, req.body?.details || {}]);
        res.json({ success: true });
    });

    const createScanHeartbeat = (jobId: string, label: string) => {
        const startedAt = Date.now();
        let lastHeartbeatAt = 0;
        const timer = setInterval(() => {
            const job = activeJobs[jobId];
            if (!job || job.status !== "running") {
                clearInterval(timer);
                return;
            }
            const now = Date.now();
            if (now - lastHeartbeatAt < 5000) return;
            lastHeartbeatAt = now;
            const elapsedSeconds = Math.floor((now - startedAt) / 1000);
            const lastOutputAt = job.lastOutputAt || startedAt;
            const quietSeconds = Math.floor((now - lastOutputAt) / 1000);
            appendJobLogs(jobId, [
                `${label} still running... elapsed ${formatDuration(elapsedSeconds)}, last output ${quietSeconds}s ago`
            ]);
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
                } catch (e) {}
            }
            let exePath = isClamd ? currentSettings.clamdscanPath : currentSettings.clamscanPath;
            let args = buildClamScanArgs(currentSettings, isClamd, "file", filePath);

            const jobId = "shield-" + Date.now() + Math.random().toString(36).substring(7);
            activeJobs[jobId] = { status: "running", logs: [], analysisLogs: [] };
            appendJobLogs(jobId, [
                `Shield scan queued: ${filePath}`,
                `Engine mode: ${isClamd ? "clamdscan/offload to RAM" : "clamscan/direct"}`,
                `Executable: ${exePath}`,
                `Arguments: ${args.join(" ")}`
            ]);
            
            try {
                const heartbeat = createScanHeartbeat(jobId, "Shield scan");
                const child = spawn(exePath, args);
                activeJobs[jobId].process = child;
                
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
                                    pendingThreats.push({
                                        id: Date.now().toString() + Math.random().toString(36).substring(7),
                                        originalPath,
                                        threatName,
                                        timestamp: Date.now()
                                    });
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

    app.get("/api/testzip", (req, res) => {
        const https = require('https');
        const unzipper = require('unzipper');
        const files: string[] = [];
        https.get('https://www.clamav.net/downloads/production/clamav-1.4.1-win-x64-portable.zip', (resp: any) => {
            resp.pipe(unzipper.Parse())
            .on('entry', function (entry: any) {
                files.push(entry.path);
                entry.autodrain();
            }).on('finish', () => {
                res.json(files);
            });
        });
    });

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
            const entries = await fs.readdir(engineBaseDir, { withFileTypes: true });
            const clamDir = entries.find(e => e.isDirectory() && e.name.toLowerCase().startsWith("clamav") && e.name !== "clamav.zip");
            if (clamDir) hasEngine = true;
            
            const dbFiles = await fs.readdir(settings.databaseDir);
            hasDb = dbFiles.some(f => f.endsWith('.cvd') || f.endsWith('.cld'));
        } catch { }
        hasYaraEngine = Boolean(settings.yaraPath && existsSync(settings.yaraPath));
        hasYaraRules = existsSync(getYaraRulesFile(settings));

        let pkgVersion = "1.0.14";
        try {
            const pkgPath = path.join(runtimeDir, process.env.NODE_ENV === "production" ? ".." : "", "package.json");
            const pkgData = await fs.readFile(pkgPath, "utf8");
            pkgVersion = JSON.parse(pkgData).version || "1.0.14";
        } catch {}
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
            const entries = await fs.readdir(engineBaseDir, { withFileTypes: true });
            const clamDir = entries.find(e => e.isDirectory() && e.name.toLowerCase().startsWith("clamav") && e.name !== "clamav.zip" && e.name !== "clamav");
            
            let finalClamDir = "clamav";
            if (clamDir) {
                // Rename the extracted folder to 'clamav'
                await fs.rename(path.join(engineBaseDir, clamDir.name), path.join(engineBaseDir, finalClamDir));
            }

            const confPath = path.join(engineBaseDir, finalClamDir, "freshclam.conf");
            const clamdConfPath = path.join(engineBaseDir, finalClamDir, "clamd.conf");
            await fs.mkdir(settings.databaseDir, { recursive: true });
            
            const confContent = `DatabaseDirectory ${settings.databaseDir}\nUpdateLogFile ${path.join(settings.logsDir, 'freshclam.log')}\nDatabaseMirror database.clamav.net\n`;
            await fs.writeFile(confPath, confContent);

            const clamdConfContent = buildClamdConfContent(settings);
            await fs.writeFile(clamdConfPath, clamdConfContent);
            
            settings.clamavDir = path.join(engineBaseDir, finalClamDir);
            settings.clamscanPath = path.join(settings.clamavDir, "clamscan.exe");
            settings.freshclamPath = path.join(settings.clamavDir, "freshclam.exe");
            settings.clamdPath = path.join(settings.clamavDir, "clamd.exe");
            settings.clamdscanPath = path.join(settings.clamavDir, "clamdscan.exe");
            settings.freshclamConf = confPath;
            settings.clamdConf = clamdConfPath;
            
            await saveConfig(settings);
            await autoDisableDefender();

            // Clean up zip
            try { await fs.unlink(zipPath); } catch {}
            
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
                        const child = spawn(settings.freshclamPath, args);
                        
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
                const lastUpdate = history.find((h: any) => h.type === "yara-update" && h.result === 0);
                const intervalMs = normalizePositiveNumber(settings.yaraUpdateIntervalHours, 168, 1, 8760) * 60 * 60 * 1000;
                const shouldUpdate = !lastUpdate || Date.now() - new Date(lastUpdate.date).getTime() > intervalMs;
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

    // Initial trigger
    scheduleNextUpdate();
    scheduleNextYaraUpdate();

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
                const child = spawn("powershell", ["-STA", "-NoProfile", "-EncodedCommand", encoded]);
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
                const child = spawn("powershell", ["-STA", "-NoProfile", "-EncodedCommand", encoded]);
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
        const { target, type } = req.body;
        const effectiveTarget = resolveScanTarget(type, target);
        const jobId = Date.now().toString();
        // type could be 'file', 'folder', 'disk', 'memory'
        
        if (isSimulated) {
            // Simulated scan
            res.json({ jobId, status: "started", simulated: true });
            
            activeJobs[jobId] = { status: "running", logs: ["Starting simulated scan..."] };
            
            // Simulate run
            setTimeout(async () => {
                const isThreat = Math.random() < 0.5 && type !== 'update';
                let threatsFound = 0;
                let actionTaken = "None";
                
                if (isThreat) {
                    threatsFound = 1;
                    const testPath = effectiveTarget || "C:\\TestPath";
                    const filePath = path.join(testPath, "eicar.com.txt");
                    activeJobs[jobId].logs.push(`FOUND: ${filePath}: Eicar-Test-Signature`);
                    
                    const action = settings.scanDetectionAction || "results";
                    if (action === "quarantine") {
                        activeJobs[jobId].logs.push(`Quarantined: ${filePath}`);
                        actionTaken = "Quarantined";
                    } else {
                        await addScanResult({
                            source: "manual",
                            scanType: type,
                            target: effectiveTarget || "C:\\",
                            originalPath: filePath,
                            threatName: "Eicar-Test-Signature (Simulated)"
                        });
                        activeJobs[jobId].logs.push(`Threat found, sent to Results: ${filePath}`);
                        actionTaken = "Sent to Results";
                    }
                }
                
                activeJobs[jobId].logs.push("Scan completed.");
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = isThreat ? 1 : 0;
                
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
            } catch (e) {}
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
                    `Enumerated ${memoryProcessCount} running process executable image${memoryProcessCount === 1 ? "" : "s"}.`,
                    "Scanning process image files with ClamAV..."
                ]);
            }
            appendJobLogs(jobId, [
                `Scan target: ${type === "memory" ? "Running process images" : (effectiveTarget || scanTarget || "Default target")}`,
                `Engine mode: ${isClamd ? "clamdscan/offload to RAM" : "clamscan/direct"}`,
                `Executable: ${exePath}`,
                `Arguments: ${args.join(" ")}`
            ]);
            const heartbeat = createScanHeartbeat(jobId, "Scan");
            const child = spawn(exePath, args);
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
                appendJobLogs(jobId, [`Scan finished with exit code ${code ?? "unknown"}.`]);
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

    app.get("/api/scan/:jobId", (req, res) => {
        const job = activeJobs[req.params.jobId];
        if (!job) {
            return res.status(404).json({ error: "Job not found" });
        }
        res.json({
            status: job.status,
            logs: job.logs,
            result: job.result
        });
        // Clear logs after sending them so we don't accumulate too much
        job.logs = [];
    });

    app.post("/api/scan/:jobId/cancel", (req, res) => {
        const job = activeJobs[req.params.jobId];
        if (job) {
            if (job.process) {
                job.process.kill();
            }
            job.status = "done";
            job.logs.push("Scan cancelled by user.");
            res.json({ status: "cancelled" });
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
            
            const args = ["--config-file=" + settings.freshclamConf, "--datadir=" + settings.databaseDir];
            const child = spawn(settings.freshclamPath, args);
            activeJobs[jobId].process = child;
            
            child.on("error", (err: any) => {
                console.error("Failed to start freshclam process:", err.message);
                if (activeJobs[jobId]) {
                    activeJobs[jobId].status = "error";
                    activeJobs[jobId].logs.push("Process error: " + err.message);
                }
            });

            child.stdout.on("data", (data) => {
                const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                if (lines.length) activeJobs[jobId].logs.push(...lines);
            });
            
            child.stderr.on("data", (data) => {
                const lines = data.toString().split('\n').map((l: string) => l.trim()).filter(Boolean);
                if (lines.length) activeJobs[jobId].logs.push(...lines);
            });
            
            child.on("close", async (code) => {
                if (!activeJobs[jobId]) return;
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = code ?? 0;
                activeJobs[jobId].process = null;
                
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

            child.on("error", (err) => {
                if (!activeJobs[jobId]) return;
                activeJobs[jobId].logs.push(`Error: ${err.message}`);
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = -1;
                activeJobs[jobId].process = null;
            });
            
            res.json({ jobId, status: "started" });
        } catch(e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    app.post("/api/update-yara", async (req, res) => {
        const jobId = "yara-update-" + Date.now().toString();
        activeJobs[jobId] = { status: "running", logs: [] };
        res.json({ jobId, status: "started" });

        const startedAt = Date.now();
        try {
            activeJobs[jobId].logs.push(`Updating YARA Forge ${normalizeYaraRuleset(settings.yaraRuleset)} rules...`);
            const result = await updateYaraForgeRules(settings, message => {
                if (activeJobs[jobId]) activeJobs[jobId].logs.push(message);
            });
            if (!activeJobs[jobId]) return;
            activeJobs[jobId].logs.push(`YARA update complete: ${result.ruleCount} rules loaded.`);
            activeJobs[jobId].status = "done";
            activeJobs[jobId].result = 0;
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
                activeJobs[jobId].logs.push(`Error: ${e.message}`);
                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = 1;
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
        const results = await getScanResults();
        if (results.length === 0) {
            return res.json({ show: false, count: 0, latestTimestamp: 0 });
        }
        const latestTimestamp = Math.max(...results.map((item: any) => Number(item.timestamp || 0)));
        const state = await getResultsReminderState();
        const now = Date.now();
        const show = now >= Number(state.remindUntil || 0) && latestTimestamp > Number(state.forgottenUntil || 0);
        res.json({ show, count: results.length, latestTimestamp });
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
        pendingThreats.push({
            id: Date.now().toString() + Math.random().toString(36).substring(7),
            originalPath: "C:\\TestPath\\fake-virus.exe",
            threatName: "Win32.Test.SimulatedThreat.A",
            timestamp: Date.now()
        });
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
