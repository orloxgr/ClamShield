import express from "express";
import fs from "fs/promises";
import { createWriteStream, createReadStream, existsSync } from "fs";
import path from "path";
import os from "os";
import { exec, spawn } from "child_process";
import { promisify } from "util";
import { createHash, randomBytes } from "crypto";
import axios from "axios";
import unzipper from "unzipper";
import chokidar from "chokidar";

const runtimeFileName = typeof __filename === "string" ? __filename : path.resolve(process.argv[1] || ".");
const runtimeDir = typeof __dirname === "string" ? __dirname : path.dirname(runtimeFileName);

const execAsync = promisify(exec);

// Path logic to handle default paths or user configurations
// Note: process.platform === "win32" is Node.js's identifier for ALL Windows systems, including 64-bit.
const programDataDir = process.platform === "win32" 
    ? path.join(process.env.PROGRAMDATA || "C:\\ProgramData", "ClamShield") 
    : path.join(process.cwd(), "data", "ClamShield");

const engineBaseDir = path.join(programDataDir, "engine");

const defaultSettings = {
    // Relying on 64-bit Program Files by default, but we'll try to use a local bundled path if possible
    clamavDir: process.platform === "win32" ? path.join(engineBaseDir, "clamav") : "/usr/bin",
    clamscanPath: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "clamscan.exe") : "/usr/bin/clamscan",
    freshclamPath: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "freshclam.exe") : "/usr/bin/freshclam",
    freshclamConf: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "freshclam.conf") : "/etc/clamav/freshclam.conf",
    clamdPath: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "clamd.exe") : "/usr/sbin/clamd",
    clamdscanPath: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "clamdscan.exe") : "/usr/bin/clamdscan",
    clamdConf: process.platform === "win32" ? path.join(engineBaseDir, "clamav", "clamd.conf") : "/etc/clamav/clamd.conf",
    databaseDir: path.join(programDataDir, "db"),
    quarantineDir: path.join(programDataDir, "quarantine"),
    logsDir: path.join(programDataDir, "logs"),
    defaultAction: "ask",
    actionOnDetection: "ask",
    autoQuarantine: false,
    autoUpdateEnabled: true,
    updateIntervalHours: 24,
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
    playSoundOnAlert: true,
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

function normalizeCachePath(filePath: string) {
    return path.resolve(filePath).toLowerCase();
}

async function loadShieldScanCache(): Promise<ShieldScanCache> {
    const cachePath = getShieldCachePath();
    try {
        const stat = await fs.stat(cachePath);
        if (stat.size > 50 * 1024 * 1024) {
            console.warn("Shield scan cache is too large; starting with a fresh cache.");
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

async function saveShieldScanCache(cache: ShieldScanCache) {
    await fs.writeFile(getShieldCachePath(), JSON.stringify(cache));
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

async function addTargetToShieldCache(cache: ShieldScanCache, targetPath: string, onProgress?: (count: number) => void) {
    let count = 0;
    for await (const filePath of walkFiles(targetPath)) {
        const fingerprint = await getFileFingerprint(filePath);
        if (!fingerprint) continue;
        cache.files[normalizeCachePath(filePath)] = fingerprint;
        count++;
        if (count % 5000 === 0) onProgress?.(count);
        if (count % 200 === 0) await sleep(1);
    }
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
                    const clamdConfContent = `DatabaseDirectory ${settings.databaseDir}\nTCPAddr 127.0.0.1\nTCPSocket 3310\nLogFile ${path.join(settings.logsDir, 'clamd.log')}\n`;
                    await fs.writeFile(settings.clamdConf, clamdConfContent);
                    console.log("Created missing clamd.conf");
                }
                
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
                const clamdConfContent = `DatabaseDirectory ${settings.databaseDir}\nTCPAddr 127.0.0.1\nTCPSocket 3310\nLogFile ${path.join(settings.logsDir, 'clamd.log')}\n`;
                await fs.writeFile(settings.clamdConf, clamdConfContent).catch(console.error);
                console.log("Created missing clamd.conf on startup");
            }
        }
    }
}

// Ensure directories exist
async function ensureDirs(settings: any) {
    const dirs = [
        programDataDir,
        settings.databaseDir,
        settings.quarantineDir,
        settings.logsDir
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
        return {
            ...defaultSettings,
            ...parsed,
            eulaAccepted: parsed.eulaAccepted !== false
        };
    } catch {
        return defaultSettings;
    }
}

async function saveConfig(settings: any) {
    const configPath = path.join(programDataDir, "settings.json");
    await fs.writeFile(configPath, JSON.stringify(settings, null, 2));
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
        return Promise.all(files.map(async file => {
            const stat = await fs.stat(path.join(quarantineDir, file));
            let meta = qMap[file];
            if (!meta) {
                const baseMatch = file.match(/^(.*?)(?:\.\d{3})?$/);
                if (baseMatch && qMap[baseMatch[1]]) {
                    meta = qMap[baseMatch[1]];
                }
            }

            return {
                id: file,
                fileName: file,
                threatName: meta ? meta.threatName : "Unknown Threat",
                originalPath: meta ? meta.originalPath : "Unknown",
                size: stat.size,
                date: stat.mtime
            };
        }));
    } catch {
        return [];
    }
}

async function addHistory(entry: any) {
    const historyPath = path.join(programDataDir, "history.json");
    const history = await getHistory();
    history.unshift({ id: Date.now().toString(), date: new Date().toISOString(), ...entry });
    await fs.writeFile(historyPath, JSON.stringify(history, null, 2));
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

    const activeJobs: Record<string, { status: string, logs: string[], analysisLogs?: string[], result?: number, process?: any }> = {};
    let pendingThreats: any[] = [];
    let shieldScanCache = await loadShieldScanCache();
    let shieldCacheSaveTimer: NodeJS.Timeout | null = null;
    const scheduleShieldCacheSave = () => {
        if (shieldCacheSaveTimer) clearTimeout(shieldCacheSaveTimer);
        shieldCacheSaveTimer = setTimeout(() => {
            saveShieldScanCache(shieldScanCache).catch(e => console.error("Failed to save shield scan cache:", e));
            shieldCacheSaveTimer = null;
        }, 15000);
    };
    const appendJobLogs = (jobId: string, lines: string[]) => {
        const job = activeJobs[jobId];
        if (!job || lines.length === 0) return;
        job.logs.push(...lines);
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
                const next = pendingShieldScans.entries().next().value as [string, { filePath: string, reason: "add" | "change" }];
                if (!next) return;
                const [normalizedPath, item] = next;
                pendingShieldScans.delete(normalizedPath);
                if (filesBeingScanned.has(normalizedPath)) continue;

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
            if (filesBeingScanned.has(normalizedPath)) return;
            pendingShieldScans.set(normalizedPath, { filePath, reason });
            processShieldQueue();
        };

        const scanShieldFile = async (filePath: string, reason: "add" | "change") => {
            const normalizedPath = path.resolve(filePath).toLowerCase();
            if (filesBeingScanned.has(normalizedPath)) return;
            filesBeingScanned.add(normalizedPath);
            console.log(`Shield: File ${reason === "add" ? "detected" : "changed"} -> ${filePath}`);
            const fingerprint = await getFileFingerprint(filePath);
            if (!fingerprint || cacheEntryMatches(fingerprint, shieldScanCache.files[normalizedPath]) || isSimulated) {
                filesBeingScanned.delete(normalizedPath);
                return;
            }
            const maxFileSizeBytes = normalizePositiveNumber(currentSettings.maxFileSize, 50, 1, 4096) * 1024 * 1024;
            if (fingerprint.size > maxFileSizeBytes) {
                shieldScanCache.files[normalizedPath] = fingerprint;
                scheduleShieldCacheSave();
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
            
            try {
                const child = spawn(exePath, args);
                activeJobs[jobId].process = child;
                
                child.on("error", (err: any) => {
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
                    if (!activeJobs[jobId]) return;
                    let threatsFound = 0;
                    let scannedFiles = 0;
                    let duration = 0;
                    
                    const qMap = await getQuarantineMap();
                    const exceptions = await getExceptions();
                    let quarantineMapChanged = false;

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
                                const action = currentSettings.actionOnDetection || (currentSettings.autoQuarantine ? "quarantine" : "warn");
                                if (action === "quarantine") {
                                    try {
                                        const quarantined = await quarantineFile(originalPath, threatName, currentSettings.quarantineDir);
                                        qMap[quarantined.fileName] = quarantined.metadata;
                                        quarantineMapChanged = true;
                                        appendJobLogs(jobId, [`Quarantined: ${originalPath} -> ${quarantined.destPath}`]);
                                    } catch (e: any) {
                                        appendJobLogs(jobId, [`Failed to quarantine ${originalPath}: ${e.message}`]);
                                    }
                                } else if (action === "ask") {
                                    pendingThreats.push({
                                        id: Date.now().toString() + Math.random().toString(36).substring(7),
                                        originalPath,
                                        threatName,
                                        timestamp: Date.now()
                                    });
                                    appendJobLogs(jobId, [`Threat found, waiting for user action: ${originalPath}`]);
                                } else {
                                    appendJobLogs(jobId, [`Threat found but action is set to Warn: ${originalPath}`]);
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

                    const isThreat = code === 1 || threatsFound > 0;
                    if (isThreat) {
                        console.log(`Shield: Threat found in ${filePath}`);
                    }

                    const latestFingerprint = await getFileFingerprint(filePath);
                    if (latestFingerprint) {
                        shieldScanCache.files[normalizedPath] = latestFingerprint;
                        scheduleShieldCacheSave();
                    } else {
                        delete shieldScanCache.files[normalizedPath];
                        scheduleShieldCacheSave();
                    }
                    
                    await addHistory({
                        type: "scan-shield",
                        target: filePath,
                        result: isThreat ? 1 : 0,
                        threatsFound,
                        scannedFiles,
                        duration,
                        actionTaken: isThreat ? "Quarantined" : "None"
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
        const quarantineItems = await getQuarantineItems(settings.quarantineDir);
        try {
            const entries = await fs.readdir(engineBaseDir, { withFileTypes: true });
            const clamDir = entries.find(e => e.isDirectory() && e.name.toLowerCase().startsWith("clamav") && e.name !== "clamav.zip");
            if (clamDir) hasEngine = true;
            
            const dbFiles = await fs.readdir(settings.databaseDir);
            hasDb = dbFiles.some(f => f.endsWith('.cvd') || f.endsWith('.cld'));
        } catch { }

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
            stats: {
                engineVersion: isSimulated ? "ClamAV (Simulated)" : "ClamAV (Installed)",
                lastScan: lastScan ? lastScan.date : null,
                lastUpdate: lastUpdate ? lastUpdate.date : null,
                lastThreat: lastThreat ? lastThreat.date : null,
                quarantineCount: quarantineItems.length,
                shieldCacheCount: Object.keys(shieldScanCache.files).length
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

            const clamdConfContent = `DatabaseDirectory ${settings.databaseDir}\nTCPAddr 127.0.0.1\nTCPSocket 3310\nLogFile ${path.join(settings.logsDir, 'clamd.log')}\n`;
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

    // Initial trigger
    scheduleNextUpdate();

    app.post("/api/settings", async (req, res) => {
        settings = { ...settings, ...req.body };
        await saveConfig(settings);
        await ensureDirs(settings);
        res.json({ success: true, settings });
        Promise.resolve()
            .then(async () => {
                await checkClamAV(settings);
                await startShield(settings);
                await manageClamd(settings);
                await manageStartup(settings);
                await scheduleDefenderEnforcement(false);
                scheduleNextUpdate();
            })
            .catch(e => console.error("Failed to apply settings side effects:", e));
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
                    
                    const action = settings.actionOnDetection || (settings.autoQuarantine ? "quarantine" : "warn");
                    if (action === "ask") {
                        pendingThreats.push({
                            id: Date.now().toString() + Math.random().toString(36).substring(7),
                            originalPath: filePath,
                            threatName: "Eicar-Test-Signature (Simulated)",
                            timestamp: Date.now()
                        });
                        activeJobs[jobId].logs.push(`Threat found, waiting for user action: ${filePath}`);
                        actionTaken = "Pending";
                    } else if (action === "quarantine") {
                        activeJobs[jobId].logs.push(`Quarantined: ${filePath}`);
                        actionTaken = "Quarantined";
                    } else {
                        activeJobs[jobId].logs.push(`Threat found but action is set to Warn: ${filePath}`);
                        actionTaken = "Warned";
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
        let scanTarget = effectiveTarget;
        if (type === "memory" && process.platform === "win32") {
            const processPaths = await getRunningProcessImagePaths();
            memoryProcessCount = processPaths.length;
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
            const child = spawn(exePath, args);
            activeJobs[jobId].process = child;
            
            child.on("error", (err: any) => {
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
                if (!activeJobs[jobId]) return;
                
                let scannedFiles = 0;
                let threatsFound = 0;
                let duration = 0;
                
                const qMap = await getQuarantineMap();
                const exceptions = await getExceptions();
                let quarantineMapChanged = false;

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
                            const action = settings.actionOnDetection || (settings.autoQuarantine ? "quarantine" : "warn");
                            if (action === "quarantine") {
                                try {
                                    const quarantined = await quarantineFile(originalPath, threatName, settings.quarantineDir);
                                    qMap[quarantined.fileName] = quarantined.metadata;
                                    quarantineMapChanged = true;
                                    appendJobLogs(jobId, [`Quarantined: ${originalPath} -> ${quarantined.destPath}`]);
                                } catch (e: any) {
                                    appendJobLogs(jobId, [`Failed to quarantine ${originalPath}: ${e.message}`]);
                                }
                            } else if (action === "ask") {
                                pendingThreats.push({
                                    id: Date.now().toString() + Math.random().toString(36).substring(7),
                                    originalPath,
                                    threatName,
                                    timestamp: Date.now()
                                });
                                appendJobLogs(jobId, [`Threat found, waiting for user action: ${originalPath}`]);
                            } else {
                                appendJobLogs(jobId, [`Threat found but action is set to Warn: ${originalPath}`]);
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

                const isThreat = code === 1;
                await addHistory({
                    type: `scan-${type}`,
                    target: type === "memory" ? "Running process images" : (effectiveTarget || "C:\\"),
                    result: isThreat ? 1 : 0,
                    threatsFound,
                    scannedFiles: type === "memory" && scannedFiles === 0 ? memoryProcessCount : scannedFiles, 
                    duration,
                    actionTaken: isThreat ? "Quarantined" : "None"
                });

                if ((type === "disk" || type === "folder" || type === "file") && effectiveTarget) {
                    appendJobLogs(jobId, ["Building real-time shield cache for this scan target..."]);
                    try {
                        const cachedCount = await addTargetToShieldCache(shieldScanCache, effectiveTarget, (count) => {
                            appendJobLogs(jobId, [`Shield cache indexed: ${count} files`]);
                        });
                        await saveShieldScanCache(shieldScanCache);
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
