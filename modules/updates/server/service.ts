import { englishText } from "../../../shared/localization/runtime";
import { appUpdateInstallLoggers } from "../../../engines/clamav/server/constants";
import { downloadToFile } from "../../../server/core/downloads";
import { programDataDir } from "../../../server/core/paths";
import { runtimeState } from "../../../server/core/runtimeState";
import { hashFile } from "../../../server/core/utils";
import { compareVersions, getCurrentAppVersion, normalizeVersion } from "./versions";
import axios from "axios";
import { spawn } from "child_process";
import fs from "fs/promises";
import path from "path";
export async function getLatestClamShieldRelease(settings: any) {
    const currentVersion = await getCurrentAppVersion();
    const releaseRes = await axios.get("https://api.github.com/repos/orloxgr/ClamShield/releases/latest", {
        headers: { "User-Agent": "ClamShield" }
    });
    const release = releaseRes.data;
    const latestVersion = normalizeVersion(release.tag_name || release.name);
    const skipped = normalizeVersion(settings.skippedAppVersion) === latestVersion;
    const newerVersionAvailable = compareVersions(latestVersion, currentVersion) > 0;
    const asset = (release.assets || []).find((item: any) => {
        const name = String(item.name || "").toLowerCase();
        return name.endsWith(".exe") && (name.includes("setup") || name.includes("clamshield"));
    }) || (release.assets || []).find((item: any) => String(item.name || "").toLowerCase().endsWith(".exe"));
    return {
        currentVersion,
        latestVersion,
        newerVersionAvailable,
        updateAvailable: newerVersionAvailable && !skipped,
        skipped,
        releaseUrl: release.html_url,
        publishedAt: release.published_at,
        assetName: asset?.name || "",
        downloadUrl: asset?.browser_download_url || "",
        assetSize: Number(asset?.size || 0),
        assetDigest: String(asset?.digest || "")
    };
}
export function emitAppUpdateInstallLog(message: string) {
    for (const logger of appUpdateInstallLoggers) {
        try {
            logger(message);
        }
        catch {
            // A disconnected UI must not interrupt the shared update.
        }
    }
}
export function emitSharedLog(loggers: Set<(message: string) => void>, message: string) {
    for (const logger of loggers) {
        try {
            logger(message);
        }
        catch {
            // A disconnected UI must not interrupt the shared update.
        }
    }
}
export function getExpectedSha256(digest: any) {
    const match = /^sha256:([a-f0-9]{64})$/i.exec(String(digest || "").trim());
    return match ? match[1].toLowerCase() : "";
}
export async function isVerifiedClamShieldInstaller(filePath: string, update: any) {
    try {
        const stat = await fs.stat(filePath);
        if (!stat.isFile() || stat.size <= 0)
            return false;
        if (update.assetSize > 0 && stat.size !== update.assetSize)
            return false;
        const expectedSha256 = getExpectedSha256(update.assetDigest);
        if (expectedSha256) {
            const actualSha256 = await hashFile(filePath);
            if (actualSha256.toLowerCase() !== expectedSha256)
                return false;
        }
        return true;
    }
    catch {
        return false;
    }
}
export async function downloadVerifiedClamShieldInstaller(update: any, log: (message: string) => void) {
    const updatesDir = path.join(programDataDir, "updates");
    const safeName = update.assetName.replace(/[<>:"/\\|?*]/g, "_") || `ClamShield-Setup-${update.latestVersion}.exe`;
    const installerPath = path.join(updatesDir, safeName);
    if (await isVerifiedClamShieldInstaller(installerPath, update)) {
        log(`Using verified ClamShield ${update.latestVersion} installer already on disk.`);
        return installerPath;
    }
    const partialPath = `${installerPath}.${process.pid}.${Date.now()}.download`;
    try {
        log(`Downloading ClamShield ${update.latestVersion} installer...`);
        await downloadToFile(update.downloadUrl, partialPath, log);
        if (!(await isVerifiedClamShieldInstaller(partialPath, update))) {
            throw new Error(englishText("backend.updates.downloaded_clamshield_installer_failed_size_or_sha_256_verificati"));
        }
        await fs.rm(installerPath, { force: true });
        await fs.rename(partialPath, installerPath);
        log("ClamShield installer download verified.");
        return installerPath;
    }
    finally {
        await fs.rm(partialPath, { force: true }).catch(() => { });
    }
}
export async function queueInstallerAfterCurrentProcessExit(installerPath: string) {
    if (process.platform !== "win32") {
        const child = spawn(installerPath, ["/S"], {
            detached: true,
            stdio: "ignore"
        });
        await new Promise<void>((resolve, reject) => {
            child.once("spawn", resolve);
            child.once("error", reject);
        });
        child.unref();
        return;
    }
    const handoffLogPath = path.join(programDataDir, "updates", "update-handoff.log");
    const quotePowerShell = (value: string) => `'${value.replace(/'/g, "''")}'`;
    const script = [
        "$ErrorActionPreference = 'Stop'",
        `$parentProcessId = ${process.pid}`,
        `$installerPath = ${quotePowerShell(installerPath)}`,
        `$handoffLogPath = ${quotePowerShell(handoffLogPath)}`,
        "while (Get-Process -Id $parentProcessId -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 250 }",
        "try {",
        "  Add-Content -LiteralPath $handoffLogPath -Value \"[$([DateTime]::UtcNow.ToString('o'))] Launching $installerPath\"",
        "  Start-Process -FilePath $installerPath -ArgumentList '/S' -WindowStyle Hidden",
        "} catch {",
        "  Add-Content -LiteralPath $handoffLogPath -Value \"[$([DateTime]::UtcNow.ToString('o'))] Handoff failed: $($_.Exception.Message)\"",
        "  exit 1",
        "}"
    ].join("\n");
    const encodedHandoff = Buffer.from(script, "utf16le").toString("base64");
    const handoffCommand = `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ${encodedHandoff}`;
    const brokerScript = [
        "$ErrorActionPreference = 'Stop'",
        `$commandLine = ${quotePowerShell(handoffCommand)}`,
        "$result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $commandLine }",
        "if ($result.ReturnValue -ne 0) { throw \"Windows process broker returned $($result.ReturnValue).\" }"
    ].join("\n");
    const encodedBroker = Buffer.from(brokerScript, "utf16le").toString("base64");
    const child = spawn("powershell.exe", [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-EncodedCommand", encodedBroker
    ], {
        windowsHide: true
    });
    let stderr = "";
    child.stderr?.on("data", data => stderr += data.toString());
    await new Promise<void>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", code => {
            if (code === 0)
                resolve();
            else
                reject(new Error(stderr.trim() || `Unable to create independent update process (exit code ${code}).`));
        });
    });
}
export async function performClamShieldInstallerHandoff(settings: any) {
    const update = await getLatestClamShieldRelease(settings);
    if (!update.newerVersionAvailable)
        return { ...update, handoffReady: false };
    if (!update.downloadUrl)
        throw new Error(englishText("backend.updates.latest_clamshield_release_does_not_include_a_windows_installer_as"));
    const installerPath = await downloadVerifiedClamShieldInstaller(update, emitAppUpdateInstallLog);
    emitAppUpdateInstallLog(`Preparing safe installer handoff: ${installerPath}`);
    await queueInstallerAfterCurrentProcessExit(installerPath);
    emitAppUpdateInstallLog("Installer handoff ready. ClamShield can now close safely.");
    return { ...update, handoffReady: true, installerPath };
}
export async function downloadAndLaunchClamShieldInstaller(settings: any, log?: (message: string) => void) {
    if (log)
        appUpdateInstallLoggers.add(log);
    if (runtimeState.queuedAppUpdateResult?.handoffReady) {
        log?.("The ClamShield installer handoff is already queued.");
        if (log)
            appUpdateInstallLoggers.delete(log);
        return runtimeState.queuedAppUpdateResult;
    }
    if (!runtimeState.appUpdateInstallPromise) {
        runtimeState.appUpdateInstallPromise = performClamShieldInstallerHandoff(settings)
            .then(result => {
            if (result.handoffReady)
                runtimeState.queuedAppUpdateResult = result;
            return result;
        })
            .finally(() => {
            runtimeState.appUpdateInstallPromise = null;
            appUpdateInstallLoggers.clear();
        });
    }
    else {
        log?.("A ClamShield update is already in progress; joining the existing update.");
    }
    try {
        return await runtimeState.appUpdateInstallPromise;
    }
    finally {
        if (log)
            appUpdateInstallLoggers.delete(log);
    }
}
