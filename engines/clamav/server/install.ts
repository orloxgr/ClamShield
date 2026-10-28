import { englishText } from "../../../shared/localization/runtime";
import { saveConfig } from "../../../modules/settings/server/service";
import { getLatestClamAVEngineRelease } from "../../../modules/updates/server/providers";
import { emitSharedLog } from "../../../modules/updates/server/service";
import { downloadToFile, extractZip } from "../../../server/core/downloads";
import { adoptClamavEngineFolder, findExtractedClamavDir } from "../../../server/core/files";
import { engineBaseDir } from "../../../server/core/paths";
import { runtimeState } from "../../../server/core/runtimeState";
import { sleep } from "../../../server/core/utils";
import { autoDisableDefender } from "../../../server/platform/defender";
import { buildClamdConfContent } from "./arguments";
import { clamavEngineUpdateLoggers } from "./constants";
import { checkClamAV, manageClamd } from "./daemon";
import { ensureFreshclamConfig } from "./freshclam";
import { getClamAVEngineVersion } from "./version";
import fs from "fs/promises";
import path from "path";
export async function installClamAVEngine(settings: any, log?: (message: string) => void) {
    if (process.platform !== "win32") {
        throw new Error(englishText("backend.clamav.auto_install_is_only_supported_on_windows_64_bit"));
    }
    const update = await getLatestClamAVEngineRelease(settings);
    const downloadUrl = update.downloadUrl;
    const assetName = update.assetName || `clamav-${update.latestVersion}-win-x64.zip`;
    if (!downloadUrl) {
        throw new Error(englishText("backend.clamav.could_not_find_a_windows_x64_clamav_zip_asset_in_the_latest_relea"));
    }
    log?.(`Downloading ClamAV Engine ${update.latestVersion}...`);
    await fs.mkdir(engineBaseDir, { recursive: true });
    const zipPath = path.join(engineBaseDir, "clamav.zip");
    await downloadToFile(downloadUrl, zipPath, log, { resume: true, expectedSize: update.assetSize });
    if (runtimeState.clamdProcess) {
        log?.("Stopping clamd before replacing the engine files...");
        runtimeState.clamdProcess.kill();
        runtimeState.clamdProcess = null;
        runtimeState.clamdConfSignature = "";
        await sleep(800);
    }
    log?.(`Extracting ${assetName}...`);
    try {
        await extractZip(zipPath, engineBaseDir);
    }
    catch (error) {
        await fs.rm(zipPath, { force: true }).catch(() => { });
        throw error;
    }
    const extractedClamDir = await findExtractedClamavDir();
    if (!extractedClamDir) {
        throw new Error(englishText("backend.clamav.clamav_archive_was_extracted_but_clamscan_exe_and_freshclam_exe_w"));
    }
    log?.("Replacing managed ClamAV engine folder...");
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
    await fs.writeFile(clamdConfPath, buildClamdConfContent(settings));
    await fs.rm(zipPath, { force: true }).catch(() => { });
    runtimeState.clamAVVersionCache = null;
    await saveConfig(settings);
    if (settings.autoDisableDefender === true) {
        await autoDisableDefender();
    }
    await checkClamAV(settings);
    await manageClamd(settings);
    const installedVersion = await getClamAVEngineVersion(settings, true);
    log?.(`ClamAV Engine ready: ${installedVersion}`);
    return { ...update, installedVersion };
}
export async function queueClamAVEngineUpdate(settings: any, log?: (message: string) => void) {
    if (log)
        clamavEngineUpdateLoggers.add(log);
    if (!runtimeState.clamavEngineUpdateInstallPromise) {
        runtimeState.clamavEngineUpdateInstallPromise = installClamAVEngine(settings, message => emitSharedLog(clamavEngineUpdateLoggers, message))
            .finally(() => {
            runtimeState.clamavEngineUpdateInstallPromise = null;
            clamavEngineUpdateLoggers.clear();
        });
    }
    else {
        log?.("A ClamAV Engine update is already in progress; joining the existing update.");
    }
    try {
        return await runtimeState.clamavEngineUpdateInstallPromise;
    }
    finally {
        if (log)
            clamavEngineUpdateLoggers.delete(log);
    }
}
