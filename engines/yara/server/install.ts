import { englishText } from "../../../shared/localization/runtime";
import { defaultSettings } from "../../../modules/settings/server/schema";
import { saveConfig } from "../../../modules/settings/server/service";
import { getLatestYaraEngineRelease } from "../../../modules/updates/server/providers";
import { emitSharedLog } from "../../../modules/updates/server/service";
import { downloadToFile, extractZip, findFileByName } from "../../../server/core/downloads";
import { adoptYaraEngineFolder } from "../../../server/core/files";
import { yaraCacheDir, yaraForgeRulesDir } from "../../../server/core/paths";
import { runtimeState } from "../../../server/core/runtimeState";
import { yaraForgePackages } from "../../../server/core/utils";
import { yaraEngineUpdateLoggers } from "../../clamav/server/constants";
import { countYaraRules, findLargestYaraFile, getYaraRulesFile, normalizeYaraRuleset } from "./rules";
import { getCurrentYaraEngineVersion } from "./version";
import { existsSync } from "fs";
import fs from "fs/promises";
import path from "path";
export async function installYaraEngine(settings: any, log?: (message: string) => void) {
    if (process.platform !== "win32") {
        throw new Error(englishText("backend.yara.yara_engine_was_not_found_install_yara_and_set_the_yarapath_setti"));
    }
    log?.("Finding latest YARA Windows release...");
    const update = await getLatestYaraEngineRelease(settings);
    if (!update.downloadUrl) {
        throw new Error(englishText("backend.yara.could_not_find_a_windows_x64_yara_release_asset"));
    }
    if (update.sourceLatestVersion && update.sourceLatestVersion !== update.latestVersion) {
        log?.(`Latest YARA source release is ${update.sourceLatestVersion}, but no Windows x64 package is published for it. Using ${update.latestVersion}.`);
    }
    await fs.mkdir(settings.yaraDir || path.dirname(settings.yaraPath), { recursive: true });
    const zipPath = path.join(settings.yaraCacheDir || yaraCacheDir, update.assetName || `yara-${update.latestVersion}-win64.zip`);
    log?.(`Downloading ${update.assetName || `YARA ${update.latestVersion}`}...`);
    await downloadToFile(update.downloadUrl, zipPath, log);
    const tempDir = path.join(settings.yaraCacheDir || yaraCacheDir, `engine-${Date.now()}`);
    await fs.rm(tempDir, { recursive: true, force: true });
    await extractZip(zipPath, tempDir);
    const yaraExe = await findFileByName(tempDir, "yara64.exe") || await findFileByName(tempDir, "yara.exe");
    const yaracExe = await findFileByName(tempDir, "yarac64.exe") || await findFileByName(tempDir, "yarac.exe");
    if (!yaraExe) {
        throw new Error(englishText("backend.yara.downloaded_yara_package_did_not_contain_yara64_exe"));
    }
    const finalYaraDir = settings.yaraDir || path.dirname(settings.yaraPath) || defaultSettings.yaraDir;
    const extractedYaraDir = path.dirname(yaraExe);
    await adoptYaraEngineFolder(extractedYaraDir, finalYaraDir);
    const finalYaraPath = path.join(finalYaraDir, path.basename(yaraExe));
    const finalYaracPath = yaracExe ? path.join(finalYaraDir, path.basename(yaracExe)) : "";
    await fs.rm(tempDir, { recursive: true, force: true });
    await fs.unlink(zipPath).catch(() => { });
    settings.yaraDir = finalYaraDir;
    settings.yaraPath = finalYaraPath;
    settings.yaraEngineInstalledVersion = update.latestVersion;
    await ensureYaraRuntime(finalYaraPath);
    runtimeState.yaraVersionCache = null;
    await saveConfig(settings, { keys: ["yaraDir", "yaraPath", "yaraEngineInstalledVersion"] });
    log?.(`YARA engine ready: ${finalYaraPath}${finalYaracPath ? ` (compiler: ${finalYaracPath})` : ""}`);
    return { ...update, installedPath: finalYaraPath, installedVersion: await getCurrentYaraEngineVersion(settings) };
}
export async function queueYaraEngineUpdate(settings: any, log?: (message: string) => void) {
    if (log)
        yaraEngineUpdateLoggers.add(log);
    if (!runtimeState.yaraEngineUpdateInstallPromise) {
        runtimeState.yaraEngineUpdateInstallPromise = installYaraEngine(settings, message => emitSharedLog(yaraEngineUpdateLoggers, message))
            .finally(() => {
            runtimeState.yaraEngineUpdateInstallPromise = null;
            yaraEngineUpdateLoggers.clear();
        });
    }
    else {
        log?.("A YARA Engine update is already in progress; joining the existing update.");
    }
    try {
        return await runtimeState.yaraEngineUpdateInstallPromise;
    }
    finally {
        if (log)
            yaraEngineUpdateLoggers.delete(log);
    }
}
// The official YARA Windows build links against the Visual C++ runtime (VCRUNTIME140.dll), which a
// fresh Windows install does not have. Without it yara64.exe exits with 0xC0000135 (DLL not found)
export // before doing anything. ClamShield's managed ClamAV engine ships that runtime next to its own
// binaries, so copy it next to YARA (app-local deployment) when Windows doesn't already provide it.
async function ensureYaraRuntime(yaraPath: string) {
    if (process.platform !== "win32" || !yaraPath)
        return;
    const target = path.join(path.dirname(yaraPath), "vcruntime140.dll");
    if (existsSync(target))
        return;
    if (existsSync(path.join(process.env.SystemRoot || "C:\\Windows", "System32", "vcruntime140.dll")))
        return;
    const source = path.join(defaultSettings.clamavDir, "vcruntime140.dll");
    if (!existsSync(source)) {
        console.warn(englishText("backend.yara.yara_needs_vcruntime140_dll_but_it_was_not_found_in_windows_or_in", {
            source: String(source)
        }));
        return;
    }
    try {
        await fs.copyFile(source, target);
        runtimeState.yaraVersionCache = null;
        console.log(englishText("backend.yara.copied_vcruntime140_dll_next_to_yara_from", {
            source: String(source)
        }));
    }
    catch (e: any) {
        console.warn(englishText("backend.yara.could_not_copy_vcruntime140_dll_next_to_yara"), e?.message || e);
    }
}
export async function ensureYaraEngine(settings: any, log?: (message: string) => void) {
    if (settings.yaraPath && existsSync(settings.yaraPath)) {
        await ensureYaraRuntime(settings.yaraPath);
        log?.(`YARA engine found: ${settings.yaraPath}`);
        return settings.yaraPath;
    }
    const result = await installYaraEngine(settings, log);
    return result.installedPath;
}
export async function updateYaraForgeRules(settings: any, log?: (message: string) => void) {
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
        throw new Error(englishText("backend.yara.yara_forge_package_did_not_contain_a_yar_rules_file", {
            label: String(pack.label)
        }));
    }
    const finalRulesFile = getYaraRulesFile(settings);
    if (path.resolve(anyRulesFile).toLowerCase() !== path.resolve(finalRulesFile).toLowerCase()) {
        await fs.copyFile(anyRulesFile, finalRulesFile);
    }
    const ruleCount = await countYaraRules(finalRulesFile);
    await fs.unlink(zipPath).catch(() => { });
    settings.lastYaraUpdate = new Date().toISOString();
    settings.lastYaraRuleset = ruleset;
    settings.lastYaraRuleCount = ruleCount;
    await saveConfig(settings);
    log?.(`YARA Forge ${pack.label} rules ready (${ruleCount} rules).`);
    return { ruleset, ruleCount, rulesFile: finalRulesFile };
}
