import { presentationText } from "../../shared/localization/presentation";
import { englishText } from "../../shared/localization/runtime";
import { loadVirusTotalApiKey } from "../../addons/virustotal/server/account";
import { getYaraRulesFile } from "../../engines/yara/server/rules";
import { runtimeDir, windowsContextMenuStatePath } from "../core/paths";
import { runHiddenProcess } from "./processes";
import { existsSync } from "fs";
import fs from "fs/promises";
import path from "path";
export function isYaraAvailableForContextMenu(settings: any) {
    return settings.yaraEnabled !== false &&
        Boolean(settings.yaraPath && existsSync(settings.yaraPath)) &&
        existsSync(getYaraRulesFile(settings));
}
export async function writeWindowsContextMenuState(settings: any) {
    try {
        await fs.mkdir(path.dirname(windowsContextMenuStatePath), { recursive: true });
        const yaraAvailable = isYaraAvailableForContextMenu(settings);
        const virusTotalAvailable = yaraAvailable &&
            settings.virusTotalCloudEnabled === true &&
            Boolean(await loadVirusTotalApiKey());
        await fs.writeFile(windowsContextMenuStatePath, JSON.stringify({
            enabled: settings.windowsContextMenuEnabled === true,
            yaraAvailable,
            virusTotalAvailable,
            updatedAt: new Date().toISOString()
        }, null, 2));
    }
    catch (e: any) {
        console.warn("Failed to update Windows context menu state:", e?.message || e);
    }
}
export function getInstalledAppDir() {
    if (process.platform === "win32" && process.execPath && /clamshield\.exe$/i.test(process.execPath)) {
        return path.dirname(process.execPath);
    }
    return runtimeDir;
}
export async function getLegacyContextMenuActions(settings: any) {
    const yaraAvailable = isYaraAvailableForContextMenu(settings);
    const virusTotalAvailable = yaraAvailable &&
        settings.virusTotalCloudEnabled === true &&
        Boolean(await loadVirusTotalApiKey());
    const actions = [
        { id: "clamav", label: presentationText("backend.platform.scan_with_clamav_only"), action: "clamav" }
    ];
    if (yaraAvailable) {
        actions.push({ id: "clamav-yara", label: presentationText("backend.platform.scan_with_clamav_yara"), action: "clamav-yara" });
    }
    if (virusTotalAvailable) {
        actions.push({ id: "clamav-yara-vt", label: presentationText("backend.platform.scan_with_clamav_yara_virustotal"), action: "clamav-yara-vt" });
    }
    actions.push({ id: "add-exception", label: presentationText("backend.platform.add_to_clamshield_exceptions"), action: "add-exception" });
    return actions;
}
export async function runRegistryCommand(args: string[], options: {
    allowFailure?: boolean;
} = {}) {
    const result = await runHiddenProcess("reg.exe", args, { timeoutMs: 30000 });
    if (result.code !== 0 && !options.allowFailure) {
        throw new Error((result.stderr || result.stdout || `reg.exe exited with code ${result.code}`).trim());
    }
}
export async function addRegistryValue(key: string, name: string | null, value: string) {
    const args = ["add", key, "/f"];
    if (name === null)
        args.push("/ve");
    else
        args.push("/v", name);
    args.push("/t", "REG_SZ", "/d", value);
    await runRegistryCommand(args);
}
export async function configureLegacyContextMenuRegistry(enabled: boolean, settings: any) {
    if (process.platform !== "win32")
        return;
    const roots = [
        "HKCU\\Software\\Classes\\*\\shell\\ClamShield",
        "HKCU\\Software\\Classes\\Directory\\shell\\ClamShield"
    ];
    for (const rootKey of roots) {
        await runRegistryCommand(["delete", rootKey, "/f"], { allowFailure: true });
    }
    if (!enabled)
        return;
    const installDir = getInstalledAppDir();
    const exePath = path.join(installDir, "ClamShield.exe");
    const helperScriptPath = path.join(installDir, "shell", "ClamShieldContextMenu.vbs");
    const wscriptPath = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "wscript.exe");
    const iconPath = `${exePath},0`;
    const actions = await getLegacyContextMenuActions(settings);
    for (const rootKey of roots) {
        await addRegistryValue(rootKey, "MUIVerb", "ClamShield");
        await addRegistryValue(rootKey, "Icon", iconPath);
        await addRegistryValue(rootKey, "SubCommands", "");
        for (const item of actions) {
            const itemKey = `${rootKey}\\shell\\${item.id}`;
            const commandKey = `${itemKey}\\command`;
            await addRegistryValue(itemKey, "MUIVerb", item.label);
            await addRegistryValue(itemKey, "MultiSelectModel", "Player");
            await addRegistryValue(itemKey, "NoWorkingDirectory", "");
            await addRegistryValue(commandKey, null, `"${wscriptPath}" "${helperScriptPath}" "${item.action}" "%1" "${exePath}"`);
        }
    }
}
export function isAppxPolicyFailure(message: string) {
    return /0x80073CFF/i.test(message) ||
        /sideloading policy/i.test(message) ||
        /developer license/i.test(message) ||
        /package origin\s+Unsigned/i.test(message);
}
export async function configureWindowsContextMenuPackage(enabled: boolean, settings: any) {
    if (process.platform !== "win32") {
        throw new Error(englishText("backend.platform.windows_context_menu_integration_is_only_available_on_windows"));
    }
    const installDir = getInstalledAppDir();
    const manifestPath = path.join(installDir, "sparse-package", "AppxManifest.xml");
    const shellDllPath = path.join(installDir, "shell", "ClamShieldShellExt.dll");
    if (enabled) {
        if (!existsSync(manifestPath))
            throw new Error(englishText("backend.platform.sparse_package_manifest_was_not_found", {
                manifestPath: String(manifestPath)
            }));
        if (!existsSync(shellDllPath))
            throw new Error(englishText("backend.platform.shell_extension_dll_was_not_found", {
                shellDllPath: String(shellDllPath)
            }));
    }
    const command = enabled
        ? `Add-AppxPackage -Register '${manifestPath.replace(/'/g, "''")}' -ExternalLocation '${installDir.replace(/'/g, "''")}' -ForceApplicationShutdown`
        : `Get-AppxPackage -Name 'Orlox.ClamShield' | Remove-AppxPackage -ErrorAction SilentlyContinue`;
    const result = await runHiddenProcess("powershell.exe", [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command
    ], { timeoutMs: 120000 });
    if (result.code !== 0) {
        const errorText = (result.stderr || result.stdout || `PowerShell exited with code ${result.code}`).trim();
        if (enabled && isAppxPolicyFailure(errorText)) {
            await configureLegacyContextMenuRegistry(true, settings);
            return {
                success: true,
                mode: "legacy",
                warning: "Windows blocked the modern context menu package because AppX sideloading is restricted on this PC. ClamShield enabled the legacy File Explorer context menu instead; on Windows 11 it may appear under \"Show more options\"."
            };
        }
        throw new Error(errorText);
    }
    await configureLegacyContextMenuRegistry(enabled, settings);
    return {
        success: true,
        mode: enabled ? "modern" : "disabled",
        warning: ""
    };
}
