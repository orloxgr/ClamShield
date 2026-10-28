import { englishText } from "../../shared/localization/runtime";
import { dedupePaths } from "./paths";
import { runPowerShellJson } from "./processes";
import { spawn } from "child_process";
import path from "path";
export function defenderStatusScript() {
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
    DisableBlockAtFirstSeen = if ($prefs) { $prefs.DisableBlockAtFirstSeen } else { $null }
    MAPSReporting = if ($prefs) { [int]$prefs.MAPSReporting } else { $null }
    SubmitSamplesConsent = if ($prefs) { [int]$prefs.SubmitSamplesConsent } else { $null }
    ScanScheduleDay = if ($prefs) { [int]$prefs.ScanScheduleDay } else { $null }
    DisableCatchupFullScan = if ($prefs) { $prefs.DisableCatchupFullScan } else { $null }
    DisableCatchupQuickScan = if ($prefs) { $prefs.DisableCatchupQuickScan } else { $null }
}
'CLAMSHIELD_JSON_START'
$result | ConvertTo-Json -Compress
'CLAMSHIELD_JSON_END'
`;
}
export function defenderDisableScript() {
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
Set-ClamShieldMpPreference 'DisableBlockAtFirstSeen' $true
Set-ClamShieldMpPreference 'MAPSReporting' 'Disabled'
Set-ClamShieldMpPreference 'SubmitSamplesConsent' 'NeverSend'
Set-ClamShieldMpPreference 'ScanScheduleDay' 'Never'
Set-ClamShieldMpPreference 'DisableCatchupFullScan' $true
Set-ClamShieldMpPreference 'DisableCatchupQuickScan' $true
Start-Sleep -Milliseconds 800
$status = $null
$prefs = $null
$errorText = $null
try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $errorText = $_.Exception.Message }
try { $prefs = Get-MpPreference -ErrorAction Stop } catch {}
$realTimeEnabled = if ($status) { [bool]$status.RealTimeProtectionEnabled } else { $null }
$cloudProtectionDisabled = if ($prefs) { ([int]$prefs.MAPSReporting -eq 0) } else { $false }
$sampleSubmissionDisabled = if ($prefs) { ([int]$prefs.SubmitSamplesConsent -eq 2) } else { $false }
$scheduledScansDisabled = if ($prefs) { ([int]$prefs.ScanScheduleDay -eq 8) -and [bool]$prefs.DisableCatchupFullScan -and [bool]$prefs.DisableCatchupQuickScan } else { $false }
$success = ($realTimeEnabled -eq $false) -and $cloudProtectionDisabled -and $sampleSubmissionDisabled -and $scheduledScansDisabled
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
    DisableBlockAtFirstSeen = if ($prefs) { $prefs.DisableBlockAtFirstSeen } else { $null }
    MAPSReporting = if ($prefs) { [int]$prefs.MAPSReporting } else { $null }
    SubmitSamplesConsent = if ($prefs) { [int]$prefs.SubmitSamplesConsent } else { $null }
    ScanScheduleDay = if ($prefs) { [int]$prefs.ScanScheduleDay } else { $null }
    DisableCatchupFullScan = if ($prefs) { $prefs.DisableCatchupFullScan } else { $null }
    DisableCatchupQuickScan = if ($prefs) { $prefs.DisableCatchupQuickScan } else { $null }
    CloudProtectionDisabled = $cloudProtectionDisabled
    SampleSubmissionDisabled = $sampleSubmissionDisabled
    ScheduledScansDisabled = $scheduledScansDisabled
    NeedsManualAction = (-not $success)
    Message = if ($success) { 'Microsoft Defender scanning, cloud-delivered protection, automatic sample submission, and scheduled catch-up scans are paused.' } else { 'One or more Microsoft Defender protections remained active. Windows Tamper Protection, administrator access, or device policy may be blocking the change.' }
}
'CLAMSHIELD_JSON_START'
$result | ConvertTo-Json -Depth 5 -Compress
'CLAMSHIELD_JSON_END'
`;
}
export function defenderRestoreScript() {
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
Set-ClamShieldMpPreference 'DisableBlockAtFirstSeen' $false
Set-ClamShieldMpPreference 'MAPSReporting' 'Advanced'
Set-ClamShieldMpPreference 'SubmitSamplesConsent' 'SendSafeSamples'
Set-ClamShieldMpPreference 'ScanScheduleDay' 'Everyday'
Set-ClamShieldMpPreference 'DisableCatchupFullScan' $false
Set-ClamShieldMpPreference 'DisableCatchupQuickScan' $false
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
$realTimeEnabled = if ($status) { [bool]$status.RealTimeProtectionEnabled } else { $null }
$success = ($realTimeEnabled -eq $true)
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
    DisableBlockAtFirstSeen = if ($prefs) { $prefs.DisableBlockAtFirstSeen } else { $null }
    MAPSReporting = if ($prefs) { [int]$prefs.MAPSReporting } else { $null }
    SubmitSamplesConsent = if ($prefs) { [int]$prefs.SubmitSamplesConsent } else { $null }
    ScanScheduleDay = if ($prefs) { [int]$prefs.ScanScheduleDay } else { $null }
    DisableCatchupFullScan = if ($prefs) { $prefs.DisableCatchupFullScan } else { $null }
    DisableCatchupQuickScan = if ($prefs) { $prefs.DisableCatchupQuickScan } else { $null }
    NeedsManualAction = (-not $success)
    Message = if ($success) { 'Microsoft Defender real-time protection is active.' } else { 'Microsoft Defender did not return to active real-time protection. Open Windows Security and review its protection settings or device policy.' }
}
'CLAMSHIELD_JSON_START'
$result | ConvertTo-Json -Depth 5 -Compress
'CLAMSHIELD_JSON_END'
`;
}
export async function getDefenderStatus() {
    if (process.platform !== "win32")
        return { Supported: false, Error: "Only supported on Windows." };
    return runPowerShellJson(defenderStatusScript());
}
export function defenderTamperProtectedResult(status: any) {
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
        DisableBlockAtFirstSeen: status?.DisableBlockAtFirstSeen ?? null,
        MAPSReporting: status?.MAPSReporting ?? null,
        SubmitSamplesConsent: status?.SubmitSamplesConsent ?? null,
        ScanScheduleDay: status?.ScanScheduleDay ?? null,
        DisableCatchupFullScan: status?.DisableCatchupFullScan ?? null,
        DisableCatchupQuickScan: status?.DisableCatchupQuickScan ?? null,
        ActionRequired: "disable-tamper-protection",
        Message: "Windows Tamper Protection is on. Open Windows Security, go to Virus & threat protection → Manage settings, turn Tamper Protection off, then return to ClamShield and check again. Until then, ClamShield will run side-by-side with Defender."
    };
}
export async function requestDefenderPause() {
    if (process.platform !== "win32")
        return { Supported: false, Success: false, Error: "Only supported on Windows." };
    const status = await getDefenderStatus();
    if (status?.IsTamperProtected === true) {
        return defenderTamperProtectedResult(status);
    }
    return runPowerShellJson(defenderDisableScript());
}
export async function restoreDefenderPreferences() {
    if (process.platform !== "win32")
        return { Supported: false, Success: false, Error: "Only supported on Windows." };
    return runPowerShellJson(defenderRestoreScript());
}
export async function openWindowsSecurity() {
    if (process.platform !== "win32")
        return { success: false, error: englishText("backend.platform.only_supported_on_windows") };
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
        const result = await new Promise<{
            success: boolean;
            error?: string;
        }>((resolve) => {
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
            }
            catch (e: any) {
                done(false, e?.message || String(e));
            }
        });
        if (result.success) {
            return { success: true, command: attempt.command, args: attempt.args };
        }
        if (result.error)
            errors.push(`${attempt.command}: ${result.error}`);
    }
    return { success: false, error: errors.join("; ") || englishText("settings.windows_security_could_not_be_opened") };
}
export async function autoDisableDefender() {
    try {
        const result = await requestDefenderPause();
        if (!result.Success && !result.SideBySideMode) {
            console.warn(englishText("backend.platform.defender_pause_was_not_fully_applied"), result.Message || result.Error || result);
        }
        return result;
    }
    catch (e: any) {
        console.warn(englishText("backend.platform.defender_pause_failed"), e.message);
        return { Supported: process.platform === "win32", Success: false, Error: e.message };
    }
}
export function powershellStringArray(values: string[]) {
    return `@(${values.map(value => `'${value.replace(/'/g, "''")}'`).join(", ")})`;
}
export function getDefenderCompatibilityExclusionPaths(settings: any) {
    if (process.platform !== "win32")
        return [];
    return dedupePaths([
        settings.yaraDir,
        settings.yaraRulesDir,
        settings.yaraCacheDir,
        settings.yaraCustomRulesDir,
        settings.quarantineDir
    ].filter(Boolean).map((folderPath: string) => path.resolve(folderPath)));
}
export function defenderCompatibilityExclusionsScript(paths: string[], enabled: boolean) {
    return `
$ErrorActionPreference = 'Continue'
$enabled = ${enabled ? "$true" : "$false"}
$paths = ${powershellStringArray(paths)}
$operations = [ordered]@{}
function Test-ClamShieldPathListed($Existing, $Path) {
    foreach ($item in @($Existing)) {
        if ([string]::Equals([string]$item, [string]$Path, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}
try { $prefsBefore = Get-MpPreference -ErrorAction Stop; $existing = @($prefsBefore.ExclusionPath) } catch { $existing = @(); $operations['Get-MpPreference'] = $_.Exception.Message }
foreach ($path in $paths) {
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    try {
        if ($enabled) {
            if (-not (Test-ClamShieldPathListed $existing $path)) {
                Add-MpPreference -ExclusionPath $path -ErrorAction Stop
            }
        } else {
            if (Test-ClamShieldPathListed $existing $path) {
                Remove-MpPreference -ExclusionPath $path -ErrorAction Stop
            }
        }
        $operations[$path] = 'ok'
    } catch {
        $operations[$path] = $_.Exception.Message
    }
}
try { $prefsAfter = Get-MpPreference -ErrorAction Stop; $active = @($prefsAfter.ExclusionPath) } catch { $active = @(); $operations['Verify'] = $_.Exception.Message }
$pending = @()
foreach ($path in $paths) {
    $listed = Test-ClamShieldPathListed $active $path
    if ($enabled -and -not $listed) { $pending += $path }
    if (-not $enabled -and $listed) { $pending += $path }
}
$success = ($pending.Count -eq 0)
$result = [ordered]@{
    Supported = $true
    Success = $success
    Enabled = $enabled
    Paths = $paths
    PendingPaths = $pending
    ActivePaths = $active
    Operations = $operations
    NeedsManualAction = (-not $success)
    Message = if ($success) { if ($enabled) { 'Defender compatibility exclusions are applied.' } else { 'Defender compatibility exclusions are removed.' } } else { 'Windows blocked one or more Defender exclusion changes.' }
}
'CLAMSHIELD_JSON_START'
$result | ConvertTo-Json -Depth 5 -Compress
'CLAMSHIELD_JSON_END'
`;
}
export async function syncDefenderCompatibilityExclusions(settings: any) {
    if (process.platform !== "win32")
        return { Supported: false, Success: false, Error: "Only supported on Windows." };
    const paths = getDefenderCompatibilityExclusionPaths(settings);
    if (paths.length === 0)
        return { Supported: true, Success: true, Paths: [] };
    return runPowerShellJson(defenderCompatibilityExclusionsScript(paths, settings.defenderCompatibilityExclusionsEnabled === true));
}
