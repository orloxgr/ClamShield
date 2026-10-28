import { englishText } from "../../../shared/localization/runtime";
import { dnsProtectionBackupPath } from "../../../server/core/paths";
import { powershellStringArray } from "../../../server/platform/defender";
import { runPowerShellJson } from "../../../server/platform/processes";
import { pathExists } from "../../../server/scanning/files";
import { dnsProtectionProfiles } from "./profiles";
import fs from "fs/promises";
export function getDnsProtectionProfile(profileId: any) {
    return dnsProtectionProfiles.find(profile => profile.id === String(profileId || "")) || null;
}
export function normalizeDnsAddresses(value: any) {
    return Array.isArray(value)
        ? value.map(item => String(item || "").trim().toLowerCase()).filter(Boolean)
        : [];
}
export function containsDnsAddresses(actual: any, expected: string[]) {
    const actualSet = new Set(normalizeDnsAddresses(actual));
    const expectedList = normalizeDnsAddresses(expected);
    return expectedList.length > 0 && expectedList.every(value => actualSet.has(value));
}
export function adapterMatchesDnsProfile(adapter: any, profile: any) {
    const checks: boolean[] = [];
    if (adapter.hasIpv4Gateway === true)
        checks.push(containsDnsAddresses(adapter.ipv4, profile.ipv4));
    if (adapter.hasIpv6Gateway === true)
        checks.push(containsDnsAddresses(adapter.ipv6, profile.ipv6));
    if (checks.length === 0) {
        return containsDnsAddresses(adapter.ipv4, profile.ipv4) || containsDnsAddresses(adapter.ipv6, profile.ipv6);
    }
    return checks.every(Boolean);
}
export function adapterPartiallyMatchesDnsProfile(adapter: any, profile: any) {
    return containsDnsAddresses(adapter.ipv4, profile.ipv4) || containsDnsAddresses(adapter.ipv6, profile.ipv6);
}
export async function getWindowsDnsAdapters() {
    if (process.platform !== "win32") {
        return { supported: false, domainJoined: false, adapters: [], error: englishText("backend.dns_protection.dns_protection_is_currently_supported_only_on_windows") };
    }
    return runPowerShellJson(`
$ErrorActionPreference = 'Stop'
$computer = Get-CimInstance Win32_ComputerSystem
$configurations = @(Get-NetIPConfiguration | Where-Object {
  $_.NetAdapter.Status -eq 'Up' -and ($_.IPv4DefaultGateway -or $_.IPv6DefaultGateway)
})
$adapters = @(
  foreach ($configuration in $configurations) {
    $index = [int]$configuration.InterfaceIndex
    $ipv4 = @((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Where-Object { $_ })
    $ipv6 = @((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses | Where-Object { $_ })
    [ordered]@{
      interfaceAlias = [string]$configuration.InterfaceAlias
      interfaceIndex = $index
      interfaceDescription = [string]$configuration.InterfaceDescription
      hasIpv4Gateway = [bool]$configuration.IPv4DefaultGateway
      hasIpv6Gateway = [bool]$configuration.IPv6DefaultGateway
      ipv4 = $ipv4
      ipv6 = $ipv6
    }
  }
)
'CLAMSHIELD_JSON_START'
[ordered]@{
  supported = $true
  domainJoined = [bool]$computer.PartOfDomain
  adapters = $adapters
} | ConvertTo-Json -Depth 6 -Compress
'CLAMSHIELD_JSON_END'
`);
}
export async function getDnsProtectionStatus(settings: any) {
    const windowsState = await getWindowsDnsAdapters();
    const activeProfile = getDnsProtectionProfile(settings.dnsProtectionProfile);
    const adapters = Array.isArray(windowsState.adapters) ? windowsState.adapters : [];
    const adapterStatuses = activeProfile
        ? adapters.map((adapter: any) => ({
            ...adapter,
            dnsProtectionApplied: adapterMatchesDnsProfile(adapter, activeProfile),
            dnsProtectionPartial: adapterPartiallyMatchesDnsProfile(adapter, activeProfile)
        }))
        : adapters;
    const matchingAdapterCount = adapterStatuses.filter((adapter: any) => adapter.dnsProtectionApplied).length;
    const partialAdapterCount = adapterStatuses.filter((adapter: any) => adapter.dnsProtectionPartial).length;
    const fullyApplied = Boolean(settings.dnsProtectionEnabled &&
        activeProfile &&
        adapterStatuses.length > 0 &&
        matchingAdapterCount === adapterStatuses.length);
    const partiallyApplied = Boolean(settings.dnsProtectionEnabled &&
        activeProfile &&
        adapterStatuses.length > 0 &&
        !fullyApplied &&
        partialAdapterCount > 0);
    const applied = fullyApplied || partiallyApplied;
    return {
        ...windowsState,
        adapters: adapterStatuses,
        enabled: settings.dnsProtectionEnabled === true,
        applied,
        fullyApplied,
        partiallyApplied,
        drifted: settings.dnsProtectionEnabled === true && !fullyApplied,
        matchingAdapterCount,
        partialAdapterCount,
        activeProfileId: activeProfile?.id || "",
        activeProfileName: activeProfile ? `${activeProfile.provider} ${activeProfile.name}` : "",
        appliedAt: settings.dnsProtectionAppliedAt || "",
        backupAvailable: await pathExists(dnsProtectionBackupPath),
        profiles: dnsProtectionProfiles
    };
}
export async function applyDnsProtectionProfile(settings: any, profileId: any) {
    const profile = getDnsProtectionProfile(profileId);
    if (!profile)
        throw new Error(englishText("backend.dns_protection.unknown_dns_protection_profile"));
    const before = await getWindowsDnsAdapters();
    const adapters = Array.isArray(before.adapters) ? before.adapters : [];
    if (adapters.length === 0)
        throw new Error(englishText("backend.dns_protection.no_active_windows_network_adapter_with_an_internet_gateway_was_fo"));
    if (!settings.dnsProtectionEnabled || !await pathExists(dnsProtectionBackupPath)) {
        await fs.writeFile(dnsProtectionBackupPath, JSON.stringify({
            createdAt: new Date().toISOString(),
            adapters
        }, null, 2), "utf8");
    }
    const serverAddresses = powershellStringArray([...profile.ipv4, ...profile.ipv6]);
    await runPowerShellJson(`
$ErrorActionPreference = 'Stop'
$serverAddresses = ${serverAddresses}
$configurations = @(Get-NetIPConfiguration | Where-Object {
  $_.NetAdapter.Status -eq 'Up' -and ($_.IPv4DefaultGateway -or $_.IPv6DefaultGateway)
})
if ($configurations.Count -eq 0) { throw 'No active Windows network adapter with an internet gateway was found.' }
$changed = @()
foreach ($configuration in $configurations) {
  Set-DnsClientServerAddress -InterfaceIndex $configuration.InterfaceIndex -ServerAddresses $serverAddresses -ErrorAction Stop
  $changed += [string]$configuration.InterfaceAlias
}
Clear-DnsClientCache -ErrorAction SilentlyContinue
'CLAMSHIELD_JSON_START'
[ordered]@{ success = $true; changedAdapters = $changed } | ConvertTo-Json -Depth 4 -Compress
'CLAMSHIELD_JSON_END'
`);
    return profile;
}
export async function restoreDnsProtectionBackup() {
    if (!await pathExists(dnsProtectionBackupPath)) {
        throw new Error(englishText("backend.dns_protection.no_saved_dns_configuration_is_available_to_restore"));
    }
    const backup = JSON.parse(await fs.readFile(dnsProtectionBackupPath, "utf8"));
    const adapters = Array.isArray(backup.adapters) ? backup.adapters : [];
    if (adapters.length === 0)
        throw new Error(englishText("backend.dns_protection.the_saved_dns_configuration_contains_no_adapters"));
    const restoreBlocks = adapters.map((adapter: any) => {
        const alias = String(adapter.interfaceAlias || "").replace(/'/g, "''");
        const addresses = [...normalizeDnsAddresses(adapter.ipv4), ...normalizeDnsAddresses(adapter.ipv6)];
        const restoreCommand = addresses.length > 0
            ? `Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses ${powershellStringArray(addresses)} -ErrorAction Stop`
            : "Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses -ErrorAction Stop";
        return `
$networkAdapter = Get-NetAdapter -InterfaceIndex ${Math.max(0, Number(adapter.interfaceIndex) || 0)} -ErrorAction SilentlyContinue
if (-not $networkAdapter) { $networkAdapter = Get-NetAdapter -Name '${alias}' -ErrorAction SilentlyContinue | Select-Object -First 1 }
if ($networkAdapter) {
  $index = [int]$networkAdapter.InterfaceIndex
  ${restoreCommand}
  $restored += [string]$networkAdapter.Name
}`;
    }).join("\n");
    const result = await runPowerShellJson(`
$ErrorActionPreference = 'Stop'
$restored = @()
${restoreBlocks}
Clear-DnsClientCache -ErrorAction SilentlyContinue
'CLAMSHIELD_JSON_START'
[ordered]@{ success = $true; restoredAdapters = $restored } | ConvertTo-Json -Depth 4 -Compress
'CLAMSHIELD_JSON_END'
`);
    await fs.unlink(dnsProtectionBackupPath).catch(() => { });
    return result;
}
