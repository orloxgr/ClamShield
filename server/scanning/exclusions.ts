import { saneSecurityToolsCacheDir, saneSecurityToolsDir, saneSecurityWorkingDir } from "../../addons/sanesecurity/server/constants";
import { appTempDir, programDataDir } from "../core/paths";
import { getWindowsSecuritySoftwareExclusionPaths, pathToClamExcludePattern } from "../core/utils";
import path from "path";

export const windowsLockedScanExclusions = [
    String.raw `^[A-Z]:\\pagefile\.sys$`,
    String.raw `^[A-Z]:\\swapfile\.sys$`,
    String.raw `^[A-Z]:\\hiberfil\.sys$`,
    String.raw `^[A-Z]:\\DumpStack\.log(?:\.tmp)?$`,
    String.raw `^[A-Z]:\\System Volume Information(\\|$)`,
    String.raw `^[A-Z]:\\\$Recycle\.Bin(\\|$)`
];

export const thunderbirdSummaryFileExcludePattern = String.raw `.*\.[Mm][Ss][Ff]$`;

export const windowsSecuritySoftwareProgramDirs = [
    ["Windows Defender"],
    ["Microsoft Defender"],
    ["Microsoft Security Client"],
    ["Malwarebytes"],
    ["Adaware"],
    ["Lavasoft"],
    ["Avast Software"],
    ["AVAST Software"],
    ["AVG"],
    ["Bitdefender"],
    ["Norton"],
    ["Norton Security"],
    ["NortonLifeLock"],
    ["McAfee"],
    ["ESET"],
    ["Kaspersky"],
    ["Kaspersky Lab"],
    ["Sophos"],
    ["Trend Micro"],
    ["F-Secure"],
    ["WithSecure"],
    ["CrowdStrike"],
    ["SentinelOne"],
    ["CarbonBlack"],
    ["VMware", "Carbon Black"],
    ["Palo Alto Networks"],
    ["Cylance"],
    ["Avira"],
    ["Panda Security"],
    ["Webroot"],
    ["Comodo"],
    ["COMODO"],
    ["Zone Labs"],
    ["CheckPoint"],
    ["Check Point"],
    ["Quick Heal"],
    ["G DATA"],
    ["Doctor Web"],
    ["DrWeb"],
    ["Emsisoft"],
    ["AhnLab"],
    ["VIPRE"],
    ["TotalAV"],
    ["WatchGuard"],
    ["Trellix"],
    ["FireEye"],
    ["Fortinet", "FortiClient"],
    ["Cisco", "AMP"],
    ["Cisco", "Secure Endpoint"],
    ["Cisco", "Cisco Secure Endpoint"]
];

export const windowsSecuritySoftwareDataDirs = [
    ["Microsoft", "Windows Defender"],
    ["Microsoft", "Microsoft Defender"],
    ["Microsoft", "Windows Defender Advanced Threat Protection"],
    ["Microsoft", "Defender"],
    ...windowsSecuritySoftwareProgramDirs
];

export const windowsSecuritySoftwareRootDirs = [
    ["AdwCleaner", "FileQuarantine"],
    ["AdwCleaner", "Quarantine"]
];

export function getClamShieldScanExclusionPaths(settings: any) {
    return [
        appTempDir,
        settings.clamavDir,
        settings.databaseDir,
        settings.yaraCacheDir,
        settings.yaraRulesDir,
        settings.yaraCustomRulesDir,
        settings.quarantineDir,
        saneSecurityToolsDir,
        saneSecurityToolsCacheDir,
        saneSecurityWorkingDir,
        ...getWindowsSecuritySoftwareExclusionPaths(),
        path.join(programDataDir, "updates")
    ].filter(Boolean);
}

export function getClamShieldScanExclusionPatterns(settings: any) {
    return [
        thunderbirdSummaryFileExcludePattern,
        ...getClamShieldScanExclusionPaths(settings).map((folderPath: string) => pathToClamExcludePattern(folderPath))
    ];
}
