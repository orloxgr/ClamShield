import { getClamAVEngineVersion } from "../../../engines/clamav/server/version";
import { getCurrentYaraEngineVersion } from "../../../engines/yara/server/version";
import { compareVersions, normalizeReleaseVersion, normalizeVersion, parseBareVersion } from "./versions";
import axios from "axios";
import { existsSync } from "fs";

export async function getLatestClamAVEngineRelease(settings: any) {
    const currentLabel = await getClamAVEngineVersion(settings, Boolean(settings?.clamscanPath && existsSync(settings.clamscanPath)));
    const currentVersion = parseBareVersion(currentLabel);
    const releaseRes = await axios.get("https://api.github.com/repos/Cisco-Talos/clamav/releases/latest", {
        headers: { "User-Agent": "ClamShield" }
    });
    const release = releaseRes.data;
    const latestVersion = normalizeReleaseVersion(release.tag_name || release.name);
    const skipped = normalizeVersion(settings.clamavEngineSkippedVersion) === latestVersion;
    const newerVersionAvailable = compareVersions(latestVersion, currentVersion) > 0;
    const asset = (release.assets || []).find((item: any) => {
        const name = String(item.name || "").toLowerCase();
        return name.includes("win") && name.includes("x64") && name.endsWith(".zip") && !name.includes("symbol");
    });
    return {
        currentVersion,
        currentLabel,
        latestVersion,
        newerVersionAvailable,
        updateAvailable: newerVersionAvailable && !skipped,
        skipped,
        releaseUrl: release.html_url,
        publishedAt: release.published_at,
        assetName: asset?.name || "",
        downloadUrl: asset?.browser_download_url || "",
        assetSize: Number(asset?.size || 0)
    };
}

export function findYaraWin64ReleaseAsset(release: any) {
    return (release.assets || []).find((item: any) => {
        const name = String(item.name || "").toLowerCase();
        return name.includes("win64") && name.endsWith(".zip");
    });
}

export async function getLatestYaraEngineRelease(settings: any) {
    const currentLabel = await getCurrentYaraEngineVersion(settings);
    const currentVersion = parseBareVersion(currentLabel);
    const releaseRes = await axios.get("https://api.github.com/repos/VirusTotal/yara/releases/latest", {
        headers: { "User-Agent": "ClamShield" }
    });
    const release = releaseRes.data;
    let installableRelease = release;
    let asset = findYaraWin64ReleaseAsset(release);
    if (!asset) {
        const releasesRes = await axios.get("https://api.github.com/repos/VirusTotal/yara/releases?per_page=20", {
            headers: { "User-Agent": "ClamShield" }
        });
        installableRelease = (releasesRes.data || []).find((item: any) => findYaraWin64ReleaseAsset(item)) || release;
        asset = findYaraWin64ReleaseAsset(installableRelease);
    }
    const sourceLatestVersion = normalizeReleaseVersion(release.tag_name || release.name);
    const latestVersion = normalizeReleaseVersion(installableRelease.tag_name || installableRelease.name);
    const skipped = normalizeVersion(settings.yaraEngineSkippedVersion) === latestVersion;
    const newerVersionAvailable = compareVersions(latestVersion, currentVersion) > 0;
    return {
        currentVersion,
        currentLabel,
        latestVersion,
        sourceLatestVersion,
        sourceLatestHasWindowsAsset: Boolean(findYaraWin64ReleaseAsset(release)),
        newerVersionAvailable,
        updateAvailable: newerVersionAvailable && !skipped,
        skipped,
        releaseUrl: installableRelease.html_url || release.html_url,
        publishedAt: installableRelease.published_at || release.published_at,
        assetName: asset?.name || "",
        downloadUrl: asset?.browser_download_url || "",
        assetSize: Number(asset?.size || 0)
    };
}
