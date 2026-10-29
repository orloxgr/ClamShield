import { englishText } from "../../../shared/localization/runtime";
import { pathExists } from "../../../server/scanning/files";
import { saneSecurityAllDatabases, saneSecurityCompleteDatabases, saneSecurityCygpathPath, saneSecurityDonateUrl, saneSecurityGpgPath, saneSecurityMalwareDatabases, saneSecurityRsyncPath, saneSecurityUsageUrl, saneSecurityWebsiteUrl } from "./constants";
import fs from "fs/promises";
import path from "path";
export function normalizeSaneSecurityProfile(value: any) {
    return String(value || "").toLowerCase() === "complete" ? "complete" : "malware";
}
export function getSaneSecurityDatabaseNames(profile: any) {
    return normalizeSaneSecurityProfile(profile) === "complete"
        ? saneSecurityCompleteDatabases
        : saneSecurityMalwareDatabases;
}
export async function removeSaneSecurityDatabaseFiles(databaseDir: string, keep: string[] = []) {
    const keepSet = new Set(keep.map(name => name.toLowerCase()));
    const removed: string[] = [];
    for (const fileName of saneSecurityAllDatabases) {
        if (keepSet.has(fileName.toLowerCase()))
            continue;
        try {
            await fs.unlink(path.join(databaseDir, fileName));
            removed.push(fileName);
        }
        catch (e: any) {
            if (e?.code !== "ENOENT")
                console.warn(englishText("backend.sanesecurity.failed_to_remove_sanesecurity_database", {
                    fileName: String(fileName)
                }), e?.message || e);
        }
    }
    return removed;
}
export async function getSaneSecurityStatus(settings: any) {
    const profile = normalizeSaneSecurityProfile(settings.saneSecurityProfile);
    const expectedFiles = getSaneSecurityDatabaseNames(profile);
    const downloadedFiles: Array<{
        name: string;
        size: number;
        updatedAt: string;
    }> = [];
    for (const name of saneSecurityAllDatabases) {
        try {
            const stat = await fs.stat(path.join(settings.databaseDir, name));
            downloadedFiles.push({
                name,
                size: stat.size,
                updatedAt: stat.mtime.toISOString()
            });
        }
        catch {
            // Missing files are reported below.
        }
    }
    const downloadedNames = new Set(downloadedFiles.map(file => file.name.toLowerCase()));
    const missingFiles = expectedFiles.filter(name => !downloadedNames.has(name.toLowerCase()));
    const newestFile = [...downloadedFiles].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0];
    const toolsInstalled = await pathExists(saneSecurityRsyncPath) &&
        await pathExists(saneSecurityGpgPath) &&
        await pathExists(saneSecurityCygpathPath);
    const installedCount = expectedFiles.length - missingFiles.length;
    return {
        connected: settings.saneSecurityEnabled === true,
        enabled: settings.saneSecurityEnabled === true,
        profile,
        expectedCount: expectedFiles.length,
        installedCount,
        installed: installedCount > 0,
        ready: settings.saneSecurityEnabled === true && installedCount > 0,
        downloadedFiles,
        missingFiles,
        toolsInstalled,
        helperSizeEstimateMb: 50,
        lastUpdated: settings.lastSaneSecurityUpdate || newestFile?.updatedAt || null,
        lastResult: settings.lastSaneSecurityUpdateResult || "",
        websiteUrl: saneSecurityWebsiteUrl,
        usageUrl: saneSecurityUsageUrl,
        donateUrl: saneSecurityDonateUrl
    };
}
