import { englishText } from "../../shared/localization/runtime";
import { defaultSettings } from "../../modules/settings/server/schema";
import { pathExists } from "../scanning/files";
import { engineBaseDir } from "./paths";
import { sleep } from "./utils";
import { randomUUID } from 'node:crypto';
import fs from "fs/promises";
import path from "path";
export async function retryRemovePath(targetPath: string, attempts = 5) {
    for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
            await fs.rm(targetPath, { recursive: true, force: true });
            return;
        }
        catch (e: any) {
            if (attempt === attempts)
                throw e;
            await sleep(500 * attempt);
        }
    }
}
export async function retryCopyDirectory(sourcePath: string, targetPath: string, attempts = 3) {
    for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
            await fs.cp(sourcePath, targetPath, { recursive: true, force: true });
            return;
        }
        catch (e: any) {
            if (attempt === attempts)
                throw e;
            await sleep(500 * attempt);
        }
    }
}
export async function findExtractedClamavDir() {
    const entries = await fs.readdir(engineBaseDir, { withFileTypes: true });
    const candidates = entries
        .filter(entry => entry.isDirectory() && entry.name.toLowerCase().startsWith("clamav") && entry.name.toLowerCase() !== "clamav")
        .map(entry => path.join(engineBaseDir, entry.name));
    for (const candidate of candidates) {
        if (await pathExists(path.join(candidate, "clamscan.exe")) && await pathExists(path.join(candidate, "freshclam.exe"))) {
            return candidate;
        }
    }
    return "";
}
export async function commitStagedEngineDirectory(stagingDir: string, finalDir: string) {
    const backup = `${finalDir}.previous-${randomUUID()}`;
    const previous = await pathExists(finalDir);
    if (previous) await fs.rename(finalDir, backup);
    try { await fs.rename(stagingDir, finalDir); }
    catch (error) {
        if (previous) {
            try { await fs.rename(backup, finalDir); }
            catch (rollback) { throw new AggregateError([error, rollback], `Engine replacement failed; previous engine is retained at ${backup}`); }
        }
        throw error;
    }
    if (previous) await retryRemovePath(backup).catch(error => console.warn('Previous engine cleanup deferred:', backup, error.message));
}
export async function adoptClamavEngineFolder(sourceDir: string) {
    const finalClamDir = path.join(engineBaseDir, "clamav");
    const stagingDir = path.join(engineBaseDir, `clamav-staging-${Date.now()}`);
    try {
        await retryRemovePath(stagingDir);
        await retryCopyDirectory(sourceDir, stagingDir);
        await commitStagedEngineDirectory(stagingDir, finalClamDir);
        if (path.resolve(sourceDir).toLowerCase() !== path.resolve(finalClamDir).toLowerCase()) {
            await retryRemovePath(sourceDir).catch(e => console.debug(englishText("backend.core.clamav_extracted_folder_cleanup_failed"), e?.message || e));
        }
        return finalClamDir;
    }
    catch (e: any) {
        await retryRemovePath(stagingDir).catch(() => { });
        if (e?.code === "EPERM" || e?.code === "EBUSY" || e?.code === "EACCES") {
            throw new Error(englishText("backend.core.windows_blocked_replacing_the_clamav_engine_folder_close_clamshie", {
                code: String(e.code)
            }));
        }
        throw e;
    }
}
export async function adoptYaraEngineFolder(sourceDir: string, finalYaraDir: string) {
    const normalizedFinalDir = path.resolve(finalYaraDir).toLowerCase();
    const normalizedManagedDir = path.resolve(defaultSettings.yaraDir).toLowerCase();
    if (normalizedFinalDir !== normalizedManagedDir) {
        await fs.mkdir(finalYaraDir, { recursive: true });
        await retryCopyDirectory(sourceDir, finalYaraDir);
        return finalYaraDir;
    }
    const stagingDir = path.join(engineBaseDir, `yara-staging-${Date.now()}`);
    try {
        await retryRemovePath(stagingDir);
        await retryCopyDirectory(sourceDir, stagingDir);
        await commitStagedEngineDirectory(stagingDir, finalYaraDir);
        return finalYaraDir;
    }
    catch (e: any) {
        await retryRemovePath(stagingDir).catch(() => { });
        if (e?.code === "EPERM" || e?.code === "EBUSY" || e?.code === "EACCES") {
            throw new Error(englishText("backend.core.windows_blocked_replacing_the_yara_engine_folder_close_clamshield", {
                code: String(e.code)
            }));
        }
        throw e;
    }
}
