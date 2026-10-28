import { englishText } from "../../../shared/localization/runtime";
import { securiteInfoSecretPath } from "../../../server/core/paths";
import { loadEncryptedSecret, saveEncryptedSecret } from "../../../server/core/secrets";
import { securiteInfoAccountUrl, securiteInfoAllDatabases, securiteInfoBaseUrl, securiteInfoBasicDatabases, securiteInfoPaidDatabases, securiteInfoPuaDatabase, securiteInfoSignupUrl } from "./constants";
import fs from "fs/promises";
import path from "path";
export function normalizeSecuriteInfoPlan(value: any) {
    return String(value || "").toLowerCase() === "paid" ? "paid" : "basic";
}
export function normalizeSecuriteInfoIncludePua(value: any) {
    return value === true;
}
export function getSecuriteInfoDatabaseNames(plan: any, includePua: any = false) {
    if (normalizeSecuriteInfoPlan(plan) !== "paid")
        return securiteInfoBasicDatabases;
    const databases = [...securiteInfoPaidDatabases];
    if (normalizeSecuriteInfoIncludePua(includePua))
        databases.push(securiteInfoPuaDatabase);
    return databases;
}
export function getConfiguredSecuriteInfoDatabaseNames(settings: any) {
    return getSecuriteInfoDatabaseNames(settings?.securiteInfoPlan, settings?.securiteInfoIncludePua);
}
export function extractSecuriteInfoToken(input: any) {
    const text = String(input || "").trim();
    if (!text)
        throw new Error(englishText("backend.securiteinfo.paste_the_databasecustomurl_instructions_from_your_securiteinfo_a"));
    if (text.length > 50000)
        throw new Error(englishText("backend.securiteinfo.the_pasted_securiteinfo_configuration_is_too_large"));
    const urlMatch = text.match(/https:\/\/www\.securiteinfo\.com\/get\/signatures\/([a-f0-9]{64,256})\//i);
    if (urlMatch?.[1])
        return urlMatch[1];
    if (/^[a-f0-9]{64,256}$/i.test(text))
        return text;
    throw new Error(englishText("backend.securiteinfo.no_valid_securiteinfo_personal_signature_url_was_found"));
}
export async function saveSecuriteInfoToken(token: string) {
    await saveEncryptedSecret(securiteInfoSecretPath, token);
}
export async function loadSecuriteInfoToken() {
    return await loadEncryptedSecret(securiteInfoSecretPath);
}
export function redactSecuriteInfoSecret(value: any, token = "") {
    let text = String(value ?? "");
    text = text.replace(/https:\/\/www\.securiteinfo\.com\/get\/signatures\/[^/\s]+/gi, `${securiteInfoBaseUrl}/[redacted]`);
    if (token)
        text = text.split(token).join("[redacted]");
    return text;
}
export async function removeSecuriteInfoDatabaseFiles(databaseDir: string, keep: string[] = []) {
    const keepSet = new Set(keep.map(name => name.toLowerCase()));
    const removed: string[] = [];
    for (const fileName of securiteInfoAllDatabases) {
        if (keepSet.has(fileName.toLowerCase()))
            continue;
        try {
            await fs.unlink(path.join(databaseDir, fileName));
            removed.push(fileName);
        }
        catch (e: any) {
            if (e?.code !== "ENOENT")
                console.warn(englishText("backend.securiteinfo.failed_to_remove_securiteinfo_database", {
                    fileName: String(fileName)
                }), e?.message || e);
        }
    }
    return removed;
}
export async function getSecuriteInfoStatus(settings: any) {
    const connected = Boolean(await loadSecuriteInfoToken());
    const plan = normalizeSecuriteInfoPlan(settings.securiteInfoPlan);
    const includePua = normalizeSecuriteInfoIncludePua(settings.securiteInfoIncludePua);
    const expectedFiles = getSecuriteInfoDatabaseNames(plan, includePua);
    const downloadedFiles: Array<{
        name: string;
        size: number;
        updatedAt: string;
    }> = [];
    for (const name of securiteInfoAllDatabases) {
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
    const expectedNameSet = new Set(expectedFiles.map(name => name.toLowerCase()));
    const newestFile = downloadedFiles
        .filter(file => expectedNameSet.has(file.name.toLowerCase()))
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0];
    return {
        connected,
        enabled: connected && settings.securiteInfoEnabled === true,
        plan,
        includePua,
        puaDatabase: securiteInfoPuaDatabase,
        puaInstalled: downloadedNames.has(securiteInfoPuaDatabase.toLowerCase()),
        expectedCount: expectedFiles.length,
        installedCount: expectedFiles.length - missingFiles.length,
        downloadedFiles,
        missingFiles,
        lastUpdated: settings.lastSecuriteInfoUpdate || newestFile?.updatedAt || null,
        lastResult: settings.lastSecuriteInfoUpdateResult || "",
        signupUrl: securiteInfoSignupUrl,
        accountUrl: securiteInfoAccountUrl
    };
}
