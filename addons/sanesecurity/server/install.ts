import { englishText } from "../../../shared/localization/runtime";
import { downloadFile, verifyAuthenticodeSignature } from "../../../server/core/downloads";
import { appTempDir } from "../../../server/core/paths";
import { runHiddenProcess } from "../../../server/platform/processes";
import { pathExists } from "../../../server/scanning/files";
import { saneSecurityCygpathPath, saneSecurityCygwinMirrorUrls, saneSecurityCygwinSetupUrl, saneSecurityGpgHomeDir, saneSecurityGpgPath, saneSecurityMirrorHost, saneSecurityPublicKeyUrl, saneSecurityRsyncPath, saneSecuritySetupPath, saneSecuritySigningKeyFingerprint, saneSecurityToolsCacheDir, saneSecurityToolsDir, saneSecurityWorkingDir } from "./constants";
import { getSaneSecurityDatabaseNames, removeSaneSecurityDatabaseFiles } from "./status";
import { resolve4 } from "dns/promises";
import fs from "fs/promises";
import path from "path";
export async function ensureSaneSecurityTools(onLog: (line: string) => void) {
    if (await pathExists(saneSecurityRsyncPath) &&
        await pathExists(saneSecurityGpgPath) &&
        await pathExists(saneSecurityCygpathPath)) {
        onLog(englishText("backend.sanesecurity.sanesecurity_helper_tools_are_already_installed"));
        return;
    }
    if (process.platform !== "win32") {
        throw new Error(englishText("backend.sanesecurity.automatic_sanesecurity_helper_installation_is_currently_supported"));
    }
    onLog(englishText("backend.sanesecurity.first_time_setup_downloading_the_official_signed_cygwin_installer"));
    await downloadFile(saneSecurityCygwinSetupUrl, saneSecuritySetupPath, onLog);
    const signature = await verifyAuthenticodeSignature(saneSecuritySetupPath);
    onLog(englishText("backend.sanesecurity.cygwin_installer_signature_verified", {
        value1: String(signature.Subject || signature.Thumbprint || englishText("backend.sanesecurity.valid_signer"))
    }));
    await fs.mkdir(saneSecurityToolsDir, { recursive: true });
    await fs.mkdir(saneSecurityToolsCacheDir, { recursive: true });
    let lastError = "";
    for (const mirrorUrl of saneSecurityCygwinMirrorUrls) {
        onLog(englishText("backend.sanesecurity.installing_rsync_and_gnupg_from", {
            mirrorUrl: String(mirrorUrl)
        }));
        const result = await runHiddenProcess(saneSecuritySetupPath, [
            "-q",
            "-W",
            "-O",
            "-B",
            "-n",
            "-d",
            "-N",
            "-R", saneSecurityToolsDir,
            "-l", saneSecurityToolsCacheDir,
            "-s", mirrorUrl,
            "-P", "rsync,gnupg2"
        ], {
            timeoutMs: 15 * 60 * 1000,
            onLine: line => {
                if (/error|warning|install|download|package/i.test(line))
                    onLog(line);
            }
        });
        if (result.code === 0 &&
            await pathExists(saneSecurityRsyncPath) &&
            await pathExists(saneSecurityGpgPath) &&
            await pathExists(saneSecurityCygpathPath)) {
            onLog(englishText("backend.sanesecurity.sanesecurity_helper_tools_installed_successfully"));
            return;
        }
        lastError = (result.stderr || result.stdout || `Cygwin setup exited with code ${result.code}`).trim();
        onLog(englishText("backend.sanesecurity.helper_installation_failed_from_this_mirror_trying_another_mirror"));
    }
    throw new Error(lastError || englishText("backend.sanesecurity.could_not_install_the_sanesecurity_helper_tools"));
}
export async function toCygwinPath(windowsPath: string) {
    const result = await runHiddenProcess(saneSecurityCygpathPath, ["-u", windowsPath], { timeoutMs: 30000 });
    if (result.code !== 0 || !result.stdout.trim()) {
        throw new Error(englishText("backend.sanesecurity.could_not_convert_a_windows_path_for_rsync", {
            windowsPath: String(windowsPath)
        }));
    }
    return result.stdout.trim();
}
export async function ensureSaneSecuritySigningKey(onLog: (line: string) => void) {
    await fs.mkdir(saneSecurityGpgHomeDir, { recursive: true });
    const keyPath = path.join(saneSecurityWorkingDir, "publickey.gpg");
    onLog(englishText("backend.sanesecurity.downloading_the_official_sanesecurity_signing_key"));
    await downloadFile(saneSecurityPublicKeyUrl, keyPath);
    const [gpgHome, keyFile] = await Promise.all([
        toCygwinPath(saneSecurityGpgHomeDir),
        toCygwinPath(keyPath)
    ]);
    const imported = await runHiddenProcess(saneSecurityGpgPath, [
        "--batch",
        "--no-autostart",
        "--homedir", gpgHome,
        "--import", keyFile
    ], { timeoutMs: 60000 });
    if (imported.code !== 0) {
        throw new Error((imported.stderr || imported.stdout || "Could not import the SaneSecurity signing key.").trim());
    }
    const fingerprints = await runHiddenProcess(saneSecurityGpgPath, [
        "--batch",
        "--no-autostart",
        "--homedir", gpgHome,
        "--with-colons",
        "--fingerprint"
    ], { timeoutMs: 60000 });
    const normalizedOutput = `${fingerprints.stdout}\n${fingerprints.stderr}`.replace(/\s/g, "").toUpperCase();
    if (!normalizedOutput.includes(saneSecuritySigningKeyFingerprint)) {
        throw new Error(englishText("backend.sanesecurity.the_downloaded_sanesecurity_signing_key_fingerprint_did_not_match"));
    }
    onLog(englishText("backend.sanesecurity.sanesecurity_signing_key_verified", {
        value1: String(saneSecuritySigningKeyFingerprint.slice(-16))
    }));
    return gpgHome;
}
export async function replaceDatabaseFile(sourcePath: string, destinationPath: string) {
    const temporaryPath = `${destinationPath}.clamshield-new`;
    const backupPath = `${destinationPath}.clamshield-backup`;
    await fs.copyFile(sourcePath, temporaryPath);
    await fs.unlink(backupPath).catch(() => { });
    let hadExistingFile = false;
    try {
        await fs.rename(destinationPath, backupPath);
        hadExistingFile = true;
    }
    catch (e: any) {
        if (e?.code !== "ENOENT") {
            await fs.unlink(temporaryPath).catch(() => { });
            throw e;
        }
    }
    try {
        await fs.rename(temporaryPath, destinationPath);
        await fs.unlink(backupPath).catch(() => { });
    }
    catch (e) {
        await fs.unlink(temporaryPath).catch(() => { });
        if (hadExistingFile) {
            await fs.rename(backupPath, destinationPath).catch(() => { });
        }
        throw e;
    }
}
export async function downloadAndInstallSaneSecurityDatabases(settings: any, onLog: (line: string) => void) {
    await ensureSaneSecurityTools(onLog);
    const gpgHome = await ensureSaneSecuritySigningKey(onLog);
    const databases = getSaneSecurityDatabaseNames(settings.saneSecurityProfile);
    const stagingDir = path.join(saneSecurityWorkingDir, "staging");
    await fs.mkdir(stagingDir, { recursive: true });
    const includePath = path.join(saneSecurityWorkingDir, "include.txt");
    const includeLines = databases.flatMap(name => [name, `${name}.sig`]);
    await fs.writeFile(includePath, `${includeLines.join("\n")}\n`, "ascii");
    const [includeFile, stagingDirectory] = await Promise.all([
        toCygwinPath(includePath),
        toCygwinPath(stagingDir)
    ]);
    const mirrorAddresses = await resolve4(saneSecurityMirrorHost).catch(() => []);
    const mirrors = Array.from(new Set([
        ...mirrorAddresses.map(address => `rsync://${address}/sanesecurity`),
        `rsync://${saneSecurityMirrorHost}/sanesecurity`
    ]));
    let downloaded = false;
    let lastRsyncError = "";
    for (const mirror of mirrors) {
        onLog(englishText("backend.sanesecurity.downloading_sanesecurity_databases_from", {
            length: String(databases.length),
            mirror: String(mirror)
        }));
        const result = await runHiddenProcess(saneSecurityRsyncPath, [
            "--no-motd",
            `--files-from=${includeFile}`,
            "-tu",
            "--timeout=120",
            mirror,
            stagingDirectory
        ], {
            timeoutMs: 5 * 60 * 1000,
            onLine: line => {
                if (/receiving|sent|total size|error|failed/i.test(line))
                    onLog(line);
            }
        });
        if (result.code === 0 || result.code === 23) {
            const allFilesPresent = (await Promise.all(databases.flatMap(name => [
                pathExists(path.join(stagingDir, name)),
                pathExists(path.join(stagingDir, `${name}.sig`))
            ]))).every(Boolean);
            if (allFilesPresent) {
                downloaded = true;
                break;
            }
        }
        lastRsyncError = (result.stderr || result.stdout || `rsync exited with code ${result.code}`).trim();
        if (/refuse\s+--compress|\(-z\)|--compress/i.test(lastRsyncError)) {
            onLog(englishText("backend.sanesecurity.this_mirror_refused_rsync_compression_retrying_mirrors_without_co"));
        }
        onLog(englishText("backend.sanesecurity.this_mirror_failed_trying_the_next_sanesecurity_mirror"));
    }
    if (!downloaded) {
        throw new Error(lastRsyncError || englishText("backend.sanesecurity.could_not_download_all_sanesecurity_databases_ensure_tcp_port_873"));
    }
    const testFile = path.join(saneSecurityWorkingDir, "scan-test.txt");
    await fs.writeFile(testFile, "ClamShield SaneSecurity database integrity test\n", "ascii");
    for (const name of databases) {
        onLog(englishText("backend.sanesecurity.verifying", {
            name: String(name)
        }));
        const databasePath = path.join(stagingDir, name);
        const signaturePath = `${databasePath}.sig`;
        const [databaseFile, signatureFile] = await Promise.all([
            toCygwinPath(databasePath),
            toCygwinPath(signaturePath)
        ]);
        const signatureResult = await runHiddenProcess(saneSecurityGpgPath, [
            "--batch",
            "--no-autostart",
            "--homedir", gpgHome,
            "--verify", signatureFile, databaseFile
        ], { timeoutMs: 60000 });
        if (signatureResult.code !== 0) {
            throw new Error(englishText("backend.sanesecurity.sanesecurity_gpg_verification_failed_for", {
                name: String(name)
            }));
        }
        const clamResult = await runHiddenProcess(settings.clamscanPath, [
            "--quiet",
            `--tempdir=${appTempDir}`,
            `--database=${databasePath}`,
            testFile
        ], { timeoutMs: 120000 });
        if (clamResult.code !== 0) {
            throw new Error(englishText("backend.sanesecurity.clamav_rejected_the_database_during_integrity_testing", {
                name: String(name)
            }));
        }
    }
    await fs.mkdir(settings.databaseDir, { recursive: true });
    for (const name of databases) {
        await replaceDatabaseFile(path.join(stagingDir, name), path.join(settings.databaseDir, name));
        onLog(englishText("backend.sanesecurity.installed", {
            name: String(name)
        }));
    }
    await removeSaneSecurityDatabaseFiles(settings.databaseDir, databases);
    return databases;
}
