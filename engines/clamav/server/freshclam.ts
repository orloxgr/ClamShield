import { englishText } from "../../../shared/localization/runtime";
import { securiteInfoBaseUrl } from "../../../addons/securiteinfo/server/constants";
import { getConfiguredSecuriteInfoDatabaseNames, loadSecuriteInfoToken, redactSecuriteInfoSecret } from "../../../addons/securiteinfo/server/service";
import { appTempDir, defaultLogsDir, engineBaseDir } from "../../../server/core/paths";
import { ensureAppTempDir, runHiddenProcess } from "../../../server/platform/processes";
import { pathExists } from "../../../server/scanning/files";
import { freshclamRunTimeoutMs } from "./constants";
import { spawn } from "child_process";
import { randomBytes } from "crypto";
import fs from "fs/promises";
import os from "os";
import path from "path";
export async function ensureFreshclamConfig(settings: any) {
    await fs.mkdir(settings.databaseDir, { recursive: true });
    await fs.mkdir(settings.logsDir || defaultLogsDir, { recursive: true });
    if (!settings.freshclamConf) {
        settings.freshclamConf = path.join(settings.clamavDir || path.join(engineBaseDir, "clamav"), "freshclam.conf");
    }
    await fs.mkdir(path.dirname(settings.freshclamConf), { recursive: true });
    const confContent = `DatabaseDirectory ${settings.databaseDir}\nUpdateLogFile ${path.join(settings.logsDir || defaultLogsDir, 'freshclam.log')}\nDatabaseMirror database.clamav.net\n`;
    await fs.writeFile(settings.freshclamConf, confContent);
}
export async function cleanupStaleFreshclamSecretFiles() {
    // Retain narrow cleanup of secret files left in Windows Temp by older versions.
    for (const tempDir of new Set([appTempDir, os.tmpdir()])) {
        try {
            const entries = await fs.readdir(tempDir, { withFileTypes: true });
            await Promise.all(entries
                .filter(entry => entry.isFile() && entry.name.startsWith("clamshield-freshclam-"))
                .map(async (entry) => {
                const target = path.join(tempDir, entry.name);
                try {
                    const stat = await fs.stat(target);
                    if (Date.now() - stat.mtimeMs > 6 * 60 * 60 * 1000) {
                        await fs.unlink(target);
                    }
                }
                catch {
                    // Ignore stale-file cleanup races.
                }
            }));
        }
        catch {
            // Best-effort cleanup for temporary configs that may contain a private URL.
        }
    }
}
export const windowsRootStorePrimedHosts = new Set<string>();
// FreshClam verifies TLS against the certificates already in the Windows root store, but it never
// triggers Windows' automatic root certificate download. A fresh Windows install does not have the
export // root behind database.clamav.net yet (GlobalSign Root CA), so every update fails with
// "SSL peer certificate or SSH remote key was not OK". One native Windows HTTPS request to the same
// host makes Windows fetch the missing root, after which FreshClam succeeds.
async function primeWindowsRootStore(hosts: string[]) {
    if (process.platform !== "win32")
        return;
    for (const host of hosts) {
        if (windowsRootStorePrimedHosts.has(host))
            continue;
        // An HTTP error response still means the TLS handshake (and the root fetch) succeeded.
        const script = `try { Invoke-WebRequest -Uri 'https://${host}/' -UseBasicParsing -Method Head -TimeoutSec 15 | Out-Null; 'ok' } catch { if ($_.Exception.Response) { 'ok' } else { 'fail' } }`;
        try {
            const result = await runHiddenProcess("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { timeoutMs: 30000 });
            if (/\bok\b/.test(result.stdout))
                windowsRootStorePrimedHosts.add(host);
        }
        catch (e: any) {
            console.warn(englishText("backend.clamav.could_not_prime_the_windows_root_store_for", {
                host: String(host)
            }), e?.message || e);
        }
    }
}
export async function prepareFreshclamConfig(settings: any, options: {
    includeOfficial?: boolean;
    includeSecuriteInfo?: boolean;
} = {}) {
    const includeOfficial = options.includeOfficial !== false;
    const includeSecuriteInfo = options.includeSecuriteInfo === true;
    await ensureFreshclamConfig(settings);
    // FreshClam always contacts the official mirror, even for SecuriteInfo-only runs.
    await primeWindowsRootStore(includeSecuriteInfo && settings.securiteInfoEnabled === true
        ? ["database.clamav.net", new URL(securiteInfoBaseUrl).host]
        : ["database.clamav.net"]);
    if (!includeSecuriteInfo || settings.securiteInfoEnabled !== true) {
        if (includeOfficial) {
            return {
                configPath: settings.freshclamConf,
                securiteInfoEnabled: false,
                officialEnabled: true,
                redact: (value: any) => String(value ?? ""),
                cleanup: async () => { }
            };
        }
        const suffix = `${Date.now()}-${randomBytes(6).toString("hex")}`;
        const tempDir = await ensureAppTempDir();
        const configPath = path.join(tempDir, `clamshield-freshclam-${suffix}.conf`);
        const logPath = path.join(tempDir, `clamshield-freshclam-${suffix}.log`);
        await fs.writeFile(configPath, `DatabaseDirectory ${settings.databaseDir}\nUpdateLogFile ${logPath}\n`, { mode: 0o600 });
        return {
            configPath,
            securiteInfoEnabled: false,
            officialEnabled: false,
            redact: (value: any) => String(value ?? ""),
            cleanup: async () => {
                await Promise.all([
                    fs.unlink(configPath).catch(() => { }),
                    fs.unlink(logPath).catch(() => { })
                ]);
            }
        };
    }
    const token = await loadSecuriteInfoToken();
    if (!token) {
        throw new Error(englishText("backend.clamav.securiteinfo_is_enabled_but_its_encrypted_account_token_is_unavai"));
    }
    const tempDir = await ensureAppTempDir();
    await cleanupStaleFreshclamSecretFiles();
    const suffix = `${Date.now()}-${randomBytes(6).toString("hex")}`;
    const configPath = path.join(tempDir, `clamshield-freshclam-${suffix}.conf`);
    const logPath = path.join(tempDir, `clamshield-freshclam-${suffix}.log`);
    const databases = getConfiguredSecuriteInfoDatabaseNames(settings);
    const lines = [
        `DatabaseDirectory ${settings.databaseDir}`,
        `UpdateLogFile ${logPath}`,
        // FreshClam requires at least one mirror even when updating custom URLs.
        "DatabaseMirror database.clamav.net",
        ...databases.map(fileName => `DatabaseCustomURL ${securiteInfoBaseUrl}/${token}/${fileName}`)
    ];
    await fs.writeFile(configPath, `${lines.join("\n")}\n`, { mode: 0o600 });
    return {
        configPath,
        securiteInfoEnabled: true,
        officialEnabled: includeOfficial,
        redact: (value: any) => redactSecuriteInfoSecret(value, token),
        cleanup: async () => {
            await Promise.all([
                fs.unlink(configPath).catch(() => { }),
                fs.unlink(logPath).catch(() => { })
            ]);
        }
    };
}
export async function runFreshclamWithConfig(settings: any, preparedConfig: Awaited<ReturnType<typeof prepareFreshclamConfig>>, options: {
    onLine?: (line: string) => void;
    onProcess?: (child: any) => void;
    timeoutMs?: number;
} = {}) {
    if (!await pathExists(settings.freshclamPath)) {
        throw new Error(englishText("backend.clamav.freshclam_executable_was_not_found_at_reinstall_the_clamav_engine", {
            freshclamPath: String(settings.freshclamPath)
        }));
    }
    const args = ["--config-file=" + preparedConfig.configPath, "--datadir=" + settings.databaseDir];
    if (preparedConfig.securiteInfoEnabled && !preparedConfig.officialEnabled) {
        args.push("--update-db=custom");
    }
    return await new Promise<number>((resolve, reject) => {
        let settled = false;
        const settle = (callback: () => void) => {
            if (settled)
                return;
            settled = true;
            callback();
        };
        const child = spawn(settings.freshclamPath, args, { windowsHide: true });
        options.onProcess?.(child);
        const handleOutput = (data: Buffer) => {
            const lines = data.toString()
                .split("\n")
                .map((line: string) => preparedConfig.redact(line.trim()))
                .filter(Boolean);
            lines.forEach(line => options.onLine?.(line));
        };
        child.stdout.on("data", handleOutput);
        child.stderr.on("data", handleOutput);
        const timeoutMs = options.timeoutMs ?? freshclamRunTimeoutMs;
        const timer = timeoutMs > 0 ? setTimeout(() => {
            settle(() => {
                options.onLine?.(`FreshClam did not finish within ${Math.round(timeoutMs / 60000)} minutes and was stopped.`);
                try {
                    child.kill();
                }
                catch { }
                resolve(-2);
            });
        }, timeoutMs) : null;
        child.on("error", (err: any) => {
            if (timer)
                clearTimeout(timer);
            settle(() => reject(new Error(preparedConfig.redact(err.message || String(err)))));
        });
        child.on("close", code => {
            if (timer)
                clearTimeout(timer);
            settle(() => resolve(code ?? 0));
        });
    });
}
