import { englishText } from "../../shared/localization/runtime";
import { runPowerShellJson } from "../platform/processes";
import { walkFiles } from "../scanning/targets";
import { formatBytes } from "./utils";
import axios from "axios";
import { createReadStream, createWriteStream } from "fs";
import fs from "fs/promises";
import path from "path";
import unzipper from "unzipper";
export async function downloadFile(url: string, destination: string, onProgress?: (message: string) => void) {
    await fs.mkdir(path.dirname(destination), { recursive: true });
    const temporaryPath = `${destination}.download`;
    await fs.unlink(temporaryPath).catch(() => { });
    const response = await axios({
        url,
        method: "GET",
        responseType: "stream",
        maxRedirects: 5,
        timeout: 120000
    });
    const totalBytes = Number(response.headers["content-length"] || 0);
    let downloadedBytes = 0;
    let lastReportedPercent = -10;
    const writer = createWriteStream(temporaryPath);
    response.data.on("data", (chunk: Buffer) => {
        downloadedBytes += chunk.length;
        if (totalBytes > 0) {
            const percent = Math.floor((downloadedBytes / totalBytes) * 100);
            if (percent >= lastReportedPercent + 10) {
                lastReportedPercent = percent;
                onProgress?.(englishText("backend.core.download_progress", {
                    value1: String(Math.min(100, percent))
                }));
            }
        }
    });
    response.data.pipe(writer);
    await new Promise<void>((resolve, reject) => {
        writer.on("finish", resolve);
        writer.on("error", reject);
        response.data.on("error", reject);
    });
    await fs.unlink(destination).catch(() => { });
    await fs.rename(temporaryPath, destination);
}
export async function verifyAuthenticodeSignature(filePath: string) {
    const quotedPath = filePath.replace(/'/g, "''");
    const result = await runPowerShellJson(`
$signature = Get-AuthenticodeSignature -LiteralPath '${quotedPath}'
'CLAMSHIELD_JSON_START'
[ordered]@{
  Status = [string]$signature.Status
  Subject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { '' }
  Thumbprint = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Thumbprint } else { '' }
} | ConvertTo-Json -Compress
'CLAMSHIELD_JSON_END'
`);
    if (result?.Status !== "Valid") {
        throw new Error(englishText("backend.core.the_downloaded_helper_has_an_invalid_authenticode_signature", {
            value1: String(result?.Status || englishText("results.unknown"))
        }));
    }
    return result;
}
export type DownloadToFileOptions = {
    headers?: Record<string, string>;
    resume?: boolean;
    expectedSize?: number;
};
export async function downloadToFile(url: string, destination: string, onProgress?: (message: string) => void, headersOrOptions: Record<string, string> | DownloadToFileOptions = {}) {
    await fs.mkdir(path.dirname(destination), { recursive: true });
    const options: DownloadToFileOptions = Object.prototype.hasOwnProperty.call(headersOrOptions, "headers") ||
        Object.prototype.hasOwnProperty.call(headersOrOptions, "resume") ||
        Object.prototype.hasOwnProperty.call(headersOrOptions, "expectedSize")
        ? headersOrOptions as DownloadToFileOptions
        : { headers: headersOrOptions as Record<string, string> };
    const requestHeaders = { ...(options.headers || {}) };
    let resumeFrom = 0;
    if (options.resume) {
        try {
            const stat = await fs.stat(destination);
            const expectedSize = Number(options.expectedSize || 0);
            if (stat.isFile() && stat.size > 0 && (!expectedSize || stat.size < expectedSize)) {
                resumeFrom = stat.size;
                requestHeaders.Range = `bytes=${resumeFrom}-`;
                onProgress?.(englishText("backend.core.resuming_download_from", {
                    value1: String(formatBytes(resumeFrom))
                }));
            }
            else if (stat.isFile() && expectedSize > 0 && stat.size === expectedSize) {
                onProgress?.(englishText("backend.core.using_existing_download", {
                    value1: String(formatBytes(stat.size))
                }));
                return;
            }
        }
        catch {
            // No partial download to resume.
        }
    }
    const response = await axios({
        url,
        method: "GET",
        responseType: "stream",
        headers: { "User-Agent": "ClamShield", ...requestHeaders }
    });
    if (resumeFrom > 0 && response.status !== 206) {
        resumeFrom = 0;
        onProgress?.(englishText("backend.core.download_server_did_not_resume_restarting_download"));
    }
    const contentLength = Number(response.headers["content-length"] || 0);
    const total = Number(options.expectedSize || 0) || (resumeFrom > 0 && response.status === 206 ? resumeFrom + contentLength : contentLength);
    let downloaded = resumeFrom;
    let lastReportedPercent = -1;
    let lastReportedAt = 0;
    const startedAt = Date.now();
    const formatSpeed = (bytesPerSecond: number) => {
        if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0)
            return "0 KB/s";
        if (bytesPerSecond >= 1024 * 1024)
            return `${(bytesPerSecond / 1024 / 1024).toFixed(1)} MB/s`;
        return `${Math.max(1, Math.round(bytesPerSecond / 1024))} KB/s`;
    };
    const formatEta = (seconds: number) => {
        if (!Number.isFinite(seconds) || seconds <= 0)
            return "";
        if (seconds >= 3600)
            return `${Math.ceil(seconds / 3600)}h`;
        if (seconds >= 60)
            return `${Math.ceil(seconds / 60)}m`;
        return `${Math.ceil(seconds)}s`;
    };
    const reportProgress = (force = false) => {
        const now = Date.now();
        const elapsedSeconds = Math.max(0.001, (now - startedAt) / 1000);
        const sessionDownloaded = Math.max(0, downloaded - resumeFrom);
        const bytesPerSecond = sessionDownloaded / elapsedSeconds;
        const speed = formatSpeed(bytesPerSecond);
        if (total > 0) {
            const percent = Math.min(100, Math.floor((downloaded / total) * 100));
            if (!force && percent === lastReportedPercent && now - lastReportedAt < 2000)
                return;
            if (!force && percent < lastReportedPercent + 2 && now - lastReportedAt < 2000)
                return;
            lastReportedPercent = percent;
            lastReportedAt = now;
            const eta = formatEta((total - downloaded) / bytesPerSecond);
            onProgress?.(englishText("backend.core.downloaded_of", {
                percent: String(percent),
                value2: String(formatBytes(downloaded)),
                value3: String(formatBytes(total)),
                speed: String(speed),
                value5: String(eta ? englishText("backend.core.remaining", {
                    eta: String(eta)
                }) : "")
            }));
            return;
        }
        if (!force && now - lastReportedAt < 2000)
            return;
        lastReportedAt = now;
        onProgress?.(englishText("backend.core.downloaded", {
            value1: String(formatBytes(downloaded)),
            speed: String(speed)
        }));
    };
    response.data.on("data", (chunk: Buffer) => {
        downloaded += chunk.length;
        reportProgress();
    });
    const writer = createWriteStream(destination, { flags: resumeFrom > 0 ? "a" : "w" });
    response.data.pipe(writer);
    await new Promise<void>((resolve, reject) => {
        writer.on("finish", () => {
            reportProgress(true);
            resolve();
        });
        writer.on("error", reject);
        response.data.on("error", reject);
    });
}
export async function extractZip(zipPath: string, destination: string) {
    await fs.mkdir(destination, { recursive: true });
    const extractStream = createReadStream(zipPath).pipe(unzipper.Extract({ path: destination }));
    await new Promise<void>((resolve, reject) => {
        extractStream.on("close", resolve);
        extractStream.on("error", reject);
    });
}
export async function findFileByName(rootPath: string, fileName: string): Promise<string | null> {
    for await (const filePath of walkFiles(rootPath)) {
        if (path.basename(filePath).toLowerCase() === fileName.toLowerCase()) {
            return filePath;
        }
    }
    return null;
}
