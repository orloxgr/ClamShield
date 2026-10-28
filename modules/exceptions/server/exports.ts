import { execAsync, falsePositiveExportsDir } from "../../../server/core/paths";
import { hashFile } from "../../../server/core/utils";
import { runPowerShellFile } from "../../../server/platform/processes";
import { buildFalsePositiveManifestRows, buildFalsePositiveProviderReport, buildYaraGithubIssue, falsePositiveProviderFolderName, getFalsePositiveProvider, safeExportFileName } from "./reports";
import { randomBytes } from "crypto";
import { existsSync } from "fs";
import fs from "fs/promises";
import path from "path";

export async function copyFalsePositiveSample(item: any, destinationDir: string) {
    if (!item.originalPath || !existsSync(item.originalPath))
        return "";
    await fs.mkdir(destinationDir, { recursive: true });
    const hash = item.sha256 || await hashFile(item.originalPath).catch(() => "");
    const suffix = hash ? hash.slice(0, 12) : randomBytes(4).toString("hex");
    const fileName = `${suffix}-${safeExportFileName(path.basename(item.originalPath))}`;
    const relativePath = path.join(path.basename(destinationDir), fileName);
    await fs.copyFile(item.originalPath, path.join(destinationDir, fileName));
    return relativePath;
}

export async function compressDirectoryToZip(sourceDir: string, zipPath: string) {
    if (process.platform === "win32") {
        await runPowerShellFile(`
$ErrorActionPreference = 'Stop'
$source = ${JSON.stringify(path.join(sourceDir, "*"))}
$destination = ${JSON.stringify(zipPath)}
if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Force }
Compress-Archive -Path $source -DestinationPath $destination -Force
`);
        return;
    }
    const escapedSource = sourceDir.replace(/'/g, "'\\''");
    const escapedZip = zipPath.replace(/'/g, "'\\''");
    await execAsync(`cd '${escapedSource}' && zip -qr '${escapedZip}' .`);
}

export async function exportFalsePositiveResults(settings: any, results: any[], options: any) {
    const includeSamples = options.includeSamples === true;
    const userNote = String(options.userNote || "").trim().slice(0, 4000);
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const exportRoot = path.join(falsePositiveExportsDir, `ClamShield-FalsePositives-${timestamp}`);
    const zipPath = `${exportRoot}.zip`;
    await fs.mkdir(exportRoot, { recursive: true });
    const enriched: any[] = [];
    for (const result of results) {
        const item = { ...result };
        item.available = Boolean(item.originalPath && existsSync(item.originalPath));
        if (item.available) {
            const stat = await fs.stat(item.originalPath).catch(() => null);
            item.sizeBytes = stat?.size || "";
            item.sha256 = item.sha256 || await hashFile(item.originalPath, "sha256").catch(() => "");
            item.sha1 = item.sha1 || await hashFile(item.originalPath, "sha1").catch(() => "");
            item.md5 = item.md5 || await hashFile(item.originalPath, "md5").catch(() => "");
        }
        enriched.push(item);
    }
    const groups = new Map<string, {
        provider: any;
        items: any[];
    }>();
    for (const item of enriched) {
        const provider = getFalsePositiveProvider(item);
        const folder = falsePositiveProviderFolderName(provider);
        if (!groups.has(folder))
            groups.set(folder, { provider, items: [] });
        groups.get(folder)!.items.push(item);
    }
    for (const [folder, group] of groups) {
        const providerDir = path.join(exportRoot, folder);
        const samplesDirName = group.provider.id === "sanesecurity" ? "raw-emails-or-samples" : "samples";
        await fs.mkdir(providerDir, { recursive: true });
        if (includeSamples) {
            for (const item of group.items) {
                item.sampleFile = await copyFalsePositiveSample(item, path.join(providerDir, samplesDirName)).catch(() => "");
            }
        }
        await fs.writeFile(path.join(providerDir, "manifest.csv"), buildFalsePositiveManifestRows(group.items), "utf8");
        await fs.writeFile(path.join(providerDir, "report.md"), buildFalsePositiveProviderReport(group.provider, group.items, { includeSamples, userNote }), "utf8");
        if (group.provider.id === "yara-forge") {
            await fs.writeFile(path.join(providerDir, "github-issue.md"), buildYaraGithubIssue(group.items, { userNote }), "utf8");
        }
    }
    await fs.writeFile(path.join(exportRoot, "README.md"), [
        "# ClamShield False Positive Export",
        "",
        "This package is grouped by provider. Review all files before sharing anything externally.",
        "",
        includeSamples
            ? "Samples are included because the user explicitly opted in. Review them before sharing externally."
            : "Samples are not included.",
        ""
    ].join("\n"), "utf8");
    await compressDirectoryToZip(exportRoot, zipPath);
    return {
        exportRoot,
        zipPath,
        providerCount: groups.size,
        itemCount: enriched.length,
        providers: Array.from(groups.values()).map(group => group.provider.name)
    };
}
