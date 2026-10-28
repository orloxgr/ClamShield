import { normalizePositiveNumber } from "../../../modules/settings/server/validation";
import { ShieldCacheEntry } from "../../../modules/shield/server/types";
import { sleep } from "../../../server/core/utils";
import { ensureAppTempDir } from "../../../server/platform/processes";
import { getFileFingerprint } from "../../../server/scanning/files";
import { createBuiltInScanPathSkipper, walkFiles } from "../../../server/scanning/targets";
import { randomBytes } from "crypto";
import { createWriteStream } from "fs";
import fs from "fs/promises";
import os from "os";
import path from "path";

export function isPathInside(childPath: string, parentPath: string) {
    const child = path.resolve(childPath).toLowerCase();
    const parent = path.resolve(parentPath).replace(/[\\/]+$/, "").toLowerCase();
    return child === parent || child.startsWith(parent + path.sep.toLowerCase()) || child.startsWith(parent + "/");
}

export function shouldSkipYaraTarget(settings: any, filePath: string, fingerprint: ShieldCacheEntry | null, shouldSkipPath = createBuiltInScanPathSkipper(settings)) {
    if (!fingerprint)
        return true;
    const maxBytes = normalizePositiveNumber(settings.yaraMaxFileSize, 50, 1, 4096) * 1024 * 1024;
    if (fingerprint.size > maxBytes)
        return true;
    if (shouldSkipPath(filePath))
        return true;
    const ownYaraPaths = [
        settings.yaraDir,
        settings.yaraRulesDir,
        settings.yaraCustomRulesDir,
        settings.yaraCacheDir
    ].filter(Boolean);
    return ownYaraPaths.some((ownPath: string) => isPathInside(filePath, ownPath));
}

export async function createYaraTargetList(settings: any, targets: string[], onProgress?: (count: number) => void) {
    const listPath = path.join(await ensureAppTempDir(), `clamshield-yara-list-${Date.now()}-${randomBytes(6).toString("hex")}.txt`);
    const writer = createWriteStream(listPath, { encoding: "utf16le" });
    const shouldSkipPath = createBuiltInScanPathSkipper(settings);
    let count = 0;
    let unreadablePathCount = 0;
    try {
        for (const target of targets.filter(Boolean)) {
            let stat;
            try {
                stat = await fs.stat(target);
            }
            catch {
                unreadablePathCount++;
                continue;
            }
            if (stat.isFile()) {
                const fingerprint = await getFileFingerprint(target);
                if (!shouldSkipYaraTarget(settings, target, fingerprint, shouldSkipPath)) {
                    writer.write(`${target}${os.EOL}`);
                    count++;
                }
                continue;
            }
            if (!stat.isDirectory())
                continue;
            for await (const filePath of walkFiles(target, shouldSkipPath)) {
                const fingerprint = await getFileFingerprint(filePath);
                if (shouldSkipYaraTarget(settings, filePath, fingerprint, shouldSkipPath))
                    continue;
                writer.write(`${filePath}${os.EOL}`);
                count++;
                if (count % 5000 === 0)
                    onProgress?.(count);
                if (count % 200 === 0)
                    await sleep(1);
            }
        }
    }
    finally {
        await new Promise<void>((resolve, reject) => {
            writer.end(() => resolve());
            writer.on("error", reject);
        });
    }
    onProgress?.(count);
    return { listPath, count, unreadablePathCount };
}
