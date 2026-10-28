import { hashFile } from "../../../server/core/utils";
import { randomBytes } from "crypto";
import fs from "fs/promises";
import path from "path";

export async function quarantineFile(originalPath: string, threatName: string, quarantineDir: string) {
    await fs.mkdir(quarantineDir, { recursive: true });
    const baseName = path.basename(originalPath);
    const timestampedName = `${Date.now()}_${randomBytes(4).toString("hex")}_${baseName}`;
    const destPath = path.join(quarantineDir, timestampedName);
    const sha256 = await hashFile(originalPath).catch(() => null);
    try {
        await fs.rename(originalPath, destPath);
    }
    catch {
        await fs.copyFile(originalPath, destPath);
        await fs.unlink(originalPath);
    }
    if (process.platform !== "win32") {
        await fs.chmod(destPath, 0o600).catch(() => { });
    }
    return {
        fileName: timestampedName,
        destPath,
        metadata: {
            originalPath,
            threatName,
            sha256,
            timestamp: Date.now()
        }
    };
}
