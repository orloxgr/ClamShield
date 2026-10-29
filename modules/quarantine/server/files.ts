import { hashFile } from "../../../server/core/utils";
import { randomBytes } from "crypto";
import { constants } from 'node:fs';
import fs from "fs/promises";
import path from "path";

export async function moveFileWithoutOverwrite(source: string, destination: string, expectedHash?: string) {
    const info = await fs.lstat(source);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error('Cannot move a linked or non-regular file.');
    // COPYFILE_EXCL closes the exists-check/rename overwrite race and also works
    // across volumes. Remove the source only after verifying the copied content.
    await fs.copyFile(source, destination, constants.COPYFILE_EXCL);
    try {
        const copiedHash = await hashFile(destination);
        if ((expectedHash && copiedHash !== expectedHash) || copiedHash !== await hashFile(source)) throw new Error('File changed during transfer; the source was retained.');
        await fs.unlink(source);
        return copiedHash;
    } catch (error) {
        await fs.unlink(destination).catch(() => {});
        throw error;
    }
}
export async function quarantineFile(originalPath: string, threatName: string, quarantineDir: string) {
    await fs.mkdir(quarantineDir, { recursive: true });
    const baseName = path.basename(originalPath);
    const timestampedName = `${Date.now()}_${randomBytes(4).toString("hex")}_${baseName}`;
    const destPath = path.join(quarantineDir, timestampedName);
    const sha256 = await moveFileWithoutOverwrite(originalPath, destPath);
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
