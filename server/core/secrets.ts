import { englishText } from "../../shared/localization/runtime";
import { nodeRequire } from "./paths";
import fs from "fs/promises";
import path from "path";
export function getElectronSafeStorage() {
    try {
        const electron = nodeRequire("electron");
        const safeStorage = electron && typeof electron === "object" ? electron.safeStorage : null;
        if (safeStorage?.isEncryptionAvailable?.())
            return safeStorage;
    }
    catch {
        // Secure storage is unavailable outside the packaged Electron desktop app.
    }
    return null;
}
export async function saveEncryptedSecret(secretPath: string, value: string) {
    const safeStorage = getElectronSafeStorage();
    if (!safeStorage) {
        throw new Error(englishText("backend.core.windows_secure_credential_storage_is_unavailable_open_clamshield"));
    }
    await fs.mkdir(path.dirname(secretPath), { recursive: true });
    await fs.writeFile(secretPath, safeStorage.encryptString(value), { mode: 0o600 });
}
export async function loadEncryptedSecret(secretPath: string) {
    const safeStorage = getElectronSafeStorage();
    if (!safeStorage)
        return "";
    try {
        const encrypted = await fs.readFile(secretPath);
        return safeStorage.decryptString(encrypted);
    }
    catch {
        return "";
    }
}
