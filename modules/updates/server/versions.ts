import { runtimeDir } from "../../../server/core/paths";
import fs from "fs/promises";
import path from "path";

export function normalizeVersion(value: any) {
    return String(value || "0.0.0").trim().replace(/^v/i, "");
}

export function compareVersions(a: string, b: string) {
    const left = normalizeVersion(a).split(".").map(part => parseInt(part, 10) || 0);
    const right = normalizeVersion(b).split(".").map(part => parseInt(part, 10) || 0);
    const length = Math.max(left.length, right.length);
    for (let i = 0; i < length; i++) {
        const delta = (left[i] || 0) - (right[i] || 0);
        if (delta !== 0)
            return delta;
    }
    return 0;
}

export function normalizeReleaseVersion(value: any) {
    return normalizeVersion(String(value || "")
        .replace(/^clamav-/i, "")
        .replace(/^yara-/i, ""));
}

export function parseBareVersion(value: any) {
    const match = String(value || "").match(/(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)/);
    return match ? normalizeVersion(match[1]) : "0.0.0";
}

export function extractBareVersion(value: any) {
    const match = String(value || "").match(/(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)/);
    return match ? normalizeVersion(match[1]) : "";
}

export function getRememberedYaraEngineVersion(settings: any) {
    const version = extractBareVersion(settings?.yaraEngineInstalledVersion);
    return version && version !== "0.0.0" ? version : "";
}

export async function getCurrentAppVersion() {
    let pkgVersion = process.env.npm_package_version || "1.0.96";
    const candidatePaths = Array.from(new Set([
        path.join(runtimeDir, "package.json"),
        path.join(runtimeDir, "..", "package.json"),
        path.join(process.cwd(), "package.json")
    ]));
    for (const pkgPath of candidatePaths) {
        try {
            const pkgData = await fs.readFile(pkgPath, "utf8");
            pkgVersion = JSON.parse(pkgData).version || pkgVersion;
            break;
        }
        catch {
            // Packaged and development layouts place package.json differently.
        }
    }
    return normalizeVersion(pkgVersion);
}
