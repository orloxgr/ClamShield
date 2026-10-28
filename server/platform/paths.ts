import { execAsync } from "../core/paths";
import fs from "fs/promises";
import os from "os";
import path from "path";

export async function isDirectory(dirPath: string) {
    try {
        const stat = await fs.stat(dirPath);
        return stat.isDirectory();
    }
    catch {
        return false;
    }
}

export function dedupePaths(paths: string[]) {
    const seen = new Set<string>();
    return paths.filter(folderPath => {
        const normalized = path.resolve(folderPath).toLowerCase();
        if (seen.has(normalized))
            return false;
        seen.add(normalized);
        return true;
    });
}

export async function existingUniqueDirs(paths: string[]) {
    const unique = dedupePaths(paths.filter(Boolean));
    const result: string[] = [];
    for (const dirPath of unique) {
        if (await isDirectory(dirPath))
            result.push(dirPath);
    }
    return result;
}

export async function existingUniqueFiles(paths: string[]) {
    const unique = dedupePaths(paths.filter(Boolean));
    const result: string[] = [];
    for (const filePath of unique) {
        try {
            const stat = await fs.stat(filePath);
            if (stat.isFile())
                result.push(filePath);
        }
        catch { }
    }
    return result;
}

export async function getWindowsKnownFolders() {
    if (process.platform !== "win32") {
        const homeDir = os.homedir();
        return {
            Desktop: path.join(homeDir, "Desktop"),
            Documents: path.join(homeDir, "Documents"),
            Downloads: path.join(homeDir, "Downloads")
        };
    }
    const fallbackHome = os.homedir();
    const fallback = {
        Desktop: path.join(fallbackHome, "Desktop"),
        Documents: path.join(fallbackHome, "Documents"),
        Downloads: path.join(fallbackHome, "Downloads")
    };
    const script = `
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders'
$props = Get-ItemProperty -Path $key
$out = [ordered]@{}
if ($props.Desktop) { $out.Desktop = [Environment]::ExpandEnvironmentVariables($props.Desktop) }
if ($props.Personal) { $out.Documents = [Environment]::ExpandEnvironmentVariables($props.Personal) }
$downloads = $props.'{374DE290-123F-4565-9164-39C4925E467B}'
if ($downloads) { $out.Downloads = [Environment]::ExpandEnvironmentVariables($downloads) }
$out | ConvertTo-Json -Compress
`;
    try {
        const encoded = Buffer.from(script, "utf16le").toString("base64");
        const { stdout } = await execAsync(`powershell -NoProfile -EncodedCommand ${encoded}`);
        const parsed = JSON.parse(stdout.trim() || "{}");
        return {
            Desktop: parsed.Desktop || fallback.Desktop,
            Documents: parsed.Documents || fallback.Documents,
            Downloads: parsed.Downloads || fallback.Downloads
        };
    }
    catch {
        return fallback;
    }
}

export async function readJsonFile(filePath: string) {
    try {
        return JSON.parse(await fs.readFile(filePath, "utf8"));
    }
    catch {
        return null;
    }
}

export async function detectChromiumDownloadFolders(browser: string, rootDir: string, directProfile = false) {
    const folders: {
        browser: string;
        path: string;
        profile: string;
    }[] = [];
    const candidatePrefs: {
        filePath: string;
        profile: string;
    }[] = [];
    if (directProfile) {
        candidatePrefs.push({ filePath: path.join(rootDir, "Preferences"), profile: "Default" });
    }
    else {
        try {
            const entries = await fs.readdir(rootDir, { withFileTypes: true });
            for (const entry of entries) {
                if (!entry.isDirectory())
                    continue;
                candidatePrefs.push({
                    filePath: path.join(rootDir, entry.name, "Preferences"),
                    profile: entry.name
                });
            }
        }
        catch {
            return folders;
        }
    }
    for (const candidate of candidatePrefs) {
        const prefs = await readJsonFile(candidate.filePath);
        const downloadDir = prefs?.download?.default_directory;
        if (typeof downloadDir === "string" && await isDirectory(downloadDir)) {
            folders.push({ browser, path: downloadDir, profile: candidate.profile });
        }
    }
    return folders;
}

export function unescapeFirefoxPrefPath(prefPath: string) {
    return prefPath.replace(/\\\\/g, "\\").replace(/\\"/g, '"');
}

export async function detectFirefoxDownloadFolders(rootDir: string) {
    const folders: {
        browser: string;
        path: string;
        profile: string;
    }[] = [];
    let profilesIni = "";
    try {
        profilesIni = await fs.readFile(path.join(rootDir, "profiles.ini"), "utf8");
    }
    catch {
        return folders;
    }
    const sections = profilesIni.split(/\r?\n\s*\r?\n/);
    for (const section of sections) {
        const pathMatch = section.match(/^Path=(.+)$/m);
        if (!pathMatch)
            continue;
        const isRelative = /^IsRelative=1$/m.test(section);
        const profilePath = isRelative ? path.join(rootDir, pathMatch[1]) : pathMatch[1];
        const prefsPath = path.join(profilePath, "prefs.js");
        let prefs = "";
        try {
            prefs = await fs.readFile(prefsPath, "utf8");
        }
        catch {
            continue;
        }
        const customPathMatch = prefs.match(/user_pref\("browser\.download\.dir",\s*"((?:\\.|[^"])*)"\);/);
        if (!customPathMatch)
            continue;
        const downloadDir = unescapeFirefoxPrefPath(customPathMatch[1]);
        if (await isDirectory(downloadDir)) {
            folders.push({ browser: "Firefox", path: downloadDir, profile: path.basename(profilePath) });
        }
    }
    return folders;
}

export async function detectBrowserDownloadFolders() {
    if (process.platform !== "win32")
        return [];
    const localAppData = process.env.LOCALAPPDATA || "";
    const appData = process.env.APPDATA || "";
    const chromiumBrowsers = [
        { browser: "Google Chrome", root: path.join(localAppData, "Google", "Chrome", "User Data") },
        { browser: "Microsoft Edge", root: path.join(localAppData, "Microsoft", "Edge", "User Data") },
        { browser: "Brave", root: path.join(localAppData, "BraveSoftware", "Brave-Browser", "User Data") },
        { browser: "Vivaldi", root: path.join(localAppData, "Vivaldi", "User Data") },
        { browser: "Opera", root: path.join(appData, "Opera Software", "Opera Stable"), directProfile: true },
        { browser: "Opera GX", root: path.join(appData, "Opera Software", "Opera GX Stable"), directProfile: true },
        { browser: "Chromium", root: path.join(localAppData, "Chromium", "User Data") }
    ];
    const detected: {
        browser: string;
        path: string;
        profile: string;
    }[] = [];
    for (const item of chromiumBrowsers) {
        if (!await isDirectory(item.root))
            continue;
        detected.push(...await detectChromiumDownloadFolders(item.browser, item.root, !!item.directProfile));
    }
    const firefoxRoot = path.join(appData, "Mozilla", "Firefox");
    if (await isDirectory(firefoxRoot)) {
        detected.push(...await detectFirefoxDownloadFolders(firefoxRoot));
    }
    const seen = new Set<string>();
    return detected.filter(item => {
        const key = path.resolve(item.path).toLowerCase();
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
}

export async function getResolvedSystemPaths() {
    const known = await getWindowsKnownFolders();
    const browserDownloads = await detectBrowserDownloadFolders();
    return {
        ...known,
        BrowserDownloads: browserDownloads
    };
}
