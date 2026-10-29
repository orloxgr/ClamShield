import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { zstdDecompressSync } from 'node:zlib';
import { URL } from 'node:url';
import * as tar from 'tar';
import inventory from './native-tools.json';
import { downloadFile } from '../../../server/core/downloads';
import { runHiddenProcess } from '../../../server/platform/processes';
import { commitStagedEngineDirectory } from '../../../server/core/files';
import { saneSecurityToolsDir, saneSecurityToolsCacheDir } from './constants';

const digest = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');
const inventoryId = digest(JSON.stringify(inventory));
export const nativeToolVersions = {
    rsync: inventory.packages.find(item => item.name === 'rsync')!.version.split('-')[0],
    gnupg: inventory.gnupg.version,
    archive: inventory.packages.find(item => item.name === 'mingw-w64-ucrt-x86_64-7zip')!.version.split('-')[0]
};
export function safeNativeArchiveEntry(name: string, type: string) {
    const clean = name.replace(/^\.\//, '');
    return type === 'File' && /^(?:usr|ucrt64)\/(?:bin\/[\w.+-]+\.(?:exe|dll)|share\/(?:licenses|doc)\/[\w.+/-]+)$/.test(clean) && !clean.split('/').includes('..');
}
async function verifiedDownload(asset: { url: string; sha256: string }, cache: string, log: (line: string) => void) {
    const url = new URL(asset.url);
    if (url.protocol !== 'https:' || !['repo.msys2.org', 'gnupg.org'].includes(url.hostname) || !/^[a-f0-9]{64}$/.test(asset.sha256)) throw new Error('Invalid trusted native-tool inventory');
    const file = path.join(cache, path.basename(url.pathname));
    let bytes = await fs.readFile(file).catch(() => null);
    if (!bytes || digest(bytes) !== asset.sha256) {
        log(`Downloading ${path.basename(file)}...`);
        await downloadFile(asset.url, file);
        bytes = await fs.readFile(file);
    }
    if (bytes.length > 128 * 1024 * 1024 || digest(bytes) !== asset.sha256) {
        await fs.unlink(file).catch(() => {});
        throw new Error(`Native helper checksum verification failed: ${path.basename(file)} (expected ${asset.sha256}, received ${digest(bytes)}, ${bytes.length} bytes)`);
    }
    return { file, bytes };
}
export async function verifyNativeTools(directory: string) {
    const checks = [
        { executable: path.join(directory, 'msys', 'usr', 'bin', 'rsync.exe'), pattern: /^rsync\s+version\s+([\d.]+)/m, version: nativeToolVersions.rsync },
        { executable: path.join(directory, 'gnupg', 'bin', 'gpg.exe'), pattern: /^gpg \(GnuPG\) ([\d.]+)/m, version: nativeToolVersions.gnupg },
        { executable: path.join(directory, 'archive', 'ucrt64', 'bin', '7z.exe'), pattern: /7-Zip[^\r\n]*?\s([\d]+\.[\d]+)/, version: nativeToolVersions.archive }
    ];
    for (const item of checks) {
        const result = await runHiddenProcess(item.executable, item.version === nativeToolVersions.archive ? [] : ['--version'], { timeoutMs: 30000 });
        const output = result.stdout + result.stderr;
        const actual = output.match(item.pattern)?.[1];
        if (actual !== item.version || result.code !== 0) throw new Error(`Native helper version check failed: ${path.basename(item.executable)} (expected ${item.version}, received ${actual || output.slice(0,160)})`);
    }
}
async function receiptMatches(directory: string) {
    try {
        const receipt = JSON.parse(await fs.readFile(path.join(directory, 'inventory.json'), 'utf8'));
        if (receipt.inventoryId !== inventoryId || !Array.isArray(receipt.files) || !receipt.files.length) return false;
        for (const file of receipt.files) {
            if (typeof file.name !== 'string' || !/^[\w.+/-]+$/.test(file.name) || file.name.startsWith('/') || file.name.split('/').includes('..')) return false;
            if (digest(await fs.readFile(path.join(directory, file.name))) !== file.sha256) return false;
        }
        await verifyNativeTools(directory);
        return true;
    } catch { return false; }
}
async function binaryReceipt(root: string, folder = root): Promise<{ name: string; sha256: string }[]> {
    const result: { name: string; sha256: string }[] = [];
    for (const entry of await fs.readdir(folder, { withFileTypes: true })) {
        const file = path.join(folder, entry.name);
        if (entry.isSymbolicLink()) throw new Error('Linked files are not allowed in native helper packages');
        if (entry.isDirectory()) result.push(...await binaryReceipt(root, file));
        else if (/\.(exe|dll)$/i.test(entry.name)) result.push({ name: path.relative(root, file).split(path.sep).join('/'), sha256: digest(await fs.readFile(file)) });
    }
    return result;
}
export async function installNativeTools(directory: string, cache: string, log: (line: string) => void) {
    directory = path.resolve(directory);
    cache = path.resolve(cache);
    if (await receiptMatches(directory)) return;
    await fs.mkdir(path.dirname(directory), { recursive: true });
    await fs.mkdir(cache, { recursive: true });
    const staging = await fs.mkdtemp(directory + '.staging-');
    try {
        for (const item of inventory.packages) {
            const asset = await verifiedDownload(item, cache, log);
            const tarPath = asset.file + '.tar';
            const uncompressed = zstdDecompressSync(asset.bytes, { maxOutputLength: 256 * 1024 * 1024 });
            await fs.writeFile(tarPath, uncompressed);
            const target = path.join(staging, item.family);
            await fs.mkdir(target, { recursive: true });
            try { await tar.x({ file: tarPath, cwd: target, strict: true, filter: (name, entry) => safeNativeArchiveEntry(name, 'type' in entry ? String(entry.type) : '') }); }
            finally { await fs.unlink(tarPath).catch(() => {}); }
        }
        const gnupg = await verifiedDownload(inventory.gnupg, cache, log);
        const extractor = path.join(staging, 'archive', 'ucrt64', 'bin', '7z.exe');
        const extracted = await runHiddenProcess(extractor, ['x', '-y', `-o${path.join(staging, 'gnupg')}`, gnupg.file], { timeoutMs: 60000 });
        if (extracted.code !== 0) throw new Error(`Could not unpack the verified official GnuPG distribution (exit ${extracted.code}): ${(extracted.stderr || extracted.stdout).slice(-1500)}`);
        await verifyNativeTools(staging);
        await fs.writeFile(path.join(staging, 'inventory.json'), JSON.stringify({ inventoryId, versions: nativeToolVersions, files: await binaryReceipt(staging) }, null, 2));
        await commitStagedEngineDirectory(staging, directory);
        log(`SaneSecurity tools ready: rsync ${nativeToolVersions.rsync}, GnuPG ${nativeToolVersions.gnupg}, 7-Zip ${nativeToolVersions.archive}.`);
    } finally {
        // mkdtemp created this exact sibling; never remove a configured root.
        if (path.dirname(staging) === path.dirname(directory) && path.basename(staging).startsWith(path.basename(directory) + '.staging-')) await fs.rm(staging, { recursive: true, force: true });
    }
}
let installation: Promise<void> | null = null;
export async function ensureSaneSecurityTools(log: (line: string) => void) {
    if (process.platform !== 'win32') throw new Error('SaneSecurity helper installation requires Windows.');
    if (!installation) installation = installNativeTools(saneSecurityToolsDir, saneSecurityToolsCacheDir, log).finally(() => { installation = null; });
    return installation;
}
