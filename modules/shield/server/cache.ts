import { englishText } from "../../../shared/localization/runtime";
import { nodeRequire, programDataDir } from "../../../server/core/paths";
import { sleep } from "../../../server/core/utils";
import { getFileFingerprint } from "../../../server/scanning/files";
import { createBuiltInScanPathSkipper, walkFiles } from "../../../server/scanning/targets";
import { ShieldCacheEntry } from "./types";
import fs from "fs/promises";
import path from "path";
export type ShieldScanCache = {
    version: number;
    files: Record<string, ShieldCacheEntry>;
};
export function getShieldCachePath() {
    return path.join(programDataDir, "shield_scan_cache.json");
}
export function getShieldCacheDbPath() {
    return path.join(programDataDir, "shield_scan_cache.sqlite");
}
export function getScanSessionsDbPath() {
    return path.join(programDataDir, "scan_sessions.sqlite");
}
export function normalizeCachePath(filePath: string) {
    return path.resolve(filePath).toLowerCase();
}
export interface ShieldScanCacheStore {
    type: "sqlite" | "memory";
    get(normalizedPath: string): ShieldCacheEntry | undefined;
    set(normalizedPath: string, entry: ShieldCacheEntry): void;
    delete(normalizedPath: string): void;
    clear(): void;
    count(): number;
    compact?(): void;
}
export async function loadLegacyShieldScanCache(): Promise<ShieldScanCache> {
    const cachePath = getShieldCachePath();
    try {
        const stat = await fs.stat(cachePath);
        if (stat.size > 50 * 1024 * 1024) {
            console.warn(englishText("backend.shield.shield_scan_cache_is_too_large_starting_with_a_fresh_cache"));
            return { version: 1, files: {} };
        }
        const data = await fs.readFile(cachePath, "utf8");
        const parsed = JSON.parse(data);
        if (parsed && parsed.version === 1 && parsed.files && typeof parsed.files === "object") {
            return parsed;
        }
    }
    catch (e: any) {
        console.debug(englishText("backend.shield.legacy_shield_scan_cache_could_not_be_loaded_starting_with_an_emp"), e?.message || e);
    }
    return { version: 1, files: {} };
}
export async function clearLegacyShieldScanCache() {
    await fs.unlink(getShieldCachePath()).catch(() => { });
}
export class MemoryShieldScanCacheStore implements ShieldScanCacheStore {
    type: "memory" = "memory";
    private cache: ShieldScanCache;
    constructor(cache: ShieldScanCache) {
        this.cache = cache;
    }
    get(normalizedPath: string) {
        return this.cache.files[normalizedPath];
    }
    set(normalizedPath: string, entry: ShieldCacheEntry) {
        this.cache.files[normalizedPath] = entry;
    }
    delete(normalizedPath: string) {
        delete this.cache.files[normalizedPath];
    }
    clear() {
        this.cache = { version: 1, files: {} };
    }
    count() {
        return Object.keys(this.cache.files).length;
    }
}
export class SqliteShieldScanCacheStore implements ShieldScanCacheStore {
    type: "sqlite" = "sqlite";
    private db: any;
    private getStmt: any;
    private setStmt: any;
    private deleteStmt: any;
    private countStmt: any;
    constructor(dbPath: string) {
        const { DatabaseSync } = nodeRequire("node:sqlite");
        this.db = new DatabaseSync(dbPath);
        this.db.exec(`
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS shield_scan_cache (
                path TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                mtime_ms INTEGER NOT NULL,
                scanned_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_shield_scan_cache_scanned_at ON shield_scan_cache(scanned_at);
        `);
        this.getStmt = this.db.prepare("SELECT size, mtime_ms as mtimeMs, scanned_at as scannedAt FROM shield_scan_cache WHERE path = ?");
        this.setStmt = this.db.prepare(`
            INSERT INTO shield_scan_cache(path, size, mtime_ms, scanned_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                size = excluded.size,
                mtime_ms = excluded.mtime_ms,
                scanned_at = excluded.scanned_at
        `);
        this.deleteStmt = this.db.prepare("DELETE FROM shield_scan_cache WHERE path = ?");
        this.countStmt = this.db.prepare("SELECT COUNT(*) as count FROM shield_scan_cache");
    }
    get(normalizedPath: string) {
        const row = this.getStmt.get(normalizedPath);
        if (!row)
            return undefined;
        return {
            size: Number(row.size),
            mtimeMs: Number(row.mtimeMs),
            scannedAt: Number(row.scannedAt)
        };
    }
    set(normalizedPath: string, entry: ShieldCacheEntry) {
        this.setStmt.run(normalizedPath, entry.size, entry.mtimeMs, entry.scannedAt);
    }
    delete(normalizedPath: string) {
        this.deleteStmt.run(normalizedPath);
    }
    clear() {
        this.db.exec("DELETE FROM shield_scan_cache; PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");
    }
    count() {
        const row = this.countStmt.get();
        return Number(row?.count || 0);
    }
    compact() {
        this.db.exec("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");
    }
    importLegacy(cache: ShieldScanCache) {
        const entries = Object.entries(cache.files || {});
        if (entries.length === 0)
            return 0;
        this.db.exec("BEGIN IMMEDIATE");
        try {
            for (const [normalizedPath, entry] of entries) {
                if (!entry || typeof entry.size !== "number" || typeof entry.mtimeMs !== "number")
                    continue;
                this.set(normalizedPath, entry);
            }
            this.db.exec("COMMIT");
        }
        catch (e) {
            this.db.exec("ROLLBACK");
            throw e;
        }
        return entries.length;
    }
}
export async function loadShieldScanCacheStore(): Promise<ShieldScanCacheStore> {
    try {
        const store = new SqliteShieldScanCacheStore(getShieldCacheDbPath());
        const legacyCache = await loadLegacyShieldScanCache();
        const legacyCount = Object.keys(legacyCache.files).length;
        if (legacyCount > 0) {
            const importedCount = store.importLegacy(legacyCache);
            await clearLegacyShieldScanCache();
            console.log(englishText("backend.shield.migrated_shield_cache_entries_to_sqlite", {
                importedCount: String(importedCount)
            }));
        }
        return store;
    }
    catch (e) {
        console.warn(englishText("backend.shield.sqlite_shield_cache_unavailable_using_in_memory_shield_cache"), e);
        return new MemoryShieldScanCacheStore(await loadLegacyShieldScanCache());
    }
}
export async function addTargetToShieldCache(cache: ShieldScanCacheStore, targetPath: string, settings: any, onProgress?: (count: number) => void) {
    let count = 0;
    const shouldSkipPath = createBuiltInScanPathSkipper(settings);
    for await (const filePath of walkFiles(targetPath, shouldSkipPath)) {
        const fingerprint = await getFileFingerprint(filePath);
        if (!fingerprint)
            continue;
        cache.set(normalizeCachePath(filePath), fingerprint);
        count++;
        if (count % 5000 === 0)
            onProgress?.(count);
        if (count % 200 === 0)
            await sleep(1);
    }
    cache.compact?.();
    onProgress?.(count);
    return count;
}
