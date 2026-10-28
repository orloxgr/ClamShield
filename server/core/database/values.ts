import fs from "fs/promises";
import path from "path";

export function appStateJson(value: any) {
    return JSON.stringify(value ?? null);
}

export function parseAppStateJson(value: any, fallback: any) {
    if (typeof value !== "string" || value.length === 0)
        return fallback;
    try {
        return JSON.parse(value);
    }
    catch {
        return fallback;
    }
}

export function asRecord(value: any) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

export function normalizedStatePath(filePath: any) {
    const value = String(filePath || "");
    if (!value)
        return "";
    try {
        return path.resolve(value).toLowerCase();
    }
    catch {
        return value.toLowerCase();
    }
}

export function optionalNumber(value: any) {
    const numberValue = Number(value);
    return Number.isFinite(numberValue) ? numberValue : null;
}

export function runAppStateTransaction<T>(db: any, work: () => T): T {
    db.exec("BEGIN IMMEDIATE");
    try {
        const result = work();
        db.exec("COMMIT");
        return result;
    }
    catch (e) {
        db.exec("ROLLBACK");
        throw e;
    }
}

export function appStateRowCount(db: any, tableName: string) {
    const row = db.prepare(`SELECT COUNT(*) as count FROM ${tableName}`).get();
    return Number(row?.count || 0);
}

export async function readLegacyJsonState(filePath: string, fallback: any) {
    try {
        return parseAppStateJson(await fs.readFile(filePath, "utf8"), fallback);
    }
    catch {
        return fallback;
    }
}

export function escapeSqlLike(value: string) {
    return value.replace(/[\\%_]/g, match => `\\${match}`);
}
