import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { asRecord, parseAppStateJson } from "../../../server/core/database/values";
import { insertHistoryRow } from "./rows";
import { randomBytes } from "crypto";

export function historySelectSql() {
    return `SELECT id, date, type, target, result, threats_found, scanned_files, duration, action_taken, payload
            FROM history`;
}

export function mapHistoryRow(row: any) {
    const payload = asRecord(parseAppStateJson(row.payload, {}));
    return {
        ...payload,
        id: row.id,
        date: row.date,
        type: row.type || payload.type,
        target: row.target || payload.target,
        result: row.result === null || row.result === undefined ? payload.result : Number(row.result),
        threatsFound: row.threats_found === null || row.threats_found === undefined ? payload.threatsFound : Number(row.threats_found),
        scannedFiles: row.scanned_files === null || row.scanned_files === undefined ? payload.scannedFiles : Number(row.scanned_files),
        duration: row.duration === null || row.duration === undefined ? payload.duration : Number(row.duration),
        actionTaken: row.action_taken || payload.actionTaken
    };
}

export function getLatestHistoryRow(db: any, whereSql: string, params: any[] = []) {
    const row = db.prepare(`${historySelectSql()} WHERE ${whereSql} ORDER BY date DESC LIMIT 1`).get(...params);
    return row ? mapHistoryRow(row) : null;
}

export async function getHistory() {
    await ensureAppStateReady();
    const rows = getAppStateDb().prepare(`${historySelectSql()} ORDER BY date DESC`).all();
    return rows.map(mapHistoryRow);
}

export async function getDashboardHistorySummary() {
    await ensureAppStateReady();
    const db = getAppStateDb();
    return {
        lastScan: getLatestHistoryRow(db, "(type LIKE 'scan%' OR type LIKE 'scheduled-scan%')"),
        lastUpdate: getLatestHistoryRow(db, "type = ?", ["update"]),
        lastAppUpdateCheck: getLatestHistoryRow(db, "type = ?", ["app-update-check"]),
        lastThreat: getLatestHistoryRow(db, "COALESCE(threats_found, 0) > 0"),
        lastCloudCheck: getLatestHistoryRow(db, "type IN (?, ?, ?, ?, ?)", [
            "virustotal-cloud-check",
            "virustotal-auto-refine",
            "virustotal-shield-check",
            "virustotal-shield-upload",
            "virustotal-results-upload"
        ])
    };
}

export async function getLatestHistoryByType(type: string) {
    await ensureAppStateReady();
    return getLatestHistoryRow(getAppStateDb(), "type = ?", [type]);
}

export async function getLatestSuccessfulClamAVUpdateHistory() {
    await ensureAppStateReady();
    return getLatestHistoryRow(getAppStateDb(), "type = ? AND result = 0 AND target LIKE ?", ["update", "%ClamAV%"]);
}

export function getLocalDateRangeMs(dateValue: any) {
    const value = String(dateValue || "").trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value))
        return null;
    const start = new Date(`${value}T00:00:00`).getTime();
    const end = new Date(`${value}T23:59:59.999`).getTime();
    if (!Number.isFinite(start) || !Number.isFinite(end))
        return null;
    return { start, end };
}

export function getLocalDateRangeIso(dateValue: any) {
    const range = getLocalDateRangeMs(dateValue);
    return range ? { start: new Date(range.start).toISOString(), end: new Date(range.end).toISOString() } : null;
}

export async function getHistoryPage(options: {
    limit?: number | null;
    offset?: number;
    date?: string;
}) {
    await ensureAppStateReady();
    const clauses: string[] = [];
    const params: any[] = [];
    const dateRange = getLocalDateRangeIso(options.date);
    if (dateRange) {
        clauses.push("date >= ? AND date <= ?");
        params.push(dateRange.start, dateRange.end);
    }
    const whereSql = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
    const db = getAppStateDb();
    const total = Number(db.prepare(`SELECT COUNT(*) AS count FROM history${whereSql}`).get(...params)?.count || 0);
    const safeOffset = Math.max(0, Math.floor(Number(options.offset || 0)));
    const limit = options.limit === null || options.limit === undefined
        ? null
        : Math.max(1, Math.min(500, Math.floor(Number(options.limit) || 50)));
    const rows = db.prepare(`
        ${historySelectSql()}${whereSql}
        ORDER BY date DESC${limit ? " LIMIT ? OFFSET ?" : ""}
    `).all(...params, ...(limit ? [limit, safeOffset] : []));
    return {
        items: rows.map(mapHistoryRow),
        total
    };
}

export async function addHistory(entry: any) {
    await ensureAppStateReady();
    const db = getAppStateDb();
    insertHistoryRow(db, {
        id: `${Date.now()}-${randomBytes(3).toString("hex")}`,
        date: new Date().toISOString(),
        ...asRecord(entry)
    });
}
