import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { asRecord, normalizedStatePath, parseAppStateJson, runAppStateTransaction } from "../../../server/core/database/values";
import { hashFile } from "../../../server/core/utils";
import { exceptionQuery, originSql, providerSql, reportStatus } from "./reporting";
import { getFalsePositiveProvider } from "./reports";
import { insertExceptionReportRow, insertExceptionRow } from "./rows";
import { existsSync } from "fs";
import path from "path";

export async function getExceptions() {
    await ensureAppStateReady();
    return getAppStateDb()
        .prepare("SELECT path FROM exceptions ORDER BY path COLLATE NOCASE")
        .all()
        .map((row: any) => row.path);
}

export async function getExceptionItemsPage(options: Record<string, any>) {
    await ensureAppStateReady();
    const { where, params, orderBy } = exceptionQuery(options);
    const db = getAppStateDb();
    const from = " FROM exceptions e LEFT JOIN exception_reports r ON r.normalized_path = e.normalized_path";
    const total = Number(db.prepare(`SELECT COUNT(*) AS count${from}${where}`).get(...params)?.count || 0);
    const totalAll = Number(db.prepare("SELECT COUNT(*) AS count FROM exceptions").get()?.count || 0);
    const limit = options.limit === null ? null : Math.max(1, Math.min(500, Math.floor(Number(options.limit) || 50)));
    const offset = limit ? Math.min(Math.max(0, Math.floor(Number(options.offset) || 0)), Math.max(0, Math.ceil(total / limit) - 1) * limit) : 0;
    const rows = db.prepare(`SELECT e.path, e.added_at, e.kind, ${originSql} AS origin, ${providerSql} AS provider_name, r.payload AS report_payload
        ${from}${where} ORDER BY ${orderBy}${limit ? " LIMIT ? OFFSET ?" : ""}`)
        .all(...params, ...(limit ? [limit, offset] : []));
    return {
        items: rows.map((row: any) => {
            const report = row.report_payload ? asRecord(parseAppStateJson(row.report_payload, {})) : null;
            return { path: row.path, addedAt: Number(row.added_at), kind: row.kind, origin: row.origin,
                providerName: row.provider_name, report: report ? { ...report, reportStatus: reportStatus(report), provider: getFalsePositiveProvider(report) } : null };
        }), total, totalAll, page: limit ? Math.floor(offset / limit) + 1 : 1
    };
}

export async function saveExceptions(list: string[], newOrigin = "unknown") {
    await ensureAppStateReady();
    const db = getAppStateDb();
    const existingRows = db.prepare("SELECT normalized_path, added_at, kind, origin FROM exceptions").all();
    const existingMetadata = new Map(existingRows.map((row: any) => [String(row.normalized_path), row]));
    const existingAddedAt = new Map<string, number>(existingRows.map((row: any) => [String(row.normalized_path), Number(row.added_at || 0)]));
    const now = Date.now();
    runAppStateTransaction(db, () => {
        db.prepare("DELETE FROM exceptions").run();
        list.forEach((item, index) => {
            const key = normalizedStatePath(item);
            insertExceptionRow(db, item, existingAddedAt.get(key) || now + index, existingMetadata.get(key) || { origin: newOrigin });
        });
    });
    const normalizedPaths = new Set(list.map(item => normalizedStatePath(item)).filter(Boolean));
    const reports = await getExceptionReports();
    let changed = false;
    for (const key of Object.keys(reports)) {
        if (!normalizedPaths.has(key)) {
            delete reports[key];
            changed = true;
        }
    }
    if (changed)
        await saveExceptionReports(reports);
}

export async function getExceptionReports() {
    await ensureAppStateReady();
    const rows = getAppStateDb().prepare(`
        SELECT normalized_path, original_path, threat_name, engine, source, yara_ruleset, sha256,
               detected_at, added_at, false_positive_opened_at, false_positive_last_opened_at,
               false_positive_channels, payload
        FROM exception_reports
    `).all();
    const reports: Record<string, any> = {};
    for (const row of rows) {
        const payload = asRecord(parseAppStateJson(row.payload, {}));
        const channels = asRecord(parseAppStateJson(row.false_positive_channels, {}));
        reports[row.normalized_path] = {
            ...payload,
            originalPath: row.original_path || payload.originalPath,
            threatName: row.threat_name || payload.threatName,
            engine: row.engine || payload.engine,
            source: row.source || payload.source,
            yaraRuleset: row.yara_ruleset || payload.yaraRuleset,
            sha256: row.sha256 || payload.sha256,
            detectedAt: row.detected_at === null || row.detected_at === undefined ? payload.detectedAt : Number(row.detected_at),
            addedAt: row.added_at === null || row.added_at === undefined ? payload.addedAt : Number(row.added_at),
            falsePositiveOpenedAt: row.false_positive_opened_at === null || row.false_positive_opened_at === undefined ? payload.falsePositiveOpenedAt : Number(row.false_positive_opened_at),
            falsePositiveLastOpenedAt: row.false_positive_last_opened_at === null || row.false_positive_last_opened_at === undefined ? payload.falsePositiveLastOpenedAt : Number(row.false_positive_last_opened_at),
            falsePositiveChannels: Object.keys(channels).length > 0 ? channels : payload.falsePositiveChannels
        };
    }
    return reports;
}

export async function saveExceptionReports(reports: Record<string, any>) {
    await ensureAppStateReady();
    const db = getAppStateDb();
    runAppStateTransaction(db, () => {
        db.prepare("DELETE FROM exception_reports").run();
        for (const [key, report] of Object.entries(asRecord(reports))) {
            insertExceptionReportRow(db, normalizedStatePath(key), report);
        }
    });
}

export function exceptionReportKey(filePath: string) {
    return path.resolve(filePath).toLowerCase();
}

export async function rememberExceptionDetection(result: any, addedFrom = "unknown") {
    if (!result?.originalPath)
        return null;
    const sha256 = result.sha256 || (existsSync(result.originalPath)
        ? await hashFile(result.originalPath).catch(() => "")
        : "");
    const report = {
        originalPath: path.resolve(result.originalPath),
        threatName: String(result.threatName || "Unknown Threat"),
        engine: String(result.engine || (String(result.threatName || "").startsWith("YARA:") ? "YARA" : "ClamAV")),
        source: String(result.source || "scan"),
        addedFrom,
        yaraRuleset: result.yaraRuleset ? String(result.yaraRuleset) : "",
        sha256,
        detectedAt: Number(result.timestamp || Date.now()),
        addedAt: Date.now()
    };
    const reports = await getExceptionReports();
    reports[exceptionReportKey(report.originalPath)] = report;
    await saveExceptionReports(reports);
    return report;
}

export function buildEmailComposeUrls(email: string, subject: string, body: string) {
    const encodedEmail = encodeURIComponent(email);
    const encodedSubject = encodeURIComponent(subject);
    const encodedBody = encodeURIComponent(body);
    return {
        mailto: `mailto:${email}?subject=${encodedSubject}&body=${encodedBody}`,
        gmail: `https://mail.google.com/mail/?view=cm&fs=1&to=${encodedEmail}&su=${encodedSubject}&body=${encodedBody}`,
        outlook: `https://outlook.live.com/mail/0/deeplink/compose?to=${encodedEmail}&subject=${encodedSubject}&body=${encodedBody}`
    };
}

export function buildFalsePositiveReport(report: any) {
    const provider = getFalsePositiveProvider(report);
    const fileName = path.basename(String(report.originalPath || "unknown-file"));
    const details = [
        "ClamShield false-positive report",
        "",
        `Detection: ${report.threatName || "Unknown Threat"}`,
        `Engine: ${report.engine || "Unavailable"}`,
        `File name: ${fileName}`,
        `SHA-256: ${report.sha256 || "Unavailable"}`,
        `Detection source: ${report.source || "scan"}`,
        report.yaraRuleset ? `YARA ruleset: ${report.yaraRuleset}` : "",
        "",
        "The file was added to ClamShield exceptions because the user believes this detection is a false positive.",
        provider.id === "securiteinfo"
            ? "If the user agrees to share the detected file and it does not contain sensitive information, please attach it as a password-protected zip archive using the password infectedsecuriteinfo. If the file is not shared, please use the SHA-256 value above."
            : "",
        provider.method === "email" && provider.id !== "securiteinfo" ? "Please attach the detected file or a password-protected archive if the provider requests a sample." : ""
    ].filter(Boolean).join("\n");
    const subject = `[False Positive] ${report.threatName || fileName}`;
    let url = provider.url;
    let emailUrls = null;
    if (provider.method === "email") {
        emailUrls = buildEmailComposeUrls(provider.email, subject, details);
        url = emailUrls.mailto;
    }
    else if (provider.method === "github") {
        url = `${provider.url}?title=${encodeURIComponent(subject)}&body=${encodeURIComponent(details)}`;
    }
    return {
        provider,
        subject,
        details,
        url,
        emailUrls,
        requiresSample: provider.id !== "yara-forge"
    };
}

export function isExcluded(filePath: string, exceptions: string[]) {
    // Normalize paths to avoid slash differences
    const normFile = path.resolve(filePath).toLowerCase();
    return exceptions.some(exc => {
        const normExc = path.resolve(exc).toLowerCase();
        return normFile === normExc || normFile.startsWith(normExc + path.sep);
    });
}
