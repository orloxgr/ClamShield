import { englishText } from "../../../shared/localization/runtime";
export type ReportStatus = "not_reported" | "unconfirmed" | "sent" | "not_applicable";
export function reportStatus(report: any): ReportStatus {
    if (!report)
        return "not_applicable";
    if (["not_reported", "unconfirmed", "sent"].includes(report.reportStatus))
        return report.reportStatus;
    return report.falsePositiveOpenedAt || report.falsePositiveLastOpenedAt
        ? "unconfirmed"
        : "not_reported";
}
export function updateReportStatus(report: any, action: string, now = Date.now()) {
    if (!["prepare", "sent", "reset"].includes(action))
        throw new Error(englishText("backend.exceptionReporting.ts.invalid_report_status_action"));
    const next = { ...report };
    next.reportStatus =
        action === "sent"
            ? "sent"
            : action === "reset"
                ? "not_reported"
                : reportStatus(report) === "sent"
                    ? "sent"
                    : "unconfirmed";
    if (action === "sent")
        next.reportSentAt = now;
    if (action === "reset") {
        delete next.reportSentAt;
        delete next.falsePositiveOpenedAt;
        delete next.falsePositiveLastOpenedAt;
        delete next.falsePositiveChannels;
    }
    if (action === "prepare")
        next.reportPreparedAt = now;
    return next;
}
export const providerSql = `CASE
    WHEN r.normalized_path IS NULL THEN 'Unknown'
    WHEN LOWER(COALESCE(r.engine,'')) = 'yara' OR LOWER(COALESCE(r.threat_name,'')) LIKE 'yara:%' THEN 'YARA Forge'
    WHEN INSTR(LOWER(COALESCE(r.threat_name,'')), 'securiteinfo.com') > 0 OR LOWER(COALESCE(r.threat_name,'')) GLOB 'securiteinfo[._-]*' THEN 'SecuriteInfo'
    WHEN LOWER(COALESCE(r.threat_name,'')) GLOB 'sanesecurity[._-]*' THEN 'SaneSecurity'
    ELSE 'ClamAV' END`;
export const originSql = `CASE WHEN e.origin <> 'unknown' THEN e.origin
    WHEN json_extract(r.payload, '$.addedFrom') IN ('scan','shield','manual') THEN json_extract(r.payload, '$.addedFrom')
    WHEN LOWER(r.source) = 'shield' THEN 'shield'
    WHEN LOWER(r.source) IN ('scan','manual','scheduled','context-menu') THEN 'scan'
    ELSE 'unknown' END`;
export const statusSql = `CASE WHEN r.normalized_path IS NULL THEN 'not_applicable'
    WHEN json_extract(r.payload,'$.reportStatus') IN ('not_reported','unconfirmed','sent') THEN json_extract(r.payload,'$.reportStatus')
    WHEN r.false_positive_opened_at IS NOT NULL OR r.false_positive_last_opened_at IS NOT NULL THEN 'unconfirmed'
    ELSE 'not_reported' END`;
export function exceptionQuery(options: Record<string, any>, now = new Date()) {
    const clauses: string[] = [], params: any[] = [];
    const add = (sql: string, value: any) => {
        clauses.push(sql);
        params.push(value);
    };
    if (options.search) {
        const term = `%${String(options.search).replace(/[\\%_]/g, "\\$&")}%`;
        clauses.push("(e.path LIKE ? ESCAPE '\\' OR r.threat_name LIKE ? ESCAPE '\\')");
        params.push(term, term);
    }
    if (options.provider && options.provider !== "all")
        add(`${providerSql} = ?`, options.provider);
    if (options.origin && options.origin !== "all")
        add(`${originSql} = ?`, options.origin);
    if (options.status && options.status !== "all")
        add(`${statusSql} = ?`, options.status);
    if (options.kind && options.kind !== "all")
        add("e.kind = ?", options.kind);
    const localDay = (value: string) => {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(value))
            throw new Error(englishText("backend.exceptionReporting.ts.invalid_date"));
        const date = new Date(`${value}T00:00:00`);
        if (!Number.isFinite(date.getTime()))
            throw new Error(englishText("backend.exceptionReporting.ts.invalid_date"));
        return date;
    };
    let start: Date | undefined, end: Date | undefined;
    if (["today", "7", "30"].includes(options.dateRange)) {
        start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        start.setDate(start.getDate() -
            (options.dateRange === "today" ? 0 : Number(options.dateRange) - 1));
        end = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    }
    else if (options.dateRange === "custom" || options.date) {
        if (options.dateFrom || options.date)
            start = localDay(options.dateFrom || options.date);
        if (options.dateTo || options.date) {
            end = localDay(options.dateTo || options.date);
            end.setDate(end.getDate() + 1);
        }
        if (start && end && start >= end)
            throw new Error(englishText("backend.exceptionReporting.ts.the_end_date_must_be_on_or_after_the_start_date"));
    }
    if (start)
        add("e.added_at >= ?", start.getTime());
    if (end)
        add("e.added_at < ?", end.getTime());
    const orderBy = options.sort === "oldest"
        ? "e.added_at ASC, e.path COLLATE NOCASE ASC"
        : options.sort === "path"
            ? "e.path COLLATE NOCASE ASC"
            : "e.added_at DESC, e.path COLLATE NOCASE ASC";
    return {
        where: clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "",
        params,
        orderBy,
    };
}
