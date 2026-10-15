export const virusTotalWarningFileThreshold = 4;

// This preference alone is default-on: only an explicit unchecked value disables it.
export const virusTotalLimitWarningsEnabled = (value: unknown) => value !== false;

export function estimateVirusTotalScan(files: number, usage: any, now = Date.now()) {
    const count = Math.max(0, Math.floor(files));
    const spacing = Math.max(1, Number(usage?.rate?.spacingMs) || 16_000);
    const start = Math.max(now, Number(usage?.rate?.nextLookupAllowedAt) || 0);
    let finishesAt = start + count * spacing;
    for (const period of ["day", "month"]) {
        const quota = usage?.[period];
        if (!quota) continue;
        const limit = Math.max(0, Number(quota.limit));
        const remaining = Math.max(0, Number(quota.remaining));
        if (!Number.isFinite(limit) || !Number.isFinite(remaining) || count <= remaining) continue;
        if (limit === 0) return { files: count, durationMs: null, duration: "until your VirusTotal quota becomes available" };
        const remainingFiles = count - remaining;
        const periodsAfterReset = Math.floor((remainingFiles - 1) / limit);
        const lastPeriodFiles = ((remainingFiles - 1) % limit) + 1;
        const reset = new Date(Number(quota.resetsAt) || now);
        if (period === "day") reset.setUTCDate(reset.getUTCDate() + periodsAfterReset);
        else reset.setUTCMonth(reset.getUTCMonth() + periodsAfterReset);
        finishesAt = Math.max(finishesAt, reset.getTime() + lastPeriodFiles * spacing);
    }
    const durationMs = Math.max(0, finishesAt - now);
    const minutes = Math.max(1, Math.ceil(durationMs / 60_000));
    const days = Math.floor(minutes / 1440), hours = Math.floor((minutes % 1440) / 60), rest = minutes % 60;
    const unit = (number: number, name: string) => `${number.toLocaleString()} ${name}${number === 1 ? "" : "s"}`;
    const duration = days ? [unit(days, "day"), hours ? unit(hours, "hour") : ""].filter(Boolean).join(" ")
        : hours ? [unit(hours, "hour"), rest ? unit(rest, "minute") : ""].filter(Boolean).join(" ") : unit(minutes, "minute");
    return { files: count, durationMs, duration };
}
