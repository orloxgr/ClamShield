export function virusTotalShieldPopupThreshold(value: unknown) {
    const parsed = Number(value);
    return value === null || value === undefined || value === "" || !Number.isFinite(parsed)
        ? 4 : Math.max(1, Math.min(20, Math.round(parsed)));
}
