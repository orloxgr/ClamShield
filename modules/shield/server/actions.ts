

export function normalizeShieldDetectionAction(raw: any) {
    const value = String(raw || "").toLowerCase();
    if (value === "ask" || value === "warn")
        return "ask";
    if (value === "quarantine_notify" || value === "quarantine-notify")
        return "quarantine_notify";
    if (value === "quarantine_silent" || value === "quarantine-silent" || value === "quarantine")
        return "quarantine_silent";
    if (value === "results_notify" || value === "results-notify")
        return "results_notify";
    if (value === "results_silent" || value === "results-silent" || value === "results")
        return "results_silent";
    return "ask";
}

export function shieldActionKind(action: any) {
    const normalized = normalizeShieldDetectionAction(action);
    if (normalized.startsWith("quarantine"))
        return "quarantine";
    if (normalized.startsWith("results"))
        return "results";
    return "ask";
}

export function shieldActionNotifies(action: any) {
    const normalized = normalizeShieldDetectionAction(action);
    return normalized === "ask" || normalized.endsWith("_notify");
}
