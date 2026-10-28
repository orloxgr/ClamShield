

export const appUpdateInstallLoggers = new Set<(message: string) => void>();

export const clamavEngineUpdateLoggers = new Set<(message: string) => void>();

export const yaraEngineUpdateLoggers = new Set<(message: string) => void>();

// A FreshClam run that never exits would hold freshclamUpdateInProgress forever and block every later update.
export const freshclamRunTimeoutMs = 30 * 60 * 1000;
