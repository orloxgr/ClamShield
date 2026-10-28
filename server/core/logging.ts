import diagnostics from "../../public/desktop-diagnostics.cjs";
import { runtimeState } from "./runtimeState";
import { appendFileSync, existsSync, mkdirSync, renameSync, rmSync, statSync } from "fs";
import path from "path";

export const maxDebugLogBytes = 25 * 1024 * 1024;

export function logArgToString(arg: any) {
    if (arg instanceof Error)
        return arg.stack || arg.message;
    if (typeof arg === "string")
        return arg;
    try {
        return JSON.stringify(arg);
    }
    catch {
        return String(arg);
    }
}

export function writeAppLog(fileName: string, level: string, args: any[]) {
    try {
        mkdirSync(runtimeState.currentLogsDir, { recursive: true });
        const logPath = path.join(runtimeState.currentLogsDir, fileName);
        rotateLogIfNeeded(logPath);
        const line = `[${new Date().toISOString()}] [${level.toUpperCase()}] ${diagnostics.sanitize(args, [process.env.CLAMSHIELD_API_TOKEN]).map(logArgToString).join(" ")}\n`;
        appendFileSync(logPath, line, "utf8");
    }
    catch {
        // Logging must never break protection or scans.
    }
}

export function rotateLogIfNeeded(logPath: string) {
    try {
        if (!existsSync(logPath) || statSync(logPath).size < maxDebugLogBytes)
            return;
        const rotatedPath = `${logPath}.1`;
        try {
            rmSync(rotatedPath, { force: true });
        }
        catch { }
        renameSync(logPath, rotatedPath);
    }
    catch {
        // Best-effort only; logging must never break protection or scans.
    }
}

export const originalConsole = {
    log: console.log.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
    debug: console.debug.bind(console)
};

console.log = (...args: any[]) => {
    originalConsole.log(...args);
    if (runtimeState.debugLoggingEnabled)
        writeAppLog("server.log", "info", args);
};

console.debug = (...args: any[]) => {
    originalConsole.debug(...args);
    if (runtimeState.debugLoggingEnabled)
        writeAppLog("server.log", "debug", args);
};

console.warn = (...args: any[]) => {
    originalConsole.warn(...args);
    if (runtimeState.debugLoggingEnabled)
        writeAppLog("server.log", "warn", args);
};

console.error = (...args: any[]) => {
    originalConsole.error(...args);
    writeAppLog("server.log", "error", args);
};

process.on("uncaughtException", error => {
    writeAppLog("server.log", "fatal", ["Uncaught exception", error]);
    originalConsole.error("Uncaught exception:", error);
});

process.on("unhandledRejection", reason => {
    writeAppLog("server.log", "fatal", ["Unhandled rejection", reason]);
    originalConsole.error("Unhandled rejection:", reason);
});
