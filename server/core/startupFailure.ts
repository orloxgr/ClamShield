import { originalConsole, writeAppLog } from "./logging";

export function reportBackendStartupFailure(error: any) {
    writeAppLog("server.log", "fatal", ["Backend startup failed", error]);
    if (process.listenerCount("clamshield-backend-failed"))
        (process as NodeJS.EventEmitter).emit("clamshield-backend-failed", error);
    else {
        originalConsole.error(error);
        process.exitCode = 1;
    }
}
