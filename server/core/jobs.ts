import { englishText } from "../../shared/localization/runtime";
import { buildVirusTotalRefinement, buildVirusTotalThreatName } from "../../addons/virustotal/server/refinement";
import { flushPendingClamdDatabaseReload } from "../../engines/clamav/server/daemon";
import { getExceptions, isExcluded } from "../../modules/exceptions/server/service";
import { getQuarantineMap } from "../../modules/quarantine/server/storage";
import { quarantineFile } from "../../modules/quarantine/server/files";
import { saveQuarantineMap } from "../../modules/quarantine/server/storage";
import { addScanResult } from "../../modules/results/server/storage";
import { normalizeShieldDetectionAction, shieldActionKind, shieldActionNotifies } from "../../modules/shield/server/actions";
import { shouldSkipBuiltInScanPath } from "../scanning/targets";
import { ScanProgress } from "../scanning/types";
import { ApplicationContext } from "./applicationContext";
import { sleep } from "./utils";
import express from "express";
export function createIsRunningClamdScanJob(context: Pick<ApplicationContext, "activeJobs">) {
    return () => Object.values(context.activeJobs).some(job => job.status === "running" &&
        (job.kind === "scan" || job.kind === "shield-scan"));
}
export function createRunDeferredMaintenance(context: ApplicationContext) {
    return (label: string, task: () => Promise<void> | void) => {
        const timer = setTimeout(() => {
            Promise.resolve()
                .then(task)
                .catch((e: any) => console.warn(englishText("backend.core.failed", {
                label: String(label)
            }), e?.message || e));
        }, 0);
        timer.unref?.();
    };
}
export function createCleanupDiscardedScanSession(context: Pick<ApplicationContext, "runDeferredMaintenance" | "scanSessions">) {
    return (jobId: string) => {
        context.runDeferredMaintenance(`Discarded scan cleanup ${jobId}`, async () => {
            let totalDeleted = 0;
            while (true) {
                const deleted = context.scanSessions.deleteFilesForJobPage(jobId, 10000);
                totalDeleted += deleted;
                if (deleted === 0)
                    break;
                await sleep(5);
            }
            if (totalDeleted > 0) {
                console.log(englishText("backend.core.discarded_scan_cleanup_removed_queued_files_for_job", {
                    value1: String(totalDeleted.toLocaleString()),
                    jobId: String(jobId)
                }));
            }
        });
    };
}
export function createFlushPendingClamdDatabaseReloadSoon(context: Pick<ApplicationContext, "runDeferredMaintenance" | "settings">) {
    return () => {
        context.runDeferredMaintenance("Deferred clamd reload", () => flushPendingClamdDatabaseReload(context.settings));
    };
}
export function createSendApiEventToClient(context: ApplicationContext) {
    return (client: express.Response, event: string, data: any) => {
        client.write(`event: ${event}\n`);
        client.write(`data: ${JSON.stringify(data)}\n\n`);
    };
}
export function createSendApiEvent(context: Pick<ApplicationContext, "eventClients" | "sendApiEventToClient">) {
    return (event: string, data: any) => {
        for (const client of Array.from(context.eventClients)) {
            try {
                context.sendApiEventToClient(client, event, data);
            }
            catch {
                context.eventClients.delete(client);
            }
        }
    };
}
export function createSendScanSummary(context: Pick<ApplicationContext, "settings" | "sendApiEvent">) {
    return (summary: any) => {
        if (context.settings.scanCompletionPopupEnabled === false)
            return;
        context.sendApiEvent("scan-summary", summary);
    };
}
export function createSendJobEventToClient(context: ApplicationContext) {
    return (client: express.Response, data: any) => {
        client.write(`event: job\n`);
        client.write(`data: ${JSON.stringify(data)}\n\n`);
    };
}
export function createBroadcastJobEvent(context: Pick<ApplicationContext, "jobEventClients" | "activeJobs" | "sendJobEventToClient">) {
    return (jobId: string, logs: string[] = []) => {
        const clients = context.jobEventClients.get(jobId);
        if (!clients || clients.size === 0)
            return;
        const job = context.activeJobs[jobId];
        if (!job) {
            for (const client of Array.from(clients)) {
                try {
                    context.sendJobEventToClient(client, { status: "missing", logs: [], progress: null });
                }
                catch { }
            }
            return;
        }
        const payload = {
            status: job.status,
            logs,
            progress: job.progress || null,
            result: job.result
        };
        for (const client of Array.from(clients)) {
            try {
                context.sendJobEventToClient(client, payload);
            }
            catch {
                clients.delete(client);
            }
        }
    };
}
export function createSaveJobProgress(context: Pick<ApplicationContext, "activeJobs" | "scanSessions" | "broadcastJobEvent">) {
    return (jobId: string, patch: Partial<ScanProgress>) => {
        const job = context.activeJobs[jobId];
        if (!job?.progress)
            return;
        job.progress = {
            ...job.progress,
            ...patch,
            updatedAt: Date.now()
        };
        job.progress.elapsedSeconds = Math.floor((Date.now() - job.progress.startedAt) / 1000);
        const lastOutputAt = job.lastOutputAt || job.progress.startedAt;
        job.progress.quietSeconds = Math.floor((Date.now() - lastOutputAt) / 1000);
        try {
            context.scanSessions.save(job.progress);
        }
        catch (e) {
            console.warn(englishText("backend.core.failed_to_save_scan_progress"), e);
        }
        context.broadcastJobEvent(jobId);
    };
}
export function createAppendJobLogs(context: Pick<ApplicationContext, "activeJobs" | "broadcastJobEvent">) {
    return (jobId: string, lines: string[]) => {
        const job = context.activeJobs[jobId];
        if (!job || lines.length === 0)
            return;
        job.logs.push(...lines);
        job.lastOutputAt = Date.now();
        if (job.logs.length > 1000)
            job.logs.splice(0, job.logs.length - 1000);
        const analysisLines = lines.filter(line => line.includes(" FOUND") ||
            line.startsWith("Scanned files:") ||
            line.startsWith("Infected files:") ||
            line.startsWith("Time:"));
        if (analysisLines.length) {
            if (!job.analysisLogs)
                job.analysisLogs = [];
            job.analysisLogs.push(...analysisLines);
            if (job.analysisLogs.length > 5000)
                job.analysisLogs.splice(0, job.analysisLogs.length - 5000);
        }
        context.broadcastJobEvent(jobId, lines);
    };
}
export function createCreateScanHeartbeat(context: Pick<ApplicationContext, "activeJobs" | "saveJobProgress">) {
    return (jobId: string, label: string) => {
        const startedAt = Date.now();
        const timer = setInterval(() => {
            const job = context.activeJobs[jobId];
            if (!job || job.status !== "running") {
                clearInterval(timer);
                return;
            }
            const now = Date.now();
            const elapsedSeconds = Math.floor((now - startedAt) / 1000);
            const lastOutputAt = job.lastOutputAt || startedAt;
            const quietSeconds = Math.floor((now - lastOutputAt) / 1000);
            context.saveJobProgress(jobId, {
                phase: job.progress?.phase || label,
                elapsedSeconds,
                quietSeconds
            });
        }, 5000);
        timer.unref?.();
        return timer;
    };
}
