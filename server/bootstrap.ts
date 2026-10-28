import {createHandleVirusTotalShieldDetection} from "../modules/shield/server/cloudDetection";
import { englishText } from "../shared/localization/runtime";
import { registerLanguageRoutes, describePresentationFields } from "./core/languages";
import { registerPostApiSanesecurityConfigure, registerPostApiSanesecurityDisconnect, registerPostApiUpdateSanesecurity } from "../addons/sanesecurity/server/routes";
import { registerPostApiSecuriteinfoConfigure, registerPostApiSecuriteinfoDisconnect } from "../addons/securiteinfo/server/routes";
import { getVirusTotalUtcDayKey, getVirusTotalUtcMonthKey, loadVirusTotalApiKey } from "../addons/virustotal/server/account";
import { registerGetApiVirustotalCloudStatus, registerGetApiVirustotalOnDemand, registerGetApiVirustotalOnDemandLimitWarning, registerGetApiVirustotalQueue, registerGetApiVirustotalRefinementStatus, registerPostApiVirustotalCloudConfigure, registerPostApiVirustotalCloudDisconnect, registerPostApiVirustotalCloudUsageRefresh, registerPostApiVirustotalCloudUsageSettings, registerPostApiVirustotalOnDemandJobId, registerPostApiVirustotalOnDemandJobIdConfirm } from "../addons/virustotal/server/routes";
import { createEnqueueContextMenuVirusTotalCheck, createEnqueueShieldVirusTotalCheck, createGetVirusTotalRefinementQueueItems, createGetVirusTotalRefinementQueueStatus, createProcessNextShieldVirusTotalCheck, createProcessNextVirusTotalRefinement, createProcessVirusTotalScanQueue, createScheduleShieldVirusTotalCheck, createScheduleVirusTotalRefinement, createScheduleVirusTotalScan } from "../addons/virustotal/server/workers";
import { checkClamAV, checkIsAdmin, manageClamd } from "../engines/clamav/server/daemon";
import { registerGetApiClamavEngineUpdate, registerPostApiClamavEngineUpdateInstall, registerPostApiClamavEngineUpdateRemind, registerPostApiClamavEngineUpdateSkip } from "../engines/clamav/server/routes";
import { registerGetApiYaraEngineUpdate, registerPostApiUpdateYara, registerPostApiYaraEngineUpdateInstall, registerPostApiYaraEngineUpdateRemind, registerPostApiYaraEngineUpdateSkip } from "../engines/yara/server/routes";
import { registerGetAlertHtml, registerGetApiEvents, registerGetApiReady, registerGetApiStatus, registerGetResultsReminderHtml, registerPostApiClientLog, registerPostApiInstallEngine, registerPostApiOpenWindowsSecurity } from "../modules/dashboard/server/routes";
import { registerGetApiDnsProtectionStatus, registerPostApiDnsProtectionApply, registerPostApiDnsProtectionRestore } from "../modules/dns-protection/server/routes";
import { registerGetApiExceptions, registerGetApiExceptionsReporting, registerPostApiContextMenuExceptions, registerPostApiExceptions, registerPostApiExceptionsAdd, registerPostApiExceptionsDeleteSelected, registerPostApiExceptionsExportFalsePositives, registerPostApiExceptionsReportFalsePositive, registerPostApiExceptionsReportStatus, registerPostApiQuarantineFileNameRestoreException, registerPostApiQuarantineRestoreSelectedException } from "../modules/exceptions/server/routes";
import { registerGetApiHistory, registerPostApiHistoryDeleteSelected } from "../modules/history/server/routes";
import { registerGetApiScanFailedFiles, registerGetApiScanJobId, registerGetApiScanJobIdEvents, registerGetApiScanResumable, registerGetScanSummaryHtml, registerPostApiScan, registerPostApiScanJobIdCancel, registerPostApiScanJobIdDiscard, registerPostApiScanLegacy } from "../modules/on-demand/server/routes";
import { ScanSessionStore } from "../modules/on-demand/server/sessions";
import { registerGetApiOpenQuarantine, registerGetApiQuarantine, registerPostApiEmptyQuarantine, registerPostApiQuarantineDeleteSelected } from "../modules/quarantine/server/routes";
import { registerGetApiPendingThreats, registerGetApiResults, registerGetApiResultsIdVirustotal, registerGetApiResultsIdVirustotalCloud, registerGetApiResultsIdVirustotalHash, registerGetApiResultsIdVirustotalUpload, registerGetApiResultsReminder, registerPostApiPendingThreatsIdAction, registerPostApiResultsActionSelected, registerPostApiResultsClearMissing, registerPostApiResultsClearSelectedUnavailable, registerPostApiResultsIdAction, registerPostApiResultsIdDismiss, registerPostApiResultsIdVirustotalSubmit, registerPostApiResultsQuarantineAll, registerPostApiResultsReminderAction, registerPostApiResultsVirustotalChecks, registerPostApiResultsVirustotalMd5All, registerPostApiResultsVirustotalRecheckAll, registerPostApiResultsVirustotalRefine, registerPostApiSimulateThreat } from "../modules/results/server/routes";
import { createBroadcastResultsReminder, createCheckResultWithVirusTotal, createGetResultsReminderPayload } from "../modules/results/server/workers";
import { registerGetApiScheduledScan, registerPostApiScheduledScanRuntime } from "../modules/scheduler/server/routes";
import { registerGetApiDefenderStatus, registerGetApiSelectFile, registerGetApiSelectFolder, registerGetApiSettings, registerGetApiSystemPaths, registerPostApiAcceptEula, registerPostApiAlertDefender, registerPostApiRestoreDefender, registerPostApiSettings, registerPostApiStopDefender, registerPostApiWindowsContextMenuConfigure } from "../modules/settings/server/routes";
import { ensureDirs, loadConfig, saveConfig } from "../modules/settings/server/service";
import { getScanSessionsDbPath, loadShieldScanCacheStore } from "../modules/shield/server/cache";
import { registerPostApiShieldCacheClear } from "../modules/shield/server/routes";
import { createQueuePendingThreat, createStartShield } from "../modules/shield/server/worker";
import { registerGetApiAppUpdate, registerGetUpdateAvailableHtml, registerPostApiAppUpdateDisable, registerPostApiAppUpdateInstall, registerPostApiAppUpdateRemind, registerPostApiAppUpdateSkip, registerPostApiUpdate } from "../modules/updates/server/routes";
import { createScheduleAppExitForUpdate, createScheduleNextAppUpdateCheck, createScheduleNextUpdate, createScheduleNextYaraUpdate, createStartSaneSecurityUpdate } from "../modules/updates/server/workers";
import { ApplicationContext } from "./core/applicationContext";
import { getAppStateDb } from "./core/database/schema";
import { normalizedStatePath } from "./core/database/values";
import { createAppendJobLogs, createBroadcastJobEvent, createCleanupDiscardedScanSession, createCreateScanHeartbeat, createFlushPendingClamdDatabaseReloadSoon, createIsRunningClamdScanJob, createRunDeferredMaintenance, createSaveJobProgress, createSendApiEvent, createSendApiEventToClient, createSendJobEventToClient, createSendScanSummary } from "./core/jobs";
import { writeAppLog } from "./core/logging";
import { cleanupOldLogs } from "./core/logs";
import { installerOptionsPath, runtimeDir } from "./core/paths";
import { runtimeState } from "./core/runtimeState";
import { apiCookieName, apiHeaderName, apiSessionToken, readCookie, requireLocalApiSession } from "./core/security";
import { reportBackendStartupFailure } from "./core/startupFailure";
import { PendingThreats } from "../modules/shield/server/pendingThreats";
import { configureWindowsContextMenuPackage, writeWindowsContextMenuState } from "./platform/contextMenu";
import { syncDefenderCompatibilityExclusions } from "./platform/defender";
import { createScheduleDefenderEnforcement } from "./platform/defenderWorker";
import { manageStartup } from "./platform/startup";
import { ScanProgress } from "./scanning/types";
import { virusTotalLimitWarningsEnabled } from "../addons/virustotal/server/virusTotalLimitWarning";
import { getVirusTotalQueuePage } from "../addons/virustotal/server/virusTotalQueueView";
import { VirusTotalScanQueue } from "../addons/virustotal/server/virusTotalScanQueue";
import { VirusTotalUsage } from "../addons/virustotal/server/virusTotalUsage";
import axios from "axios";
import express from "express";
import fs from "fs/promises";
import path from "path";
export async function startServer() {
    const app = express();
    const context: ApplicationContext = {
        get settings() { return settings; }, set settings(value) { settings = value; },
        get legacyUsage() { return legacyUsage; },
        get defenderTimer() { return defenderTimer; }, set defenderTimer(value) { defenderTimer = value; },
        get scheduleDefenderEnforcement() { return scheduleDefenderEnforcement; },
        get scanSessions() { return scanSessions; },
        get virusTotalScanQueue() { return virusTotalScanQueue; },
        get resetSessions() { return resetSessions; },
        get activeJobs() { return activeJobs; },
        get isRunningClamdScanJob() { return isRunningClamdScanJob; },
        get scheduledScanRuntime() { return scheduledScanRuntime; }, set scheduledScanRuntime(value) { scheduledScanRuntime = value; },
        get appUpdateExitScheduled() { return appUpdateExitScheduled; }, set appUpdateExitScheduled(value) { appUpdateExitScheduled = value; },
        get runDeferredMaintenance() { return runDeferredMaintenance; },
        get cleanupDiscardedScanSession() { return cleanupDiscardedScanSession; },
        get flushPendingClamdDatabaseReloadSoon() { return flushPendingClamdDatabaseReloadSoon; },
        get scheduleAppExitForUpdate() { return scheduleAppExitForUpdate; },
        get pendingThreatStore() { return pendingThreatStore; },
        get pendingThreats() { return pendingThreats; },
        get pendingThreatActions() { return pendingThreatActions; },
        get queuePendingThreat() { return queuePendingThreat; },
        get virusTotalShieldQueue() { return virusTotalShieldQueue; },
        get virusTotalShieldActiveItem() { return virusTotalShieldActiveItem; }, set virusTotalShieldActiveItem(value) { virusTotalShieldActiveItem = value; },
        get eventClients() { return eventClients; },
        get sendApiEventToClient() { return sendApiEventToClient; },
        get sendApiEvent() { return sendApiEvent; },
        get sendScanSummary() { return sendScanSummary; },
        get jobEventClients() { return jobEventClients; },
        get sendJobEventToClient() { return sendJobEventToClient; },
        get broadcastJobEvent() { return broadcastJobEvent; },
        get getResultsReminderPayload() { return getResultsReminderPayload; },
        get scheduleVirusTotalRefinement() { return scheduleVirusTotalRefinement; }, set scheduleVirusTotalRefinement(value) { scheduleVirusTotalRefinement = value; },
        get broadcastResultsReminder() { return broadcastResultsReminder; },
        get scheduleShieldVirusTotalCheck() { return scheduleShieldVirusTotalCheck; }, set scheduleShieldVirusTotalCheck(value) { scheduleShieldVirusTotalCheck = value; },
        get handleVirusTotalShieldDetection() { return handleVirusTotalShieldDetection; },
        get processNextShieldVirusTotalCheck() { return processNextShieldVirusTotalCheck; },
        get enqueueShieldVirusTotalCheck() { return enqueueShieldVirusTotalCheck; },
        get enqueueContextMenuVirusTotalCheck() { return enqueueContextMenuVirusTotalCheck; },
        get virusTotalScanTimer() { return virusTotalScanTimer; }, set virusTotalScanTimer(value) { virusTotalScanTimer = value; },
        get virusTotalScanRunning() { return virusTotalScanRunning; }, set virusTotalScanRunning(value) { virusTotalScanRunning = value; },
        get virusTotalScanNextAllowedAt() { return virusTotalScanNextAllowedAt; }, set virusTotalScanNextAllowedAt(value) { virusTotalScanNextAllowedAt = value; },
        get scheduleVirusTotalScan() { return scheduleVirusTotalScan; },
        get processVirusTotalScanQueue() { return processVirusTotalScanQueue; },
        get shieldScanCache() { return shieldScanCache; },
        get saveJobProgress() { return saveJobProgress; },
        get appendJobLogs() { return appendJobLogs; },
        get startSaneSecurityUpdate() { return startSaneSecurityUpdate; },
        get createScanHeartbeat() { return createScanHeartbeat; },
        get shieldWatcher() { return shieldWatcher; }, set shieldWatcher(value) { shieldWatcher = value; },
        get startShield() { return startShield; },
        get autoUpdateTimer() { return autoUpdateTimer; }, set autoUpdateTimer(value) { autoUpdateTimer = value; },
        get scheduleNextUpdate() { return scheduleNextUpdate; },
        get yaraAutoUpdateTimer() { return yaraAutoUpdateTimer; }, set yaraAutoUpdateTimer(value) { yaraAutoUpdateTimer = value; },
        get scheduleNextYaraUpdate() { return scheduleNextYaraUpdate; },
        get appUpdateTimer() { return appUpdateTimer; }, set appUpdateTimer(value) { appUpdateTimer = value; },
        get scheduleNextAppUpdateCheck() { return scheduleNextAppUpdateCheck; },
        get getVirusTotalRefinementQueueItems() { return getVirusTotalRefinementQueueItems; },
        get getVirusTotalRefinementQueueStatus() { return getVirusTotalRefinementQueueStatus; },
        get processNextVirusTotalRefinement() { return processNextVirusTotalRefinement; },
        get checkResultWithVirusTotal() { return checkResultWithVirusTotal; },
        get PORT() { return PORT; }
    };
    app.use(express.json());
    app.use((req, res, next) => {
        const hasValidSession = readCookie(req, apiCookieName) === apiSessionToken || req.header(apiHeaderName) === apiSessionToken;
        if (hasValidSession) {
            res.cookie(apiCookieName, apiSessionToken, {
                httpOnly: true,
                sameSite: "strict",
                secure: false,
                path: "/"
            });
        }
        next();
    });
    app.use(requireLocalApiSession);
    let settings = await loadConfig();
    runtimeState.currentVirusTotalSettings = () => settings;
    await ensureDirs(settings);
    registerLanguageRoutes(app, context);
    app.use((req, res, next) => {
        const json = res.json.bind(res);
        res.json = value => json(describePresentationFields(value));
        next();
    });
    runtimeState.virusTotalUsageTracker = new VirusTotalUsage(getAppStateDb(), async (apiKey) => {
        // VirusTotal permits an API key as the user ID for this self-service endpoint.
        // Do not log Axios errors: the request URL contains the key.
        const response = await axios.get(`https://www.virustotal.com/api/v3/users/${encodeURIComponent(apiKey)}/overall_quotas`, {
            headers: { "x-apikey": apiKey }, timeout: 15000
        });
        return response.data;
    });
    runtimeState.virusTotalUsageTracker.setKey(await loadVirusTotalApiKey());
    const legacyUsage = getAppStateDb().prepare("SELECT count FROM virus_total_usage WHERE period = ?");
    runtimeState.virusTotalUsageTracker.seedLegacyCounts(Number(legacyUsage.get(`virustotal:${getVirusTotalUtcDayKey()}`)?.count || 0), Number(legacyUsage.get(`virustotal:${getVirusTotalUtcMonthKey()}`)?.count || 0));
    if (settings.virusTotalCloudEnabled === true) {
        runtimeState.virusTotalUsageTracker.refresh(runtimeState.virusTotalUsageRefreshEveryRequests).catch(() => { });
    }
    if (runtimeState.pendingInstallerOptionsApplied) {
        await saveConfig(settings, { keys: ["startMinimized", "windowsContextMenuEnabled"] });
        await fs.rm(installerOptionsPath, { force: true }).catch(() => { });
    }
    await cleanupOldLogs(settings);
    if (settings.defenderCompatibilityExclusionsEnabled === true) {
        syncDefenderCompatibilityExclusions(settings)
            .catch(e => console.warn(englishText("backend.bootstrap.ts.defender_compatibility_exclusions_were_not_fully_applied"), e?.message || e));
    }
    console.log(englishText("backend.bootstrap.ts.clamshield_service_starting"), {
        version: process.env.npm_package_version,
        logsDir: settings.logsDir,
        debugLoggingEnabled: settings.enableDebugLog === true
    });
    let defenderTimer: NodeJS.Timeout | null = null;
    const scheduleDefenderEnforcement = createScheduleDefenderEnforcement(context);
    await scheduleDefenderEnforcement(true);
    await checkClamAV(settings);
    await manageStartup(settings);
    runtimeState.cachedIsAdmin = await checkIsAdmin();
    if (runtimeState.pendingInstallerOptionsApplied) {
        try {
            await configureWindowsContextMenuPackage(settings.windowsContextMenuEnabled === true, settings);
        }
        catch (e: any) {
            console.warn(englishText("backend.bootstrap.ts.installer_selected_windows_context_menu_integration_could_not_be"), e?.message || e);
            if (settings.windowsContextMenuEnabled === true) {
                settings = { ...settings, windowsContextMenuEnabled: false };
                await saveConfig(settings, { keys: ["windowsContextMenuEnabled"] });
            }
        }
    }
    await writeWindowsContextMenuState(settings);
    const scanSessions = new ScanSessionStore(getScanSessionsDbPath());
    const virusTotalScanQueue = new VirusTotalScanQueue(getAppStateDb());
    virusTotalScanQueue.recover();
    if (!virusTotalLimitWarningsEnabled(settings.virusTotalShowLimitWarnings))
        virusTotalScanQueue.disableConfirmations();
    const resetSessions = scanSessions.resetInterruptedRunningSessions();
    if (resetSessions.paused > 0 || resetSessions.completed > 0) {
        console.log(englishText("backend.bootstrap.ts.recovered_interrupted_scan_sessions_resumable_paused_non_resumabl", {
            paused: String(resetSessions.paused),
            completed: String(resetSessions.completed),
            value3: String(resetSessions.resetFiles.toLocaleString())
        }));
    }
    const activeJobs: Record<string, {
        status: string;
        kind?: string;
        logs: string[];
        analysisLogs?: string[];
        result?: number;
        process?: any;
        processes?: Set<any>;
        lastOutputAt?: number;
        progress?: ScanProgress;
    }> = {};
    const isRunningClamdScanJob = createIsRunningClamdScanJob(context);
    runtimeState.shouldDeferClamdDatabaseReload = isRunningClamdScanJob;
    let scheduledScanRuntime = {
        state: "idle",
        message: settings.scheduledScanEnabled ? englishText("desktop.electron_main.waiting_for_the_next_scheduled_scan") : englishText("desktop.electron_main.scheduled_scanning_is_disabled"),
        activeJobId: "",
        currentTarget: "",
        queueIndex: 0,
        totalTargets: 0,
        idleSeconds: 0,
        updatedAt: Date.now()
    };
    let appUpdateExitScheduled = false;
    const runDeferredMaintenance = createRunDeferredMaintenance(context);
    const cleanupDiscardedScanSession = createCleanupDiscardedScanSession(context);
    const flushPendingClamdDatabaseReloadSoon = createFlushPendingClamdDatabaseReloadSoon(context);
    const scheduleAppExitForUpdate = createScheduleAppExitForUpdate(context);
    const pendingThreatStore = new PendingThreats();
    const pendingThreats = pendingThreatStore.items;
    const pendingThreatActions = new Map<string, Promise<any>>();
    const queuePendingThreat = createQueuePendingThreat(context);
    const virusTotalShieldQueue = new Map<string, {
        filePath: string;
        queuedAt: number;
        notBefore?: number;
        uploadedHash?: string;
        pendingUploadHash?: string;
        forceCloudCheck?: boolean;
        analysisId?: string;
    }>();
    let virusTotalShieldActiveItem: any = null;
    runtimeState.virusTotalQueueViewHandler = (options, configured) => {
        const pending = new Map<string, any>();
        for (const [id, item] of virusTotalShieldQueue)
            pending.set(id, {
                id: `shield:${id}`, filePath: item.filePath, createdAt: item.queuedAt,
                phase: item.pendingUploadHash ? "needs_upload" : item.uploadedHash ? englishText("backend.virustotal.analysing") : englishText("backend.virustotal.pending"),
                nextAttemptAt: item.notBefore || 0, analysisId: item.analysisId || ""
            });
        if (virusTotalShieldActiveItem)
            pending.set(normalizedStatePath(virusTotalShieldActiveItem.filePath), virusTotalShieldActiveItem);
        return getVirusTotalQueuePage(getAppStateDb(), settings, [...pending.values()], {
            enabled: settings.virusTotalCloudEnabled === true, configured,
            activeResultsId: runtimeState.virusTotalActiveResultsId, activeScanId: runtimeState.virusTotalActiveScanId,
            activeResultsPhase: runtimeState.virusTotalActiveResultsPhase,
            resultsNextAt: runtimeState.virusTotalRefinementNextAllowedAt, shieldNextAt: runtimeState.virusTotalShieldNextAllowedAt,
            scanNextAt: virusTotalScanNextAllowedAt, lookupNextAt: runtimeState.virusTotalNextLookupAllowedAt,
            resultsWaitReason: runtimeState.virusTotalResultsWaitReason, shieldWaitReason: runtimeState.virusTotalShieldWaitReason,
        }, options);
    };
    const eventClients = new Set<express.Response>();
    const sendApiEventToClient = createSendApiEventToClient(context);
    const sendApiEvent = createSendApiEvent(context);
    const sendScanSummary = createSendScanSummary(context);
    const jobEventClients = new Map<string, Set<express.Response>>();
    const sendJobEventToClient = createSendJobEventToClient(context);
    const broadcastJobEvent = createBroadcastJobEvent(context);
    const getResultsReminderPayload = createGetResultsReminderPayload(context);
    let scheduleVirusTotalRefinement: (delayMs?: number) => void = createScheduleVirusTotalRefinement(context);
    const broadcastResultsReminder = createBroadcastResultsReminder(context);
    runtimeState.pendingThreatHandler = threat => sendApiEvent("threat", threat);
    runtimeState.scanResultsChangedHandler = async () => {
        await broadcastResultsReminder();
        scheduleVirusTotalRefinement();
    };
    let scheduleShieldVirusTotalCheck: (delayMs?: number) => void = createScheduleShieldVirusTotalCheck(context);
    const handleVirusTotalShieldDetection = createHandleVirusTotalShieldDetection(context);
    const processNextShieldVirusTotalCheck = createProcessNextShieldVirusTotalCheck(context);
    scheduleShieldVirusTotalCheck = (delayMs = 0) => {
        if (runtimeState.virusTotalShieldTimer)
            clearTimeout(runtimeState.virusTotalShieldTimer);
        if (virusTotalShieldQueue.size === 0)
            return;
        if (settings.virusTotalCloudEnabled !== true)
            return;
        if (settings.virusTotalShieldBackgroundCheckEnabled !== true && !Array.from(virusTotalShieldQueue.values()).some(item => item.forceCloudCheck || item.uploadedHash))
            return;
        const delay = Math.max(0, Math.min(Number(delayMs || 0), 15 * 60 * 1000));
        runtimeState.virusTotalShieldTimer = setTimeout(() => {
            runtimeState.virusTotalShieldTimer = null;
            processNextShieldVirusTotalCheck().catch(e => console.warn(englishText("backend.bootstrap.ts.virustotal_shield_check_failed"), e?.message || e));
        }, delay);
    };
    const enqueueShieldVirusTotalCheck = createEnqueueShieldVirusTotalCheck(context);
    const enqueueContextMenuVirusTotalCheck = createEnqueueContextMenuVirusTotalCheck(context);
    let virusTotalScanTimer: NodeJS.Timeout | null = null;
    let virusTotalScanRunning = false;
    let virusTotalScanNextAllowedAt = 0;
    const scheduleVirusTotalScan = createScheduleVirusTotalScan(context);
    const processVirusTotalScanQueue = createProcessVirusTotalScanQueue(context);
    // Cloud checks can outlive the local scan and resume after an app restart.
    scheduleVirusTotalScan(5000);
    const shieldScanCache = await loadShieldScanCacheStore();
    console.log(englishText("backend.bootstrap.ts.shield_cache_backend", {
        type: String(shieldScanCache.type)
    }));
    const saveJobProgress = createSaveJobProgress(context);
    const appendJobLogs = createAppendJobLogs(context);
    const startSaneSecurityUpdate = createStartSaneSecurityUpdate(context);
    registerPostApiClientLog(app, context);
    registerGetApiEvents(app, context);
    const createScanHeartbeat = createCreateScanHeartbeat(context);
    let shieldWatcher: any = null;
    const startShield = createStartShield(context);
    startShield(settings);
    await manageClamd(settings);
    registerGetApiReady(app, context);
    registerGetApiStatus(app, context);
    registerPostApiInstallEngine(app, context);
    // Add automatic update task
    let autoUpdateTimer: NodeJS.Timeout | null = null;
    const scheduleNextUpdate = createScheduleNextUpdate(context);
    let yaraAutoUpdateTimer: NodeJS.Timeout | null = null;
    const scheduleNextYaraUpdate = createScheduleNextYaraUpdate(context);
    let appUpdateTimer: NodeJS.Timeout | null = null;
    const scheduleNextAppUpdateCheck = createScheduleNextAppUpdateCheck(context);
    const getVirusTotalRefinementQueueItems = createGetVirusTotalRefinementQueueItems(context);
    const getVirusTotalRefinementQueueStatus = createGetVirusTotalRefinementQueueStatus(context);
    const processNextVirusTotalRefinement = createProcessNextVirusTotalRefinement(context);
    scheduleVirusTotalRefinement = (delayMs = 0) => {
        if (runtimeState.virusTotalRefinementTimer)
            clearTimeout(runtimeState.virusTotalRefinementTimer);
        if (settings.virusTotalCloudEnabled !== true)
            return;
        const delay = Math.max(0, Math.min(Number(delayMs || 0), 15 * 60 * 1000));
        runtimeState.virusTotalRefinementTimer = setTimeout(() => {
            runtimeState.virusTotalRefinementTimer = null;
            processNextVirusTotalRefinement().catch(e => console.warn(englishText("backend.bootstrap.ts.virustotal_refinement_failed"), e?.message || e));
        }, delay);
    };
    // Initial trigger
    scheduleNextUpdate();
    scheduleNextYaraUpdate();
    scheduleNextAppUpdateCheck();
    scheduleVirusTotalRefinement(5000);
    scheduleShieldVirusTotalCheck(5000);
    registerGetApiSettings(app, context);
    registerPostApiWindowsContextMenuConfigure(app, context);
    registerPostApiSettings(app, context);
    registerGetApiScheduledScan(app, context);
    registerPostApiScheduledScanRuntime(app, context);
    registerPostApiSecuriteinfoConfigure(app, context);
    registerPostApiSecuriteinfoDisconnect(app, context);
    registerPostApiSanesecurityConfigure(app, context);
    registerPostApiSanesecurityDisconnect(app, context);
    registerGetApiVirustotalCloudStatus(app, context);
    registerPostApiVirustotalCloudUsageRefresh(app, context);
    registerPostApiVirustotalCloudUsageSettings(app, context);
    registerPostApiVirustotalCloudConfigure(app, context);
    registerPostApiVirustotalCloudDisconnect(app, context);
    registerGetApiVirustotalQueue(app, context);
    registerGetApiVirustotalRefinementStatus(app, context);
    registerPostApiResultsVirustotalRefine(app, context);
    registerPostApiUpdateSanesecurity(app, context);
    registerPostApiShieldCacheClear(app, context);
    registerPostApiAcceptEula(app, context);
    registerGetApiSystemPaths(app, context);
    registerGetApiDnsProtectionStatus(app, context);
    registerPostApiDnsProtectionApply(app, context);
    registerPostApiDnsProtectionRestore(app, context);
    registerGetApiDefenderStatus(app, context);
    registerPostApiAlertDefender(app, context);
    registerPostApiStopDefender(app, context);
    registerPostApiRestoreDefender(app, context);
    registerPostApiOpenWindowsSecurity(app, context);
    registerGetApiHistory(app, context);
    registerPostApiHistoryDeleteSelected(app, context);
    registerGetApiScanFailedFiles(app, context);
    registerGetApiSelectFolder(app, context);
    registerGetApiSelectFile(app, context);
    registerPostApiContextMenuExceptions(app, context);
    registerGetApiVirustotalOnDemandLimitWarning(app, context);
    registerPostApiVirustotalOnDemandJobIdConfirm(app, context);
    registerGetApiVirustotalOnDemand(app, context);
    registerPostApiVirustotalOnDemandJobId(app, context);
    registerPostApiScan(app, context);
    registerPostApiScanLegacy(app, context);
    registerGetApiScanResumable(app, context);
    registerPostApiScanJobIdDiscard(app, context);
    registerGetApiScanJobIdEvents(app, context);
    registerGetApiScanJobId(app, context);
    registerPostApiScanJobIdCancel(app, context);
    registerPostApiUpdate(app, context);
    registerPostApiUpdateYara(app, context);
    registerGetApiAppUpdate(app, context);
    registerPostApiAppUpdateSkip(app, context);
    registerPostApiAppUpdateRemind(app, context);
    registerPostApiAppUpdateDisable(app, context);
    registerPostApiAppUpdateInstall(app, context);
    registerGetApiClamavEngineUpdate(app, context);
    registerPostApiClamavEngineUpdateSkip(app, context);
    registerPostApiClamavEngineUpdateRemind(app, context);
    registerPostApiClamavEngineUpdateInstall(app, context);
    registerGetApiYaraEngineUpdate(app, context);
    registerPostApiYaraEngineUpdateSkip(app, context);
    registerPostApiYaraEngineUpdateRemind(app, context);
    registerPostApiYaraEngineUpdateInstall(app, context);
    registerGetApiResults(app, context);
    registerPostApiResultsVirustotalMd5All(app, context);
    registerPostApiResultsVirustotalRecheckAll(app, context);
    registerGetApiResultsIdVirustotalHash(app, context);
    registerPostApiResultsVirustotalChecks(app, context);
    registerGetApiResultsIdVirustotal(app, context);
    const checkResultWithVirusTotal = createCheckResultWithVirusTotal(context);
    registerGetApiResultsIdVirustotalCloud(app, context);
    registerPostApiResultsIdVirustotalSubmit(app, context);
    registerGetApiResultsIdVirustotalUpload(app, context);
    registerPostApiResultsQuarantineAll(app, context);
    registerPostApiResultsClearMissing(app, context);
    registerPostApiResultsClearSelectedUnavailable(app, context);
    registerPostApiResultsActionSelected(app, context);
    registerGetApiResultsReminder(app, context);
    registerPostApiResultsReminderAction(app, context);
    registerPostApiResultsIdDismiss(app, context);
    registerPostApiResultsIdAction(app, context);
    registerGetApiPendingThreats(app, context);
    registerPostApiSimulateThreat(app, context);
    registerPostApiPendingThreatsIdAction(app, context);
    registerPostApiEmptyQuarantine(app, context);
    registerGetApiExceptions(app, context);
    registerGetApiExceptionsReporting(app, context);
    registerPostApiExceptionsAdd(app, context);
    registerPostApiExceptionsDeleteSelected(app, context);
    registerPostApiExceptionsExportFalsePositives(app, context);
    registerPostApiExceptionsReportFalsePositive(app, context);
    registerPostApiExceptionsReportStatus(app, context);
    registerPostApiExceptions(app, context);
    registerGetApiQuarantine(app, context);
    registerPostApiQuarantineFileNameRestoreException(app, context);
    registerPostApiQuarantineRestoreSelectedException(app, context);
    registerPostApiQuarantineDeleteSelected(app, context);
    registerGetApiOpenQuarantine(app, context);
    registerGetAlertHtml(app, context);
    registerGetResultsReminderHtml(app, context);
    registerGetScanSummaryHtml(app, context);
    registerGetUpdateAvailableHtml(app, context);
    // Vite Middleware for Frontend
    if (process.env.NODE_ENV !== "production") {
        const { createServer: createViteServer } = await import("vite");
        const vite = await createViteServer({
            server: { middlewareMode: true },
            appType: "spa"
        });
        app.use(vite.middlewares);
    }
    else {
        const distPath = path.join(runtimeDir);
        app.use(express.static(distPath));
        app.get("*", (req, res, next) => {
            if (path.extname(req.path)) {
                const error: any = new Error(englishText("backend.bootstrap.ts.a_requested_interface_resource_was_not_found"));
                error.status = 404;
                return next(error);
            }
            res.sendFile(path.join(distPath, "index.html"), error => {
                if (error)
                    next(error);
            });
        });
    }
    app.use((error: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
        writeAppLog("server.log", "error", ["HTTP request failed", { method: req.method, path: req.path, code: error.code, status: error.status || 500, message: error.message, stack: error.stack }]);
        if (res.headersSent)
            return next(error);
        res.status(error.status || 500).json({ error: englishText("backend.bootstrap.ts.the_local_service_could_not_complete_this_request_see_the_applica") });
    });
    const PORT = process.env.PORT || 3000;
    app.listen(Number(PORT), "127.0.0.1", () => {
        console.log(englishText("backend.bootstrap.ts.server_running_on_http_127_0_0_1_simulated", {
            PORT: String(PORT),
            isSimulated: String(runtimeState.isSimulated)
        }));
    }).on("error", reportBackendStartupFailure);
}
