import { getSaneSecurityStatus } from "../../../../addons/sanesecurity/server/status";
import { getSecuriteInfoStatus } from "../../../../addons/securiteinfo/server/service";
import { getVirusTotalDashboardStatus } from "../../../../addons/virustotal/server/status";
import { getClamAVEngineVersion } from "../../../../engines/clamav/server/version";
import { getYaraRulesFile, normalizeYaraRuleset } from "../../../../engines/yara/server/rules";
import { getCurrentYaraEngineVersion } from "../../../../engines/yara/server/version";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { pathExists } from "../../../../server/scanning/files";
import { getDashboardHistorySummary } from "../../../history/server/storage";
import { getQuarantineCount } from "../../../quarantine/server/storage";
import { restoreInstalledSignatureProviderSettings } from "../../../settings/server/service";
import { getCurrentAppVersion } from "../../../updates/server/versions";
import { existsSync } from "fs";
import fs from "fs/promises";
export function registerGetApiStatus(app: any, context: Pick<ApplicationContext, "settings" | "activeJobs" | "scheduledScanRuntime" | "shieldScanCache">) {
    app.get("/api/status", async (req, res) => {
        context.settings = await restoreInstalledSignatureProviderSettings(context.settings);
        const historySummary = await getDashboardHistorySummary();
        let hasEngine = false;
        let hasDb = false;
        let hasYaraEngine = false;
        let hasYaraRules = false;
        const quarantineCount = await getQuarantineCount(context.settings.quarantineDir);
        try {
            hasEngine = await pathExists(context.settings.clamscanPath) && await pathExists(context.settings.freshclamPath);
            const dbFiles = await fs.readdir(context.settings.databaseDir);
            hasDb = dbFiles.some(f => f.endsWith('.cvd') || f.endsWith('.cld'));
        }
        catch { }
        hasYaraEngine = Boolean(context.settings.yaraPath && existsSync(context.settings.yaraPath));
        hasYaraRules = existsSync(getYaraRulesFile(context.settings));
        const [securiteInfo, saneSecurity, virusTotalCloud, engineVersion, yaraEngineVersion] = await Promise.all([
            getSecuriteInfoStatus(context.settings),
            getSaneSecurityStatus(context.settings),
            getVirusTotalDashboardStatus(context.settings),
            getClamAVEngineVersion(context.settings, hasEngine),
            getCurrentYaraEngineVersion(context.settings)
        ]);
        const pkgVersion = await getCurrentAppVersion();
        const activeScanJobIds = Object.entries(context.activeJobs)
            .filter(([, job]) => job.status === "running" && ["disk", "folder", "file", "memory", "context"].includes(job.progress?.type || ""))
            .map(([jobId]) => jobId);
        res.json({
            appVersion: pkgVersion,
            isSimulated: runtimeState.isSimulated,
            isInstalling: runtimeState.isInstalling,
            installProgress: runtimeState.installProgress,
            isSignatureUpdateRunning: runtimeState.freshclamUpdateInProgress,
            isSaneSecurityUpdateRunning: runtimeState.saneSecurityUpdateInProgress,
            signatureUpdateJobId: runtimeState.freshclamUpdateInProgress ? runtimeState.freshclamUpdateJobId : null,
            signatureUpdateTarget: runtimeState.freshclamUpdateTarget,
            saneSecurityUpdateJobId: runtimeState.saneSecurityUpdateInProgress ? runtimeState.saneSecurityUpdateJobId : null,
            platform: process.platform,
            isAdmin: runtimeState.cachedIsAdmin,
            settings: context.settings,
            scheduledScanRuntime: context.scheduledScanRuntime,
            activeScanJobIds,
            hasEngine,
            hasDb,
            hasYaraEngine,
            hasYaraRules,
            securiteInfo,
            saneSecurity,
            virusTotalCloud,
            stats: {
                engineVersion,
                yaraEngineVersion,
                yaraRuleset: normalizeYaraRuleset(context.settings.yaraRuleset),
                yaraRuleCount: context.settings.lastYaraRuleCount || 0,
                lastYaraUpdate: context.settings.lastYaraUpdate || null,
                clamavEngineLastCheck: context.settings.clamavEngineLastCheck || null,
                clamavEngineLastCheckResult: context.settings.clamavEngineLastCheckResult || "",
                yaraEngineLastCheck: context.settings.yaraEngineLastCheck || null,
                yaraEngineLastCheckResult: context.settings.yaraEngineLastCheckResult || "",
                lastClamAVUpdate: context.settings.lastClamAVUpdate || null,
                lastClamAVUpdateResult: context.settings.lastClamAVUpdateResult || "",
                lastAppUpdateCheck: context.settings.lastAppUpdateCheck || (historySummary.lastAppUpdateCheck ? historySummary.lastAppUpdateCheck.date : null),
                lastScan: historySummary.lastScan ? historySummary.lastScan.date : null,
                lastUpdate: historySummary.lastUpdate ? historySummary.lastUpdate.date : null,
                lastThreat: historySummary.lastThreat ? historySummary.lastThreat.date : null,
                lastCloudCheck: historySummary.lastCloudCheck ? historySummary.lastCloudCheck.date : null,
                quarantineCount,
                shieldCacheCount: context.shieldScanCache.count(),
                shieldCacheBackend: context.shieldScanCache.type
            }
        });
    });
}
