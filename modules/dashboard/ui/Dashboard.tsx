import { t, localizeText, useLanguage } from "../../../src/lib/i18n";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router";
import { Shield, ShieldAlert, Cpu, Database, Clock, Activity, FileWarning, DownloadCloud, Loader2, ExternalLink, X, RefreshCw, Cloud, KeyRound, SearchCheck, Trash2, UploadCloud } from "lucide-react";

import PageHeader from "../../../src/components/PageHeader";
import UpdateJobProgress from "../../../src/components/UpdateJobProgress";
import VirusTotalQueueDialog from "../../../addons/virustotal/ui/VirusTotalQueueDialog";
import { formatRelativeTime, formatSystemDateTime } from "../../../src/lib/dateFormat";
export default function Dashboard() {
    useLanguage();
    const [status, setStatus] = useState<any>(null);
    const [securiteInfoDialogOpen, setSecuriteInfoDialogOpen] = useState(false);
    const [securiteInfoSetupUrl, setSecuriteInfoSetupUrl] = useState("");
    const [securiteInfoPlan, setSecuriteInfoPlan] = useState<"basic" | "paid">("basic");
    const [securiteInfoIncludePua, setSecuriteInfoIncludePua] = useState(false);
    const [securiteInfoBusy, setSecuriteInfoBusy] = useState(false);
    const [securiteInfoMessage, setSecuriteInfoMessage] = useState("");
    const [securiteInfoJob, setSecuriteInfoJob] = useState<{
        jobId: string;
        simulated?: boolean;
    } | null>(null);
    const [saneSecurityDialogOpen, setSaneSecurityDialogOpen] = useState(false);
    const [saneSecurityProfile, setSaneSecurityProfile] = useState<"malware" | "complete">("malware");
    const [saneSecurityBusy, setSaneSecurityBusy] = useState(false);
    const [saneSecurityMessage, setSaneSecurityMessage] = useState("");
    const [saneSecurityJobId, setSaneSecurityJobId] = useState<string | null>(null);
    const [virusTotalDialogOpen, setVirusTotalDialogOpen] = useState(false);
    const [virusTotalQueueOpen, setVirusTotalQueueOpen] = useState(false);
    const [virusTotalApiKey, setVirusTotalApiKey] = useState("");
    const [virusTotalCloudEnabled, setVirusTotalCloudEnabled] = useState(false);
    const [virusTotalAutoRefineEnabled, setVirusTotalAutoRefineEnabled] = useState(false);
    const [virusTotalResultsUploadUnknownEnabled, setVirusTotalResultsUploadUnknownEnabled] = useState(false);
    const [virusTotalResultsUploadMaxSizeMb, setVirusTotalResultsUploadMaxSizeMb] = useState(20);
    const [virusTotalBusy, setVirusTotalBusy] = useState<"save" | "disconnect" | "refine" | null>(null);
    const [virusTotalMessage, setVirusTotalMessage] = useState("");
    const [usageFetchBusy, setUsageFetchBusy] = useState(false);
    const [usageFetchError, setUsageFetchError] = useState("");
    const [usageRefreshEvery, setUsageRefreshEvery] = useState("500");
    const fetchStatus = useCallback(() => {
        fetch("/api/status", { cache: "no-store" }).then(r => r.json()).then(setStatus).catch(() => { });
    }, []);
    useEffect(() => {
        if (status?.signatureUpdateTarget === "securiteinfo" && status.signatureUpdateJobId) {
            setSecuriteInfoJob(current => current?.jobId === status.signatureUpdateJobId ? current : { jobId: status.signatureUpdateJobId });
        }
        if (status?.saneSecurityUpdateJobId)
            setSaneSecurityJobId(status.saneSecurityUpdateJobId);
    }, [status?.signatureUpdateTarget, status?.signatureUpdateJobId, status?.saneSecurityUpdateJobId]);
    useEffect(() => {
        fetchStatus();
        const interval = setInterval(fetchStatus, 3000);
        return () => clearInterval(interval);
    }, []);
    useEffect(() => {
        setUsageRefreshEvery(String(status?.settings?.virusTotalUsageRefreshEveryRequests ?? 500));
    }, [status?.settings?.virusTotalUsageRefreshEveryRequests]);
    const fetchVirusTotalUsage = async () => {
        setUsageFetchBusy(true);
        setUsageFetchError("");
        try {
            const response = await fetch("/api/virustotal-cloud/usage/refresh", { method: "POST" });
            const data = await response.json();
            if (!response.ok)
                throw new Error(data.error || "Could not fetch VirusTotal usage.");
            setStatus((current: any) => current ? { ...current, virusTotalCloud: { ...current.virusTotalCloud, usage: data.usage } } : current);
        }
        catch (error: any) {
            setUsageFetchError(error.message);
        }
        finally {
            setUsageFetchBusy(false);
        }
    };
    const saveUsageRefreshEvery = async () => {
        const parsed = Number(usageRefreshEvery);
        const value = Number.isFinite(parsed) ? Math.max(1, Math.min(10000, Math.round(parsed))) : 500;
        setUsageRefreshEvery(String(value));
        if (value === (status?.settings?.virusTotalUsageRefreshEveryRequests ?? 500))
            return;
        setUsageFetchError("");
        try {
            const response = await fetch("/api/virustotal-cloud/usage/settings", {
                method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refreshEveryRequests: value })
            });
            const data = await response.json();
            if (!response.ok)
                throw new Error(data.error || "Could not save the usage refresh interval.");
            fetchStatus();
        }
        catch (error: any) {
            setUsageFetchError(error.message);
        }
    };
    const installEngine = async () => {
        try {
            await fetch("/api/install-engine", { method: "POST" });
            fetchStatus();
        }
        catch (e) {
            console.error(e);
        }
    };
    const connectSecuriteInfo = async () => {
        setSecuriteInfoBusy(true);
        setSecuriteInfoMessage("");
        try {
            const configureRes = await fetch("/api/securiteinfo/configure", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    setupText: securiteInfoSetupUrl,
                    plan: securiteInfoPlan,
                    includePua: securiteInfoIncludePua
                })
            });
            const configureData = await configureRes.json();
            if (!configureRes.ok)
                throw new Error(configureData.error || "Could not connect SecuriteInfo.");
            fetchStatus();
            const updateRes = await fetch("/api/update", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target: "securiteinfo" })
            });
            const updateData = await updateRes.json();
            if (!updateRes.ok)
                throw new Error(updateData.error || "Connected, but the signature update could not start.");
            setSecuriteInfoSetupUrl("");
            setSecuriteInfoJob({ jobId: updateData.jobId, simulated: updateData.simulated });
            setSecuriteInfoMessage("SecuriteInfo connected. Signature update started.");
            fetchStatus();
        }
        catch (e: any) {
            setSecuriteInfoMessage(e.message || "Could not connect SecuriteInfo.");
        }
        finally {
            setSecuriteInfoBusy(false);
        }
    };
    const updateSecuriteInfo = async () => {
        setSecuriteInfoBusy(true);
        setSecuriteInfoMessage("");
        try {
            const settingsRes = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    securiteInfoPlan,
                    securiteInfoIncludePua
                })
            });
            const settingsData = await settingsRes.json();
            if (!settingsRes.ok)
                throw new Error(settingsData.error || "Could not save SecuriteInfo settings.");
            const res = await fetch("/api/update", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target: "securiteinfo" })
            });
            const data = await res.json();
            if (!res.ok)
                throw new Error(data.error || "Could not start the signature update.");
            setSecuriteInfoJob({ jobId: data.jobId, simulated: data.simulated });
            setSecuriteInfoMessage("SecuriteInfo settings saved. Signature update started.");
            fetchStatus();
        }
        catch (e: any) {
            setSecuriteInfoMessage(e.message || "Could not start the signature update.");
        }
        finally {
            setSecuriteInfoBusy(false);
        }
    };
    const disconnectSecuriteInfo = async () => {
        if (!window.confirm(t("dashboard.disconnect_securiteinfo_and_remove_its_downloaded_signature_files")))
            return;
        setSecuriteInfoBusy(true);
        setSecuriteInfoMessage("");
        try {
            const res = await fetch("/api/securiteinfo/disconnect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ removeDatabases: true })
            });
            const data = await res.json();
            if (!res.ok)
                throw new Error(data.error || "Could not disconnect SecuriteInfo.");
            setSecuriteInfoMessage("SecuriteInfo disconnected and its signature files were removed.");
            fetchStatus();
        }
        catch (e: any) {
            setSecuriteInfoMessage(e.message || "Could not disconnect SecuriteInfo.");
        }
        finally {
            setSecuriteInfoBusy(false);
        }
    };
    const configureSaneSecurity = async () => {
        setSaneSecurityBusy(true);
        setSaneSecurityMessage("");
        try {
            const configureRes = await fetch("/api/sanesecurity/configure", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ profile: saneSecurityProfile })
            });
            const configureData = await configureRes.json();
            if (!configureRes.ok)
                throw new Error(configureData.error || "Could not configure SaneSecurity.");
            const updateRes = await fetch("/api/update-sanesecurity", { method: "POST" });
            const updateData = await updateRes.json();
            if (!updateRes.ok)
                throw new Error(updateData.error || "Configured, but the signature update could not start.");
            setSaneSecurityJobId(updateData.jobId);
            setSaneSecurityMessage("Installation started. The first setup downloads the helper tools before verifying and installing the databases.");
            fetchStatus();
        }
        catch (e: any) {
            setSaneSecurityMessage(e.message || "Could not configure SaneSecurity.");
        }
        finally {
            setSaneSecurityBusy(false);
        }
    };
    const updateSaneSecurity = async () => {
        setSaneSecurityBusy(true);
        setSaneSecurityMessage("");
        try {
            const res = await fetch("/api/update-sanesecurity", { method: "POST" });
            const data = await res.json();
            if (!res.ok)
                throw new Error(data.error || "Could not start the SaneSecurity update.");
            setSaneSecurityJobId(data.jobId);
            setSaneSecurityMessage("SaneSecurity update started.");
            fetchStatus();
        }
        catch (e: any) {
            setSaneSecurityMessage(e.message || "Could not start the SaneSecurity update.");
        }
        finally {
            setSaneSecurityBusy(false);
        }
    };
    const disconnectSaneSecurity = async () => {
        if (!window.confirm(t("dashboard.disconnect_sanesecurity_and_remove_its_downloaded_signature_files")))
            return;
        setSaneSecurityBusy(true);
        setSaneSecurityMessage("");
        try {
            const res = await fetch("/api/sanesecurity/disconnect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ removeDatabases: true })
            });
            const data = await res.json();
            if (!res.ok)
                throw new Error(data.error || "Could not disconnect SaneSecurity.");
            setSaneSecurityMessage("SaneSecurity disconnected and its signature databases were removed.");
            fetchStatus();
        }
        catch (e: any) {
            setSaneSecurityMessage(e.message || "Could not disconnect SaneSecurity.");
        }
        finally {
            setSaneSecurityBusy(false);
        }
    };
    const saveVirusTotalCloud = async () => {
        setVirusTotalBusy("save");
        setVirusTotalMessage("");
        try {
            const res = await fetch("/api/virustotal-cloud/configure", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    apiKey: virusTotalApiKey,
                    enabled: virusTotalCloudEnabled,
                    autoRefineEnabled: virusTotalAutoRefineEnabled,
                    resultsUploadUnknownEnabled: virusTotalResultsUploadUnknownEnabled,
                    resultsUploadMaxSizeMb: virusTotalResultsUploadMaxSizeMb
                })
            });
            const data = await res.json();
            if (!res.ok)
                throw new Error(data.error || "Could not save VirusTotal Cloud Check.");
            setVirusTotalApiKey("");
            setVirusTotalMessage(data.message || "VirusTotal Cloud Check saved.");
            fetchStatus();
        }
        catch (e: any) {
            setVirusTotalMessage(e.message || "Could not save VirusTotal Cloud Check.");
        }
        finally {
            setVirusTotalBusy(null);
        }
    };
    const disconnectVirusTotalCloud = async () => {
        if (!window.confirm(t("dashboard.disable_virustotal_cloud_check_and_remove_the_saved_api_key")))
            return;
        setVirusTotalBusy("disconnect");
        setVirusTotalMessage("");
        try {
            const res = await fetch("/api/virustotal-cloud/disconnect", { method: "POST" });
            const data = await res.json();
            if (!res.ok)
                throw new Error(data.error || "Could not disconnect VirusTotal Cloud Check.");
            setVirusTotalApiKey("");
            setVirusTotalCloudEnabled(false);
            setVirusTotalAutoRefineEnabled(false);
            setVirusTotalResultsUploadUnknownEnabled(false);
            setVirusTotalMessage(data.message || "VirusTotal Cloud Check disabled.");
            fetchStatus();
        }
        catch (e: any) {
            setVirusTotalMessage(e.message || "Could not disconnect VirusTotal Cloud Check.");
        }
        finally {
            setVirusTotalBusy(null);
        }
    };
    const runVirusTotalRefinement = async () => {
        setVirusTotalBusy("refine");
        setVirusTotalMessage("");
        try {
            const res = await fetch("/api/results/virustotal-refine", { method: "POST" });
            const data = await res.json();
            if (!res.ok)
                throw new Error(data.error || "Could not start VirusTotal refinement.");
            setVirusTotalMessage("VirusTotal refinement queue started.");
            fetchStatus();
        }
        catch (e: any) {
            setVirusTotalMessage(e.message || "Could not start VirusTotal refinement.");
        }
        finally {
            setVirusTotalBusy(null);
        }
    };
    if (!status)
        return <div className="p-8">{t("shield.loading")}</div>;
    const isProtected = status.settings?.shieldEnabled && !status.isSimulated;
    const securiteInfo = status.securiteInfo || {};
    const securiteInfoInstalled = securiteInfo.connected && Number(securiteInfo.installedCount || 0) > 0;
    const saneSecurity = status.saneSecurity || {};
    const saneSecurityInstalledCount = Number(saneSecurity.installedCount || 0);
    const saneSecurityFilesPresent = saneSecurityInstalledCount > 0;
    const saneSecurityInstalled = saneSecurity.connected && saneSecurityFilesPresent;
    const virusTotalCloud = status.virusTotalCloud || {};
    const virusTotalConfigured = virusTotalCloud.configured === true;
    const virusTotalEnabled = virusTotalCloud.enabled === true;
    const virusTotalAutoRefine = virusTotalCloud.autoRefineEnabled === true;
    const virusTotalCheckedCount = Number(virusTotalCloud.checkedCount || 0);
    const virusTotalQueuedCount = Math.max(0, Number(virusTotalCloud.queuedCount || 0));
    const virusTotalTotalFindings = Number(virusTotalCloud.totalFindings || 0);
    const virusTotalUsageDay = virusTotalCloud.usage?.day || {};
    const virusTotalUsageDayCount = Number(virusTotalUsageDay.count || 0);
    const virusTotalUsageDayLimit = Number(virusTotalUsageDay.limit || 0);
    const virusTotalUsageSync = virusTotalCloud.usage?.sync || {};
    const usageFetchCoolingDown = Number(virusTotalUsageSync.nextFetchAllowedAt || 0) > Date.now();
    const formatUpdateDate = (value: any) => formatSystemDateTime(value);
    const metadataValueClass = "font-medium text-slate-200";
    const attentionValueClass = "font-medium text-amber-400";
    const openSecuriteInfoDialog = () => {
        setSecuriteInfoPlan(securiteInfo.plan === "paid" ? "paid" : "basic");
        setSecuriteInfoIncludePua(securiteInfo.includePua === true);
        setSecuriteInfoMessage("");
        setSecuriteInfoDialogOpen(true);
    };
    const openVirusTotalDialog = () => {
        setVirusTotalCloudEnabled(virusTotalEnabled || !virusTotalConfigured);
        setVirusTotalAutoRefineEnabled(virusTotalAutoRefine);
        setVirusTotalResultsUploadUnknownEnabled(virusTotalCloud.resultsUploadUnknownEnabled === true);
        setVirusTotalResultsUploadMaxSizeMb(Number(virusTotalCloud.resultsUploadMaxSizeMb || 20));
        setVirusTotalApiKey("");
        setVirusTotalMessage("");
        setVirusTotalDialogOpen(true);
    };
    return (<div className="px-8 max-w-6xl mx-auto space-y-8 pb-20">
      <PageHeader title={t("dashboard.dashboard")} description={t("dashboard.system_protection_overview")} actions={(<div className={`mt-1 shrink-0 inline-flex items-center gap-2.5 rounded-lg border px-4 py-2.5 text-base ${isProtected
                ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-300"
                : "bg-rose-500/10 border-rose-500/20 text-rose-300"}`}>
            {localizeText(isProtected ? <Shield className="w-5 h-5"/> : <ShieldAlert className="w-5 h-5"/>)}
            <span className="font-semibold">
              {localizeText(isProtected ? "You're Protected" : status.isSimulated ? "Engine missing" : "Shield off")}
            </span>
          </div>)}/>

      {localizeText(status.isSimulated && status.platform === "win32" && (<div className="p-6 bg-indigo-500/10 border border-indigo-500/20 rounded-xl flex items-center justify-between">
            <div>
              <h3 className="font-semibold text-indigo-300 text-lg flex items-center gap-2">
                <DownloadCloud className="w-5 h-5"/>{t("dashboard.download_windows_engine")}</h3>
              <p className="text-slate-400 text-sm mt-1">
                {localizeText(status.isInstalling
                ? "Downloading and installing official ClamAV 64-bit engine automatically..."
                : "ClamAV engine is missing. We can download and configure it for you automatically.")}
              </p>
              {localizeText(status.isInstalling && (<p className="text-indigo-400 text-sm mt-2 font-mono flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin"/>
                  {localizeText(status.installProgress)}
                </p>))}
            </div>
            {localizeText(!status.isInstalling && (<button onClick={installEngine} className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded-lg transition-colors">{t("dashboard.install_clamav_engine")}</button>))}
        </div>))}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <h3 className="font-medium text-slate-300 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-indigo-400"/>{t("dashboard.engine_info")}</h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">{t("dashboard.clamav_version")}</span>
              <span className={`${status.hasEngine && !status.isSimulated ? metadataValueClass : attentionValueClass} text-right`}>
                {localizeText(status.stats.engineVersion)}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50 gap-4">
              <span className="text-slate-500">{t("dashboard.clamav_signatures")}</span>
              <span className="font-medium text-slate-200 text-right">{localizeText(formatUpdateDate(status.stats.lastUpdate))}</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">{t("updates.yara_engine")}</span>
              <span className={status.hasYaraEngine ? metadataValueClass : attentionValueClass}>
                {localizeText(status.hasYaraEngine
            ? /^\d/.test(status.stats.yaraEngineVersion || "")
                ? `YARA ${status.stats.yaraEngineVersion}`
                : "Installed · version unavailable"
            : "Not installed")}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50 gap-4">
              <span className="text-slate-500">{t("dashboard.yara_rules")}</span>
              <div className="flex items-center gap-3 min-w-0">
                <span className={`${status.hasYaraRules ? metadataValueClass : attentionValueClass} text-right min-w-0`}>
                  <span className="block">
                    {localizeText(status.hasYaraRules
            ? `${status.stats.yaraRuleset || "core"} · ${status.stats.yaraRuleCount || 0} rules`
            : "Missing")}
                  </span>
                  <span className={`block text-xs ${status.stats.lastYaraUpdate ? "text-slate-500" : "text-amber-400"}`}>
                    {localizeText(status.stats.lastYaraUpdate ? formatUpdateDate(status.stats.lastYaraUpdate) : "Update required")}
                  </span>
                </span>
                <Link to="/updates" className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium">{t("dashboard.manage")}</Link>
              </div>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50 gap-4">
              <span className="text-slate-500">SecuriteInfo</span>
              {localizeText(securiteInfoInstalled ? (<div className="flex items-center gap-3">
                  <span className="font-medium text-slate-200 text-right">{localizeText(formatUpdateDate(securiteInfo.lastUpdated))}</span>
                  <button onClick={openSecuriteInfoDialog} className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium">{t("dashboard.manage")}</button>
                </div>) : (<button onClick={openSecuriteInfoDialog} className="px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg text-xs font-medium transition-colors">
                  {localizeText(securiteInfo.connected ? "Finish setup" : "Install")}
                </button>))}
            </div>
            <div className="flex justify-between items-center py-2 gap-4">
              <span className="text-slate-500">SaneSecurity</span>
              {localizeText(saneSecurityInstalled ? (<div className="flex items-center gap-3">
                  <span className="font-medium text-slate-200 text-right">{localizeText(formatUpdateDate(saneSecurity.lastUpdated))}</span>
                  <button onClick={() => {
                setSaneSecurityProfile(saneSecurity.profile === "complete" ? "complete" : "malware");
                setSaneSecurityMessage("");
                setSaneSecurityDialogOpen(true);
            }} className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium">{t("dashboard.manage")}</button>
                </div>) : (<button onClick={() => {
                setSaneSecurityProfile(saneSecurity.profile === "complete" ? "complete" : "malware");
                setSaneSecurityMessage("");
                setSaneSecurityDialogOpen(true);
            }} className="px-3 py-1.5 bg-violet-700 hover:bg-violet-600 text-white rounded-lg text-xs font-medium transition-colors">
                  {localizeText(saneSecurity.connected ? "Finish setup" : saneSecurityFilesPresent ? "Reconnect" : "Install")}
                </button>))}
            </div>
            {localizeText(status.isSimulated && (<div className="mt-4 p-3 bg-amber-500/10 border border-amber-500/20 rounded-md text-amber-400 text-xs text-center flex flex-col gap-2">
                <span>{t("dashboard.running_in_simulated_mode_clamav_not_detected_on_path")}</span>
                <button onClick={() => fetch('/api/simulate-threat', { method: 'POST' })} className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 rounded border border-amber-500/30 transition-colors">{t("dashboard.trigger_test_threat_modal")}</button>
              </div>))}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-start justify-between gap-3">
            <h3 className="font-medium text-slate-300 flex items-center gap-2">
              <Cloud className="w-5 h-5 text-cyan-400"/>{t("dashboard.virustotal_cloud")}</h3>
            <button onClick={openVirusTotalDialog} className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium">
              {localizeText(virusTotalConfigured ? "Manage" : "Setup")}
            </button>
          </div>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">{t("dashboard.status")}</span>
              <span className={virusTotalEnabled && virusTotalConfigured ? metadataValueClass : attentionValueClass}>
                {localizeText(virusTotalEnabled && virusTotalConfigured ? "Enabled" : virusTotalConfigured ? "Disabled" : "Not configured")}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">{t("dashboard.auto_refinement")}</span>
              <span className={virusTotalAutoRefine ? metadataValueClass : "font-medium text-slate-500"}>
                {localizeText(virusTotalAutoRefine ? "On" : "Off")}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">{t("dashboard.checked_findings")}</span>
              <span className="font-medium text-slate-200 text-right">
                {localizeText(virusTotalCheckedCount)}/{localizeText(virusTotalTotalFindings)}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">{t("dashboard.pending_tasks")}</span>
              <div className="flex items-center gap-3">
                <span className="font-medium text-slate-200">{localizeText(virusTotalQueuedCount)}</span>
                <button onClick={() => setVirusTotalQueueOpen(true)} className="rounded bg-slate-800 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-700">{t("results.view_queue")}</button>
              </div>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50 gap-4">
              <span className="text-slate-500">{t("dashboard.api_today")}</span>
              <div className="flex flex-wrap items-center justify-end gap-2">
                <span className="font-medium text-slate-200 text-right">{localizeText(virusTotalUsageDayCount)}/{localizeText(virusTotalUsageDayLimit)}</span>
                <button onClick={fetchVirusTotalUsage} disabled={!virusTotalConfigured || usageFetchBusy || usageFetchCoolingDown || virusTotalUsageSync.fetching} title={usageFetchCoolingDown ? t("dashboard.usage_fetches_are_limited_to_once_per_minute") : t("dashboard.fetch_usage_and_allowances_reported_by_virustotal")} className="inline-flex items-center gap-1.5 px-2 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-slate-300 disabled:opacity-50 disabled:cursor-not-allowed">
                  <RefreshCw className={`w-3 h-3 ${usageFetchBusy || virusTotalUsageSync.fetching ? "animate-spin" : ""}`}/>
                  {localizeText(usageFetchBusy || virusTotalUsageSync.fetching ? "Fetching…" : "Fetch usage")}
                </button>
              </div>
            </div>
            <div className="space-y-2 text-xs border-b border-slate-800/50 pb-3">
              <label className="flex flex-wrap items-center justify-between gap-2 text-slate-400">
                <span>{t("dashboard.auto_fetch_every")}</span>
                <span className="flex items-center gap-2"><input type="number" min={1} max={10000} value={usageRefreshEvery} onChange={event => setUsageRefreshEvery(event.target.value)} onBlur={saveUsageRefreshEvery} onKeyDown={event => { if (event.key === "Enter")
        event.currentTarget.blur(); }} aria-label={t("dashboard.requests_between_virustotal_usage_fetches")} className="w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200 focus:outline-none focus:border-indigo-500"/>{t("dashboard.requests")}</span>
              </label>
              <p className="text-slate-500">{localizeText(virusTotalUsageDay.source === "virustotal" ? "Reported by VirusTotal" : virusTotalUsageDay.source === "estimate_since_sync" ? "Estimated since last sync" : "Local estimate")}
                {localizeText(virusTotalUsageSync.fetchedAt ? ` · Synced ${formatSystemDateTime(virusTotalUsageSync.fetchedAt)}` : " · Not synced yet")}</p>
              {localizeText((usageFetchError || virusTotalUsageSync.error) && <p role="status" className="text-amber-300">{localizeText(usageFetchError || virusTotalUsageSync.error)}</p>)}
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4 lg:col-span-2">
          <h3 className="font-medium text-slate-300 flex items-center gap-2">
            <Activity className="w-5 h-5 text-indigo-400"/>{t("dashboard.recent_activity")}</h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500 flex items-center gap-2"><Clock className="w-4 h-4"/>{t("dashboard.last_scan")}</span>
              <span className="font-medium text-slate-200">
                {localizeText(status.stats.lastScan ? formatRelativeTime(status.stats.lastScan) : "Never")}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500 flex items-center gap-2"><Database className="w-4 h-4"/>{t("dashboard.signatures_updated")}</span>
              <span className="font-medium text-slate-200">
                {localizeText(status.stats.lastUpdate ? formatRelativeTime(status.stats.lastUpdate) : "Never")}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50 gap-4">
              <span className="text-slate-500 flex items-center gap-2"><Cloud className="w-4 h-4"/>{t("dashboard.virustotal_cloud_68a218e")}</span>
              <span className="font-medium text-slate-200 text-right">
                {localizeText(status.stats.lastCloudCheck ? formatRelativeTime(status.stats.lastCloudCheck) : "Never")}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500 flex items-center gap-2"><FileWarning className="w-4 h-4"/>{t("dashboard.quarantined_items")}</span>
              <span className="font-medium text-slate-200">{localizeText(status.stats.quarantineCount)}{t("scan.files")}</span>
            </div>
          </div>
        </div>
      </div>

      {localizeText(virusTotalQueueOpen && <VirusTotalQueueDialog onClose={() => setVirusTotalQueueOpen(false)}/>)}
      {localizeText(securiteInfoDialogOpen && (<div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6">
          <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl">
            <div className="sticky top-0 z-10 bg-slate-900 flex items-center justify-between gap-4 px-6 py-4 border-b border-slate-800">
              <div className="min-w-0">
                <h2 className="text-xl font-semibold text-white">
                  {localizeText(securiteInfo.connected ? "Manage SecuriteInfo" : "Install SecuriteInfo Signatures")}
                </h2>
                <p className="text-xs text-slate-500 mt-1">{t("dashboard.your_private_token_is_encrypted_by_windows_and_is_never_returned")}</p>
              </div>
              <button onClick={() => setSecuriteInfoDialogOpen(false)} aria-label={t("dashboard.close_securiteinfo")} className="shrink-0 p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg">
                <X className="w-5 h-5"/>
              </button>
            </div>
            <div className="p-6 space-y-5">
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 space-y-2">
                <p className="text-sm text-slate-300">{t("dashboard.securiteinfo_is_an_optional_third_party_clamav_signature_source_a")}</p>
                <p className="text-xs text-slate-500">{t("dashboard.basic_installs")}<code className="text-cyan-300">securiteinfo.ign2</code>{t("dashboard.and")}{localizeText(" ")}
                  <code className="text-cyan-300">securiteinfoold.hdb</code>{t("dashboard.paid_plan_details")}
                </p>
                <p className="text-xs text-slate-500">{t("dashboard.securiteinfo_reports_over_90_and_up_to_99_zero_day_detection_in_i")}</p>
                {localizeText(securiteInfo.connected && (<p className="text-xs text-emerald-400">{t("dashboard.connected_as")}{localizeText(securiteInfo.plan === "paid" ? "Paid" : "Basic")} - {localizeText(securiteInfo.installedCount || 0)}/{localizeText(securiteInfo.expectedCount || 0)}{t("dashboard.databases_installed")}{localizeText(securiteInfo.plan === "paid" ? ` - PUA ${securiteInfo.includePua ? "on" : "off"}` : "")}
                  </p>))}
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">{t("dashboard.account_plan")}</label>
                <div className="grid sm:grid-cols-2 gap-3">
                  <button onClick={() => {
                setSecuriteInfoPlan("basic");
                setSecuriteInfoIncludePua(false);
            }} className={`text-left p-4 rounded-xl border transition-colors ${securiteInfoPlan === "basic"
                ? "border-cyan-500 bg-cyan-500/10"
                : "border-slate-700 bg-slate-950/40 hover:border-slate-600"}`}>
                    <span className="block text-white font-medium">{t("dashboard.basic_free")}</span>
                    <span className="block text-slate-500 text-xs mt-1">{t("dashboard.downloads")}<code>securiteinfo.ign2</code>{t("dashboard.and_e3ee915")}<code>securiteinfoold.hdb</code>.
                    </span>
                  </button>
                  <button onClick={() => setSecuriteInfoPlan("paid")} className={`text-left p-4 rounded-xl border transition-colors ${securiteInfoPlan === "paid"
                ? "border-cyan-500 bg-cyan-500/10"
                : "border-slate-700 bg-slate-950/40 hover:border-slate-600"}`}>
                    <span className="block text-white font-medium">{t("updates.paid")}</span>
                    <span className="block text-slate-500 text-xs mt-1">{t("dashboard.downloads_supported_paid_databases_including_0_hour_signatures_pu")}</span>
                  </button>
                </div>
              </div>
              <div className={`flex items-start justify-between gap-4 rounded-xl border p-4 ${securiteInfoPlan === "paid"
                ? "border-amber-500/30 bg-amber-500/10"
                : "border-slate-800 bg-slate-950/40 opacity-60"}`}>
                <div className="space-y-1">
                  <span className="text-sm font-medium text-slate-200 flex items-center gap-2">
                    <FileWarning className="w-4 h-4 text-amber-300"/>{t("dashboard.include_pua_and_vulnerability_signatures")}</span>
                  <span className="block text-xs text-amber-100/80">{t("dashboard.caution")}<code>{localizeText(securiteInfo.puaDatabase || "securiteinfo-pua-app-and-vulnerabilities.ndb")}</code>{t("dashboard.detects_potentially_unwanted_applications_and_vulnerable_componen")}</span>
                  {localizeText(securiteInfoPlan !== "paid" && (<span className="block text-xs text-slate-500">{t("updates.available_for_paid_securiteinfo_plans")}</span>))}
                </div>
                <input type="checkbox" checked={securiteInfoPlan === "paid" && securiteInfoIncludePua} disabled={securiteInfoPlan !== "paid"} onChange={event => setSecuriteInfoIncludePua(event.target.checked)} className="mt-1 w-5 h-5 rounded border-slate-600 text-amber-500 focus:ring-amber-500 focus:ring-offset-slate-900 bg-slate-800"/>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">{t("dashboard.paste_any_one_of_your")}<code className="text-cyan-300">{t("dashboard.databasecustomurl")}</code> lines
                </label>
                <input type="password" value={securiteInfoSetupUrl} onChange={event => setSecuriteInfoSetupUrl(event.target.value)} placeholder={t("dashboard.databasecustomurl_https_www_securiteinfo_com_get_signatures_secur")} autoComplete="off" className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"/>
                <p className="text-xs text-slate-500 mt-2">{t("dashboard.both_urls_contain_the_same_private_account_token_paste_either_one")}</p>
              </div>
              {localizeText(securiteInfoMessage && (<div className="p-3 rounded-lg border border-cyan-500/20 bg-cyan-500/10 text-cyan-200 text-sm">
                  {localizeText(securiteInfoMessage)}
                </div>))}
              <UpdateJobProgress jobId={securiteInfoJob?.jobId || null} title={t("updates.securiteinfo_output")} simulated={securiteInfoJob?.simulated} onFinished={fetchStatus}/>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <a href="https://www.securiteinfo.com/clients/customers/signup" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-sm text-cyan-400 hover:text-cyan-300">
                  <ExternalLink className="w-4 h-4"/>{t("dashboard.requires_a_free_securiteinfo_account")}</a>
                <div className="flex flex-wrap gap-2 justify-end">
                  {localizeText(securiteInfo.connected && (<>
                      <button onClick={updateSecuriteInfo} disabled={securiteInfoBusy || status.isSignatureUpdateRunning} className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
                        <RefreshCw className={`w-4 h-4 ${status.isSignatureUpdateRunning ? "animate-spin" : ""}`}/>
                        {localizeText(status.isSignatureUpdateRunning ? "Updating..." : "Save & Update")}
                      </button>
                      <button onClick={disconnectSecuriteInfo} disabled={securiteInfoBusy} className="px-4 py-2.5 bg-slate-800 hover:bg-rose-950/60 disabled:opacity-50 text-slate-300 hover:text-rose-300 rounded-lg text-sm font-medium transition-colors">{t("dashboard.disconnect")}</button>
                    </>))}
                  <button onClick={connectSecuriteInfo} disabled={securiteInfoBusy || status.isSignatureUpdateRunning || !securiteInfoSetupUrl.trim()} className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors">
                    {localizeText(securiteInfoBusy && <Loader2 className="w-4 h-4 animate-spin"/>)}
                    {localizeText(securiteInfo.connected ? "Replace & Update" : "Connect & Update")}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>))}

      {localizeText(saneSecurityDialogOpen && (<div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-6">
          <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl">
            <div className="sticky top-0 bg-slate-900 flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div>
                <h2 className="text-xl font-semibold text-white">
                  {localizeText(saneSecurity.connected ? "Manage SaneSecurity" : saneSecurityFilesPresent ? "Reconnect SaneSecurity" : "Install SaneSecurity Signatures")}
                </h2>
                <p className="text-xs text-slate-500 mt-1">{t("dashboard.public_third_party_signatures_for_clamav_no_account_is_required")}</p>
                {localizeText(saneSecurityFilesPresent && (<p className={`text-xs mt-1 ${saneSecurity.connected ? "text-emerald-400" : "text-amber-300"}`}>
                    {localizeText(saneSecurity.profile === "complete" ? "Complete" : "Malware Protection")} - {localizeText(saneSecurity.installedCount || 0)}/{localizeText(saneSecurity.expectedCount || 0)}{t("dashboard.databases_installed")}{localizeText(saneSecurity.connected ? "" : " - reconnect required")}
                  </p>))}
              </div>
              <button onClick={() => setSaneSecurityDialogOpen(false)} aria-label={t("dashboard.close_sanesecurity")} className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg">
                <X className="w-5 h-5"/>
              </button>
            </div>
            <div className="p-6 space-y-5">
              <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-4 space-y-2">
                <p className="text-sm text-slate-300">{t("dashboard.clamshield_downloads_the_databases_from_sanesecurity_s_public_rsy")}</p>
                <p className="text-xs text-slate-500">{t("dashboard.first_time_setup_downloads_an_official_signed_cygwin_helper_of_ap")}</p>
                <p className="text-xs text-amber-300/80">{t("dashboard.third_party_signatures_can_improve_detection_but_may_also_increas")}</p>
                {localizeText(false && saneSecurity.connected && (<p className="text-xs text-emerald-400">
                    {localizeText(saneSecurity.profile === "complete" ? "Complete" : "Malware Protection")} · {localizeText(saneSecurity.installedCount || 0)}/{localizeText(saneSecurity.expectedCount || 0)}{t("dashboard.databases_installed_1917fb8")}</p>))}
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">{t("dashboard.signature_profile")}</label>
                <div className="grid sm:grid-cols-2 gap-3">
                  <button onClick={() => setSaneSecurityProfile("malware")} className={`text-left p-4 rounded-xl border transition-colors ${saneSecurityProfile === "malware"
                ? "border-violet-500 bg-violet-500/10"
                : "border-slate-700 bg-slate-950/40 hover:border-slate-600"}`}>
                    <span className="block text-white font-medium">{t("updates.malware_protection")}</span>
                    <span className="block text-slate-500 text-xs mt-1">{t("dashboard.installs_9_malware_phishing_macro_hash_whitelist_and_exploit_focu")}</span>
                  </button>
                  <button onClick={() => setSaneSecurityProfile("complete")} className={`text-left p-4 rounded-xl border transition-colors ${saneSecurityProfile === "complete"
                ? "border-violet-500 bg-violet-500/10"
                : "border-slate-700 bg-slate-950/40 hover:border-slate-600"}`}>
                    <span className="block text-white font-medium">{t("scan.complete")}</span>
                    <span className="block text-slate-500 text-xs mt-1">{t("dashboard.installs_20_databases_adding_spam_scam_url_attachment_image_and_s")}</span>
                  </button>
                </div>
              </div>

              {localizeText(saneSecurityMessage && (<div className="p-3 rounded-lg border border-violet-500/20 bg-violet-500/10 text-violet-200 text-sm">
                  {localizeText(saneSecurityMessage)}
                </div>))}
              <UpdateJobProgress jobId={saneSecurityJobId} title={t("updates.sanesecurity_output")} onFinished={fetchStatus}/>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex flex-wrap gap-4">
                  <a href={saneSecurity.usageUrl || "https://sanesecurity.com/usage/signatures/"} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-sm text-violet-400 hover:text-violet-300">
                    <ExternalLink className="w-4 h-4"/>{t("dashboard.signature_information")}</a>
                  <a href={saneSecurity.donateUrl || "https://sanesecurity.com/donate/"} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-slate-300">
                    <ExternalLink className="w-4 h-4"/>{t("dashboard.support_sanesecurity")}</a>
                </div>
                <div className="flex flex-wrap gap-2 justify-end">
                  {localizeText(saneSecurity.connected && (<>
                      <button onClick={updateSaneSecurity} disabled={saneSecurityBusy || status.isSaneSecurityUpdateRunning} className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
                        <RefreshCw className={`w-4 h-4 ${status.isSaneSecurityUpdateRunning ? "animate-spin" : ""}`}/>
                        {localizeText(status.isSaneSecurityUpdateRunning ? "Updating..." : "Update now")}
                      </button>
                      <button onClick={disconnectSaneSecurity} disabled={saneSecurityBusy || status.isSaneSecurityUpdateRunning} className="px-4 py-2.5 bg-slate-800 hover:bg-rose-950/60 disabled:opacity-50 text-slate-300 hover:text-rose-300 rounded-lg text-sm font-medium transition-colors">{t("dashboard.disconnect")}</button>
                    </>))}
                  <button onClick={configureSaneSecurity} disabled={saneSecurityBusy || status.isSaneSecurityUpdateRunning} className="inline-flex items-center gap-2 px-5 py-2.5 bg-violet-700 hover:bg-violet-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors">
                    {localizeText((saneSecurityBusy || status.isSaneSecurityUpdateRunning) && <Loader2 className="w-4 h-4 animate-spin"/>)}
                    {localizeText(saneSecurity.connected ? "Save & Update" : saneSecurityFilesPresent ? "Reconnect & Update" : "Install & Update")}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>))}

      {localizeText(virusTotalDialogOpen && (<div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6">
          <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl">
            <div className="sticky top-0 z-10 bg-slate-900 flex items-center justify-between gap-4 px-6 py-4 border-b border-slate-800">
              <div className="min-w-0">
                <h2 className="text-xl font-semibold text-white">
                  {localizeText(virusTotalConfigured ? "Manage VirusTotal Cloud" : "Set up VirusTotal Cloud")}
                </h2>
              </div>
              <button onClick={() => setVirusTotalDialogOpen(false)} className="shrink-0 p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg">
                <X className="w-5 h-5"/>
              </button>
            </div>
            <div className="p-6 space-y-5">
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 space-y-2">
                <p className="text-sm text-slate-300">{t("dashboard.virustotal_cloud_check_adds_cloud_verdicts_to_results_and_real_ti")}</p>
                {localizeText(virusTotalConfigured && (<p className="text-xs text-emerald-400">{t("dashboard.configured")}{localizeText(virusTotalCheckedCount)}/{localizeText(virusTotalTotalFindings)}{t("dashboard.findings_checked")}{localizeText(virusTotalQueuedCount > 0 ? ` - ${virusTotalQueuedCount} queued` : "")}
                  </p>))}
              </div>

              <div className="space-y-3">
                <label className="flex items-start justify-between gap-4 rounded-xl border border-slate-800 bg-slate-950/40 p-4">
                  <span className="space-y-1">
                    <span className="text-sm font-medium text-slate-200 flex items-center gap-2">
                      <Cloud className="w-4 h-4 text-cyan-300"/>{t("dashboard.enable_virustotal_cloud_check")}</span>
                  </span>
                  <input type="checkbox" checked={virusTotalCloudEnabled} onChange={event => {
                setVirusTotalCloudEnabled(event.target.checked);
                if (!event.target.checked) {
                    setVirusTotalAutoRefineEnabled(false);
                    setVirusTotalResultsUploadUnknownEnabled(false);
                }
            }} className="mt-1 w-5 h-5 rounded border-slate-600 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-900 bg-slate-800"/>
                </label>

                <label className={`flex items-start justify-between gap-4 rounded-xl border p-4 ${virusTotalCloudEnabled
                ? "border-slate-800 bg-slate-950/40"
                : "border-slate-800 bg-slate-950/40 opacity-60"}`}>
                  <span className="space-y-1">
                    <span className="text-sm font-medium text-slate-200 flex items-center gap-2">
                      <SearchCheck className="w-4 h-4 text-cyan-300"/>{t("dashboard.false_positive_refinement")}</span>
                    <span className="block text-xs text-slate-500">{t("dashboard.adds_virustotal_verdicts_to_results_findings")}</span>
                  </span>
                  <input type="checkbox" checked={virusTotalCloudEnabled && virusTotalAutoRefineEnabled} disabled={!virusTotalCloudEnabled} onChange={event => setVirusTotalAutoRefineEnabled(event.target.checked)} className="mt-1 w-5 h-5 rounded border-slate-600 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-900 bg-slate-800"/>
                </label>

                <div className={`rounded-xl border p-4 space-y-3 ${virusTotalCloudEnabled
                ? "border-slate-800 bg-slate-950/40"
                : "border-slate-800 bg-slate-950/40 opacity-60"}`}>
                  <div className="flex items-start justify-between gap-4">
                    <span className="space-y-1">
                      <span className="text-sm font-medium text-slate-200 flex items-center gap-2">
                        <UploadCloud className="w-4 h-4 text-cyan-300"/>{t("settings.upload_results_files_without_a_vt_report")}</span>
                      <span className="block text-xs text-slate-500">{t("settings.only_after_virustotal_has_no_report_for_the_hash")}</span>
                    </span>
                    <input type="checkbox" checked={virusTotalCloudEnabled && virusTotalResultsUploadUnknownEnabled} disabled={!virusTotalCloudEnabled} onChange={event => setVirusTotalResultsUploadUnknownEnabled(event.target.checked)} className="mt-1 w-5 h-5 rounded border-slate-600 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-900 bg-slate-800"/>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <label className="text-sm font-medium text-slate-400">{t("shield.max_upload_size_mb")}</label>
                    <input type="number" min={1} max={32} value={virusTotalResultsUploadMaxSizeMb} disabled={!virusTotalCloudEnabled || !virusTotalResultsUploadUnknownEnabled} onChange={event => {
                const value = Number(event.target.value);
                setVirusTotalResultsUploadMaxSizeMb(Number.isFinite(value) ? Math.min(32, Math.max(1, Math.round(value))) : 20);
            }} className="w-28 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 disabled:cursor-not-allowed"/>
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">{t("settings.virustotal_api_key")}</label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500"/>
                  <input type="password" value={virusTotalApiKey} onChange={event => setVirusTotalApiKey(event.target.value)} placeholder={virusTotalConfigured ? t("settings.leave_blank_to_keep_the_saved_key") : t("settings.paste_your_virustotal_api_key")} autoComplete="off" className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-10 pr-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"/>
                </div>
              </div>

              {localizeText(virusTotalMessage && (<div className="p-3 rounded-lg border border-cyan-500/20 bg-cyan-500/10 text-cyan-200 text-sm">
                  {localizeText(virusTotalMessage)}
                </div>))}

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-sm text-cyan-400 hover:text-cyan-300">
                  <ExternalLink className="w-4 h-4"/>{t("settings.get_api_key")}</a>
                <div className="flex flex-wrap gap-2 justify-end">
                  {localizeText(virusTotalConfigured && (<>
                      <button onClick={runVirusTotalRefinement} disabled={virusTotalBusy !== null || !virusTotalEnabled || !virusTotalAutoRefine} className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
                        {localizeText(virusTotalBusy === "refine" ? <Loader2 className="w-4 h-4 animate-spin"/> : <SearchCheck className="w-4 h-4"/>)}{t("dashboard.run_queue")}</button>
                      <button onClick={disconnectVirusTotalCloud} disabled={virusTotalBusy !== null} className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-rose-950/60 disabled:opacity-50 text-slate-300 hover:text-rose-300 rounded-lg text-sm font-medium transition-colors">
                        <Trash2 className="w-4 h-4"/>{t("dashboard.disconnect")}</button>
                    </>))}
                  <button onClick={saveVirusTotalCloud} disabled={virusTotalBusy !== null || (!virusTotalConfigured && !virusTotalApiKey.trim())} className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors">
                    {localizeText(virusTotalBusy === "save" && <Loader2 className="w-4 h-4 animate-spin"/>)}{t("shield.save")}</button>
                </div>
              </div>
            </div>
          </div>
        </div>))}
    </div>);
}
