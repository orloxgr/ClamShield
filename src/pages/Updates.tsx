import { useEffect, useRef, useState } from "react";
import { ChevronDown, Database, DownloadCloud, FileWarning, KeyRound, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";

const MAX_TERMINAL_LINES = 800;
type DetailsPanel = "clamav" | "securiteinfo" | "sanesecurity" | "yara" | "app";

function appendOutput(previous: string[], next: string[]) {
  return [...previous, ...next].slice(-MAX_TERMINAL_LINES);
}

export default function Updates() {
  const [updateState, setUpdateState] = useState<"idle" | "running" | "done">("idle");
  const [output, setOutput] = useState<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSimulated, setIsSimulated] = useState(false);
  const [saneUpdateState, setSaneUpdateState] = useState<"idle" | "running" | "done">("idle");
  const [saneOutput, setSaneOutput] = useState<string[]>([]);
  const [saneJobId, setSaneJobId] = useState<string | null>(null);
  const [yaraUpdateState, setYaraUpdateState] = useState<"idle" | "running" | "done">("idle");
  const [yaraOutput, setYaraOutput] = useState<string[]>([]);
  const [yaraJobId, setYaraJobId] = useState<string | null>(null);
  const [appUpdateState, setAppUpdateState] = useState<"idle" | "checking" | "available" | "none" | "running" | "done">("idle");
  const [appUpdateInfo, setAppUpdateInfo] = useState<any>(null);
  const [appOutput, setAppOutput] = useState<string[]>([]);
  const [appJobId, setAppJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<any>(null);
  const [openPanel, setOpenPanel] = useState<DetailsPanel | null>(null);
  const updateEventSourceRef = useRef<EventSource | null>(null);
  const saneEventSourceRef = useRef<EventSource | null>(null);
  const yaraEventSourceRef = useRef<EventSource | null>(null);
  const appEventSourceRef = useRef<EventSource | null>(null);

  const closeJobStream = (ref: { current: EventSource | null }) => {
    if (ref.current) {
      ref.current.close();
      ref.current = null;
    }
  };

  const refreshStatus = async () => {
    try {
      const res = await fetch("/api/status");
      const data = await res.json();
      setStatus(data);
    } catch {
      setStatus(null);
    }
  };

  useEffect(() => {
    refreshStatus();
    const interval = window.setInterval(refreshStatus, 3000);
    return () => window.clearInterval(interval);
  }, []);

  const saveUpdateSettings = async (patch: any) => {
    const nextSettings = { ...(status?.settings || {}), ...patch };
    setStatus((current: any) => current ? { ...current, settings: nextSettings } : current);
    await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(nextSettings)
    });
    refreshStatus();
  };

  const updateNumberSetting = (key: string, rawValue: string, fallback: number, min: number, max: number) => {
    const parsed = Number(rawValue);
    const value = Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
    saveUpdateSettings({ [key]: value });
  };

  const runUpdate = async (target: "clamav" | "securiteinfo" = "clamav") => {
    closeJobStream(updateEventSourceRef);
    setUpdateState("running");
    setOutput([target === "securiteinfo" ? "Triggering SecuriteInfo FreshClam update..." : "Triggering ClamAV FreshClam update..."]);
    try {
      const res = await fetch("/api/update", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start update.");
      setJobId(data.jobId);
      setIsSimulated(!!data.simulated);
      if (data.simulated) {
        setOutput(prev => appendOutput(prev, ["Running in simulation mode...", "Checking for database updates..."]));
        setTimeout(() => {
          setOutput(prev => appendOutput(prev, ["Database updated successfully."]));
          setUpdateState("done");
          setJobId(null);
        }, 2500);
      }
    } catch (e: any) {
      setOutput(prev => appendOutput(prev, [`Error: ${e.message}`]));
      setUpdateState("done");
      setJobId(null);
    }
  };

  const runYaraUpdate = async () => {
    closeJobStream(yaraEventSourceRef);
    setYaraUpdateState("running");
    setYaraOutput(["Checking YARA engine, then updating YARA Forge rules..."]);
    try {
      const res = await fetch("/api/update-yara", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start YARA update.");
      setYaraJobId(data.jobId);
    } catch (e: any) {
      setYaraOutput(prev => appendOutput(prev, [`Error: ${e.message}`]));
      setYaraUpdateState("done");
      setYaraJobId(null);
    }
  };

  const runSaneUpdate = async () => {
    closeJobStream(saneEventSourceRef);
    setSaneUpdateState("running");
    setSaneOutput(["Starting SaneSecurity signature update..."]);
    try {
      const res = await fetch("/api/update-sanesecurity", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start the SaneSecurity update.");
      setSaneJobId(data.jobId);
    } catch (e: any) {
      setSaneOutput(prev => appendOutput(prev, [`Error: ${e.message}`]));
      setSaneUpdateState("done");
      setSaneJobId(null);
    }
  };

  const checkAppUpdate = async () => {
    setAppUpdateState("checking");
    setAppOutput(["Checking GitHub releases for a newer ClamShield version..."]);
    try {
      const res = await fetch("/api/app-update");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to check ClamShield updates.");
      setAppUpdateInfo(data);
      setAppOutput(prev => appendOutput(prev, [
        `Installed: ${data.currentVersion}`,
        `Latest: ${data.latestVersion}`,
        data.updateAvailable ? `Update available: ${data.assetName || data.releaseUrl}` : "ClamShield is up to date."
      ]));
      setAppUpdateState(data.updateAvailable ? "available" : "none");
    } catch (e: any) {
      setAppOutput(prev => appendOutput(prev, [`Error: ${e.message}`]));
      setAppUpdateState("done");
    }
  };

  const installAppUpdate = async () => {
    closeJobStream(appEventSourceRef);
    setAppUpdateState("running");
    setAppOutput(prev => appendOutput(prev, ["Downloading and launching the ClamShield installer..."]));
    try {
      const res = await fetch("/api/app-update/install", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start ClamShield update.");
      setAppJobId(data.jobId);
    } catch (e: any) {
      setAppOutput(prev => appendOutput(prev, [`Error: ${e.message}`]));
      setAppUpdateState("done");
      setAppJobId(null);
    }
  };

  const skipAppVersion = async () => {
    if (!appUpdateInfo?.latestVersion) return;
    await fetch("/api/app-update/skip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: appUpdateInfo.latestVersion })
    });
    setAppOutput(prev => appendOutput(prev, [`Skipped ClamShield ${appUpdateInfo.latestVersion}.`]));
    setAppUpdateState("none");
  };

  const disableAppUpdates = async () => {
    await fetch("/api/app-update/disable", { method: "POST" });
    setAppOutput(prev => appendOutput(prev, ["ClamShield update checks disabled. You can re-enable them in Updates."]));
    setAppUpdateState("done");
    refreshStatus();
  };

  const bindJobStream = (
    active: boolean,
    activeJobId: string | null,
    ref: { current: EventSource | null },
    onLogs: (logs: string[]) => void,
    onDone: () => void,
    label: string
  ) => {
    if (!active || !activeJobId) return undefined;
    const source = new EventSource(`/api/scan/${encodeURIComponent(activeJobId)}/events`);
    ref.current = source;
    const handleJobEvent = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        if (data.logs?.length) onLogs(data.logs);
        if (data.status === "done" || data.status === "missing") {
          onDone();
          refreshStatus();
          closeJobStream(ref);
        }
      } catch (e) {
        console.error(`Failed to process ${label} event:`, e);
      }
    };
    source.addEventListener("job", handleJobEvent);
    source.onerror = () => console.error(`${label} event stream disconnected; waiting for reconnect.`);
    return () => closeJobStream(ref);
  };

  useEffect(() => bindJobStream(
    updateState === "running" && !isSimulated,
    jobId,
    updateEventSourceRef,
    logs => setOutput(prev => appendOutput(prev, logs)),
    () => { setUpdateState("done"); setJobId(null); },
    "FreshClam"
  ), [updateState, jobId, isSimulated]);

  useEffect(() => bindJobStream(
    saneUpdateState === "running",
    saneJobId,
    saneEventSourceRef,
    logs => setSaneOutput(prev => appendOutput(prev, logs)),
    () => { setSaneUpdateState("done"); setSaneJobId(null); },
    "SaneSecurity"
  ), [saneUpdateState, saneJobId]);

  useEffect(() => bindJobStream(
    yaraUpdateState === "running",
    yaraJobId,
    yaraEventSourceRef,
    logs => setYaraOutput(prev => appendOutput(prev, logs)),
    () => { setYaraUpdateState("done"); setYaraJobId(null); },
    "YARA"
  ), [yaraUpdateState, yaraJobId]);

  useEffect(() => bindJobStream(
    appUpdateState === "running",
    appJobId,
    appEventSourceRef,
    logs => setAppOutput(prev => appendOutput(prev, logs)),
    () => { setAppUpdateState("done"); setAppJobId(null); },
    "ClamShield update"
  ), [appUpdateState, appJobId]);

  const updateSettings = status?.settings || {};
  const signatureUpdateActive = updateState === "running" || status?.isSignatureUpdateRunning;
  const saneUpdateActive = saneUpdateState === "running" || status?.isSaneSecurityUpdateRunning;
  const signatureUpdateFailed = updateState === "done" && output.some(line => /error|failed/i.test(line));
  const saneUpdateFailed = saneUpdateState === "done" && saneOutput.some(line => /error|failed/i.test(line));

  const formatExact = (value?: string | null) => value ? new Date(value).toLocaleString() : "Never";
  const formatAge = (value?: string | null) => {
    if (!value) return "not updated yet";
    const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
    if (seconds < 60) return "just now";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
    const days = Math.floor(hours / 24);
    return `${days} day${days === 1 ? "" : "s"} ago`;
  };
  const statusLine = (value?: string | null, result?: string) => `${formatExact(value)} (${formatAge(value)})${result ? ` - ${result}` : ""}`;
  const progressValue = (state: "idle" | "running" | "done", active: boolean, lines: string[], donePercent = 100) => {
    if (state === "done") return donePercent;
    if (!active) return 0;
    return Math.min(94, Math.max(12, 20 + lines.length * 4));
  };
  const signatureProgress = progressValue(updateState, signatureUpdateActive, output);
  const saneProgress = progressValue(saneUpdateState, saneUpdateActive, saneOutput);

  return (
    <div className="px-8 max-w-4xl mx-auto space-y-8 pb-20">
      <PageHeader title="Updates" description="Update ClamAV, SecuriteInfo, SaneSecurity, YARA Forge, and ClamShield." />

      <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-full"><Database className="w-8 h-8" /></div>
            <div>
              <h3 className="font-semibold text-white text-lg">ClamAV Official Signatures</h3>
              <p className="text-slate-400 text-sm mt-1">{statusLine(status?.stats?.lastClamAVUpdate, status?.stats?.lastClamAVUpdateResult)}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button onClick={() => setOpenPanel(openPanel === "clamav" ? null : "clamav")} className="inline-flex items-center gap-2 px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">
              Settings <ChevronDown className={`w-4 h-4 transition-transform ${openPanel === "clamav" ? "rotate-180" : ""}`} />
            </button>
            <button onClick={() => runUpdate("clamav")} disabled={signatureUpdateActive} className="flex items-center gap-2 px-6 py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              <RefreshCw className={`w-5 h-5 ${signatureUpdateActive ? "animate-spin" : ""}`} />
              {signatureUpdateActive ? "Updating..." : "Update ClamAV"}
            </button>
          </div>
        </div>
        {openPanel === "clamav" && (
          <div className="px-8 pb-8 pt-2 border-t border-slate-800 grid sm:grid-cols-2 gap-4">
            <label className="flex items-center justify-between gap-4 sm:col-span-2">
              <span className="text-sm text-slate-300">Automatic ClamAV updates</span>
              <input type="checkbox" checked={updateSettings.autoUpdateEnabled !== false} onChange={event => saveUpdateSettings({ autoUpdateEnabled: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" />
            </label>
            <label className="block">
              <span className="text-xs font-medium text-slate-400">Update interval (hours)</span>
              <input type="number" min={24} max={720} value={updateSettings.clamavUpdateIntervalHours || updateSettings.updateIntervalHours || 24} onChange={event => updateNumberSetting("clamavUpdateIntervalHours", event.target.value, 24, 24, 720)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500" />
            </label>
          </div>
        )}
      </section>

      <section className="bg-slate-900 border border-cyan-500/20 rounded-xl overflow-hidden">
        <div className="p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-start gap-4 min-w-0">
            <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-full shrink-0"><Database className="w-8 h-8" /></div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-semibold text-white text-lg">SecuriteInfo Signatures</h3>
                <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-[11px] border border-slate-700">Third-party source</span>
              </div>
              <p className="text-slate-400 text-sm mt-1">{status?.securiteInfo?.connected ? `${status.securiteInfo.plan === "paid" ? "Paid" : "Basic"} - ${status.securiteInfo.installedCount || 0}/${status.securiteInfo.expectedCount || 0} databases - ${statusLine(status.securiteInfo.lastUpdated, status.securiteInfo.lastResult)}` : "Not installed"}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button onClick={() => setOpenPanel(openPanel === "securiteinfo" ? null : "securiteinfo")} className="inline-flex items-center gap-2 px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">
              Settings <ChevronDown className={`w-4 h-4 transition-transform ${openPanel === "securiteinfo" ? "rotate-180" : ""}`} />
            </button>
            {status?.securiteInfo?.connected ? (
              <button onClick={() => runUpdate("securiteinfo")} disabled={signatureUpdateActive} className="flex items-center gap-2 px-6 py-3 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                <RefreshCw className={`w-5 h-5 ${signatureUpdateActive ? "animate-spin" : ""}`} />
                {signatureUpdateActive ? "Updating..." : "Update SecuriteInfo"}
              </button>
            ) : (
              <Link to="/" className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg font-medium transition-colors"><KeyRound className="w-4 h-4" />Configure on Dashboard</Link>
            )}
          </div>
        </div>
        {openPanel === "securiteinfo" && (
          <div className="px-8 pb-8 pt-2 border-t border-cyan-500/20 space-y-4">
            <label className="block max-w-xs">
              <span className="text-xs font-medium text-slate-400">Update interval (hours)</span>
              <input type="number" min={1} max={24} value={updateSettings.securiteInfoUpdateIntervalHours || 1} onChange={event => updateNumberSetting("securiteInfoUpdateIntervalHours", event.target.value, 1, 1, 24)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500" />
            </label>
            <label className={`flex items-start justify-between gap-4 cursor-pointer rounded-lg border border-slate-800 bg-slate-950/50 p-4 ${updateSettings.securiteInfoPlan === "paid" ? "" : "opacity-60"}`}>
              <div>
                <span className="text-slate-200 font-medium flex items-center gap-2"><FileWarning className="w-4 h-4 text-amber-300" />SecuriteInfo PUA signatures</span>
                <span className="text-slate-500 text-xs block mt-1">Optional database <code>securiteinfo-pua-app-and-vulnerabilities.ndb</code>. It may generate many false positives.</span>
                {updateSettings.securiteInfoPlan !== "paid" && <span className="text-slate-500 text-xs block mt-1">Available for paid SecuriteInfo plans.</span>}
              </div>
              <input type="checkbox" checked={updateSettings.securiteInfoPlan === "paid" && updateSettings.securiteInfoIncludePua === true} disabled={updateSettings.securiteInfoPlan !== "paid"} onChange={event => saveUpdateSettings({ securiteInfoIncludePua: event.target.checked })} className="mt-1 w-5 h-5 rounded border-slate-600 text-amber-500 focus:ring-amber-500 focus:ring-offset-slate-900 bg-slate-800" />
            </label>
          </div>
        )}
      </section>

      <section className="bg-slate-900 border border-violet-500/20 rounded-xl overflow-hidden">
        <div className="p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-start gap-4 min-w-0">
            <div className="p-3 bg-violet-500/10 text-violet-400 rounded-full shrink-0"><ShieldCheck className="w-8 h-8" /></div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-semibold text-white text-lg">SaneSecurity Signatures</h3>
                <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-[11px] border border-slate-700">Signed third-party source</span>
              </div>
              <p className="text-slate-400 text-sm mt-1">{status?.saneSecurity?.connected ? `${status.saneSecurity.profile === "complete" ? "Complete" : "Malware Protection"} - ${status.saneSecurity.installedCount || 0}/${status.saneSecurity.expectedCount || 0} databases - ${statusLine(status.saneSecurity.lastUpdated, status.saneSecurity.lastResult)}` : "Not installed"}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button onClick={() => setOpenPanel(openPanel === "sanesecurity" ? null : "sanesecurity")} className="inline-flex items-center gap-2 px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">
              Settings <ChevronDown className={`w-4 h-4 transition-transform ${openPanel === "sanesecurity" ? "rotate-180" : ""}`} />
            </button>
            {status?.saneSecurity?.connected ? (
              <button onClick={runSaneUpdate} disabled={saneUpdateActive} className="flex items-center gap-2 px-6 py-3 bg-violet-700 hover:bg-violet-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                <RefreshCw className={`w-5 h-5 ${saneUpdateActive ? "animate-spin" : ""}`} />
                {saneUpdateActive ? "Updating..." : "Update SaneSecurity"}
              </button>
            ) : (
              <Link to="/" className="inline-flex items-center gap-2 px-6 py-3 bg-violet-700 hover:bg-violet-600 text-white rounded-lg font-medium transition-colors"><ShieldCheck className="w-4 h-4" />Configure on Dashboard</Link>
            )}
          </div>
        </div>
        {openPanel === "sanesecurity" && (
          <div className="px-8 pb-8 pt-2 border-t border-violet-500/20 max-w-xs">
            <label className="block">
              <span className="text-xs font-medium text-slate-400">Update interval (hours)</span>
              <input type="number" min={1} max={24} value={updateSettings.saneSecurityUpdateIntervalHours || 1} onChange={event => updateNumberSetting("saneSecurityUpdateIntervalHours", event.target.value, 1, 1, 24)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500" />
            </label>
          </div>
        )}
      </section>

      <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-full"><ShieldCheck className="w-8 h-8" /></div>
            <div>
              <h3 className="font-semibold text-white text-lg">YARA Forge Rules</h3>
              <p className="text-slate-400 text-sm">{status?.stats?.lastYaraUpdate ? `${statusLine(status.stats.lastYaraUpdate)} - ${status.stats.yaraRuleset} - ${status.stats.yaraRuleCount || 0} rules` : "Update required"}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button onClick={() => setOpenPanel(openPanel === "yara" ? null : "yara")} className="inline-flex items-center gap-2 px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Settings <ChevronDown className={`w-4 h-4 transition-transform ${openPanel === "yara" ? "rotate-180" : ""}`} /></button>
            <button onClick={runYaraUpdate} disabled={yaraUpdateState === "running"} className="flex items-center gap-2 px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              <RefreshCw className={`w-5 h-5 ${yaraUpdateState === "running" ? "animate-spin" : ""}`} />
              {yaraUpdateState === "running" ? "Updating..." : "Update YARA Rules"}
            </button>
          </div>
        </div>
        {openPanel === "yara" && (
          <div className="px-8 pb-8 pt-2 border-t border-slate-800 space-y-4">
            <label className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Enable YARA scanning</span><input type="checkbox" checked={updateSettings.yaraEnabled !== false} onChange={event => saveUpdateSettings({ yaraEnabled: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" /></label>
            <label className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Auto-update YARA rules</span><input type="checkbox" checked={updateSettings.yaraAutoUpdateEnabled !== false} onChange={event => saveUpdateSettings({ yaraAutoUpdateEnabled: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" /></label>
            <div className="grid sm:grid-cols-2 gap-4">
              <label className="block"><span className="text-xs font-medium text-slate-400">Ruleset</span><select value={updateSettings.yaraRuleset || "core"} onChange={event => saveUpdateSettings({ yaraRuleset: event.target.value })} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"><option value="core">Core</option><option value="extended">Extended</option><option value="full">Full</option></select></label>
              <label className="block"><span className="text-xs font-medium text-slate-400">Update interval (hours)</span><input type="number" min={1} max={8760} value={updateSettings.yaraUpdateIntervalHours || 168} onChange={event => updateNumberSetting("yaraUpdateIntervalHours", event.target.value, 168, 1, 8760)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500" /></label>
            </div>
          </div>
        )}
      </section>

      <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-center gap-4 min-w-0">
            <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-full"><DownloadCloud className="w-8 h-8" /></div>
            <div className="min-w-0">
              <h3 className="font-semibold text-white text-lg">ClamShield Application</h3>
              <p className="text-slate-400 text-sm">
                Installed: {status?.appVersion || "Unknown"}{appUpdateInfo?.latestVersion ? ` - Latest: ${appUpdateInfo.latestVersion}` : ""} - Last checked: {statusLine(status?.stats?.lastAppUpdateCheck)}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {appUpdateState === "available" && <>
              <button onClick={skipAppVersion} className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Skip Version</button>
              <button onClick={disableAppUpdates} className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Disable Checks</button>
            </>}
            <button onClick={() => setOpenPanel(openPanel === "app" ? null : "app")} className="inline-flex items-center gap-2 px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Settings <ChevronDown className={`w-4 h-4 transition-transform ${openPanel === "app" ? "rotate-180" : ""}`} /></button>
            <button onClick={appUpdateState === "available" ? installAppUpdate : checkAppUpdate} disabled={appUpdateState === "checking" || appUpdateState === "running"} className="flex items-center gap-2 px-6 py-3 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              <RefreshCw className={`w-5 h-5 ${appUpdateState === "checking" || appUpdateState === "running" ? "animate-spin" : ""}`} />
              {appUpdateState === "checking" ? "Checking..." : appUpdateState === "running" ? "Installing..." : appUpdateState === "available" ? "Install Update" : "Check ClamShield"}
            </button>
          </div>
        </div>
        {openPanel === "app" && (
          <div className="px-8 pb-8 pt-2 border-t border-slate-800 space-y-4">
            <label className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Check for ClamShield app updates</span><input type="checkbox" checked={updateSettings.appUpdateCheckEnabled !== false} onChange={event => saveUpdateSettings({ appUpdateCheckEnabled: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" /></label>
            <label className="block max-w-xs"><span className="text-xs font-medium text-slate-400">Update interval (hours)</span><input type="number" min={1} max={8760} value={updateSettings.appUpdateIntervalHours || 168} onChange={event => updateNumberSetting("appUpdateIntervalHours", event.target.value, 168, 1, 8760)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500" /></label>
            <label className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Silent install ClamShield updates</span><input type="checkbox" checked={updateSettings.appSilentAutoInstall === true} onChange={event => saveUpdateSettings({ appSilentAutoInstall: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" /></label>
          </div>
        )}
      </section>

      {(saneUpdateActive || saneUpdateState === "done") && (
        <div className="bg-slate-900 border border-violet-500/20 rounded-xl px-6 py-5 space-y-3">
          <div className="flex items-center justify-between gap-4 text-sm">
            <span className="text-slate-300 font-medium">{saneUpdateActive ? "Downloading and verifying SaneSecurity databases" : saneUpdateFailed ? "SaneSecurity update failed" : "SaneSecurity update complete"}</span>
            <span className="text-slate-500 tabular-nums">{saneProgress}%</span>
          </div>
          <div className="h-2.5 overflow-hidden rounded-full bg-slate-800"><div className={`h-full rounded-full transition-all duration-700 ${saneUpdateFailed ? "bg-gradient-to-r from-rose-600 to-orange-400" : "bg-gradient-to-r from-violet-500 to-fuchsia-400"} ${saneUpdateActive ? "animate-pulse" : ""}`} style={{ width: `${saneProgress}%` }} /></div>
          <p className="text-xs text-slate-500 truncate">{saneOutput.at(-1) || "SaneSecurity is preparing its signed database update..."}</p>
        </div>
      )}

      {(signatureUpdateActive || updateState === "done") && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl px-6 py-5 space-y-3">
          <div className="flex items-center justify-between gap-4 text-sm">
            <span className="text-slate-300 font-medium">{signatureUpdateActive ? "Updating signature databases" : signatureUpdateFailed ? "Signature update failed" : "Signature update complete"}</span>
            <span className="text-slate-500 tabular-nums">{signatureProgress}%</span>
          </div>
          <div className="h-2.5 overflow-hidden rounded-full bg-slate-800"><div className={`h-full rounded-full transition-all duration-700 ${signatureUpdateFailed ? "bg-gradient-to-r from-rose-600 to-orange-400" : "bg-gradient-to-r from-emerald-500 to-cyan-400"} ${signatureUpdateActive ? "animate-pulse" : ""}`} style={{ width: `${signatureProgress}%` }} /></div>
          <p className="text-xs text-slate-500 truncate">{output.at(-1) || "FreshClam is checking signature sources..."}</p>
        </div>
      )}

      {(updateState === "running" || updateState === "done") && (
        <Terminal title="FreshClam Output" running={updateState === "running"} lines={output} />
      )}
      {(saneUpdateState === "running" || saneUpdateState === "done") && (
        <Terminal title="SaneSecurity Output" running={saneUpdateState === "running"} lines={saneOutput} accent="text-violet-300/80" />
      )}
      {(yaraUpdateState === "running" || yaraUpdateState === "done") && (
        <Terminal title="YARA Output" running={yaraUpdateState === "running"} lines={yaraOutput} />
      )}
      {appUpdateState !== "idle" && (
        <Terminal title="ClamShield Output" running={appUpdateState === "checking" || appUpdateState === "running"} lines={appOutput} />
      )}
    </div>
  );
}

function Terminal({ title, running, lines, accent = "text-emerald-400/80" }: { title: string; running: boolean; lines: string[]; accent?: string }) {
  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-64">
      <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center gap-2">
        <span className="font-mono text-sm text-slate-300 flex items-center gap-2">
          {running ? <Loader2 className="w-4 h-4 animate-spin text-indigo-400" /> : null}
          {title}
        </span>
      </div>
      <div className={`flex-1 p-4 overflow-auto font-mono text-xs ${accent} leading-relaxed space-y-1 flex flex-col justify-end`}>
        {lines.map((line, index) => <div key={index}>{line}</div>)}
      </div>
    </div>
  );
}
