import { useEffect, useRef, useState } from "react";
import { ChevronDown, Database, DownloadCloud, FileWarning, KeyRound, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";
import { formatSystemDateTime } from "../lib/dateFormat";

const MAX_TERMINAL_LINES = 800;
type DetailsPanel = "clamav" | "securiteinfo" | "sanesecurity" | "yara" | "clamavEngine" | "yaraEngine" | "app";
type EngineUpdateKind = "clamavEngine" | "yaraEngine";
type UpdateCheckState = "idle" | "checking" | "available" | "none" | "running" | "done";

function appendOutput(previous: string[], next: string[]) {
  return [...previous, ...next].slice(-MAX_TERMINAL_LINES);
}

export default function Updates() {
  const [updateState, setUpdateState] = useState<"idle" | "running" | "done">("idle");
  const [output, setOutput] = useState<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSimulated, setIsSimulated] = useState(false);
  const [signatureTarget, setSignatureTarget] = useState<"clamav" | "securiteinfo">("clamav");
  const [saneUpdateState, setSaneUpdateState] = useState<"idle" | "running" | "done">("idle");
  const [saneOutput, setSaneOutput] = useState<string[]>([]);
  const [saneJobId, setSaneJobId] = useState<string | null>(null);
  const [yaraUpdateState, setYaraUpdateState] = useState<"idle" | "running" | "done">("idle");
  const [yaraOutput, setYaraOutput] = useState<string[]>([]);
  const [yaraJobId, setYaraJobId] = useState<string | null>(null);
  const [clamavEngineState, setClamavEngineState] = useState<UpdateCheckState>("idle");
  const [clamavEngineInfo, setClamavEngineInfo] = useState<any>(null);
  const [clamavEngineOutput, setClamavEngineOutput] = useState<string[]>([]);
  const [clamavEngineJobId, setClamavEngineJobId] = useState<string | null>(null);
  const [yaraEngineState, setYaraEngineState] = useState<UpdateCheckState>("idle");
  const [yaraEngineInfo, setYaraEngineInfo] = useState<any>(null);
  const [yaraEngineOutput, setYaraEngineOutput] = useState<string[]>([]);
  const [yaraEngineJobId, setYaraEngineJobId] = useState<string | null>(null);
  const [appUpdateState, setAppUpdateState] = useState<UpdateCheckState>("idle");
  const [appUpdateInfo, setAppUpdateInfo] = useState<any>(null);
  const [appOutput, setAppOutput] = useState<string[]>([]);
  const [appJobId, setAppJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<any>(null);
  const [openPanel, setOpenPanel] = useState<DetailsPanel | null>(null);
  const updateEventSourceRef = useRef<EventSource | null>(null);
  const saneEventSourceRef = useRef<EventSource | null>(null);
  const yaraEventSourceRef = useRef<EventSource | null>(null);
  const clamavEngineEventSourceRef = useRef<EventSource | null>(null);
  const yaraEngineEventSourceRef = useRef<EventSource | null>(null);
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
    setSignatureTarget(target);
    setUpdateState("running");
    setOutput([target === "securiteinfo" ? "Triggering SecuriteInfo update..." : "Triggering ClamAV FreshClam update..."]);
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
        data.newerVersionAvailable
          ? data.skipped
            ? `Skipped ClamShield ${data.latestVersion}. You can still install it manually.`
            : `Update available: ${data.assetName || data.releaseUrl}`
          : "ClamShield is up to date."
      ]));
      setAppUpdateState(data.newerVersionAvailable ? "available" : "none");
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
    setAppUpdateState("available");
  };

  const remindAppTomorrow = async () => {
    if (!appUpdateInfo?.latestVersion) return;
    await fetch("/api/app-update/remind", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ remindAfter: Date.now() + 24 * 60 * 60 * 1000 })
    });
    setAppOutput(prev => appendOutput(prev, [`Will remind you tomorrow about ClamShield ${appUpdateInfo.latestVersion}.`]));
    setAppUpdateState("available");
  };

  const engineConfig = {
    clamavEngine: {
      label: "ClamAV Engine",
      checkPath: "/api/clamav-engine-update",
      installPath: "/api/clamav-engine-update/install",
      skipPath: "/api/clamav-engine-update/skip",
      remindPath: "/api/clamav-engine-update/remind",
      setState: setClamavEngineState,
      setInfo: setClamavEngineInfo,
      setOutput: setClamavEngineOutput,
      setJobId: setClamavEngineJobId,
      ref: clamavEngineEventSourceRef
    },
    yaraEngine: {
      label: "YARA Engine",
      checkPath: "/api/yara-engine-update",
      installPath: "/api/yara-engine-update/install",
      skipPath: "/api/yara-engine-update/skip",
      remindPath: "/api/yara-engine-update/remind",
      setState: setYaraEngineState,
      setInfo: setYaraEngineInfo,
      setOutput: setYaraEngineOutput,
      setJobId: setYaraEngineJobId,
      ref: yaraEngineEventSourceRef
    }
  };

  const checkEngineUpdate = async (kind: EngineUpdateKind) => {
    const config = engineConfig[kind];
    config.setState("checking");
    config.setOutput([`Checking ${config.label} releases...`]);
    try {
      const res = await fetch(config.checkPath);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Failed to check ${config.label} updates.`);
      config.setInfo(data);
      config.setOutput(prev => appendOutput(prev, [
        `Installed: ${data.currentVersion || data.currentLabel || "Unknown"}`,
        `Latest: ${data.latestVersion || "Unknown"}`,
        data.newerVersionAvailable
          ? data.skipped
            ? `Skipped ${config.label} ${data.latestVersion}. You can still install it manually.`
            : `Update available: ${data.assetName || data.releaseUrl}`
          : `${config.label} is up to date.`
      ]));
      config.setState(data.newerVersionAvailable ? "available" : "none");
    } catch (e: any) {
      config.setOutput(prev => appendOutput(prev, [`Error: ${e.message}`]));
      config.setState("done");
    }
  };

  const installEngineUpdate = async (kind: EngineUpdateKind) => {
    const config = engineConfig[kind];
    closeJobStream(config.ref);
    config.setState("running");
    config.setOutput(prev => appendOutput(prev, [`Installing ${config.label} update...`]));
    try {
      const res = await fetch(config.installPath, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Failed to start ${config.label} update.`);
      config.setJobId(data.jobId);
    } catch (e: any) {
      config.setOutput(prev => appendOutput(prev, [`Error: ${e.message}`]));
      config.setState("done");
      config.setJobId(null);
    }
  };

  const skipEngineVersion = async (kind: EngineUpdateKind, info: any) => {
    if (!info?.latestVersion) return;
    const config = engineConfig[kind];
    await fetch(config.skipPath, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: info.latestVersion })
    });
    config.setOutput(prev => appendOutput(prev, [`Skipped ${config.label} ${info.latestVersion}.`]));
    config.setState("none");
  };

  const remindEngineTomorrow = async (kind: EngineUpdateKind, info: any) => {
    if (!info?.latestVersion) return;
    const config = engineConfig[kind];
    await fetch(config.remindPath, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ remindAfter: Date.now() + 24 * 60 * 60 * 1000 })
    });
    config.setOutput(prev => appendOutput(prev, [`Will remind you tomorrow about ${config.label} ${info.latestVersion}.`]));
    config.setState("none");
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
    clamavEngineState === "running",
    clamavEngineJobId,
    clamavEngineEventSourceRef,
    logs => setClamavEngineOutput(prev => appendOutput(prev, logs)),
    () => { setClamavEngineState("done"); setClamavEngineJobId(null); },
    "ClamAV Engine update"
  ), [clamavEngineState, clamavEngineJobId]);

  useEffect(() => bindJobStream(
    yaraEngineState === "running",
    yaraEngineJobId,
    yaraEngineEventSourceRef,
    logs => setYaraEngineOutput(prev => appendOutput(prev, logs)),
    () => { setYaraEngineState("done"); setYaraEngineJobId(null); },
    "YARA Engine update"
  ), [yaraEngineState, yaraEngineJobId]);

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
  const yaraUpdateActive = yaraUpdateState === "running";
  const clamavEngineActive = clamavEngineState === "checking" || clamavEngineState === "running";
  const yaraEngineActive = yaraEngineState === "checking" || yaraEngineState === "running";
  const appUpdateActive = appUpdateState === "checking" || appUpdateState === "running";
  const signatureUpdateFailed = updateState === "done" && output.some(line => /error|failed/i.test(line));
  const saneUpdateFailed = saneUpdateState === "done" && saneOutput.some(line => /error|failed/i.test(line));
  const yaraUpdateFailed = yaraUpdateState === "done" && yaraOutput.some(line => /error|failed/i.test(line));
  const clamavEngineFailed = clamavEngineState === "done" && clamavEngineOutput.some(line => /error|failed/i.test(line));
  const yaraEngineFailed = yaraEngineState === "done" && yaraEngineOutput.some(line => /error|failed/i.test(line));
  const appUpdateFailed = appUpdateState === "done" && appOutput.some(line => /error|failed/i.test(line));

  const formatExact = (value?: string | null) => formatSystemDateTime(value);
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
  const yaraProgress = progressValue(yaraUpdateState, yaraUpdateActive, yaraOutput);
  const clamavEngineProgress = clamavEngineActive ? Math.min(94, Math.max(12, 20 + clamavEngineOutput.length * 4)) : clamavEngineState !== "idle" ? 100 : 0;
  const yaraEngineProgress = yaraEngineActive ? Math.min(94, Math.max(12, 20 + yaraEngineOutput.length * 4)) : yaraEngineState !== "idle" ? 100 : 0;
  const appProgress = appUpdateActive
    ? Math.min(94, Math.max(12, 20 + appOutput.length * 4))
    : appUpdateState !== "idle" ? 100 : 0;
  const signatureOutputTitle = signatureTarget === "securiteinfo" ? "SecuriteInfo Output" : "FreshClam Output";
  const signatureProgressLabel = output.at(-1) || (signatureTarget === "securiteinfo" ? "SecuriteInfo is checking signature sources..." : "FreshClam is checking signature sources...");

  return (
    <div className="px-8 max-w-4xl mx-auto space-y-8 pb-20 flex flex-col">
      <PageHeader title="Updates" description="Update signatures, engines, YARA Forge rules, and ClamShield." />

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
            <div className="flex items-center justify-between gap-4 sm:col-span-2">
              <span className="text-sm text-slate-300">Automatic ClamAV updates</span>
              <input type="checkbox" checked={updateSettings.autoUpdateEnabled !== false} onChange={event => saveUpdateSettings({ autoUpdateEnabled: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" />
            </div>
            <label className="block">
              <span className="text-xs font-medium text-slate-400">Update interval (hours)</span>
              <input type="number" min={24} max={720} value={updateSettings.clamavUpdateIntervalHours || updateSettings.updateIntervalHours || 24} onChange={event => updateNumberSetting("clamavUpdateIntervalHours", event.target.value, 24, 24, 720)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500" />
            </label>
          </div>
        )}
        {signatureTarget === "clamav" && (signatureUpdateActive || updateState === "done") && (
          <ProgressPanel
            title={signatureUpdateActive ? "Updating official ClamAV signatures" : signatureUpdateFailed ? "ClamAV update failed" : "ClamAV update complete"}
            progress={signatureProgress}
            failed={signatureUpdateFailed}
            active={signatureUpdateActive}
            label={signatureProgressLabel}
            barClass="bg-gradient-to-r from-emerald-500 to-cyan-400"
          />
        )}
        {signatureTarget === "clamav" && (updateState === "running" || updateState === "done") && (
          <div className="px-8 pb-8 pt-4 border-t border-slate-800">
            <Terminal title={signatureOutputTitle} running={updateState === "running"} lines={output} />
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
            <div className={`flex items-start justify-between gap-4 rounded-lg border border-slate-800 bg-slate-950/50 p-4 ${updateSettings.securiteInfoPlan === "paid" ? "" : "opacity-60"}`}>
              <div>
                <span className="text-slate-200 font-medium flex items-center gap-2"><FileWarning className="w-4 h-4 text-amber-300" />SecuriteInfo PUA signatures</span>
                <span className="text-slate-500 text-xs block mt-1">Optional database <code>securiteinfo-pua-app-and-vulnerabilities.ndb</code>. It may generate many false positives.</span>
                {updateSettings.securiteInfoPlan !== "paid" && <span className="text-slate-500 text-xs block mt-1">Available for paid SecuriteInfo plans.</span>}
              </div>
              <input type="checkbox" checked={updateSettings.securiteInfoPlan === "paid" && updateSettings.securiteInfoIncludePua === true} disabled={updateSettings.securiteInfoPlan !== "paid"} onChange={event => saveUpdateSettings({ securiteInfoIncludePua: event.target.checked })} className="mt-1 w-5 h-5 rounded border-slate-600 text-amber-500 focus:ring-amber-500 focus:ring-offset-slate-900 bg-slate-800" />
            </div>
          </div>
        )}
        {signatureTarget === "securiteinfo" && (signatureUpdateActive || updateState === "done") && (
          <ProgressPanel
            title={signatureUpdateActive ? "Updating SecuriteInfo signatures" : signatureUpdateFailed ? "SecuriteInfo update failed" : "SecuriteInfo update complete"}
            progress={signatureProgress}
            failed={signatureUpdateFailed}
            active={signatureUpdateActive}
            label={signatureProgressLabel}
            barClass="bg-gradient-to-r from-cyan-500 to-sky-400"
            borderClass="border-cyan-500/20"
          />
        )}
        {signatureTarget === "securiteinfo" && (updateState === "running" || updateState === "done") && (
          <div className="px-8 pb-8 pt-4 border-t border-cyan-500/20">
            <Terminal title={signatureOutputTitle} running={updateState === "running"} lines={output} accent="text-cyan-300/80" />
          </div>
        )}
      </section>

      <section className="bg-slate-900 border border-violet-500/20 rounded-xl overflow-hidden">
        <div className="p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-start gap-4 min-w-0">
            <div className="p-3 bg-violet-500/10 text-violet-400 rounded-full shrink-0"><Database className="w-8 h-8" /></div>
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
        {(saneUpdateActive || saneUpdateState === "done") && (
          <ProgressPanel
            title={saneUpdateActive ? "Downloading and verifying SaneSecurity databases" : saneUpdateFailed ? "SaneSecurity update failed" : "SaneSecurity update complete"}
            progress={saneProgress}
            failed={saneUpdateFailed}
            active={saneUpdateActive}
            label={saneOutput.at(-1) || "SaneSecurity is preparing its signed database update..."}
            barClass="bg-gradient-to-r from-violet-500 to-fuchsia-400"
            borderClass="border-violet-500/20"
          />
        )}
        {(saneUpdateState === "running" || saneUpdateState === "done") && (
          <div className="px-8 pb-8 pt-4 border-t border-violet-500/20">
            <Terminal title="SaneSecurity Output" running={saneUpdateState === "running"} lines={saneOutput} accent="text-violet-300/80" />
          </div>
        )}
      </section>

      <section className="order-last bg-slate-900 border border-emerald-500/20 rounded-xl overflow-hidden">
        <div className="p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-center gap-4 min-w-0">
            <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-full"><DownloadCloud className="w-8 h-8" /></div>
            <div className="min-w-0">
              <h3 className="font-semibold text-white text-lg">ClamAV Engine</h3>
              <p className="text-slate-400 text-sm">
                Installed: {status?.stats?.engineVersion || "Unknown"}{clamavEngineInfo?.latestVersion ? ` - Latest: ${clamavEngineInfo.latestVersion}` : ""} - Last checked: {statusLine(status?.stats?.clamavEngineLastCheck, status?.stats?.clamavEngineLastCheckResult)}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {clamavEngineState === "available" && <>
              <button onClick={() => skipEngineVersion("clamavEngine", clamavEngineInfo)} className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Skip Version</button>
              <button onClick={() => remindEngineTomorrow("clamavEngine", clamavEngineInfo)} className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Remind Tomorrow</button>
            </>}
            <button onClick={() => setOpenPanel(openPanel === "clamavEngine" ? null : "clamavEngine")} className="inline-flex items-center gap-2 px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Settings <ChevronDown className={`w-4 h-4 transition-transform ${openPanel === "clamavEngine" ? "rotate-180" : ""}`} /></button>
            <button onClick={clamavEngineState === "available" ? () => installEngineUpdate("clamavEngine") : () => checkEngineUpdate("clamavEngine")} disabled={clamavEngineActive} className="flex items-center gap-2 px-6 py-3 bg-emerald-700 hover:bg-emerald-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              <RefreshCw className={`w-5 h-5 ${clamavEngineActive ? "animate-spin" : ""}`} />
              {clamavEngineState === "checking" ? "Checking..." : clamavEngineState === "running" ? "Installing..." : clamavEngineState === "available" ? "Install Update" : "Check ClamAV"}
            </button>
          </div>
        </div>
        {openPanel === "clamavEngine" && (
          <div className="px-8 pb-8 pt-2 border-t border-emerald-500/20 space-y-4">
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Check for ClamAV Engine updates</span><input type="checkbox" checked={updateSettings.clamavEngineUpdateCheckEnabled !== false} onChange={event => saveUpdateSettings({ clamavEngineUpdateCheckEnabled: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Notify me when update is available</span><input type="checkbox" checked={updateSettings.clamavEngineUpdateNotifyAvailable !== false} onChange={event => saveUpdateSettings({ clamavEngineUpdateNotifyAvailable: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Notify me on failed update</span><input type="checkbox" checked={updateSettings.clamavEngineUpdateNotifyFailed === true} onChange={event => saveUpdateSettings({ clamavEngineUpdateNotifyFailed: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <label className="block max-w-xs"><span className="text-xs font-medium text-slate-400">Update interval (hours)</span><input type="number" min={1} max={8760} value={updateSettings.clamavEngineUpdateIntervalHours || 24} onChange={event => updateNumberSetting("clamavEngineUpdateIntervalHours", event.target.value, 24, 1, 8760)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-emerald-500" /></label>
          </div>
        )}
        {clamavEngineState !== "idle" && (
          <ProgressPanel
            title={clamavEngineActive ? "Checking ClamAV Engine updates" : clamavEngineFailed ? "ClamAV Engine update failed" : clamavEngineState === "available" ? (clamavEngineInfo?.skipped ? "ClamAV Engine update skipped" : "ClamAV Engine update available") : "ClamAV Engine update check complete"}
            progress={clamavEngineProgress}
            failed={clamavEngineFailed}
            active={clamavEngineActive}
            label={clamavEngineOutput.at(-1) || "ClamAV Engine is checking GitHub releases..."}
            barClass="bg-gradient-to-r from-emerald-500 to-cyan-400"
            borderClass="border-emerald-500/20"
          />
        )}
        {clamavEngineState !== "idle" && (
          <div className="px-8 pb-8 pt-4 border-t border-emerald-500/20">
            <Terminal title="ClamAV Engine Output" running={clamavEngineActive} lines={clamavEngineOutput} />
          </div>
        )}
      </section>

      <section className="order-last bg-slate-900 border border-amber-500/20 rounded-xl overflow-hidden">
        <div className="p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-center gap-4 min-w-0">
            <div className="p-3 bg-amber-500/10 text-amber-300 rounded-full"><DownloadCloud className="w-8 h-8" /></div>
            <div className="min-w-0">
              <h3 className="font-semibold text-white text-lg">YARA Engine</h3>
              <p className="text-slate-400 text-sm">
                Installed: {status?.stats?.yaraEngineVersion || "Unknown"}{yaraEngineInfo?.latestVersion ? ` - Latest: ${yaraEngineInfo.latestVersion}` : ""} - Last checked: {statusLine(status?.stats?.yaraEngineLastCheck, status?.stats?.yaraEngineLastCheckResult)}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {yaraEngineState === "available" && <>
              <button onClick={() => skipEngineVersion("yaraEngine", yaraEngineInfo)} className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Skip Version</button>
              <button onClick={() => remindEngineTomorrow("yaraEngine", yaraEngineInfo)} className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Remind Tomorrow</button>
            </>}
            <button onClick={() => setOpenPanel(openPanel === "yaraEngine" ? null : "yaraEngine")} className="inline-flex items-center gap-2 px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Settings <ChevronDown className={`w-4 h-4 transition-transform ${openPanel === "yaraEngine" ? "rotate-180" : ""}`} /></button>
            <button onClick={yaraEngineState === "available" ? () => installEngineUpdate("yaraEngine") : () => checkEngineUpdate("yaraEngine")} disabled={yaraEngineActive} className="flex items-center gap-2 px-6 py-3 bg-amber-600 hover:bg-amber-500 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              <RefreshCw className={`w-5 h-5 ${yaraEngineActive ? "animate-spin" : ""}`} />
              {yaraEngineState === "checking" ? "Checking..." : yaraEngineState === "running" ? "Installing..." : yaraEngineState === "available" ? "Install Update" : "Check YARA"}
            </button>
          </div>
        </div>
        {openPanel === "yaraEngine" && (
          <div className="px-8 pb-8 pt-2 border-t border-amber-500/20 space-y-4">
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Check for YARA Engine updates</span><input type="checkbox" checked={updateSettings.yaraEngineUpdateCheckEnabled !== false} onChange={event => saveUpdateSettings({ yaraEngineUpdateCheckEnabled: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-amber-500 focus:ring-amber-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Notify me when update is available</span><input type="checkbox" checked={updateSettings.yaraEngineUpdateNotifyAvailable !== false} onChange={event => saveUpdateSettings({ yaraEngineUpdateNotifyAvailable: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-amber-500 focus:ring-amber-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Notify me on failed update</span><input type="checkbox" checked={updateSettings.yaraEngineUpdateNotifyFailed === true} onChange={event => saveUpdateSettings({ yaraEngineUpdateNotifyFailed: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-amber-500 focus:ring-amber-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <label className="block max-w-xs"><span className="text-xs font-medium text-slate-400">Update interval (hours)</span><input type="number" min={1} max={8760} value={updateSettings.yaraEngineUpdateIntervalHours || 24} onChange={event => updateNumberSetting("yaraEngineUpdateIntervalHours", event.target.value, 24, 1, 8760)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-amber-500" /></label>
          </div>
        )}
        {yaraEngineState !== "idle" && (
          <ProgressPanel
            title={yaraEngineActive ? "Checking YARA Engine updates" : yaraEngineFailed ? "YARA Engine update failed" : yaraEngineState === "available" ? (yaraEngineInfo?.skipped ? "YARA Engine update skipped" : "YARA Engine update available") : "YARA Engine update check complete"}
            progress={yaraEngineProgress}
            failed={yaraEngineFailed}
            active={yaraEngineActive}
            label={yaraEngineOutput.at(-1) || "YARA Engine is checking GitHub releases..."}
            barClass="bg-gradient-to-r from-amber-500 to-emerald-400"
            borderClass="border-amber-500/20"
          />
        )}
        {yaraEngineState !== "idle" && (
          <div className="px-8 pb-8 pt-4 border-t border-amber-500/20">
            <Terminal title="YARA Engine Output" running={yaraEngineActive} lines={yaraEngineOutput} accent="text-amber-300/80" />
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
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Auto-update YARA rules</span><input type="checkbox" checked={updateSettings.yaraAutoUpdateEnabled !== false} onChange={event => saveUpdateSettings({ yaraAutoUpdateEnabled: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <div className="grid sm:grid-cols-2 gap-4">
              <label className="block"><span className="text-xs font-medium text-slate-400">Ruleset</span><select value={updateSettings.yaraRuleset || "core"} onChange={event => saveUpdateSettings({ yaraRuleset: event.target.value })} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"><option value="core">Core</option><option value="extended">Extended</option><option value="full">Full</option></select></label>
              <label className="block"><span className="text-xs font-medium text-slate-400">Update interval (hours)</span><input type="number" min={1} max={8760} value={updateSettings.yaraUpdateIntervalHours || 168} onChange={event => updateNumberSetting("yaraUpdateIntervalHours", event.target.value, 168, 1, 8760)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500" /></label>
            </div>
          </div>
        )}
        {(yaraUpdateActive || yaraUpdateState === "done") && (
          <ProgressPanel
            title={yaraUpdateActive ? "Updating YARA Forge rules" : yaraUpdateFailed ? "YARA update failed" : "YARA update complete"}
            progress={yaraProgress}
            failed={yaraUpdateFailed}
            active={yaraUpdateActive}
            label={yaraOutput.at(-1) || "YARA Forge is checking rules..."}
            barClass="bg-gradient-to-r from-indigo-500 to-emerald-400"
          />
        )}
        {(yaraUpdateState === "running" || yaraUpdateState === "done") && (
          <div className="px-8 pb-8 pt-4 border-t border-slate-800">
            <Terminal title="YARA Output" running={yaraUpdateState === "running"} lines={yaraOutput} />
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
              <button onClick={remindAppTomorrow} className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">Remind Tomorrow</button>
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
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Check for ClamShield app updates</span><input type="checkbox" checked={updateSettings.appUpdateCheckEnabled !== false} onChange={event => saveUpdateSettings({ appUpdateCheckEnabled: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Notify me when update is available</span><input type="checkbox" checked={updateSettings.appUpdateNotifyAvailable !== false} onChange={event => saveUpdateSettings({ appUpdateNotifyAvailable: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Notify me on failed update</span><input type="checkbox" checked={updateSettings.appUpdateNotifyFailed === true} onChange={event => saveUpdateSettings({ appUpdateNotifyFailed: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
            <label className="block max-w-xs"><span className="text-xs font-medium text-slate-400">Update interval (hours)</span><input type="number" min={1} max={8760} value={updateSettings.appUpdateIntervalHours || 168} onChange={event => updateNumberSetting("appUpdateIntervalHours", event.target.value, 168, 1, 8760)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500" /></label>
            <div className="flex items-center justify-between gap-4"><span className="text-sm text-slate-300">Silent install ClamShield updates</span><input type="checkbox" checked={updateSettings.appSilentAutoInstall === true} onChange={event => saveUpdateSettings({ appSilentAutoInstall: event.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" /></div>
          </div>
        )}
        {appUpdateState !== "idle" && (
          <ProgressPanel
            title={appUpdateActive ? "Checking ClamShield updates" : appUpdateFailed ? "ClamShield update check failed" : appUpdateState === "available" ? (appUpdateInfo?.skipped ? "ClamShield update skipped" : "ClamShield update available") : "ClamShield update check complete"}
            progress={appProgress}
            failed={appUpdateFailed}
            active={appUpdateActive}
            label={appOutput.at(-1) || "ClamShield is checking GitHub releases..."}
            barClass="bg-gradient-to-r from-cyan-500 to-indigo-400"
          />
        )}
        {appUpdateState !== "idle" && (
          <div className="px-8 pb-8 pt-4 border-t border-slate-800">
            <Terminal title="ClamShield Output" running={appUpdateActive} lines={appOutput} />
          </div>
        )}
      </section>

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

function ProgressPanel({
  title,
  progress,
  failed,
  active,
  label,
  barClass,
  borderClass = "border-slate-800"
}: {
  title: string;
  progress: number;
  failed: boolean;
  active: boolean;
  label: string;
  barClass: string;
  borderClass?: string;
}) {
  return (
    <div className={`px-8 py-5 border-t ${borderClass} space-y-3`}>
      <div className="flex items-center justify-between gap-4 text-sm">
        <span className="text-slate-300 font-medium">{title}</span>
        <span className="text-slate-500 tabular-nums">{progress}%</span>
      </div>
      <div className="h-2.5 overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full transition-all duration-700 ${failed ? "bg-gradient-to-r from-rose-600 to-orange-400" : barClass} ${active ? "animate-pulse" : ""}`}
          style={{ width: `${progress}%` }}
        />
      </div>
      <p className="text-xs text-slate-500 truncate">{label}</p>
    </div>
  );
}
