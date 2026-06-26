import { useState, useRef, useEffect } from "react";
import { RefreshCw, Database, Loader2, ShieldCheck, DownloadCloud, KeyRound } from "lucide-react";
import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";

const MAX_TERMINAL_LINES = 800;

function appendOutput(previous: string[], next: string[]) {
  return [...previous, ...next].slice(-MAX_TERMINAL_LINES);
}

export default function Updates() {
  const [updateState, setUpdateState] = useState<"idle" | "running" | "done">("idle");
  const [output, setOutput] = useState<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSimulated, setIsSimulated] = useState<boolean>(false);
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

  const runUpdate = async () => {
    closeJobStream(updateEventSourceRef);
    setUpdateState("running");
    setOutput(["Triggering freshclam..."]);
    try {
      const res = await fetch("/api/update", { method: "POST" });
      const data = await res.json();
      
      if (!res.ok) {
        throw new Error(data.error || "Failed to start update.");
      }
      
      setJobId(data.jobId);
      setIsSimulated(!!data.simulated);
      
      if (data.simulated) {
        setOutput(prev => appendOutput(prev, ["Running in simulation mode...", "Checking for database updates..."]));
        setTimeout(() => {
          setOutput(prev => appendOutput(prev, ["main.cvd is up to date (version: 62, sigs: XXXXXX, f-level: 90)", "daily.cvd is up to date", "bytecode.cvd is up to date", "Database updated successfully."]));
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
    setAppOutput(prev => appendOutput(prev, ["ClamShield update checks disabled. You can re-enable them in Settings."]));
    setAppUpdateState("done");
    refreshStatus();
  };

  useEffect(() => {
    if (updateState === "running" && jobId && !isSimulated) {
      const source = new EventSource(`/api/scan/${encodeURIComponent(jobId)}/events`);
      updateEventSourceRef.current = source;
      const handleJobEvent = (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          if (data.logs && data.logs.length > 0) {
            setOutput(prev => appendOutput(prev, data.logs));
          }
          if (data.status === "done" || data.status === "missing") {
            setUpdateState("done");
            setJobId(null);
            refreshStatus();
            closeJobStream(updateEventSourceRef);
          }
        } catch (e) {
          console.error("Failed to process update event:", e);
        }
      };
      source.addEventListener("job", handleJobEvent);
      source.onerror = () => console.error("FreshClam event stream disconnected; waiting for reconnect.");
    }

    return () => {
      closeJobStream(updateEventSourceRef);
    };
  }, [updateState, jobId, isSimulated]);

  useEffect(() => {
    if (saneUpdateState === "running" && saneJobId) {
      const source = new EventSource(`/api/scan/${encodeURIComponent(saneJobId)}/events`);
      saneEventSourceRef.current = source;
      const handleJobEvent = (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          if (data.logs && data.logs.length > 0) {
            setSaneOutput(prev => appendOutput(prev, data.logs));
          }
          if (data.status === "done" || data.status === "missing") {
            setSaneUpdateState("done");
            setSaneJobId(null);
            refreshStatus();
            closeJobStream(saneEventSourceRef);
          }
        } catch (e) {
          console.error("Failed to process SaneSecurity update event:", e);
        }
      };
      source.addEventListener("job", handleJobEvent);
      source.onerror = () => console.error("SaneSecurity event stream disconnected; waiting for reconnect.");
    }

    return () => {
      closeJobStream(saneEventSourceRef);
    };
  }, [saneUpdateState, saneJobId]);

  useEffect(() => {
    if (yaraUpdateState === "running" && yaraJobId) {
      const source = new EventSource(`/api/scan/${encodeURIComponent(yaraJobId)}/events`);
      yaraEventSourceRef.current = source;
      const handleJobEvent = (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          if (data.logs && data.logs.length > 0) {
            setYaraOutput(prev => appendOutput(prev, data.logs));
          }
          if (data.status === "done" || data.status === "missing") {
            setYaraUpdateState("done");
            setYaraJobId(null);
            refreshStatus();
            closeJobStream(yaraEventSourceRef);
          }
        } catch (e) {
          console.error("Failed to process YARA update event:", e);
        }
      };
      source.addEventListener("job", handleJobEvent);
      source.onerror = () => console.error("YARA event stream disconnected; waiting for reconnect.");
    }

    return () => {
      closeJobStream(yaraEventSourceRef);
    };
  }, [yaraUpdateState, yaraJobId]);

  useEffect(() => {
    if (appUpdateState === "running" && appJobId) {
      const source = new EventSource(`/api/scan/${encodeURIComponent(appJobId)}/events`);
      appEventSourceRef.current = source;
      const handleJobEvent = (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          if (data.logs && data.logs.length > 0) {
            setAppOutput(prev => appendOutput(prev, data.logs));
          }
          if (data.status === "done" || data.status === "missing") {
            setAppUpdateState("done");
            setAppJobId(null);
            closeJobStream(appEventSourceRef);
          }
        } catch (e) {
          console.error("Failed to process ClamShield update event:", e);
        }
      };
      source.addEventListener("job", handleJobEvent);
      source.onerror = () => console.error("ClamShield update event stream disconnected; waiting for reconnect.");
    }

    return () => {
      closeJobStream(appEventSourceRef);
    };
  }, [appUpdateState, appJobId]);

  const signatureUpdateActive = updateState === "running" || status?.isSignatureUpdateRunning;
  const signatureUpdateFailed = updateState === "done" && output.some(line => /error|failed/i.test(line));
  const signatureEvents = output.filter(line =>
    /updated|up to date|up-to-date|download|database/i.test(line) &&
    !/triggering|preparing/i.test(line)
  ).length;
  const signatureProgress = updateState === "done"
    ? 100
    : signatureUpdateActive
      ? Math.min(92, Math.max(15, 25 + signatureEvents * 7))
      : 0;
  const signatureProgressLabel = output.length > 0
    ? output[output.length - 1]
    : "FreshClam is checking signature sources...";
  const saneUpdateActive = saneUpdateState === "running" || status?.isSaneSecurityUpdateRunning;
  const saneUpdateFailed = saneUpdateState === "done" && saneOutput.some(line => /error|failed/i.test(line));
  const saneVerificationEvents = saneOutput.filter(line => /verified|verifying|installed|complete|progress/i.test(line)).length;
  const saneProgress = saneUpdateState === "done"
    ? 100
    : saneUpdateActive
      ? Math.min(94, Math.max(8, 10 + saneVerificationEvents * 4))
      : 0;
  const saneProgressLabel = saneOutput.length > 0
    ? saneOutput[saneOutput.length - 1]
    : "SaneSecurity is preparing its signed database update...";

  return (
    <div className="px-8 max-w-4xl mx-auto space-y-8 pb-20">
      <PageHeader title="Updates" description="Update ClamAV, SecuriteInfo, SaneSecurity, YARA Forge, and ClamShield." />

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-full">
            <Database className="w-8 h-8" />
          </div>
          <div>
            <h3 className="font-semibold text-white text-lg">Virus Definitions</h3>
            <p className="text-slate-400 text-sm">Last checked: Recently</p>
          </div>
        </div>
        <button
          onClick={runUpdate}
          disabled={updateState === "running" || status?.isSignatureUpdateRunning}
          className="flex items-center gap-2 px-6 py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RefreshCw className={`w-5 h-5 ${updateState === "running" || status?.isSignatureUpdateRunning ? "animate-spin" : ""}`} />
          {updateState === "running" || status?.isSignatureUpdateRunning ? "Updating..." : "Update ClamAV"}
        </button>
      </div>

      <div className="bg-slate-900 border border-cyan-500/20 rounded-xl p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div className="flex items-start gap-4 min-w-0">
          <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-full shrink-0">
            <Database className="w-8 h-8" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-semibold text-white text-lg">SecuriteInfo Signatures</h3>
              <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-[11px] border border-slate-700">
                Third-party source
              </span>
            </div>
            <p className="text-slate-400 text-sm mt-1">
              {status?.securiteInfo?.connected
                ? `${status.securiteInfo.plan === "paid" ? "Paid" : "Basic"} · ${status.securiteInfo.installedCount || 0}/${status.securiteInfo.expectedCount || 0} databases · ${status.securiteInfo.lastUpdated ? new Date(status.securiteInfo.lastUpdated).toLocaleString() : "Update required"}`
                : "Not installed"}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {status?.securiteInfo?.connected ? (
            <button
              onClick={runUpdate}
              disabled={updateState === "running" || status?.isSignatureUpdateRunning}
              className="flex items-center gap-2 px-6 py-3 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RefreshCw className={`w-5 h-5 ${updateState === "running" || status?.isSignatureUpdateRunning ? "animate-spin" : ""}`} />
              {updateState === "running" || status?.isSignatureUpdateRunning ? "Updating..." : "Update SecuriteInfo"}
            </button>
          ) : (
            <Link
              to="/"
              className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg font-medium transition-colors"
            >
              <KeyRound className="w-4 h-4" />
              Configure on Dashboard
            </Link>
          )}
        </div>
      </div>

      <div className="bg-slate-900 border border-violet-500/20 rounded-xl p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div className="flex items-start gap-4 min-w-0">
          <div className="p-3 bg-violet-500/10 text-violet-400 rounded-full shrink-0">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-semibold text-white text-lg">SaneSecurity Signatures</h3>
              <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-[11px] border border-slate-700">
                Signed third-party source
              </span>
            </div>
            <p className="text-slate-400 text-sm mt-1">
              {status?.saneSecurity?.connected
                ? `${status.saneSecurity.profile === "complete" ? "Complete" : "Malware Protection"} · ${status.saneSecurity.installedCount || 0}/${status.saneSecurity.expectedCount || 0} databases · ${status.saneSecurity.lastUpdated ? new Date(status.saneSecurity.lastUpdated).toLocaleString() : "Update required"}`
                : "Not installed"}
            </p>
          </div>
        </div>
        {status?.saneSecurity?.connected ? (
          <button
            onClick={runSaneUpdate}
            disabled={saneUpdateActive}
            className="flex items-center gap-2 px-6 py-3 bg-violet-700 hover:bg-violet-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
          >
            <RefreshCw className={`w-5 h-5 ${saneUpdateActive ? "animate-spin" : ""}`} />
            {saneUpdateActive ? "Updating..." : "Update SaneSecurity"}
          </button>
        ) : (
          <Link
            to="/"
            className="inline-flex items-center gap-2 px-6 py-3 bg-violet-700 hover:bg-violet-600 text-white rounded-lg font-medium transition-colors shrink-0"
          >
            <ShieldCheck className="w-4 h-4" />
            Configure on Dashboard
          </Link>
        )}
      </div>

      {(saneUpdateActive || saneUpdateState === "done") && (
        <div className="bg-slate-900 border border-violet-500/20 rounded-xl px-6 py-5 space-y-3">
          <div className="flex items-center justify-between gap-4 text-sm">
            <span className="text-slate-300 font-medium">
              {saneUpdateActive
                ? "Downloading and verifying SaneSecurity databases"
                : saneUpdateFailed
                  ? "SaneSecurity update failed"
                  : "SaneSecurity update complete"}
            </span>
            <span className="text-slate-500 tabular-nums">{saneProgress}%</span>
          </div>
          <div className="h-2.5 overflow-hidden rounded-full bg-slate-800">
            <div
              className={`h-full rounded-full transition-all duration-700 ${
                saneUpdateFailed
                  ? "bg-gradient-to-r from-rose-600 to-orange-400"
                  : "bg-gradient-to-r from-violet-500 to-fuchsia-400"
              } ${saneUpdateActive ? "animate-pulse" : ""}`}
              style={{ width: `${saneProgress}%` }}
            />
          </div>
          <p className="text-xs text-slate-500 truncate">{saneProgressLabel}</p>
        </div>
      )}

      {(signatureUpdateActive || updateState === "done") && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl px-6 py-5 space-y-3">
          <div className="flex items-center justify-between gap-4 text-sm">
            <span className="text-slate-300 font-medium">
              {signatureUpdateActive
                ? "Updating signature databases"
                : signatureUpdateFailed
                  ? "Signature update failed"
                  : "Signature update complete"}
            </span>
            <span className="text-slate-500 tabular-nums">{signatureProgress}%</span>
          </div>
          <div className="h-2.5 overflow-hidden rounded-full bg-slate-800">
            <div
              className={`h-full rounded-full transition-all duration-700 ${
                signatureUpdateFailed
                  ? "bg-gradient-to-r from-rose-600 to-orange-400"
                  : "bg-gradient-to-r from-emerald-500 to-cyan-400"
              } ${
                signatureUpdateActive ? "animate-pulse" : ""
              }`}
              style={{ width: `${signatureProgress}%` }}
            />
          </div>
          <p className="text-xs text-slate-500 truncate">{signatureProgressLabel}</p>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-full">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div>
            <h3 className="font-semibold text-white text-lg">YARA Forge Rules</h3>
            <p className="text-slate-400 text-sm">
              {status?.stats?.lastYaraUpdate
                ? `Last checked: ${new Date(status.stats.lastYaraUpdate).toLocaleString()} · ${status.stats.yaraRuleset} · ${status.stats.yaraRuleCount || 0} rules`
                : "Core rules are enabled by default. Download rules before the first YARA scan."}
            </p>
          </div>
        </div>
        <button
          onClick={runYaraUpdate}
          disabled={yaraUpdateState === "running"}
          className="flex items-center gap-2 px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RefreshCw className={`w-5 h-5 ${yaraUpdateState === "running" ? "animate-spin" : ""}`} />
          {yaraUpdateState === "running" ? "Updating..." : "Update YARA Rules"}
        </button>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 flex items-center justify-between gap-6">
        <div className="flex items-center gap-4 min-w-0">
          <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-full">
            <DownloadCloud className="w-8 h-8" />
          </div>
          <div className="min-w-0">
            <h3 className="font-semibold text-white text-lg">ClamShield Application</h3>
            <p className="text-slate-400 text-sm">
              Installed: {status?.appVersion || "Unknown"}
              {appUpdateInfo?.latestVersion ? ` - Latest: ${appUpdateInfo.latestVersion}` : ""}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {appUpdateState === "available" && (
            <>
              <button
                onClick={skipAppVersion}
                className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors"
              >
                Skip Version
              </button>
              <button
                onClick={disableAppUpdates}
                className="px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors"
              >
                Disable Checks
              </button>
            </>
          )}
          <button
            onClick={appUpdateState === "available" ? installAppUpdate : checkAppUpdate}
            disabled={appUpdateState === "checking" || appUpdateState === "running"}
            className="flex items-center gap-2 px-6 py-3 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <RefreshCw className={`w-5 h-5 ${appUpdateState === "checking" || appUpdateState === "running" ? "animate-spin" : ""}`} />
            {appUpdateState === "checking"
              ? "Checking..."
              : appUpdateState === "running"
                ? "Installing..."
                : appUpdateState === "available"
                  ? "Install Update"
                  : "Check ClamShield"}
          </button>
        </div>
      </div>

      {(updateState === "running" || updateState === "done") && (
        <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-64">
           <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center gap-2">
            <span className="font-mono text-sm text-slate-300 flex items-center gap-2">
              {updateState === "running" ? <Loader2 className="w-4 h-4 animate-spin text-indigo-400" /> : null}
              FreshClam Output
            </span>
          </div>
          <div className="flex-1 p-4 overflow-auto font-mono text-xs text-emerald-400/80 leading-relaxed space-y-1 flex flex-col justify-end">
            {output.map((line, i) => <div key={i}>{line}</div>)}
          </div>
        </div>
      )}

      {(saneUpdateState === "running" || saneUpdateState === "done") && (
        <div className="bg-slate-950 border border-violet-500/20 rounded-xl overflow-hidden shadow-2xl flex flex-col h-64">
          <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center gap-2">
            <span className="font-mono text-sm text-slate-300 flex items-center gap-2">
              {saneUpdateState === "running" ? <Loader2 className="w-4 h-4 animate-spin text-violet-400" /> : null}
              SaneSecurity Output
            </span>
          </div>
          <div className="flex-1 p-4 overflow-auto font-mono text-xs text-violet-300/80 leading-relaxed space-y-1 flex flex-col justify-end">
            {saneOutput.map((line, i) => <div key={i}>{line}</div>)}
          </div>
        </div>
      )}

      {(yaraUpdateState === "running" || yaraUpdateState === "done") && (
        <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-64">
           <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center gap-2">
            <span className="font-mono text-sm text-slate-300 flex items-center gap-2">
              {yaraUpdateState === "running" ? <Loader2 className="w-4 h-4 animate-spin text-indigo-400" /> : null}
              YARA Output
            </span>
          </div>
          <div className="flex-1 p-4 overflow-auto font-mono text-xs text-emerald-400/80 leading-relaxed space-y-1 flex flex-col justify-end">
            {yaraOutput.map((line, i) => <div key={i}>{line}</div>)}
          </div>
        </div>
      )}

      {appUpdateState !== "idle" && (
        <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-64">
           <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center gap-2">
            <span className="font-mono text-sm text-slate-300 flex items-center gap-2">
              {appUpdateState === "checking" || appUpdateState === "running" ? <Loader2 className="w-4 h-4 animate-spin text-cyan-400" /> : null}
              ClamShield Output
            </span>
          </div>
          <div className="flex-1 p-4 overflow-auto font-mono text-xs text-emerald-400/80 leading-relaxed space-y-1 flex flex-col justify-end">
            {appOutput.map((line, i) => <div key={i}>{line}</div>)}
          </div>
        </div>
      )}
    </div>
  );
}
