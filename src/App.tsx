/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import { Shield, Search, Activity, Archive, RefreshCw, History, Settings, Loader2, Download, AlertTriangle, ShieldCheck, FileWarning, CalendarClock, Globe2 } from "lucide-react";
import Dashboard from "./pages/Dashboard";
import Scan from "./pages/Scan";
import ResultsPage from "./pages/Results";
import ShieldSettings from "./pages/ShieldSettings";
import Quarantine from "./pages/Quarantine";
import Updates from "./pages/Updates";
import HistoryPage from "./pages/History";
import SettingsPage from "./pages/Settings";
import ExceptionsPage from "./pages/Exceptions";
import ScheduledScanner from "./pages/ScheduledScanner";
import DnsProtection from "./pages/DnsProtection";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { ScanProvider, useScan } from "./context/ScanContext";
import React, { type ReactNode, useEffect, useState } from "react";

// Tailwind class merger utility
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

function sendClientLog(level: "error" | "warn" | "info" | "debug", message: string, details?: any) {
  fetch("/api/client-log", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ level, message, details }),
    keepalive: true
  }).catch(() => {});
}

function normalizeSetupLogLines(lines: unknown[]) {
  return lines
    .flatMap(line => String(line ?? "").split(/\r\n|\n|\r/g))
    .map(line => line.trim())
    .filter(Boolean);
}

class ErrorBoundary extends React.Component<{ children: ReactNode }, { error: Error | null }> {
  constructor(props: { children: ReactNode }) {
    super(props);
  }

  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: any) {
    console.error("ClamShield UI crashed:", error, info);
    sendClientLog("error", "ClamShield UI crashed", {
      message: error.message,
      stack: error.stack,
      componentStack: info?.componentStack
    });
  }

  render() {
    if (!this.state.error) return (this as any).props.children;

    return (
      <div className="h-screen bg-slate-950 text-slate-200 flex items-center justify-center p-8">
        <div className="max-w-xl w-full bg-slate-900 border border-red-500/30 rounded-xl p-6 shadow-2xl">
          <div className="flex items-center gap-3 text-red-400 mb-3">
            <AlertTriangle className="w-5 h-5" />
            <h1 className="font-semibold">ClamShield UI recovered from an error</h1>
          </div>
          <p className="text-sm text-slate-400 mb-4">
            The scan service can keep running in the background. Reload the interface to continue.
          </p>
          <pre className="max-h-40 overflow-auto rounded bg-slate-950 border border-slate-800 p-3 text-xs text-slate-400 mb-4">
            {this.state.error.message}
          </pre>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium"
          >
            Reload UI
          </button>
        </div>
      </div>
    );
  }
}

function SetupWizard({ status, onComplete }: { status: any, onComplete: () => void }) {
  const [eulaAccepted, setEulaAccepted] = useState(Boolean(status?.settings?.eulaAccepted));
  const [installing, setInstalling] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [updatingYara, setUpdatingYara] = useState(false);
  const [progressMsg, setProgressMsg] = useState("");
  const [setupError, setSetupError] = useState("");
  const [setupLogs, setSetupLogs] = useState<string[]>([]);

  const needsEngine = !status.hasEngine && !status.isSimulated;
  const needsDb = !status.hasDb && !status.isSimulated;
  const needsYara = status.settings?.yaraEnabled !== false && (!status.hasYaraEngine || !status.hasYaraRules) && !status.isSimulated;

  useEffect(() => {
    const storedAcceptance = localStorage.getItem("clamshield_notice_2026-06-25") === "true";
    if (status?.settings?.eulaAccepted || storedAcceptance) {
      setEulaAccepted(true);
      if (!status?.settings?.eulaAccepted && storedAcceptance) {
        fetch("/api/accept-eula", { method: "POST" }).then(onComplete).catch(() => {});
      }
    } else {
      setEulaAccepted(false);
    }
  }, [status?.settings?.eulaAccepted]);

  if (eulaAccepted && !needsEngine && !needsDb && !needsYara) return null;

  const acceptEula = async () => {
    localStorage.setItem("clamshield_notice_2026-06-25", "true");
    await fetch("/api/accept-eula", { method: "POST" });
    setEulaAccepted(true);
    if (!needsEngine && !needsDb && !needsYara) {
      onComplete();
    }
  };

  const doInstall = async () => {
    setInstalling(true);
    setSetupError("");
    setSetupLogs([]);
    setProgressMsg("Downloading and extracting ClamAV engine...");
    const startRes = await fetch("/api/install-engine", { method: "POST" });
    const startData = await startRes.json().catch(() => ({}));
    if (!startRes.ok) {
      setInstalling(false);
      setSetupError(startData.error || "Failed to start ClamAV engine installation.");
      return;
    }
    
    // Poll for status
    const iv = setInterval(async () => {
      const res = await fetch("/api/status").then(r => r.json());
      setProgressMsg(res.installProgress || "Installing...");
      if (!res.isInstalling && String(res.installProgress || "").startsWith("Error:")) {
        clearInterval(iv);
        setInstalling(false);
        setSetupError(res.installProgress);
        return;
      }
      if (!res.isInstalling && !res.hasEngine) {
        clearInterval(iv);
        setInstalling(false);
        setSetupError("ClamAV engine installation finished, but the required executables were not found.");
        return;
      }
      if (!res.isInstalling && res.hasEngine) {
        clearInterval(iv);
        setInstalling(false);
        onComplete();
      }
    }, 2000);
  };

  const doUpdate = async () => {
    setUpdating(true);
    setSetupError("");
    setSetupLogs([]);
    setProgressMsg("Downloading initial virus definitions (this may take a few minutes)...");
    const res = await fetch("/api/update", { method: "POST" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setUpdating(false);
      setSetupError(data.error || "Failed to start virus definition update.");
      return;
    }
    if (data.jobId) {
      const iv = setInterval(async () => {
        const statusRes = await fetch(`/api/scan/${data.jobId}`).then(r => r.json());
        if (Array.isArray(statusRes.logs) && statusRes.logs.length > 0) {
          const nextLogs = normalizeSetupLogLines(statusRes.logs);
          if (nextLogs.length > 0) {
            setSetupLogs(prev => [...prev, ...nextLogs].slice(-12));
            setProgressMsg(nextLogs[nextLogs.length - 1]);
          }
        }
        if (statusRes.status === "done") {
          clearInterval(iv);
          setUpdating(false);
          const latestStatus = await fetch("/api/status").then(r => r.json()).catch(() => null);
          if (Number(statusRes.result || 0) === 0 && latestStatus?.hasDb) {
            onComplete();
          } else {
            setSetupError("Virus definitions did not install. FreshClam failed or no database files were created.");
          }
        }
      }, 2000);
    } else {
      setUpdating(false);
      setSetupError("FreshClam did not return a job id.");
    }
  };

  const doYaraUpdate = async () => {
    setUpdatingYara(true);
    setSetupError("");
    setSetupLogs([]);
    setProgressMsg("Downloading YARA engine and Core rules...");
    const response = await fetch("/api/update-yara", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ruleset: "core" })
    });
    const res = await response.json().catch(() => ({}));
    if (!response.ok) {
      setUpdatingYara(false);
      setSetupError(res.error || "Failed to start YARA setup.");
      return;
    }
    if (res.jobId) {
      const iv = setInterval(async () => {
        const statusRes = await fetch(`/api/scan/${res.jobId}`).then(r => r.json());
        if (Array.isArray(statusRes.logs) && statusRes.logs.length > 0) {
          const nextLogs = normalizeSetupLogLines(statusRes.logs);
          if (nextLogs.length > 0) {
            setSetupLogs(prev => [...prev, ...nextLogs].slice(-12));
            setProgressMsg(nextLogs[nextLogs.length - 1]);
          }
        }
        if (statusRes.status === "done") {
          clearInterval(iv);
          setUpdatingYara(false);
          if (Number(statusRes.result || 0) === 0) {
            onComplete();
          } else {
            setSetupError("YARA setup failed. Check the log output below.");
          }
        }
      }, 1000);
    } else {
      setUpdatingYara(false);
      setSetupError("YARA setup did not return a job id.");
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/90 flex items-center justify-center backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-8 shadow-2xl">
        <div className="flex flex-col items-center text-center space-y-6">
          <div className="w-16 h-16 bg-indigo-500/10 rounded-full flex items-center justify-center mb-2">
            <Shield className="w-8 h-8 text-indigo-400" />
          </div>
          
          <div>
            <h2 className="text-2xl font-bold text-white mb-2">Welcome to ClamShield</h2>
            <p className="text-slate-400">{!eulaAccepted ? "Please read the terms below." : "Let's get your antivirus engine ready."}</p>
          </div>

          {setupError && (
            <div className="w-full bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-left">
              <p className="text-sm font-semibold text-red-300 mb-1">Setup could not continue</p>
              <p className="text-xs text-red-200/80">{setupError}</p>
            </div>
          )}

          {!eulaAccepted ? (
             <div className="w-full space-y-4">
                <div className="bg-slate-950 rounded-lg p-4 border border-slate-800 text-left h-48 overflow-auto text-sm text-slate-300">
                  <p className="font-semibold mb-2">Software Notice and Disclaimer</p>
                  <p className="mb-2"><strong>ClamShield is a Windows user interface and orchestration layer for third-party malware detection tools.</strong> It manages and invokes ClamAV for signature-based scanning and YARA for rule-based pattern matching. ClamShield is not an independent antivirus engine or a complete endpoint security suite.</p>
                  <p className="mb-2">No security product can detect, block, or remove every threat. False negatives, false positives, outdated signatures, unavailable engines, configuration choices, encrypted content, unsupported formats, and malware designed to evade analysis may affect results.</p>
                  <p className="mb-2">If enabled in Settings, ClamShield may attempt to pause or manage Microsoft Defender. Reducing or disabling another security product may reduce overall protection. You are responsible for reviewing this setting and maintaining appropriate security controls and backups.</p>
                  <p className="mb-2">ClamShield is provided "as is" and without warranties, to the maximum extent permitted by applicable law. Liability is limited to the maximum extent permitted by applicable law. Nothing in this notice excludes rights or liabilities that cannot legally be excluded.</p>
                  <p className="mb-2">ClamAV is provided by Cisco and licensed under GPL-2.0. YARA is a third-party pattern-matching tool. Their names and trademarks belong to their respective owners. ClamShield is not endorsed by or affiliated with those projects or their owners.</p>
                  <p>By clicking "I Agree", you confirm that you have read and accepted this notice.</p>
                </div>
                <button 
                  onClick={acceptEula}
                  className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-white font-medium transition-colors"
                >
                  I Agree
                </button>
             </div>
          ) : (installing || updating || updatingYara) ? (
            <div className="w-full space-y-4 py-4">
              <Loader2 className="w-8 h-8 animate-spin text-indigo-500 mx-auto" />
              {setupLogs.length > 0 ? (
                <div className="w-full bg-slate-950 rounded-lg border border-slate-800 p-3 text-left max-h-40 overflow-auto font-mono text-xs text-slate-300 space-y-1">
                  {setupLogs.map((line, index) => (
                    <div key={`${index}-${line}`} className="whitespace-pre-wrap break-words">{line}</div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-indigo-300 animate-pulse whitespace-pre-wrap break-words">{progressMsg}</p>
              )}
            </div>
          ) : (
             <div className="w-full space-y-4">
              {needsEngine ? (
                <div className="bg-slate-950 rounded-lg p-4 border border-slate-800 text-left">
                  <h3 className="font-semibold text-slate-200 mb-1 flex items-center gap-2">
                    <Download className="w-4 h-4 text-indigo-400" />
                    1. Install Engine
                  </h3>
                  <p className="text-sm text-slate-400 mb-4">ClamAV engine is missing. We need to download it first.</p>
                  <button 
                    onClick={doInstall}
                    className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-white font-medium transition-colors"
                  >
                    Download & Install
                  </button>
                </div>
              ) : needsDb ? (
                <div className="bg-slate-950 rounded-lg p-4 border border-slate-800 text-left">
                  <h3 className="font-semibold text-slate-200 mb-1 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    2. Update Database
                  </h3>
                  <p className="text-sm text-slate-400 mb-4">You have the engine, but no virus definitions yet. Download the latest signatures.</p>
                  <button 
                    onClick={doUpdate}
                    className="w-full py-2 bg-amber-600 hover:bg-amber-500 rounded-lg text-white font-medium transition-colors"
                  >
                    Update Definitions
                  </button>
                </div>
              ) : needsYara ? (
                <div className="bg-slate-950 rounded-lg p-4 border border-slate-800 text-left">
                  <h3 className="font-semibold text-slate-200 mb-1 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    3. Install YARA Core
                  </h3>
                  <p className="text-sm text-slate-400 mb-4">
                    YARA detection is enabled by default. Download the YARA engine and Core rules before first use.
                  </p>
                  <button
                    onClick={doYaraUpdate}
                    className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-white font-medium transition-colors"
                  >
                    Download YARA Core
                  </button>
                </div>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Sidebar({ status }: { status?: any }) {
  const { scanState } = useScan();
  const navItems = [
    { name: "Dashboard", path: "/", icon: Activity },
    { name: "On-Demand Scan", path: "/scan", icon: Search },
    { name: "Scheduled Scanner", path: "/scheduled-scanner", icon: CalendarClock },
    { name: "Results", path: "/results", icon: FileWarning },
    { name: "Shield", path: "/shield", icon: Shield },
    { name: "Exceptions", path: "/exceptions", icon: ShieldCheck },
    { name: "Quarantine", path: "/quarantine", icon: Archive },
    { name: "DNS Protection", path: "/dns-protection", icon: Globe2 },
    { name: "Updates", path: "/updates", icon: RefreshCw },
    { name: "History", path: "/history", icon: History },
    { name: "Settings", path: "/settings", icon: Settings },
  ];

  return (
    <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-full text-slate-300">
      <div className="p-6 flex items-center gap-3 border-b border-slate-800">
        <Shield className="w-8 h-8 text-emerald-500" />
        <h1 className="text-xl font-bold text-white tracking-wide">ClamShield</h1>
      </div>
      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              cn(
                "flex items-center justify-between px-3 py-2.5 rounded-md font-medium transition-colors",
                isActive
                  ? "bg-emerald-500/10 text-emerald-400"
                  : "hover:bg-slate-800 hover:text-white"
              )
            }
          >
            <div className="flex items-center gap-3">
              <item.icon className="w-5 h-5" />
              {item.name}
            </div>
            {item.path === "/scan" && scanState === "running" && (
              <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
            )}
          </NavLink>
        ))}
      </nav>
      <div className="p-4 border-t border-slate-800 text-xs text-slate-500 flex flex-col gap-1">
        <div className="flex justify-between items-center">
          <span>Powered by ClamAV®</span>
          <span className="bg-slate-900 border border-slate-700 px-2 py-1 rounded text-[10px]">
            v{status?.appVersion || "—"}
          </span>
        </div>
        <span className="text-slate-600 block mt-1">Made by Byron Iniotakis</span>
      </div>
    </div>
  );
}

export default function App() {
  const [status, setStatus] = useState<any>(null);

  const fetchStatus = () => {
    fetch("/api/status").then(r => r.json()).then(setStatus).catch(error => {
      console.error("Failed to load ClamShield status:", error);
      sendClientLog("error", "Failed to load ClamShield status", {
        message: error?.message,
        stack: error?.stack
      });
    });
  };

  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      sendClientLog("error", "Unhandled renderer error", {
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        stack: event.error?.stack
      });
    };
    const handleRejection = (event: PromiseRejectionEvent) => {
      const reason: any = event.reason;
      sendClientLog("error", "Unhandled renderer promise rejection", {
        message: reason?.message || String(reason),
        stack: reason?.stack
      });
    };
    window.addEventListener("error", handleError);
    window.addEventListener("unhandledrejection", handleRejection);
    fetchStatus();
    return () => {
      window.removeEventListener("error", handleError);
      window.removeEventListener("unhandledrejection", handleRejection);
    };
  }, []);

  if (!status) {
    return <div className="h-screen flex items-center justify-center bg-slate-950"><Loader2 className="w-8 h-8 animate-spin text-indigo-500" /></div>;
  }

  return (
    <ScanProvider>
      <ErrorBoundary>
        <Router>
          <div className="flex h-screen bg-slate-950 text-slate-200 selection:bg-emerald-500/30">
            <SetupWizard status={status} onComplete={fetchStatus} />
            <Sidebar status={status} />
            <main className="flex-1 overflow-auto relative">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/scan" element={<Scan />} />
                <Route path="/scheduled-scanner" element={<ScheduledScanner />} />
                <Route path="/results" element={<ResultsPage />} />
                <Route path="/shield" element={<ShieldSettings />} />
                <Route path="/exceptions" element={<ExceptionsPage />} />
                <Route path="/quarantine" element={<Quarantine />} />
                <Route path="/dns-protection" element={<DnsProtection />} />
                <Route path="/updates" element={<Updates />} />
                <Route path="/history" element={<HistoryPage />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Routes>
            </main>
          </div>
        </Router>
      </ErrorBoundary>
    </ScanProvider>
  );
}
