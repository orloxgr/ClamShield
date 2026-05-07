/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import { Shield, Search, Activity, Archive, RefreshCw, History, Settings, Loader2, Download, AlertTriangle, ShieldCheck, FileWarning } from "lucide-react";
import Dashboard from "./pages/Dashboard";
import Scan from "./pages/Scan";
import ResultsPage from "./pages/Results";
import ShieldSettings from "./pages/ShieldSettings";
import Quarantine from "./pages/Quarantine";
import Updates from "./pages/Updates";
import HistoryPage from "./pages/History";
import SettingsPage from "./pages/Settings";
import ExceptionsPage from "./pages/Exceptions";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { ScanProvider, useScan } from "./context/ScanContext";
import React, { type ReactNode, useEffect, useState } from "react";

// Tailwind class merger utility
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
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
  const [progressMsg, setProgressMsg] = useState("");

  const needsEngine = !status.hasEngine && !status.isSimulated;
  const needsDb = !status.hasDb && !status.isSimulated;

  useEffect(() => {
    const storedAcceptance = localStorage.getItem("clamshield_eula") === "true";
    if (status?.settings?.eulaAccepted || storedAcceptance) {
      setEulaAccepted(true);
      if (!status?.settings?.eulaAccepted && storedAcceptance) {
        fetch("/api/accept-eula", { method: "POST" }).then(onComplete).catch(() => {});
      }
    } else {
      setEulaAccepted(false);
    }
  }, [status?.settings?.eulaAccepted]);

  if (eulaAccepted && !needsEngine && !needsDb) return null;

  const acceptEula = async () => {
    localStorage.setItem("clamshield_eula", "true");
    await fetch("/api/accept-eula", { method: "POST" });
    setEulaAccepted(true);
    if (!needsEngine && !needsDb) {
      onComplete();
    }
  };

  const doInstall = async () => {
    setInstalling(true);
    setProgressMsg("Downloading and extracting ClamAV engine...");
    fetch("/api/install-engine", { method: "POST" });
    
    // Poll for status
    const iv = setInterval(async () => {
      const res = await fetch("/api/status").then(r => r.json());
      setProgressMsg(res.installProgress || "Installing...");
      if (!res.isInstalling && res.hasEngine) {
        clearInterval(iv);
        setInstalling(false);
        onComplete();
      }
    }, 2000);
  };

  const doUpdate = async () => {
    setUpdating(true);
    setProgressMsg("Downloading initial virus definitions (this may take a few minutes)...");
    const res = await fetch("/api/update", { method: "POST" }).then(r => r.json());
    if (res.jobId) {
      const iv = setInterval(async () => {
        const statusRes = await fetch(`/api/scan/${res.jobId}`).then(r => r.json());
        if (statusRes.status === "done") {
          clearInterval(iv);
          setUpdating(false);
          onComplete();
        }
      }, 2000);
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

          {!eulaAccepted ? (
             <div className="w-full space-y-4">
                <div className="bg-slate-950 rounded-lg p-4 border border-slate-800 text-left h-48 overflow-auto text-sm text-slate-300">
                  <p className="font-semibold mb-2">Terms of Service and Disclaimer</p>
                  <p className="mb-2">This application (ClamShield) downloads, wraps, and utilizes the ClamAV® engine.</p>
                  <p className="mb-2"><strong>ClamAV® is licensed under the GNU General Public License v2 (GPL-2.0).</strong></p>
                  <p className="mb-2">This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.</p>
                  <p>By clicking "I Agree", you acknowledge and agree to these terms, and agree to abide by the ClamAV® licensing terms.</p>
                </div>
                <button 
                  onClick={acceptEula}
                  className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-white font-medium transition-colors"
                >
                  I Agree
                </button>
             </div>
          ) : (installing || updating) ? (
            <div className="w-full space-y-4 py-4">
              <Loader2 className="w-8 h-8 animate-spin text-indigo-500 mx-auto" />
              <p className="text-sm text-indigo-300 animate-pulse">{progressMsg}</p>
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
    { name: "Scan", path: "/scan", icon: Search },
    { name: "Results", path: "/results", icon: FileWarning },
    { name: "Shield", path: "/shield", icon: Shield },
    { name: "Exceptions", path: "/exceptions", icon: ShieldCheck },
    { name: "Quarantine", path: "/quarantine", icon: Archive },
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
            v{status?.appVersion || "1.0.14"}
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
    fetch("/api/status").then(r => r.json()).then(setStatus);
  };

  useEffect(() => {
    fetchStatus();
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
                <Route path="/results" element={<ResultsPage />} />
                <Route path="/shield" element={<ShieldSettings />} />
                <Route path="/exceptions" element={<ExceptionsPage />} />
                <Route path="/quarantine" element={<Quarantine />} />
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
