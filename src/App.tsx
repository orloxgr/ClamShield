import { t, localizeText, useLanguage } from "./lib/i18n";
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router";
import { Shield, Search, Activity, Archive, RefreshCw, History, Settings, Loader2, Download, AlertTriangle, ShieldCheck, FileWarning, CalendarClock, Globe2 } from "lucide-react";
import Dashboard from "../modules/dashboard/ui/Dashboard";
import Scan from "../modules/on-demand/ui/Scan";
import ResultsPage from "../modules/results/ui/Results";
import ShieldSettings from "../modules/shield/ui/ShieldSettings";
import Quarantine from "../modules/quarantine/ui/Quarantine";
import Updates from "../modules/updates/ui/Updates";
import HistoryPage from "../modules/history/ui/History";
import SettingsPage from "../modules/settings/ui/Settings";
import { reportUiFailure } from "./lib/uiDiagnostics";
import StartupShell from "./components/StartupShell";
import ExceptionsPage from "../modules/exceptions/ui/Exceptions";
import ScheduledScanner from "../modules/scheduler/ui/ScheduledScanner";
import DnsProtection from "../modules/dns-protection/ui/DnsProtection";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { ScanProvider, useScan } from "../modules/on-demand/ui/ScanContext";
import React, { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
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
    }).catch(() => { });
}
function normalizeSetupLogLines(lines: unknown[]) {
    return lines
        .flatMap(line => String(line ?? "").split(/\r\n|\n|\r/g))
        .map(line => line.trim())
        .filter(Boolean);
}
function SetupWizard({ status, onComplete }: {
    status: any;
    onComplete: () => void;
}) {
    useLanguage();
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
                fetch("/api/accept-eula", { method: "POST" }).then(onComplete).catch(() => { });
            }
        }
        else {
            setEulaAccepted(false);
        }
    }, [status?.settings?.eulaAccepted]);
    // The background updater can install the signatures while this screen is open; re-check so setup moves on.
    useEffect(() => {
        if (!eulaAccepted || !needsDb || installing || updating || updatingYara)
            return;
        const iv = setInterval(onComplete, 5000);
        return () => clearInterval(iv);
    }, [eulaAccepted, needsDb, installing, updating, updatingYara]);
    if (eulaAccepted && !needsEngine && !needsDb && !needsYara)
        return null;
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
            const nextProgress = res.installProgress || "Installing...";
            setProgressMsg(nextProgress);
            if (nextProgress) {
                setSetupLogs(prev => {
                    if (prev[prev.length - 1] === nextProgress)
                        return prev;
                    return [...prev, nextProgress].slice(-12);
                });
            }
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
                    }
                    else {
                        setSetupError("Virus definitions did not install. FreshClam failed or no database files were created.");
                    }
                }
            }, 2000);
        }
        else {
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
                    }
                    else {
                        setSetupError("YARA setup failed. Check the log output below.");
                    }
                }
            }, 1000);
        }
        else {
            setUpdatingYara(false);
            setSetupError("YARA setup did not return a job id.");
        }
    };
    return (<div className="fixed inset-0 z-50 bg-slate-950/90 flex items-center justify-center backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-8 shadow-2xl">
        <div className="flex flex-col items-center text-center space-y-6">
          <div className="w-16 h-16 bg-indigo-500/10 rounded-full flex items-center justify-center mb-2">
            <img src="/shield.svg" width={32} height={32} alt="" aria-hidden="true" className="shrink-0"/>
          </div>
          
          <div>
            <h2 className="text-2xl font-bold text-white mb-2">{t("navigation.welcome_to_clamshield")}</h2>
            <p className="text-slate-400">{localizeText(!eulaAccepted ? "Please read the terms below." : "Let's get your antivirus engine ready.")}</p>
          </div>

          {localizeText(setupError && (<div className="w-full bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-left">
              <p className="text-sm font-semibold text-red-300 mb-1">{t("navigation.setup_could_not_continue")}</p>
              <p className="text-xs text-red-200/80">{localizeText(setupError)}</p>
            </div>))}

          {localizeText(!eulaAccepted ? (<div className="w-full space-y-4">
                <div className="bg-slate-950 rounded-lg p-4 border border-slate-800 text-left h-48 overflow-auto text-sm text-slate-300">
                  <p className="font-semibold mb-2">{t("navigation.software_notice_and_disclaimer")}</p>
                  <p className="mb-2"><strong>{t("navigation.clamshield_is_a_windows_user_interface_and_orchestration_layer_fo")}</strong>{t("navigation.it_manages_and_invokes_clamav_for_signature_based_scanning_and_ya")}</p>
                  <p className="mb-2">{t("navigation.no_security_product_can_detect_block_or_remove_every_threat_false")}</p>
                  <p className="mb-2">{t("navigation.if_enabled_in_settings_clamshield_may_attempt_to_pause_or_manage")}</p>
                  <p className="mb-2">{t("navigation.clamshield_is_provided_as_is_and_without_warranties_to_the_maximu")}</p>
                  <p className="mb-2">{t("navigation.clamav_is_provided_by_cisco_and_licensed_under_gpl_2_0_yara_is_a")}</p>
                  <p>{t("navigation.by_clicking_i_agree_you_confirm_that_you_have_read_and_accepted_t")}</p>
                </div>
                <button onClick={acceptEula} className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-white font-medium transition-colors">{t("navigation.i_agree")}</button>
             </div>) : (installing || updating || updatingYara) ? (<div className="w-full space-y-4 py-4">
              <Loader2 className="w-8 h-8 animate-spin text-indigo-500 mx-auto"/>
              {localizeText(setupLogs.length > 0 ? (<div className="w-full bg-slate-950 rounded-lg border border-slate-800 p-3 text-left max-h-40 overflow-auto font-mono text-xs text-slate-300 space-y-1">
                  {localizeText(setupLogs.map((line, index) => (<div key={`${index}-${line}`} className="whitespace-pre-wrap break-words">{localizeText(line)}</div>)))}
                </div>) : (<p className="text-sm text-indigo-300 animate-pulse whitespace-pre-wrap break-words">{localizeText(progressMsg)}</p>))}
            </div>) : (<div className="w-full space-y-4">
              {localizeText(needsEngine ? (<div className="bg-slate-950 rounded-lg p-4 border border-slate-800 text-left">
                  <h3 className="font-semibold text-slate-200 mb-1 flex items-center gap-2">
                    <Download className="w-4 h-4 text-indigo-400"/>{t("navigation.1_install_engine")}</h3>
                  <p className="text-sm text-slate-400 mb-4">{t("navigation.clamav_engine_is_missing_we_need_to_download_it_first")}</p>
                  <button onClick={doInstall} className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-white font-medium transition-colors">{t("navigation.download_install")}</button>
                </div>) : needsDb ? (<div className="bg-slate-950 rounded-lg p-4 border border-slate-800 text-left">
                  <h3 className="font-semibold text-slate-200 mb-1 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400"/>{t("navigation.2_update_database")}</h3>
                  <p className="text-sm text-slate-400 mb-4">{t("navigation.you_have_the_engine_but_no_virus_definitions_yet_download_the_lat")}</p>
                  <button onClick={doUpdate} className="w-full py-2 bg-amber-600 hover:bg-amber-500 rounded-lg text-white font-medium transition-colors">{t("navigation.update_definitions")}</button>
                </div>) : needsYara ? (<div className="bg-slate-950 rounded-lg p-4 border border-slate-800 text-left">
                  <h3 className="font-semibold text-slate-200 mb-1 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400"/>{t("navigation.3_install_yara_core")}</h3>
                  <p className="text-sm text-slate-400 mb-4">{t("navigation.yara_detection_is_enabled_by_default_download_the_yara_engine_and")}</p>
                  <button onClick={doYaraUpdate} className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-white font-medium transition-colors">{t("navigation.download_yara_core")}</button>
                </div>) : null)}
            </div>))}
        </div>
      </div>
    </div>);
}
function Sidebar({ status }: {
    status?: any;
}) {
    useLanguage();
    const { scanState } = useScan();
    const navItems = [
        { name: "Dashboard", path: "/", icon: Activity },
        { name: "Shield", path: "/shield", icon: Shield },
        { name: "On-Demand Scan", path: "/scan", icon: Search },
        { name: "Scheduled Scanner", path: "/scheduled-scanner", icon: CalendarClock },
        { name: "Results", path: "/results", icon: FileWarning },
        { name: "Exceptions", path: "/exceptions", icon: ShieldCheck },
        { name: "Quarantine", path: "/quarantine", icon: Archive },
        { name: "DNS Protection", path: "/dns-protection", icon: Globe2 },
        { name: "Updates", path: "/updates", icon: RefreshCw },
        { name: "History", path: "/history", icon: History },
        { name: "Settings", path: "/settings", icon: Settings },
    ];
    return (<div className="w-64 shrink-0 min-w-0 bg-slate-900 border-r border-slate-800 flex flex-col h-full text-slate-300">
      <div className="p-6 flex items-center gap-3 border-b border-slate-800">
        <img src="/shield.svg" width={32} height={32} alt="" aria-hidden="true" className="shrink-0"/>
        <h1 className="text-xl font-bold text-white tracking-wide">ClamShield</h1>
      </div>
      <nav className="min-h-0 flex-1 overflow-y-auto p-4 space-y-1">
        {localizeText(navItems.map((item) => (<NavLink key={item.path} to={item.path} className={({ isActive }) => cn("flex items-center justify-between px-3 py-2.5 rounded-md font-medium transition-colors", isActive
                ? "bg-emerald-500/10 text-emerald-400"
                : "hover:bg-slate-800 hover:text-white")}>
            <div className="min-w-0 flex-1 flex items-center gap-3">
              <item.icon className="w-5 h-5 shrink-0"/>
              <span className="min-w-0 [overflow-wrap:anywhere]">{localizeText(item.name)}</span>
            </div>
            {localizeText(item.path === "/scan" && scanState === "running" && (<Loader2 className="w-4 h-4 animate-spin text-emerald-400"/>))}
          </NavLink>)))}
      </nav>
      <div className="p-4 border-t border-slate-800 text-xs text-slate-500 flex flex-col gap-1">
        <div className="flex justify-between items-center">
          <span>{t("navigation.powered_by_clamav")}</span>
          <span className="bg-slate-900 border border-slate-700 px-2 py-1 rounded text-[10px]">
            v{localizeText(status?.appVersion || "—")}
          </span>
        </div>
        <span className="text-slate-600 block mt-1">{t("navigation.made_by_byron_iniotakis")}</span>
      </div>
    </div>);
}
export default function App() {
    useLanguage();
    const [status, setStatus] = useState<any>(null);
    const [startupRetrying, setStartupRetrying] = useState(false);
    const startupErrorRef = useRef("The local service did not return protection status.");
    const statusRequestRef = useRef<Promise<boolean> | null>(null);
    const fetchStatus = useCallback(() => {
        if (statusRequestRef.current)
            return statusRequestRef.current;
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 10000);
        const request = fetch("/api/status", { cache: "no-store", signal: controller.signal }).then(async (response) => {
            if (!response.ok)
                throw new Error(`Status request failed (HTTP ${response.status}).`);
            const data = await response.json();
            setStatus(data);
            setStartupRetrying(false);
            return true;
        }).catch((error: any) => {
            const message = error.name === "AbortError" ? "Protection status request timed out after 10 seconds." : error.message;
            if (startupErrorRef.current !== message)
                sendClientLog("error", "Initial protection status unavailable", { message });
            startupErrorRef.current = message;
            setStartupRetrying(true);
            return false;
        }).finally(() => { window.clearTimeout(timeout); statusRequestRef.current = null; });
        statusRequestRef.current = request;
        return request;
    }, []);
    useEffect(() => {
        if (status)
            return;
        const timer = window.setTimeout(() => reportUiFailure({ stage: "Loading protection status", code: "STATUS_UNAVAILABLE", message: startupErrorRef.current }), 45000);
        return () => window.clearTimeout(timer);
    }, [status]);
    useEffect(() => {
        let stopped = false;
        let timer: number | undefined;
        const load = async () => {
            const loaded = await fetchStatus();
            if (!loaded && !stopped)
                timer = window.setTimeout(load, 2000);
        };
        load();
        return () => {
            stopped = true;
            if (timer !== undefined)
                window.clearTimeout(timer);
        };
    }, [fetchStatus]);
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
        return () => {
            window.removeEventListener("error", handleError);
            window.removeEventListener("unhandledrejection", handleRejection);
        };
    }, []);
    if (!status) {
        return <StartupShell retrying={startupRetrying} onRetry={fetchStatus}/>;
    }
    return (<ScanProvider>
        <Router>
          <div className="flex h-screen bg-slate-950 text-slate-200 selection:bg-emerald-500/30">
            <SetupWizard status={status} onComplete={fetchStatus}/>
            <Sidebar status={status}/>
            <main className="flex-1 overflow-auto relative">
              <Routes>
                <Route path="/" element={<Dashboard />}/>
                <Route path="/scan" element={<Scan />}/>
                <Route path="/scheduled-scanner" element={<ScheduledScanner />}/>
                <Route path="/results" element={<ResultsPage />}/>
                <Route path="/shield" element={<ShieldSettings />}/>
                <Route path="/exceptions" element={<ExceptionsPage />}/>
                <Route path="/quarantine" element={<Quarantine />}/>
                <Route path="/dns-protection" element={<DnsProtection />}/>
                <Route path="/updates" element={<Updates />}/>
                <Route path="/history" element={<HistoryPage />}/>
                <Route path="/settings" element={<SettingsPage />}/>
              </Routes>
            </main>
          </div>
        </Router>
    </ScanProvider>);
}
