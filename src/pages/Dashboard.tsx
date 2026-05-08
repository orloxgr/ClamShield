import { useEffect, useState } from "react";
import { Shield, ShieldAlert, Cpu, Database, Clock, Activity, FileWarning, DownloadCloud, Loader2 } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

export default function Dashboard() {
  const [status, setStatus] = useState<any>(null);

  const fetchStatus = () => {
    fetch("/api/status").then(r => r.json()).then(setStatus);
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  const installEngine = async () => {
    try {
      await fetch("/api/install-engine", { method: "POST" });
      fetchStatus();
    } catch (e) {
      console.error(e);
    }
  };

  if (!status) return <div className="p-8">Loading...</div>;

  const isProtected = status.settings?.shieldEnabled && !status.isSimulated;

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      <header>
        <h1 className="text-3xl font-bold text-white mb-2">Dashboard</h1>
        <p className="text-slate-400">System protection overview</p>
      </header>

      {/* Main Status card */}
      <div className={`p-8 rounded-2xl border flex items-center gap-6 ${isProtected ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-red-500/10 border-red-500/20'}`}>
        <div className={`p-4 rounded-full ${isProtected ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
          {isProtected ? <Shield className="w-12 h-12" /> : <ShieldAlert className="w-12 h-12" />}
        </div>
        <div className="flex-1">
          <h2 className="text-2xl font-semibold text-white mb-1">
            {isProtected ? "You're Protected" : status.isSimulated ? "Engine Missing" : "Shield is OFF"}
          </h2>
          <p className={isProtected ? "text-emerald-400/80" : "text-red-400/80"}>
            {isProtected 
              ? "Your system is being monitored in real-time." 
              : status.isSimulated 
                ? "ClamAV engine is not installed. Background scanning is disabled." 
                : "Real-time protection is disabled. Enable it in Shield settings."}
          </p>
        </div>
      </div>

      {status.isSimulated && status.platform === "win32" && (
        <div className="p-6 bg-indigo-500/10 border border-indigo-500/20 rounded-xl flex items-center justify-between">
            <div>
              <h3 className="font-semibold text-indigo-300 text-lg flex items-center gap-2">
                <DownloadCloud className="w-5 h-5" />
                Download Windows Engine
              </h3>
              <p className="text-slate-400 text-sm mt-1">
                {status.isInstalling 
                  ? "Downloading and installing official ClamAV 64-bit engine automatically..." 
                  : "ClamAV engine is missing. We can download and configure it for you automatically."}
              </p>
              {status.isInstalling && (
                <p className="text-indigo-400 text-sm mt-2 font-mono flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  {status.installProgress}
                </p>
              )}
            </div>
            {!status.isInstalling && (
              <button 
                onClick={installEngine}
                className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded-lg transition-colors"
              >
                Install ClamAV Engine
              </button>
            )}
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <h3 className="font-medium text-slate-300 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-indigo-400" />
            Engine Info
          </h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">Version</span>
              <span className="font-medium text-slate-200">{status.stats.engineVersion}</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">Platform</span>
              <span className="font-medium text-slate-200">{status.platform}</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">YARA Engine</span>
              <span className={status.hasYaraEngine ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                {status.hasYaraEngine ? "Installed" : "Not installed"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">YARA Rules</span>
              <span className={status.hasYaraRules ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                {status.hasYaraRules
                  ? `${status.stats.yaraRuleset || "core"} · ${status.stats.yaraRuleCount || 0} rules`
                  : "Missing"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2">
              <span className="text-slate-500">Privileges</span>
              <span className={status.isAdmin ? "text-emerald-400" : "text-amber-400"}>
                {status.isAdmin ? "Administrator" : "Standard User"}
              </span>
            </div>
            {status.isSimulated && (
              <div className="mt-4 p-3 bg-amber-500/10 border border-amber-500/20 rounded-md text-amber-400 text-xs text-center flex flex-col gap-2">
                <span>Running in Simulated Mode (ClamAV not detected on path)</span>
                <button 
                  onClick={() => fetch('/api/simulate-threat', { method: 'POST' })}
                  className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 rounded border border-amber-500/30 transition-colors"
                >
                  Trigger Test Threat Modal
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <h3 className="font-medium text-slate-300 flex items-center gap-2">
            <Activity className="w-5 h-5 text-indigo-400" />
            Recent Activity
          </h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500 flex items-center gap-2"><Clock className="w-4 h-4"/> Last Scan</span>
              <span className="font-medium text-slate-200">
                {status.stats.lastScan ? formatDistanceToNow(new Date(status.stats.lastScan), {addSuffix: true}) : "Never"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500 flex items-center gap-2"><Database className="w-4 h-4"/> Signatures Updated</span>
              <span className="font-medium text-slate-200">
                {status.stats.lastUpdate ? formatDistanceToNow(new Date(status.stats.lastUpdate), {addSuffix: true}) : "Never"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500 flex items-center gap-2"><FileWarning className="w-4 h-4"/> Quarantined Items</span>
              <span className="font-medium text-slate-200">{status.stats.quarantineCount} files</span>
            </div>
          </div>
        </div>
      </div>
      
    </div>
  );
}
