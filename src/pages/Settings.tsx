import { useEffect, useState } from "react";
import { Save, Folder, Shield, Sliders, ShieldAlert, Heart } from "lucide-react";

export default function SettingsPage() {
  const [settings, setSettings] = useState<any>(null);
  const [defenderStatus, setDefenderStatus] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    fetch("/api/status").then(r => r.json()).then(d => setSettings(d.settings));
    fetch("/api/defender-status").then(r => r.json()).then(d => setDefenderStatus(d)).catch(() => {});
  }, []);

  const refreshDefenderStatus = async () => {
    try {
      const res = await fetch("/api/defender-status");
      const data = await res.json();
      setDefenderStatus(data);
      return data;
    } catch {
      return null;
    }
  };

  const defenderResultMessage = (data: any, fallback: string) => {
    if (data?.success || data?.Success) return data.Message || fallback;
    return data?.Message || data?.error || "Windows 10/11 blocked the Defender change. Check Tamper Protection or policy.";
  };

  const saveSettings = async () => {
    setSaving(true);
    setMsg("");
    try {
      await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings)
      });
      setMsg("Settings saved successfully.");
    } catch (e: any) {
      setMsg("Failed to save settings: " + e.message);
    }
    setSaving(false);
    setTimeout(() => setMsg(""), 3000);
  };

  if (!settings) return <div className="p-8">Loading...</div>;

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8 pb-20">
      <header className="flex items-center justify-between">
         <div>
          <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
          <p className="text-slate-400">Configure ClamAV paths and scanner options</p>
         </div>
         <button 
           onClick={saveSettings}
           disabled={saving}
           className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors"
         >
           <Save className="w-4 h-4" />
           {saving ? "Saving..." : "Save Config"}
         </button>
      </header>
      
      {msg && <div className="p-3 bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 rounded-md text-sm">{msg}</div>}

      <div className="space-y-6">
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between font-medium text-slate-200">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-indigo-400" />
              System Integration
            </div>
          </div>
          <div className="p-6 space-y-4">
            <label className="flex items-center justify-between cursor-pointer py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">Run ClamShield on Startup</span>
                <span className="text-slate-500 text-xs">Automatically launch ClamShield background service when you sign into Windows.</span>
              </div>
              <input 
                type="checkbox" 
                checked={settings.runOnStartup || false} 
                onChange={e => setSettings({...settings, runOnStartup: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>

            <h3 className="text-slate-200 font-medium pt-2 block">Windows Security</h3>
            <p className="text-sm text-slate-400">
              Register ClamShield to alert Windows Defender that another antivirus software is installed. 
              This will disable Windows Defender's real-time protection to prevent conflicts, avoiding having 2 antivirus apps running at the same time.
            </p>
            <label className="flex items-center justify-between cursor-pointer py-2 border-t border-slate-800 pt-4">
              <div>
                <span className="text-slate-200 font-medium block">Automatically keep Defender paused</span>
                <span className="text-slate-500 text-xs">Runs once on startup, verifies the result, and re-applies at the interval below if Windows turns it back on.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.autoDisableDefender !== false}
                onChange={e => setSettings({...settings, autoDisableDefender: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>
            {settings.autoDisableDefender !== false && (
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-slate-400 block w-1/3">Re-apply every minutes</label>
                <input
                  type="number"
                  min={1}
                  max={1440}
                  value={settings.defenderEnforceIntervalMinutes || 5}
                  onChange={e => setSettings({...settings, defenderEnforceIntervalMinutes: parseInt(e.target.value)})}
                  className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                />
              </div>
            )}
            <div className="flex items-start gap-2 bg-slate-800/50 p-3 rounded-lg border border-indigo-500/20 text-indigo-200/80 text-xs">
              <ShieldAlert className="w-4 h-4 shrink-0 text-indigo-400 mt-0.5" />
              <p>
                <strong>Note:</strong> Windows 10/11 Tamper Protection or local policy can block third-party apps from pausing Microsoft Defender. ClamShield will try the supported PowerShell preferences and then verify the actual Defender state.
              </p>
            </div>
            {defenderStatus?.Supported !== false && (
              <div className="grid sm:grid-cols-2 gap-3 text-xs">
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">Defender real-time protection</span>
                  <span className={defenderStatus?.RealTimeProtectionEnabled === false ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                    {defenderStatus?.RealTimeProtectionEnabled === false ? "Paused" : "Active or unknown"}
                  </span>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">Tamper Protection</span>
                  <span className={defenderStatus?.IsTamperProtected ? "text-amber-400 font-medium" : "text-slate-300 font-medium"}>
                    {defenderStatus?.IsTamperProtected === null || defenderStatus?.IsTamperProtected === undefined
                      ? "Unknown"
                      : defenderStatus.IsTamperProtected ? "On" : "Off"}
                  </span>
                </div>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={async () => {
                  try {
                    const res = await fetch("/api/alert-defender", { method: "POST" });
                    const data = await res.json();
                    setMsg(defenderResultMessage(data, "Windows Defender paused successfully."));
                    await refreshDefenderStatus();
                  } catch (e: any) {
                    setMsg("Error: " + e.message);
                  }
                }}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors text-sm"
              >
                Register w/ Windows Security
              </button>
              <button
                onClick={async () => {
                   try {
                    const res = await fetch("/api/stop-defender", { method: "POST" });
                    const data = await res.json();
                    setMsg(defenderResultMessage(data, "Windows Defender Real-Time Protection paused."));
                    await refreshDefenderStatus();
                  } catch (e: any) {
                    setMsg("Error: " + e.message);
                  }
                }}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg font-medium transition-colors text-sm"
              >
                Pause Defender
              </button>
              <button
                onClick={async () => {
                   try {
                    const res = await fetch("/api/restore-defender", { method: "POST" });
                    const data = await res.json();
                    setMsg(defenderResultMessage(data, "Windows Defender real-time protection restored."));
                    await refreshDefenderStatus();
                  } catch (e: any) {
                    setMsg("Error: " + e.message);
                  }
                }}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg font-medium transition-colors text-sm"
              >
                Restore Defender
              </button>
            </div>
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between font-medium text-slate-200">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-indigo-400" />
              Notifications & Alerts
            </div>
          </div>
          <div className="p-6 space-y-4">
            <label className="flex items-center justify-between cursor-pointer py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">Play Sound on Threat Found</span>
                <span className="text-slate-500 text-xs">Play a system beep sound when a threat is detected.</span>
              </div>
              <input 
                type="checkbox" 
                checked={settings.playSoundOnAlert || false} 
                onChange={e => setSettings({...settings, playSoundOnAlert: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
            <Folder className="w-5 h-5 text-indigo-400" />
            ClamAV Paths
          </div>
          <div className="p-6 space-y-4">
            {['clamavDir', 'clamscanPath', 'freshclamPath', 'freshclamConf', 'databaseDir', 'quarantineDir', 'logsDir'].map((key) => (
              <div key={key}>
                <label className="block text-sm font-medium text-slate-400 mb-1 capitalize">
                  {key.replace(/([A-Z])/g, ' $1').trim()}
                </label>
                <input
                  type="text"
                  value={settings[key] || ""}
                  onChange={e => setSettings({...settings, [key]: e.target.value})}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                />
              </div>
            ))}
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
           <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
            <Shield className="w-5 h-5 text-indigo-400" />
            Real-Time Shield Setup
          </div>
          <div className="p-6 space-y-4">
            {['monitorDesktop', 'monitorDocuments', 'monitorDownloads'].map(key => (
              <label key={key} className="flex items-center justify-between cursor-pointer py-2">
                <span className="text-slate-300 capitalize text-sm">{key.replace(/([A-Z])/g, ' $1').replace('monitor ', 'Monitor ').trim()}</span>
                <input 
                  type="checkbox" 
                  checked={settings[key] || false} 
                  onChange={e => setSettings({...settings, [key]: e.target.checked})}
                  className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
                />
              </label>
            ))}
            <label className="flex items-center justify-between cursor-pointer py-2 border-t border-slate-800 pt-4">
              <div>
                <span className="text-slate-300 block text-sm">Auto-detect browser download folders</span>
                <span className="text-xs text-slate-500">Adds installed Chrome, Edge, Firefox, Brave, Opera, Vivaldi, and Chromium download paths.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.autoDetectBrowserDownloads !== false}
                onChange={e => setSettings({...settings, autoDetectBrowserDownloads: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>
            <div className="flex items-center justify-between border-t border-slate-800 pt-4">
              <label className="text-sm font-medium text-slate-400 block w-1/3">Shield Folder Depth</label>
              <input
                type="number"
                min={0}
                max={20}
                value={settings.shieldDepth ?? 1}
                onChange={e => setSettings({...settings, shieldDepth: parseInt(e.target.value)})}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium text-slate-400 block w-1/3">Concurrent Shield Scans</label>
              <input
                type="number"
                min={1}
                max={4}
                value={settings.shieldMaxConcurrentScans ?? 1}
                onChange={e => setSettings({...settings, shieldMaxConcurrentScans: parseInt(e.target.value)})}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium text-slate-400 block w-1/3">Polling Interval (ms)</label>
              <input 
                type="number"
                value={settings.shieldPollInterval || 1000}
                onChange={e => setSettings({...settings, shieldPollInterval: parseInt(e.target.value)})}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium text-slate-400 block w-1/3">Stability Threshold (ms)</label>
              <input 
                type="number"
                value={settings.shieldStabilityThreshold || 2000}
                onChange={e => setSettings({...settings, shieldStabilityThreshold: parseInt(e.target.value)})}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
           <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
            <Sliders className="w-5 h-5 text-indigo-400" />
            Scanner Options
          </div>
          <div className="p-6 space-y-4">
            <label className="flex items-center justify-between cursor-pointer py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">Offload ClamShield to memory</span>
                <span className="text-slate-500 text-xs">Larger memory footprint (~1GB RAM), less CPU overhead.</span>
              </div>
              <input 
                type="checkbox" 
                checked={settings.offloadToMemory || false} 
                onChange={e => setSettings({...settings, offloadToMemory: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>

            <label className="flex items-center justify-between cursor-pointer py-2">
              <span className="text-slate-300 capitalize text-sm mb-1 block">Auto-Update Signatures</span>
              <input 
                type="checkbox" 
                checked={settings.autoUpdateEnabled} 
                onChange={e => setSettings({...settings, autoUpdateEnabled: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>
            {settings.autoUpdateEnabled && (
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-slate-400 block w-1/3">Update every XX hours</label>
                <input 
                  type="number"
                  value={settings.updateIntervalHours || 24}
                  min={1}
                  max={720}
                  onChange={e => setSettings({...settings, updateIntervalHours: parseInt(e.target.value)})}
                  className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                />
              </div>
            )}
            
            <div className="flex items-center justify-between py-2">
              <span className="text-slate-300 capitalize text-sm mb-1 block">When virus found</span>
              <select
                value={settings.actionOnDetection || (settings.autoQuarantine ? "quarantine" : "warn")}
                onChange={e => setSettings({...settings, actionOnDetection: e.target.value, autoQuarantine: e.target.value === "quarantine"})}
                className="w-1/2 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              >
                <option value="quarantine">Auto Quarantine</option>
                <option value="ask">Ask Me</option>
                <option value="warn">Warn Only</option>
              </select>
            </div>

            <div className="flex items-center justify-between border-t border-slate-800 pt-4">
              <label className="text-sm font-medium text-slate-400 block w-1/3">Max File Size (MB)</label>
              <input 
                type="number"
                value={settings.maxFileSize}
                onChange={e => setSettings({...settings, maxFileSize: parseInt(e.target.value)})}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            {['scanArchives', 'recursive', 'followSymlinks'].map(key => (
              <label key={key} className="flex items-center justify-between cursor-pointer py-2">
                <span className="text-slate-300 capitalize text-sm">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
                <input 
                  type="checkbox" 
                  checked={settings[key]} 
                  onChange={e => setSettings({...settings, [key]: e.target.checked})}
                  className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
                />
              </label>
            ))}
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
           <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
            <Heart className="w-5 h-5 text-rose-500" />
            Support Us
          </div>
          <div className="p-6 space-y-6">
            <div>
              <p className="text-sm text-slate-300 mb-4">
                Enjoying ClamShield? Consider supporting the development of this application. Your donations help keep it maintained and free!
              </p>
              <div className="grid sm:grid-cols-3 gap-3">
                <a href="https://www.paypal.com/ncp/payment/LDBFB3RRB3E9J" target="_blank" rel="noopener noreferrer" className="flex items-center justify-center py-2 px-4 rounded-lg bg-[#0070ba] hover:bg-[#003087] text-white text-sm font-medium transition-colors">
                  Buy me a coffee (€5)
                </a>
                <a href="https://www.paypal.com/ncp/payment/G5RNTC3UF58VU" target="_blank" rel="noopener noreferrer" className="flex items-center justify-center py-2 px-4 rounded-lg bg-[#0070ba] hover:bg-[#003087] text-white text-sm font-medium transition-colors">
                  Buy me a beer (€10)
                </a>
                <a href="https://www.paypal.com/ncp/payment/4NP9RNUYRFRFA" target="_blank" rel="noopener noreferrer" className="flex items-center justify-center py-2 px-4 rounded-lg bg-[#0070ba] hover:bg-[#003087] text-white text-sm font-medium transition-colors">
                  Buy me a meal (€15)
                </a>
              </div>
            </div>
            
            <div className="pt-4 border-t border-slate-800">
              <p className="text-sm text-slate-400 mb-3">
                We also recommend supporting <strong className="text-slate-300">Sanesecurity</strong>, who provides excellent third-party signatures for ClamAV to detect the newest threats.
              </p>
              <a href="https://sanesecurity.com/donate/" target="_blank" rel="noopener noreferrer" className="inline-flex items-center justify-center py-2 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium transition-colors border border-slate-700">
                Donate to Sanesecurity
              </a>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
