import { useEffect, useState } from "react";
import { Bug, Save, Folder, Shield, Sliders, ShieldAlert, Heart, RefreshCw, ChevronDown } from "lucide-react";

type ActionNotice = {
  kind: "success" | "warning" | "error" | "info";
  text: string;
};

type SettingsSection = "system" | "notifications" | "diagnostics" | "paths" | "shield" | "scanner" | "support";

export default function SettingsPage() {
  const [settings, setSettings] = useState<any>(null);
  const [defenderStatus, setDefenderStatus] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<ActionNotice | null>(null);
  const [defenderActionPending, setDefenderActionPending] = useState<"pause" | "restore" | "refresh" | null>(null);
  const [openSection, setOpenSection] = useState<SettingsSection | null>("system");

  useEffect(() => {
    fetch("/api/status").then(r => r.json()).then(d => setSettings(d.settings));
    fetch("/api/defender-status").then(r => r.json()).then(d => setDefenderStatus(d)).catch(() => {});
  }, []);

  const refreshDefenderStatus = async () => {
    try {
      const res = await fetch("/api/defender-status");
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || "Could not read Microsoft Defender status.");
      setDefenderStatus(data);
      return data;
    } catch (e: any) {
      setNotice({ kind: "error", text: e?.message || "Could not read Microsoft Defender status." });
      return null;
    }
  };

  const defenderResultNotice = (data: any, fallback: string): ActionNotice => {
    if (data?.success || data?.Success) {
      return { kind: "success", text: data.Message || fallback };
    }
    if (data?.SideBySideMode || data?.NeedsManualAction) {
      return {
        kind: "warning",
        text: data.Message || "Windows Tamper Protection is on. Open Windows Security, turn it off, then check again."
      };
    }
    return {
      kind: "error",
      text: data?.Message || data?.error || "Windows blocked the Defender change. Check Tamper Protection, administrator access, or device policy."
    };
  };

  const openWindowsSecurity = async () => {
    try {
      const res = await fetch("/api/open-windows-security", { method: "POST" });
      const data = await res.json();
      setNotice(data.success
        ? { kind: "info", text: "Windows Security opened. Go to Virus & threat protection → Manage settings → Tamper Protection." }
        : { kind: "error", text: data.error || "Windows Security could not be opened." });
    } catch (e: any) {
      setNotice({ kind: "error", text: "Could not open Windows Security: " + e.message });
    }
  };

  const runDefenderAction = async (action: "pause" | "restore") => {
    setDefenderActionPending(action);
    try {
      const endpoint = action === "pause" ? "/api/stop-defender" : "/api/restore-defender";
      const res = await fetch(endpoint, { method: "POST" });
      const data = await res.json();
      setNotice(defenderResultNotice(
        data,
        action === "pause"
          ? "Microsoft Defender real-time protection is paused."
          : "Microsoft Defender preferences were restored."
      ));
      await refreshDefenderStatus();
    } catch (e: any) {
      setNotice({ kind: "error", text: `Could not ${action} Microsoft Defender: ${e.message}` });
    } finally {
      setDefenderActionPending(null);
    }
  };

  const checkTamperProtection = async () => {
    setDefenderActionPending("refresh");
    const status = await refreshDefenderStatus();
    if (status) {
      setNotice(status.IsTamperProtected === true
        ? { kind: "warning", text: "Tamper Protection is still on. Windows will block Defender pause requests." }
        : status.IsTamperProtected === false
          ? { kind: "success", text: "Tamper Protection is off. You can now try Pause Defender." }
          : { kind: "info", text: "Windows did not report the Tamper Protection state. You may still try the action below." });
    }
    setDefenderActionPending(null);
  };

  const updateNumberSetting = (key: string, rawValue: string, fallback: number, min: number, max: number) => {
    const parsed = Number(rawValue);
    const nextValue = Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
    setSettings((current: any) => ({ ...current, [key]: nextValue }));
  };

  const saveSettings = async () => {
    setSaving(true);
    setNotice(null);
    try {
      await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings)
      });
      setNotice({ kind: "success", text: "Settings saved successfully." });
    } catch (e: any) {
      setNotice({ kind: "error", text: "Failed to save settings: " + e.message });
    }
    setSaving(false);
    setTimeout(() => setNotice(null), 3000);
  };

  if (!settings) return <div className="p-8">Loading...</div>;

  const tamperProtectionOn = defenderStatus?.IsTamperProtected === true;
  const noticeClass = notice?.kind === "success"
    ? "bg-emerald-500/20 border-emerald-500/30 text-emerald-300"
    : notice?.kind === "warning"
      ? "bg-amber-500/15 border-amber-500/30 text-amber-200"
      : notice?.kind === "error"
        ? "bg-rose-500/15 border-rose-500/30 text-rose-200"
        : "bg-indigo-500/15 border-indigo-500/30 text-indigo-200";
  const toggleSection = (section: SettingsSection) => {
    setOpenSection(current => current === section ? null : section);
  };

  return (
    <div className="px-8 max-w-4xl mx-auto space-y-6 pb-20">
      <div className="sticky top-0 z-30 -mx-8 px-8 py-5 bg-slate-950/95 backdrop-blur border-b border-slate-800/80 space-y-3">
        <header className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-white mb-1">Settings</h1>
            <p className="text-slate-400">Configure ClamAV paths and scanner options</p>
          </div>
          <button
            onClick={saveSettings}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors shrink-0"
          >
            <Save className="w-4 h-4" />
            {saving ? "Saving..." : "Save Config"}
          </button>
        </header>
        {notice && <div className={`p-3 border rounded-md text-sm ${noticeClass}`}>{notice.text}</div>}
      </div>

      <div className="space-y-6">
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button
            type="button"
            onClick={() => toggleSection("system")}
            aria-expanded={openSection === "system"}
            className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${
              openSection === "system" ? "border-b border-slate-800" : ""
            }`}
          >
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-indigo-400" />
              System Integration
            </div>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "system" ? "rotate-180" : ""}`} />
          </button>
          {openSection === "system" && (
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
            <label className="flex items-center justify-between cursor-pointer py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">Start Minimized to Tray</span>
                <span className="text-slate-500 text-xs">Open ClamShield as a tray icon without showing the main window.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.startMinimized || false}
                onChange={e => setSettings({...settings, startMinimized: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>

            <h3 className="text-slate-200 font-medium pt-2 block">Windows Security</h3>
            <p className="text-sm text-slate-400">
              ClamShield runs alongside Microsoft Defender by default. ClamShield is a user interface for ClamAV and YARA,
              so it does not claim to be an independent antivirus provider or register itself as one in Windows Security.
              You may optionally request that Defender real-time protection be paused to reduce duplicate scanning.
            </p>
            <label
              className={`flex items-center justify-between py-2 border-t border-slate-800 pt-4 ${
                tamperProtectionOn ? "cursor-not-allowed opacity-60" : "cursor-pointer"
              }`}
              title={tamperProtectionOn ? "Open Windows Security and disable Tamper Protection first." : undefined}
            >
              <div>
                <span className="text-slate-200 font-medium block">Automatically keep Defender paused</span>
                <span className="text-slate-500 text-xs">Optional. Only works when Windows permits the change and Tamper Protection is off.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.autoDisableDefender === true}
                disabled={tamperProtectionOn}
                onChange={e => setSettings({...settings, autoDisableDefender: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800 disabled:cursor-not-allowed"
              />
            </label>
            {settings.autoDisableDefender === true && (
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-slate-400 block w-1/3">Re-apply every (minutes)</label>
                <input
                  type="number"
                  min={1}
                  max={1440}
                  value={settings.defenderEnforceIntervalMinutes || 5}
                  onChange={e => updateNumberSetting("defenderEnforceIntervalMinutes", e.target.value, 5, 1, 1440)}
                  className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                />
              </div>
            )}
            <div className="flex items-start gap-2 bg-slate-800/50 p-3 rounded-lg border border-indigo-500/20 text-indigo-200/80 text-xs">
              <ShieldAlert className="w-4 h-4 shrink-0 text-indigo-400 mt-0.5" />
              <p>
                <strong>Windows controls this setting:</strong> Tamper Protection blocks apps from changing protected Microsoft Defender settings.
                Keeping Defender and ClamShield in side-by-side mode is supported and avoids leaving the computer without Defender protection.
              </p>
            </div>
            {tamperProtectionOn && (
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-sm text-amber-100 space-y-3">
                <div className="flex items-start gap-3">
                  <ShieldAlert className="w-5 h-5 shrink-0 text-amber-400 mt-0.5" />
                  <div>
                    <p className="font-semibold text-amber-300">Action required before Defender can be paused</p>
                    <ol className="mt-2 list-decimal list-inside space-y-1 text-amber-100/80">
                      <li>Open Windows Security.</li>
                      <li>Select Virus & threat protection, then Manage settings.</li>
                      <li>Turn Tamper Protection off.</li>
                      <li>Return here and click Check again.</li>
                    </ol>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={openWindowsSecurity}
                    className="px-3 py-2 bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-lg font-semibold transition-colors text-xs"
                  >
                    Open Tamper Protection Settings
                  </button>
                  <button
                    onClick={checkTamperProtection}
                    disabled={defenderActionPending !== null}
                    className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors text-xs"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${defenderActionPending === "refresh" ? "animate-spin" : ""}`} />
                    {defenderActionPending === "refresh" ? "Checking..." : "Check again"}
                  </button>
                </div>
              </div>
            )}
            {defenderStatus?.Supported !== false && (
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">Defender real-time protection</span>
                  <span className={defenderStatus?.RealTimeProtectionEnabled === false ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                    {defenderStatus?.RealTimeProtectionEnabled === false
                      ? "Paused"
                      : defenderStatus?.RealTimeProtectionEnabled === true ? "Active" : "Unknown"}
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
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">ClamShield mode</span>
                  <span className={defenderStatus?.RealTimeProtectionEnabled === false ? "text-emerald-400 font-medium" : "text-indigo-300 font-medium"}>
                    {defenderStatus?.RealTimeProtectionEnabled === false ? "Defender paused" : "Side-by-side"}
                  </span>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">Cloud-delivered protection</span>
                  <span className={defenderStatus?.MAPSReporting === 0 ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                    {defenderStatus?.MAPSReporting === 0
                      ? "Off"
                      : defenderStatus?.MAPSReporting === null || defenderStatus?.MAPSReporting === undefined ? "Unknown" : "On"}
                  </span>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">Automatic sample submission</span>
                  <span className={defenderStatus?.SubmitSamplesConsent === 2 ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                    {defenderStatus?.SubmitSamplesConsent === 2
                      ? "Never send"
                      : defenderStatus?.SubmitSamplesConsent === null || defenderStatus?.SubmitSamplesConsent === undefined ? "Unknown" : "Enabled or prompt"}
                  </span>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">Scheduled Defender scans</span>
                  <span className={defenderStatus?.ScanScheduleDay === 8 ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                    {defenderStatus?.ScanScheduleDay === 8
                      ? "Off"
                      : defenderStatus?.ScanScheduleDay === null || defenderStatus?.ScanScheduleDay === undefined ? "Unknown" : "Enabled"}
                  </span>
                </div>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <div className="relative group">
                <button
                  onClick={() => runDefenderAction("pause")}
                  disabled={tamperProtectionOn || defenderActionPending !== null}
                  className="px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:bg-slate-700 disabled:text-slate-400 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors text-sm"
                >
                  {defenderActionPending === "pause" ? "Pausing..." : "Pause Defender"}
                </button>
                {tamperProtectionOn && (
                  <div
                    role="tooltip"
                    className="pointer-events-none absolute left-1/2 bottom-full z-20 mb-2 w-64 -translate-x-1/2 rounded-lg border border-amber-500/30 bg-slate-950 px-3 py-2 text-center text-xs leading-relaxed text-amber-200 opacity-0 shadow-xl transition-opacity group-hover:opacity-100"
                  >
                    Open Windows Security and disable Tamper Protection first.
                    <span className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-slate-950" />
                  </div>
                )}
              </div>
              <button
                onClick={openWindowsSecurity}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg font-medium transition-colors text-sm"
              >
                Open Defender Settings
              </button>
              <button
                onClick={() => runDefenderAction("restore")}
                disabled={defenderActionPending !== null}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors text-sm"
              >
                {defenderActionPending === "restore" ? "Restoring..." : "Restore Defender"}
              </button>
            </div>
          </div>
          )}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button
            type="button"
            onClick={() => toggleSection("notifications")}
            aria-expanded={openSection === "notifications"}
            className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${
              openSection === "notifications" ? "border-b border-slate-800" : ""
            }`}
          >
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-indigo-400" />
              Notifications & Alerts
            </div>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "notifications" ? "rotate-180" : ""}`} />
          </button>
          {openSection === "notifications" && (
          <div className="p-6 space-y-4">
            <label className="flex items-center justify-between cursor-pointer py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">Play Sound on Threat Found</span>
                <span className="text-slate-500 text-xs">Play a short bundled alert sound when a threat popup opens. Off by default.</span>
              </div>
              <input 
                type="checkbox" 
                checked={settings.playSoundOnAlert || false} 
                onChange={e => setSettings({...settings, playSoundOnAlert: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>
          </div>
          )}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button
            type="button"
            onClick={() => toggleSection("diagnostics")}
            aria-expanded={openSection === "diagnostics"}
            className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${
              openSection === "diagnostics" ? "border-b border-slate-800" : ""
            }`}
          >
            <div className="flex items-center gap-2">
              <Bug className="w-5 h-5 text-indigo-400" />
              Diagnostics
            </div>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "diagnostics" ? "rotate-180" : ""}`} />
          </button>
          {openSection === "diagnostics" && (
          <div className="p-6 space-y-4">
            <label className="flex items-center justify-between cursor-pointer py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">Enable Debug Log</span>
                <span className="text-slate-500 text-xs">Writes extra startup, popup, and service details. Error and crash logs are always kept so white screens can be diagnosed.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.enableDebugLog === true}
                onChange={e => setSettings({...settings, enableDebugLog: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium text-slate-400 block w-1/3">
                Delete logs after days
                <span className="block text-xs font-normal text-slate-500 mt-1">Default is 7 days. Logs are stored under C:\ProgramData\ClamShield\logs.</span>
              </label>
              <input
                type="number"
                min={1}
                max={365}
                value={settings.logRetentionDays || 7}
                onChange={e => updateNumberSetting("logRetentionDays", e.target.value, 7, 1, 365)}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="text-xs text-slate-500 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
              Main app, popup, renderer, and service errors are written to the logs folder. Turn on debug log only while investigating a problem.
            </div>
          </div>
          )}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button
            type="button"
            onClick={() => toggleSection("paths")}
            aria-expanded={openSection === "paths"}
            className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${
              openSection === "paths" ? "border-b border-slate-800" : ""
            }`}
          >
            <span className="flex items-center gap-2">
              <Folder className="w-5 h-5 text-indigo-400" />
              ClamAV Paths
            </span>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "paths" ? "rotate-180" : ""}`} />
          </button>
          {openSection === "paths" && (
          <div className="p-6 space-y-4">
            {['clamavDir', 'clamscanPath', 'freshclamPath', 'freshclamConf', 'clamdPath', 'clamdscanPath', 'clamdConf', 'yaraDir', 'yaraPath', 'yaraRulesDir', 'yaraCustomRulesDir', 'yaraCacheDir', 'databaseDir', 'quarantineDir', 'logsDir'].map((key) => (
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
          )}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button
            type="button"
            onClick={() => toggleSection("shield")}
            aria-expanded={openSection === "shield"}
            className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${
              openSection === "shield" ? "border-b border-slate-800" : ""
            }`}
          >
            <span className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-indigo-400" />
              Real-Time Shield Setup
            </span>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "shield" ? "rotate-180" : ""}`} />
          </button>
          {openSection === "shield" && (
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
            <label className="flex items-center justify-between cursor-pointer py-2">
              <div>
                <span className="text-slate-300 block text-sm">Low impact Shield scans</span>
                <span className="text-xs text-slate-500">Runs real-time ClamAV scans below normal CPU priority to reduce foreground slowdowns.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.shieldLowImpactMode !== false}
                onChange={e => setSettings({...settings, shieldLowImpactMode: e.target.checked})}
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
                onChange={e => updateNumberSetting("shieldDepth", e.target.value, 1, 0, 20)}
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
                onChange={e => updateNumberSetting("shieldMaxConcurrentScans", e.target.value, 1, 1, 4)}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium text-slate-400 block w-1/3">
                Polling Interval (ms)
                <span className="block text-xs font-normal text-slate-500 mt-1">How often Shield checks if a changing file is stable. Lower is faster but costs more CPU/disk wakeups.</span>
              </label>
              <input 
                type="number"
                value={settings.shieldPollInterval || 1000}
                onChange={e => updateNumberSetting("shieldPollInterval", e.target.value, 1000, 100, 60000)}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium text-slate-400 block w-1/3">
                Stability Threshold (ms)
                <span className="block text-xs font-normal text-slate-500 mt-1">How long a file must stop changing before scan. Higher is safer for many downloads and large files.</span>
              </label>
              <input 
                type="number"
                value={settings.shieldStabilityThreshold || 2000}
                onChange={e => updateNumberSetting("shieldStabilityThreshold", e.target.value, 2000, 100, 120000)}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>
          )}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button
            type="button"
            onClick={() => toggleSection("scanner")}
            aria-expanded={openSection === "scanner"}
            className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${
              openSection === "scanner" ? "border-b border-slate-800" : ""
            }`}
          >
            <span className="flex items-center gap-2">
              <Sliders className="w-5 h-5 text-indigo-400" />
              Scanner Options
            </span>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "scanner" ? "rotate-180" : ""}`} />
          </button>
          {openSection === "scanner" && (
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
                  onChange={e => updateNumberSetting("updateIntervalHours", e.target.value, 24, 1, 720)}
                  className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                />
              </div>
            )}

            <label className="flex items-center justify-between cursor-pointer py-2 border-t border-slate-800 pt-4">
              <div>
                <span className="text-slate-300 block text-sm">Check for ClamShield app updates weekly</span>
                <span className="text-xs text-slate-500">Looks for a newer GitHub release while ClamShield is running.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.appUpdateCheckEnabled !== false}
                onChange={e => setSettings({...settings, appUpdateCheckEnabled: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>
            {settings.appUpdateCheckEnabled !== false && (
              <>
                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium text-slate-400 block w-1/3">ClamShield update interval (hours)</label>
                  <input
                    type="number"
                    min={1}
                    max={8760}
                    value={settings.appUpdateIntervalHours || 168}
                    onChange={e => updateNumberSetting("appUpdateIntervalHours", e.target.value, 168, 1, 8760)}
                    className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <label className="flex items-center justify-between cursor-pointer py-2">
                  <div>
                    <span className="text-slate-300 block text-sm">Silent install ClamShield updates</span>
                    <span className="text-xs text-slate-500">Downloads and launches the installer automatically, then closes ClamShield so files can be replaced.</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={settings.appSilentAutoInstall === true}
                    onChange={e => setSettings({...settings, appSilentAutoInstall: e.target.checked})}
                    className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
                  />
                </label>
              </>
            )}
            
            <div className="flex items-center justify-between py-2">
              <span className="text-slate-300 text-sm mb-1 block">Send scanned items to</span>
              <select
                value={settings.scanDetectionAction || "results"}
                onChange={e => setSettings({...settings, scanDetectionAction: e.target.value})}
                className="w-1/2 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              >
                <option value="results">Results checklist</option>
                <option value="quarantine">Quarantine</option>
              </select>
            </div>

            <label className="flex items-center justify-between cursor-pointer py-2 border-t border-slate-800 pt-4">
              <div>
                <span className="text-slate-200 font-medium block">Enable YARA scanning</span>
                <span className="text-slate-500 text-xs">Runs YARA Forge rules as a second detection layer. Core is enabled by default for low false positives.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.yaraEnabled !== false}
                onChange={e => setSettings({...settings, yaraEnabled: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>

            {settings.yaraEnabled !== false && (
              <>
                <div className="flex items-center justify-between py-2">
                  <div className="w-1/2 pr-4">
                    <span className="text-slate-300 text-sm mb-1 block">YARA Forge ruleset</span>
                    <span className="text-xs text-slate-500">Core is fastest and safest. Extended is balanced. Full is widest and heavier.</span>
                  </div>
                  <select
                    value={settings.yaraRuleset || "core"}
                    onChange={e => setSettings({...settings, yaraRuleset: e.target.value})}
                    className="w-1/2 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="core">Core</option>
                    <option value="extended">Extended</option>
                    <option value="full">Full</option>
                  </select>
                </div>

                <label className="flex items-center justify-between cursor-pointer py-2">
                  <div>
                    <span className="text-slate-300 block text-sm">Auto-update YARA rules weekly</span>
                    <span className="text-xs text-slate-500">Checks YARA Forge once per week when ClamShield is running.</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={settings.yaraAutoUpdateEnabled !== false}
                    onChange={e => setSettings({...settings, yaraAutoUpdateEnabled: e.target.checked})}
                    className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
                  />
                </label>

                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium text-slate-400 block w-1/3">YARA timeout seconds</label>
                  <input
                    type="number"
                    min={1}
                    max={3600}
                    value={settings.yaraTimeoutSeconds || 15}
                    onChange={e => updateNumberSetting("yaraTimeoutSeconds", e.target.value, 15, 1, 3600)}
                    className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                  />
                </div>

                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium text-slate-400 block w-1/3">YARA max file size (MB)</label>
                  <input
                    type="number"
                    min={1}
                    max={4096}
                    value={settings.yaraMaxFileSize || 50}
                    onChange={e => updateNumberSetting("yaraMaxFileSize", e.target.value, 50, 1, 4096)}
                    className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </>
            )}

            <div className="flex items-center justify-between py-2">
              <span className="text-slate-300 text-sm mb-1 block">Real-time shield detections</span>
              <select
                value={settings.actionOnDetection === "warn" ? "ask" : (settings.actionOnDetection || (settings.autoQuarantine ? "quarantine" : "ask"))}
                onChange={e => setSettings({...settings, actionOnDetection: e.target.value, autoQuarantine: e.target.value === "quarantine"})}
                className="w-1/2 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              >
                <option value="quarantine">Auto Quarantine</option>
                <option value="ask">Ask Me</option>
                <option value="results">Send silently to Results</option>
              </select>
            </div>

            <div className="flex items-center justify-between border-t border-slate-800 pt-4">
              <label className="text-sm font-medium text-slate-400 block w-1/3">Max File Size (MB)</label>
              <input 
                type="number"
                value={settings.maxFileSize}
                onChange={e => updateNumberSetting("maxFileSize", e.target.value, 50, 1, 4096)}
                className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="w-1/3 pr-4">
                <label className="text-sm font-medium text-slate-400 block">Adaptive scan batches</label>
                <span className="text-xs text-slate-500">Manual scans use smaller batches for small folders and larger batches for big folders to keep progress responsive.</span>
              </div>
              <div className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-3 text-xs text-slate-400 leading-relaxed">
                {"<=100 files: 1 per batch | 101-500: 3 | 501-1000: 10 | 1001+: 100"}
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="w-1/3 pr-4">
                <label className="text-sm font-medium text-slate-400 block">Pause between batches (ms)</label>
                <span className="text-xs text-slate-500">Adds a small pause between manual scan batches to reduce CPU and disk pressure.</span>
              </div>
              <input
                type="number"
                value={settings.scanBatchDelayMs || 0}
                min={0}
                max={60000}
                onChange={e => updateNumberSetting("scanBatchDelayMs", e.target.value, 0, 0, 60000)}
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
          )}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button
            type="button"
            onClick={() => toggleSection("support")}
            aria-expanded={openSection === "support"}
            className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${
              openSection === "support" ? "border-b border-slate-800" : ""
            }`}
          >
            <span className="flex items-center gap-2">
              <Heart className="w-5 h-5 text-rose-500" />
              Support Us
            </span>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "support" ? "rotate-180" : ""}`} />
          </button>
          {openSection === "support" && (
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
          )}
        </section>
      </div>
    </div>
  );
}
