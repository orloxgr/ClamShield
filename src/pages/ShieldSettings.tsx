import { useEffect, useState } from "react";
import { Bell, Plus, RotateCcw, Save, SlidersHorizontal, X } from "lucide-react";
import PageHeader from "../components/PageHeader";

export default function ShieldSettings() {
  const [settings, setSettings] = useState<any>(null);
  const [systemPaths, setSystemPaths] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetch("/api/status").then(r => r.json()).then(d => setSettings(d.settings));
    fetch("/api/system-paths").then(r => r.json()).then(d => setSystemPaths(d));
  }, []);

  const updateSettings = async (nextSettings: any) => {
    setSettings(nextSettings);
    setSaving(true);
    await persistSettings(nextSettings);
    setSaving(false);
  };

  const persistSettings = async (nextSettings = settings, showMessage = false) => {
    if (!nextSettings) return;
    setSaving(true);
    try {
      await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(nextSettings)
      });
      if (showMessage) {
        setMessage("Shield settings saved.");
        setTimeout(() => setMessage(""), 3000);
      }
    } catch (e: any) {
      setMessage(e.message || "Failed to save Shield settings.");
    } finally {
      setSaving(false);
    }
  };

  const toggle = (key: string) => {
    if (!settings) return;
    updateSettings({ ...settings, [key]: !settings[key] });
  };

  const updateNumberSetting = (key: string, rawValue: string, fallback: number, min: number, max: number) => {
    const parsed = Number(rawValue);
    const nextValue = Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
    updateSettings({ ...settings, [key]: nextValue });
  };
  const shieldIntensityDetails = (value: number) => {
    const cores = typeof navigator !== "undefined" && navigator.hardwareConcurrency ? navigator.hardwareConcurrency : 1;
    const allCores = Math.min(32, Math.max(1, cores));
    const halfCores = Math.min(allCores, Math.max(2, Math.ceil(cores * 0.5)));
    const threeQuarterCores = Math.min(allCores, Math.max(2, Math.ceil(cores * 0.75)));
    if (value <= 10) return "1-10: Extremely gentle. Idle priority, 1 Shield worker, 100-file total event window, 500 ms pause.";
    if (value <= 20) return "11-20: Very gentle. Idle priority, 1 Shield worker, 250-file total event window, 250 ms pause.";
    if (value <= 30) return "21-30: Gentle. Below-normal priority, 1 Shield worker, 500-file total event window, 150 ms pause.";
    if (value <= 40) return "31-40: Light. Below-normal priority, 1 Shield worker, 1,000-file total event window, 75 ms pause.";
    if (value <= 50) return "41-50: Balanced. Below-normal priority, 2 Shield workers, 2,000-file total event window split between workers, 25 ms pause.";
    if (value <= 60) return "51-60: Active. Normal priority, 2 Shield workers, 3,000-file total event window split between workers, no pause.";
    if (value <= 70) return `61-70: Fast. Normal priority, ${halfCores} Shield workers, 5,000-file total event window split between workers, no pause.`;
    if (value <= 80) return `71-80: Very fast. Normal priority, ${threeQuarterCores} Shield workers, 10,000-file total event window split between workers, no pause.`;
    if (value <= 90) return `81-90: Maximum minus one core. High priority, ${Math.max(1, allCores - 1)} Shield workers, 15,000-file total event window split between workers, no pause.`;
    return `91-100: Maximum. High priority, all ${allCores} logical cores, 25,000-file total event window split between workers, no pause. The PC may be hard to use when many files change.`;
  };

  const handleAddFolder = async () => {
    try {
      const res = await fetch("/api/select-folder");
      const data = await res.json();
      if (res.ok && data.path) {
        const folders = Array.isArray(settings.customWatchedFolders) ? settings.customWatchedFolders : [];
        if (!folders.includes(data.path)) {
          updateSettings({ ...settings, customWatchedFolders: [...folders, data.path] });
        }
      } else if (data.error) {
        console.warn("Folder picker ignored or failed:", data.error);
      }
    } catch (e) {
      console.error("Failed to add folder:", e);
    }
  };

  const handleRemoveFolder = (pathToRemove: string) => {
    const folders = Array.isArray(settings.customWatchedFolders) ? settings.customWatchedFolders : [];
    updateSettings({ ...settings, customWatchedFolders: folders.filter((p: string) => p !== pathToRemove) });
  };

  const forgetScannedFiles = async () => {
    if (!confirm("Forget the real-time shield scanned-file cache? Existing files will be treated as unknown again when they change or are scanned.")) return;
    setMessage("");
    try {
      const res = await fetch("/api/shield-cache/clear", { method: "POST" });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Failed to clear cache.");
      setMessage("Scanned file cache cleared.");
    } catch (e: any) {
      setMessage(e.message || "Failed to clear cache.");
    }
  };

  if (!settings) return <div className="p-8">Loading...</div>;

  const normalizeShieldAction = (value: string) => {
    if (value === "warn") return "ask";
    if (value === "quarantine") return "quarantine_silent";
    if (value === "results") return "results_silent";
    if (["ask", "quarantine_notify", "quarantine_silent", "results_notify", "results_silent"].includes(value)) return value;
    return "ask";
  };
  const shieldAction = normalizeShieldAction(settings.actionOnDetection || "ask");
  const shieldActionDescription: Record<string, string> = {
    ask: "Opens the threat popup so you can quarantine, add an exception, or decide later.",
    quarantine_notify: "Quarantines the file immediately, then shows a Shield notification popup.",
    quarantine_silent: "Quarantines the file immediately without showing a popup.",
    results_notify: "Saves the detection to Results, then shows a Shield notification popup.",
    results_silent: "Saves the detection to Results without showing a popup."
  };

  const defaultFolders = [
    { key: 'monitorDownloads', name: 'Downloads Folder', pathLabel: systemPaths?.Downloads },
    { key: 'monitorDesktop', name: 'Desktop Folder', pathLabel: systemPaths?.Desktop },
    { key: 'monitorDocuments', name: 'Documents Folder', pathLabel: systemPaths?.Documents },
  ];
  const browserDownloads = Array.isArray(systemPaths?.BrowserDownloads) ? systemPaths.BrowserDownloads : [];

  return (
    <div className="px-8 max-w-4xl mx-auto space-y-8 pb-20">
      <PageHeader
        title="Real-Time Shield"
        description="Background protection against new and modified files"
        actions={(
        <div className="flex items-center gap-3">
          <span className={settings.shieldEnabled ? "text-emerald-400 font-medium" : "text-slate-500 font-medium"}>
            {settings.shieldEnabled ? "ON" : "OFF"}
          </span>
          <button 
            onClick={() => toggle('shieldEnabled')}
            className={`relative inline-flex h-7 w-12 items-center rounded-full transition-colors focus:outline-none ${settings.shieldEnabled ? 'bg-emerald-500' : 'bg-slate-700'}`}
          >
            <span className={`inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${settings.shieldEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
          <button
            onClick={() => persistSettings(settings, true)}
            disabled={saving}
            className="inline-flex items-center gap-2 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Save className="w-4 h-4" />
            {saving ? "Saving..." : "Save"}
          </button>
        </div>
        )}
      />

      {message && (
        <div className="p-3 bg-slate-900 border border-slate-800 text-slate-300 rounded-md text-sm">
          {message}
        </div>
      )}

      <div className={`space-y-6 ${!settings.shieldEnabled && 'opacity-50 pointer-events-none'}`}>
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between font-medium text-slate-200">
            <div className="flex items-center gap-2">
               <SlidersHorizontal className="w-5 h-5 text-indigo-400" />
               Monitored Locations
            </div>
            <button 
                onClick={handleAddFolder}
                className="flex items-center gap-1 text-xs px-3 py-1.5 bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 rounded-md transition-colors"
            >
                <Plus className="w-3.5 h-3.5" />
                Add Folder
            </button>
          </div>
          <div className="p-4 space-y-4">
            {defaultFolders.map(folder => (
              <div key={folder.key} className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
                <div>
                    <span className="text-slate-300 block">{folder.name}</span>
                    <span className="text-xs text-slate-500 block">{folder.pathLabel || "Loading path..."}</span>
                </div>
                <input 
                  type="checkbox" 
                  checked={settings[folder.key]} 
                  onChange={() => toggle(folder.key)}
                  className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
                />
              </div>
            ))}

            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">Browser Download Folders</span>
                <span className="text-xs text-slate-500 block">
                  {browserDownloads.length > 0
                    ? `${browserDownloads.length} installed browser location${browserDownloads.length === 1 ? "" : "s"} detected`
                    : "No custom browser download folders detected"}
                </span>
              </div>
              <input
                type="checkbox"
                checked={settings.autoDetectBrowserDownloads !== false}
                onChange={() => toggle('autoDetectBrowserDownloads')}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </div>

            {settings.autoDetectBrowserDownloads !== false && browserDownloads.length > 0 && (
              <div className="ml-2 mr-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3 space-y-2">
                {browserDownloads.map((item: any) => (
                  <div key={`${item.browser}-${item.profile}-${item.path}`} className="flex flex-col gap-0.5">
                    <span className="text-xs font-medium text-slate-400">{item.browser} / {item.profile}</span>
                    <span className="text-xs text-slate-500 font-mono break-all">{item.path}</span>
                  </div>
                ))}
              </div>
            )}

            {Array.isArray(settings.customWatchedFolders) && settings.customWatchedFolders.length > 0 && (
                <div className="pt-4 mt-4 border-t border-slate-800">
                    <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 px-2">Custom Folders</h3>
                    <div className="space-y-2">
                    {settings.customWatchedFolders.map((customPath: string) => (
                        <div key={customPath} className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
                            <span className="text-slate-300 text-sm font-mono truncate mr-4">{customPath}</span>
                            <button 
                                onClick={() => handleRemoveFolder(customPath)} 
                                className="text-slate-500 hover:text-red-400 bg-transparent rounded-full p-1 transition-colors shrink-0"
                                title="Remove Folder"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        </div>
                    ))}
                    </div>
                </div>
            )}
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
            <SlidersHorizontal className="w-5 h-5 text-indigo-400" />
            Performance
          </div>
          <div className="p-4 space-y-4">
            <div className="p-2 space-y-3">
              <div className="flex items-center justify-between gap-6">
                <div>
                  <span className="text-slate-300 block">Shield intensity</span>
                  <span className="text-xs text-slate-500">Current value: {settings.shieldScanIntensity || 41}/100</span>
                </div>
                <input
                  type="range"
                  min={1}
                  max={100}
                  value={settings.shieldScanIntensity || 41}
                  onChange={e => updateNumberSetting("shieldScanIntensity", e.target.value, 41, 1, 100)}
                  className="w-1/2 accent-indigo-500"
                />
              </div>
              <p className="text-xs text-slate-500 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                {shieldIntensityDetails(settings.shieldScanIntensity || 41)}
              </p>
            </div>
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">Folder depth</span>
                <span className="text-xs text-slate-500">How many levels below watched folders the shield monitors</span>
              </div>
              <input
                type="number"
                min={0}
                max={20}
                value={settings.shieldDepth ?? 1}
                onChange={e => updateNumberSetting("shieldDepth", e.target.value, 1, 0, 20)}
                className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">Polling interval</span>
                <span className="text-xs text-slate-500">How often ClamShield checks whether a changing file has become stable. Lower values react sooner but wake the disk/CPU more often.</span>
              </div>
              <input
                type="number"
                min={100}
                max={60000}
                value={settings.shieldPollInterval || 1000}
                onChange={e => updateNumberSetting("shieldPollInterval", e.target.value, 1000, 100, 60000)}
                className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">Stability threshold</span>
                <span className="text-xs text-slate-500">How long a file must stop changing before Shield scans it. Higher values are better for many simultaneous downloads and large files.</span>
              </div>
              <input
                type="number"
                min={100}
                max={120000}
                value={settings.shieldStabilityThreshold || 2000}
                onChange={e => updateNumberSetting("shieldStabilityThreshold", e.target.value, 2000, 100, 120000)}
                className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex items-center justify-between p-2 border-t border-slate-800 pt-4">
              <div>
                <span className="text-slate-300 block">Forget scanned file cache</span>
                <span className="text-xs text-slate-500">Clears only the Shield cache of already-scanned file fingerprints. It does not delete Results, Quarantine, Exceptions, or History.</span>
              </div>
              <button
                onClick={forgetScannedFiles}
                className="inline-flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700 text-sm"
              >
                <RotateCcw className="w-4 h-4" />
                Forget
              </button>
            </div>
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
            <Bell className="w-5 h-5 text-indigo-400" />
            Notifications
          </div>
          <div className="p-4 space-y-4">
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">When Shield finds a threat</span>
                <span className="text-xs text-slate-500">Choose the real-time Shield action and whether it notifies you.</span>
              </div>
              <select
                value={shieldAction}
                onChange={e => {
                  const action = e.target.value;
                  updateSettings({
                    ...settings,
                    actionOnDetection: action,
                    autoQuarantine: action.startsWith("quarantine"),
                    shieldShowPopup: action === "ask" || action.endsWith("_notify")
                  });
                }}
                className="w-72 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              >
                <option value="ask">Ask me</option>
                <option value="quarantine_notify">Auto quarantine and notify me</option>
                <option value="quarantine_silent">Auto quarantine silently</option>
                <option value="results_notify">Send to Results and notify me</option>
                <option value="results_silent">Send silently to Results</option>
              </select>
            </div>
            <p className="text-xs text-slate-500 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
              {shieldActionDescription[shieldAction]}
            </p>
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">Play sound on Shield notification</span>
                <span className="text-xs text-slate-500">Play a short bundled alert sound when Shield opens a decision or notification popup.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.playSoundOnAlert || false}
                onChange={e => updateSettings({...settings, playSoundOnAlert: e.target.checked})}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
