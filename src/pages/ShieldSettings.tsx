import { useEffect, useState } from "react";
import { Bell, Plus, RotateCcw, SlidersHorizontal, X } from "lucide-react";

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
    await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(nextSettings)
    });
    setSaving(false);
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

  const defaultFolders = [
    { key: 'monitorDownloads', name: 'Downloads Folder', pathLabel: systemPaths?.Downloads },
    { key: 'monitorDesktop', name: 'Desktop Folder', pathLabel: systemPaths?.Desktop },
    { key: 'monitorDocuments', name: 'Documents Folder', pathLabel: systemPaths?.Documents },
  ];
  const browserDownloads = Array.isArray(systemPaths?.BrowserDownloads) ? systemPaths.BrowserDownloads : [];

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Real-Time Shield</h1>
          <p className="text-slate-400">Background protection against new and modified files</p>
        </div>
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
        </div>
      </header>

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
              <label key={folder.key} className="flex items-center justify-between cursor-pointer p-2 hover:bg-slate-800/50 rounded-lg">
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
              </label>
            ))}

            <label className="flex items-center justify-between cursor-pointer p-2 hover:bg-slate-800/50 rounded-lg">
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
            </label>

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
            <label className="flex items-center justify-between cursor-pointer p-2 hover:bg-slate-800/50 rounded-lg">
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
            </label>
            <label className="flex items-center justify-between cursor-pointer p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">Concurrent scans</span>
                <span className="text-xs text-slate-500">Keep this at 1 for lowest disk impact</span>
              </div>
              <input
                type="number"
                min={1}
                max={4}
                value={settings.shieldMaxConcurrentScans ?? 1}
                onChange={e => updateNumberSetting("shieldMaxConcurrentScans", e.target.value, 1, 1, 4)}
                className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              />
            </label>
            <label className="flex items-center justify-between cursor-pointer p-2 hover:bg-slate-800/50 rounded-lg">
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
            </label>
            <label className="flex items-center justify-between cursor-pointer p-2 hover:bg-slate-800/50 rounded-lg">
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
            </label>
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
            <label className="flex items-center justify-between cursor-pointer p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">Show bottom-right popup on file scan</span>
                <span className="text-xs text-slate-500">Displays a small toast when downloading/modifying files</span>
              </div>
              <input 
                type="checkbox" 
                checked={settings.shieldShowPopup} 
                onChange={() => toggle('shieldShowPopup')}
                className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
              />
            </label>
            <label className="flex items-center justify-between cursor-pointer p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">When threat found</span>
                <span className="text-xs text-slate-500">Choose how the real-time shield handles detections</span>
              </div>
              <select
                value={settings.actionOnDetection === "warn" ? "ask" : (settings.actionOnDetection || "ask")}
                onChange={e => updateSettings({ ...settings, actionOnDetection: e.target.value, autoQuarantine: e.target.value === "quarantine" })}
                className="w-56 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              >
                <option value="ask">Ask me</option>
                <option value="quarantine">Auto quarantine</option>
                <option value="results">Send silently to Results</option>
              </select>
            </label>
          </div>
        </section>
      </div>
    </div>
  );
}
