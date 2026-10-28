import { t, localizeText, useLanguage } from "../../../src/lib/i18n";
import { useEffect, useState } from "react";
import { Bell, Cloud, Plus, RotateCcw, Save, SlidersHorizontal, X } from "lucide-react";
import PageHeader from "../../../src/components/PageHeader";
export default function ShieldSettings() {
    useLanguage();
    const [settings, setSettings] = useState<any>(null);
    const [systemPaths, setSystemPaths] = useState<any>(null);
    const [virusTotalCloudStatus, setVirusTotalCloudStatus] = useState<any>(null);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState("");
    useEffect(() => {
        fetch("/api/status").then(r => r.json()).then(d => {
            setSettings(d.settings);
            setVirusTotalCloudStatus(d.virusTotalCloud || null);
        });
        fetch("/api/system-paths").then(r => r.json()).then(d => setSystemPaths(d));
    }, []);
    const updateSettings = async (nextSettings: any) => {
        const patch = getSettingsPatch(settings, nextSettings);
        setSettings(nextSettings);
        setSaving(true);
        await persistSettings(patch);
        setSaving(false);
    };
    const getSettingsPatch = (previousSettings: any, nextSettings: any) => {
        const patch: Record<string, any> = {};
        if (!previousSettings || !nextSettings)
            return patch;
        for (const key of Object.keys(nextSettings)) {
            if (JSON.stringify(previousSettings[key]) !== JSON.stringify(nextSettings[key])) {
                patch[key] = nextSettings[key];
            }
        }
        return patch;
    };
    const persistSettings = async (patch: Record<string, any> = {}, showMessage = false) => {
        if (!patch || Object.keys(patch).length === 0) {
            if (showMessage) {
                setMessage("Shield settings saved.");
                setTimeout(() => setMessage(""), 3000);
            }
            return;
        }
        setSaving(true);
        try {
            await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(patch)
            });
            if (showMessage) {
                setMessage("Shield settings saved.");
                setTimeout(() => setMessage(""), 3000);
            }
        }
        catch (e: any) {
            setMessage(e.message || "Failed to save Shield settings.");
        }
        finally {
            setSaving(false);
        }
    };
    const toggle = (key: string) => {
        if (!settings)
            return;
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
        if (value <= 10)
            return "1-10: Extremely gentle. Idle priority, 1 Shield worker, 100-file total event window, 500 ms pause.";
        if (value <= 20)
            return "11-20: Very gentle. Idle priority, 1 Shield worker, 250-file total event window, 250 ms pause.";
        if (value <= 30)
            return "21-30: Gentle. Below-normal priority, 1 Shield worker, 500-file total event window, 150 ms pause.";
        if (value <= 40)
            return "31-40: Light. Below-normal priority, 1 Shield worker, 1,000-file total event window, 75 ms pause.";
        if (value <= 50)
            return "41-50: Balanced. Below-normal priority, 2 Shield workers, 2,000-file total event window split between workers, 25 ms pause.";
        if (value <= 60)
            return "51-60: Active. Normal priority, 2 Shield workers, 3,000-file total event window split between workers, no pause.";
        if (value <= 70)
            return `61-70: Fast. Normal priority, ${halfCores} Shield workers, 5,000-file total event window split between workers, no pause.`;
        if (value <= 80)
            return `71-80: Very fast. Normal priority, ${threeQuarterCores} Shield workers, 10,000-file total event window split between workers, no pause.`;
        if (value <= 90)
            return `81-90: Maximum minus one core. High priority, ${Math.max(1, allCores - 1)} Shield workers, 15,000-file total event window split between workers, no pause.`;
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
            }
            else if (data.error) {
                console.warn("Folder picker ignored or failed:", data.error);
            }
        }
        catch (e) {
            console.error("Failed to add folder:", e);
        }
    };
    const handleRemoveFolder = (pathToRemove: string) => {
        const folders = Array.isArray(settings.customWatchedFolders) ? settings.customWatchedFolders : [];
        updateSettings({ ...settings, customWatchedFolders: folders.filter((p: string) => p !== pathToRemove) });
    };
    const forgetScannedFiles = async () => {
        if (!confirm(t("shield.forget_the_real_time_shield_scanned_file_cache_existing_files_wil")))
            return;
        setMessage("");
        try {
            const res = await fetch("/api/shield-cache/clear", { method: "POST" });
            const data = await res.json();
            if (!res.ok || !data.success)
                throw new Error(data.error || "Failed to clear cache.");
            setMessage("Scanned file cache cleared.");
        }
        catch (e: any) {
            setMessage(e.message || "Failed to clear cache.");
        }
    };
    if (!settings)
        return <div className="p-8">{t("shield.loading")}</div>;
    const normalizeShieldAction = (value: string) => {
        if (value === "warn")
            return "ask";
        if (value === "quarantine")
            return "quarantine_silent";
        if (value === "results")
            return "results_silent";
        if (["ask", "quarantine_notify", "quarantine_silent", "results_notify", "results_silent"].includes(value))
            return value;
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
    const virusTotalReady = settings.virusTotalCloudEnabled === true &&
        virusTotalCloudStatus?.configured === true;
    const defaultFolders = [
        { key: 'monitorDownloads', name: 'Downloads Folder', pathLabel: systemPaths?.Downloads },
        { key: 'monitorDesktop', name: 'Desktop Folder', pathLabel: systemPaths?.Desktop },
        { key: 'monitorDocuments', name: 'Documents Folder', pathLabel: systemPaths?.Documents },
    ];
    const browserDownloads = Array.isArray(systemPaths?.BrowserDownloads) ? systemPaths.BrowserDownloads : [];
    return (<div className="px-8 max-w-4xl mx-auto space-y-8 pb-20">
      <PageHeader title={t("shield.real_time_shield")} description={t("shield.background_protection_against_new_and_modified_files")} actions={(<div className="flex items-center gap-3">
          <span className={settings.shieldEnabled ? "text-emerald-400 font-medium" : "text-slate-500 font-medium"}>
            {localizeText(settings.shieldEnabled ? "ON" : "OFF")}
          </span>
          <button onClick={() => toggle('shieldEnabled')} className={`relative inline-flex h-7 w-12 items-center rounded-full transition-colors focus:outline-none ${settings.shieldEnabled ? 'bg-emerald-500' : 'bg-slate-700'}`}>
            <span className={`inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${settings.shieldEnabled ? 'translate-x-6' : 'translate-x-1'}`}/>
          </button>
          <button onClick={() => persistSettings({}, true)} disabled={saving} className="inline-flex items-center gap-2 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors">
            <Save className="w-4 h-4"/>
            {localizeText(saving ? "Saving..." : "Save")}
          </button>
        </div>)}/>

      {localizeText(message && (<div className="p-3 bg-slate-900 border border-slate-800 text-slate-300 rounded-md text-sm">
          {localizeText(message)}
        </div>))}

      <div className={`space-y-6 ${!settings.shieldEnabled && 'opacity-50 pointer-events-none'}`}>
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between font-medium text-slate-200">
            <div className="flex items-center gap-2">
               <SlidersHorizontal className="w-5 h-5 text-indigo-400"/>{t("shield.monitored_locations")}</div>
            <button onClick={handleAddFolder} className="flex items-center gap-1 text-xs px-3 py-1.5 bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 rounded-md transition-colors">
                <Plus className="w-3.5 h-3.5"/>{t("shield.add_folder")}</button>
          </div>
          <div className="p-4 space-y-4">
            {localizeText(defaultFolders.map(folder => (<div key={folder.key} className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
                <div>
                    <span className="text-slate-300 block">{localizeText(folder.name)}</span>
                    <span className="text-xs text-slate-500 block">{localizeText(folder.pathLabel || "Loading path...")}</span>
                </div>
                <input type="checkbox" checked={settings[folder.key]} onChange={() => toggle(folder.key)} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
              </div>)))}

            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">{t("shield.browser_download_folders")}</span>
                <span className="text-xs text-slate-500 block">
                  {localizeText(browserDownloads.length > 0
            ? `${browserDownloads.length} installed browser location${browserDownloads.length === 1 ? "" : "s"} detected`
            : "No custom browser download folders detected")}
                </span>
              </div>
              <input type="checkbox" checked={settings.autoDetectBrowserDownloads !== false} onChange={() => toggle('autoDetectBrowserDownloads')} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>

            {localizeText(settings.autoDetectBrowserDownloads !== false && browserDownloads.length > 0 && (<div className="ml-2 mr-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3 space-y-2">
                {localizeText(browserDownloads.map((item: any) => (<div key={`${item.browser}-${item.profile}-${item.path}`} className="flex flex-col gap-0.5">
                    <span className="text-xs font-medium text-slate-400">{localizeText(item.browser)} / {localizeText(item.profile)}</span>
                    <span className="text-xs text-slate-500 font-mono break-all">{localizeText(item.path)}</span>
                  </div>)))}
              </div>))}

            {localizeText(Array.isArray(settings.customWatchedFolders) && settings.customWatchedFolders.length > 0 && (<div className="pt-4 mt-4 border-t border-slate-800">
                    <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 px-2">{t("shield.custom_folders")}</h3>
                    <div className="space-y-2">
                    {localizeText(settings.customWatchedFolders.map((customPath: string) => (<div key={customPath} className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
                            <span className="text-slate-300 text-sm font-mono truncate mr-4">{localizeText(customPath)}</span>
                            <button onClick={() => handleRemoveFolder(customPath)} className="text-slate-500 hover:text-red-400 bg-transparent rounded-full p-1 transition-colors shrink-0" title={t("shield.remove_folder")}>
                                <X className="w-4 h-4"/>
                            </button>
                        </div>)))}
                    </div>
                </div>))}
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
            <SlidersHorizontal className="w-5 h-5 text-indigo-400"/>{t("shield.performance")}</div>
          <div className="p-4 space-y-4">
            <div className="p-2 space-y-3">
              <div className="flex items-center justify-between gap-6">
                <div>
                  <span className="text-slate-300 block">{t("shield.shield_intensity")}</span>
                  <span className="text-xs text-slate-500">{t("shield.current_value")}{localizeText(settings.shieldScanIntensity || 41)}/100</span>
                </div>
                <input type="range" min={1} max={100} value={settings.shieldScanIntensity || 41} onChange={e => updateNumberSetting("shieldScanIntensity", e.target.value, 41, 1, 100)} className="w-1/2 accent-indigo-500"/>
              </div>
              <p className="text-xs text-slate-500 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                {localizeText(shieldIntensityDetails(settings.shieldScanIntensity || 41))}
              </p>
            </div>
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">{t("shield.folder_depth")}</span>
                <span className="text-xs text-slate-500">{t("shield.how_many_levels_below_watched_folders_the_shield_monitors")}</span>
              </div>
              <input type="number" min={0} max={20} value={settings.shieldDepth ?? 1} onChange={e => updateNumberSetting("shieldDepth", e.target.value, 1, 0, 20)} className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"/>
            </div>
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">{t("shield.polling_interval")}</span>
                <span className="text-xs text-slate-500">{t("shield.how_often_clamshield_checks_whether_a_changing_file_has_become_st")}</span>
              </div>
              <input type="number" min={100} max={60000} value={settings.shieldPollInterval || 1000} onChange={e => updateNumberSetting("shieldPollInterval", e.target.value, 1000, 100, 60000)} className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"/>
            </div>
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">{t("shield.stability_threshold")}</span>
                <span className="text-xs text-slate-500">{t("shield.how_long_a_file_must_stop_changing_before_shield_scans_it_higher")}</span>
              </div>
              <input type="number" min={100} max={120000} value={settings.shieldStabilityThreshold || 2000} onChange={e => updateNumberSetting("shieldStabilityThreshold", e.target.value, 2000, 100, 120000)} className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"/>
            </div>
            <div className="flex items-center justify-between p-2 border-t border-slate-800 pt-4">
              <div>
                <span className="text-slate-300 block">{t("shield.forget_scanned_file_cache")}</span>
                <span className="text-xs text-slate-500">{t("shield.clears_only_the_shield_cache_of_already_scanned_file_fingerprints")}</span>
              </div>
              <button onClick={forgetScannedFiles} className="inline-flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700 text-sm">
                <RotateCcw className="w-4 h-4"/>{t("shield.forget")}</button>
            </div>
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
            <Cloud className="w-5 h-5 text-cyan-400"/>{t("shield.cloud_checks")}</div>
          <div className="p-4 space-y-4">
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg gap-6">
              <div>
                <span className="text-slate-300 block">{t("shield.use_virustotal_in_real_time_shield")}</span>
                <span className="text-xs text-slate-500">{t("shield.adds_virustotal_as_a_background_shield_engine")}</span>
                <span className={`block text-xs mt-1 ${virusTotalReady ? "text-emerald-300" : "text-amber-300"}`}>
                  {localizeText(virusTotalReady
            ? "Ready"
            : "Set up VirusTotal Cloud Check first.")}
                </span>
              </div>
              <input type="checkbox" checked={settings.virusTotalShieldBackgroundCheckEnabled === true} onChange={e => updateSettings({
            ...settings,
            virusTotalShieldBackgroundCheckEnabled: e.target.checked,
            virusTotalShieldUploadUnknownEnabled: e.target.checked ? settings.virusTotalShieldUploadUnknownEnabled === true : false
        })} className="w-5 h-5 rounded border-slate-600 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>
            <div className={`space-y-3 p-2 rounded-lg ${settings.virusTotalShieldBackgroundCheckEnabled === true && virusTotalReady ? "hover:bg-slate-800/50" : "opacity-60"}`}>
              <div className="flex items-center justify-between gap-6">
                <div>
                  <span className="text-slate-300 block">{t("shield.upload_files_without_a_virustotal_report")}</span>
                  <span className="text-xs text-slate-500">{t("shield.only_after_the_hash_is_unknown")}</span>
                </div>
                <input type="checkbox" checked={settings.virusTotalShieldUploadUnknownEnabled === true} disabled={!virusTotalReady || settings.virusTotalShieldBackgroundCheckEnabled !== true} onChange={e => updateSettings({ ...settings, virusTotalShieldUploadUnknownEnabled: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-900 bg-slate-800 disabled:cursor-not-allowed"/>
              </div>
              <div className="flex items-center justify-between gap-6">
                <label className="text-sm font-medium text-slate-400">{t("shield.max_upload_size_mb")}</label>
                <input type="number" min={1} max={32} value={settings.virusTotalShieldUploadMaxSizeMb || 20} disabled={!virusTotalReady || settings.virusTotalShieldBackgroundCheckEnabled !== true || settings.virusTotalShieldUploadUnknownEnabled !== true} onChange={e => updateNumberSetting("virusTotalShieldUploadMaxSizeMb", e.target.value, 20, 1, 32)} className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-cyan-500 disabled:cursor-not-allowed"/>
              </div>
            </div>
          </div>
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
            <Bell className="w-5 h-5 text-indigo-400"/>{t("shield.notifications")}</div>
          <div className="p-4 space-y-4">
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">{t("shield.when_shield_finds_a_threat")}</span>
                <span className="text-xs text-slate-500">{t("shield.choose_the_real_time_shield_action_and_whether_it_notifies_you")}</span>
              </div>
              <select value={shieldAction} onChange={e => {
            const action = e.target.value;
            updateSettings({
                ...settings,
                actionOnDetection: action,
                autoQuarantine: action.startsWith("quarantine"),
                shieldShowPopup: action === "ask" || action.endsWith("_notify")
            });
        }} className="w-72 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500">
                <option value="ask">{t("shield.ask_me")}</option>
                <option value="quarantine_notify">{t("shield.auto_quarantine_and_notify_me")}</option>
                <option value="quarantine_silent">{t("shield.auto_quarantine_silently")}</option>
                <option value="results_notify">{t("shield.send_to_results_and_notify_me")}</option>
                <option value="results_silent">{t("shield.send_silently_to_results")}</option>
              </select>
            </div>
            <p className="text-xs text-slate-500 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
              {localizeText(shieldActionDescription[shieldAction])}
            </p>
            <div className="flex items-center justify-between p-2 hover:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-slate-300 block">{t("shield.play_sound_on_shield_notification")}</span>
                <span className="text-xs text-slate-500">{t("shield.play_a_short_bundled_alert_sound_when_shield_opens_a_decision_or")}</span>
              </div>
              <input type="checkbox" checked={settings.playSoundOnAlert || false} onChange={e => updateSettings({ ...settings, playSoundOnAlert: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>
          </div>
        </section>
      </div>
    </div>);
}
