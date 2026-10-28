import LanguageSettings from "./LanguageSettings";
import { t, localizeText, useLanguage } from "../../../src/lib/i18n";
import { useEffect, useRef, useState } from "react";
import { Bug, Save, Folder, Shield, Sliders, ShieldAlert, Heart, RefreshCw, ChevronDown, Cloud, KeyRound, Trash2 } from "lucide-react";
type ActionNotice = {
    kind: "success" | "warning" | "error" | "info";
    text: string;
};
type SettingsSection = "system" | "scanner" | "cloud" | "diagnostics" | "paths";
function getScrollableParent(element: HTMLElement) {
    let parent = element.parentElement;
    while (parent) {
        const style = window.getComputedStyle(parent);
        if (/(auto|scroll|overlay)/.test(style.overflowY) && parent.scrollHeight > parent.clientHeight) {
            return parent;
        }
        parent = parent.parentElement;
    }
    return null;
}
export default function SettingsPage() {
    useLanguage();
    const [settings, setSettings] = useState<any>(null);
    const [defenderStatus, setDefenderStatus] = useState<any>(null);
    const [saving, setSaving] = useState(false);
    const [notice, setNotice] = useState<ActionNotice | null>(null);
    const [defenderActionPending, setDefenderActionPending] = useState<"pause" | "restore" | "refresh" | null>(null);
    const [contextMenuPending, setContextMenuPending] = useState(false);
    const [virusTotalApiKey, setVirusTotalApiKey] = useState("");
    const [virusTotalCloudStatus, setVirusTotalCloudStatus] = useState<any>(null);
    const [virusTotalPending, setVirusTotalPending] = useState<"save" | "disconnect" | null>(null);
    const [openSection, setOpenSection] = useState<SettingsSection | null>("system");
    const autosaveTimerRef = useRef<number | null>(null);
    const pendingAutosavePatchRef = useRef<Record<string, any>>({});
    const baselineSettingsRef = useRef<any>(null);
    const stickyHeaderRef = useRef<HTMLDivElement | null>(null);
    const pendingScrollSectionRef = useRef<SettingsSection | null>(null);
    const sectionHeaderRefs = useRef<Record<SettingsSection, HTMLButtonElement | null>>({
        system: null,
        scanner: null,
        cloud: null,
        diagnostics: null,
        paths: null
    });
    useEffect(() => {
        fetch("/api/settings").then(r => r.json()).then(d => {
            setSettings(d.settings);
            baselineSettingsRef.current = d.settings;
            setVirusTotalCloudStatus(d.virusTotalCloud || null);
        });
        fetch("/api/defender-status").then(r => r.json()).then(d => setDefenderStatus(d)).catch(() => { });
        return () => {
            if (autosaveTimerRef.current)
                window.clearTimeout(autosaveTimerRef.current);
        };
    }, []);
    useEffect(() => {
        if (!openSection || pendingScrollSectionRef.current !== openSection)
            return;
        let frame = 0;
        let secondFrame = 0;
        frame = window.requestAnimationFrame(() => {
            secondFrame = window.requestAnimationFrame(() => {
                const header = sectionHeaderRefs.current[openSection];
                if (!header)
                    return;
                const stickyHeight = stickyHeaderRef.current?.getBoundingClientRect().height || 0;
                const scrollParent = getScrollableParent(header);
                if (scrollParent) {
                    const headerRect = header.getBoundingClientRect();
                    const parentRect = scrollParent.getBoundingClientRect();
                    const top = headerRect.top - parentRect.top + scrollParent.scrollTop - stickyHeight - 12;
                    scrollParent.scrollTo({ top: Math.max(0, top), behavior: "smooth" });
                }
                else {
                    const top = header.getBoundingClientRect().top + window.scrollY - stickyHeight - 12;
                    window.scrollTo({ top: Math.max(0, top), behavior: "smooth" });
                }
                pendingScrollSectionRef.current = null;
            });
        });
        return () => {
            window.cancelAnimationFrame(frame);
            window.cancelAnimationFrame(secondFrame);
        };
    }, [openSection]);
    const refreshDefenderStatus = async () => {
        try {
            const res = await fetch("/api/defender-status");
            const data = await res.json();
            if (!res.ok)
                throw new Error(data?.error || "Could not read Microsoft Defender status.");
            setDefenderStatus(data);
            return data;
        }
        catch (e: any) {
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
        }
        catch (e: any) {
            setNotice({ kind: "error", text: "Could not open Windows Security: " + e.message });
        }
    };
    const runDefenderAction = async (action: "pause" | "restore") => {
        setDefenderActionPending(action);
        try {
            const endpoint = action === "pause" ? "/api/stop-defender" : "/api/restore-defender";
            const res = await fetch(endpoint, { method: "POST" });
            const data = await res.json();
            setNotice(defenderResultNotice(data, action === "pause"
                ? "Microsoft Defender real-time protection is paused."
                : "Microsoft Defender preferences were restored."));
            await refreshDefenderStatus();
        }
        catch (e: any) {
            setNotice({ kind: "error", text: `Could not ${action} Microsoft Defender: ${e.message}` });
        }
        finally {
            setDefenderActionPending(null);
        }
    };
    const configureWindowsContextMenu = async (enabled: boolean) => {
        setContextMenuPending(true);
        try {
            const response = await fetch("/api/windows-context-menu/configure", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enabled })
            });
            const data = await response.json().catch(() => ({}));
            if (!response.ok || !data.success) {
                throw new Error(data.error || "Could not configure the Windows Context Menu.");
            }
            if (data.settings) {
                setSettings(data.settings);
                baselineSettingsRef.current = data.settings;
            }
            else {
                const nextSettings = { ...settings, windowsContextMenuEnabled: enabled };
                setSettings(nextSettings);
                baselineSettingsRef.current = nextSettings;
            }
            setNotice({ kind: "success", text: data.message || (enabled ? "Windows Context Menu enabled." : "Windows Context Menu disabled.") });
        }
        catch (e: any) {
            setNotice({ kind: "error", text: e.message || "Could not configure the Windows Context Menu." });
        }
        finally {
            setContextMenuPending(false);
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
        updateSettings({ ...settings, [key]: nextValue });
    };
    const getChangedSettingsPatch = (previousSettings: any, nextSettings: any) => {
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
    const scheduleAutosave = (patch: Record<string, any>) => {
        if (Object.keys(patch).length === 0)
            return;
        pendingAutosavePatchRef.current = { ...pendingAutosavePatchRef.current, ...patch };
        if (autosaveTimerRef.current)
            window.clearTimeout(autosaveTimerRef.current);
        autosaveTimerRef.current = window.setTimeout(() => {
            const pendingPatch = pendingAutosavePatchRef.current;
            pendingAutosavePatchRef.current = {};
            saveSettings({ silent: true, patch: pendingPatch });
        }, 350);
    };
    const updateSettings = (nextSettings: any) => {
        const patch = getChangedSettingsPatch(settings, nextSettings);
        setSettings(nextSettings);
        scheduleAutosave(patch);
    };
    const saveSettings = async (options: {
        silent?: boolean;
        patch?: Record<string, any>;
    } = {}) => {
        if (!options.patch && autosaveTimerRef.current) {
            window.clearTimeout(autosaveTimerRef.current);
            autosaveTimerRef.current = null;
        }
        const settingsToSave = options.patch || {
            ...pendingAutosavePatchRef.current,
            ...getChangedSettingsPatch(baselineSettingsRef.current, settings)
        };
        if (!options.patch)
            pendingAutosavePatchRef.current = {};
        if (Object.keys(settingsToSave).length === 0) {
            if (!options.silent)
                setNotice({ kind: "success", text: "Settings saved successfully." });
            return;
        }
        setSaving(true);
        if (!options.silent)
            setNotice(null);
        try {
            const res = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(settingsToSave)
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok)
                throw new Error(data.error || "Settings save failed.");
            if (data.settings && !options.silent) {
                setSettings(data.settings);
                baselineSettingsRef.current = data.settings;
            }
            else {
                baselineSettingsRef.current = { ...(baselineSettingsRef.current || {}), ...settingsToSave };
            }
            if (!options.silent)
                setNotice({ kind: "success", text: "Settings saved successfully." });
        }
        catch (e: any) {
            pendingAutosavePatchRef.current = { ...settingsToSave, ...pendingAutosavePatchRef.current };
            setNotice({ kind: "error", text: "Failed to save settings: " + e.message });
        }
        setSaving(false);
        if (!options.silent)
            setTimeout(() => setNotice(null), 3000);
    };
    const saveVirusTotalCloud = async () => {
        setVirusTotalPending("save");
        try {
            const res = await fetch("/api/virustotal-cloud/configure", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    apiKey: virusTotalApiKey,
                    enabled: settings.virusTotalCloudEnabled !== false,
                    autoRefineEnabled: settings.virusTotalAutoRefineEnabled === true
                })
            });
            const data = await res.json();
            if (!res.ok || !data.success)
                throw new Error(data.error || "Could not configure VirusTotal Cloud Check.");
            setVirusTotalApiKey("");
            setVirusTotalCloudStatus(data.virusTotalCloud);
            setSettings({
                ...settings,
                virusTotalCloudEnabled: data.virusTotalCloud?.enabled === true,
                virusTotalAutoRefineEnabled: data.virusTotalCloud?.autoRefineEnabled === true,
                virusTotalResultsUploadUnknownEnabled: data.virusTotalCloud?.resultsUploadUnknownEnabled === true,
                virusTotalShieldUploadUnknownEnabled: data.virusTotalCloud?.shieldUploadUnknownEnabled === true
            });
            setNotice({ kind: "success", text: data.message || "VirusTotal Cloud Check configured." });
        }
        catch (e: any) {
            setNotice({ kind: "error", text: e.message || "Could not configure VirusTotal Cloud Check." });
        }
        finally {
            setVirusTotalPending(null);
        }
    };
    const disconnectVirusTotalCloud = async () => {
        setVirusTotalPending("disconnect");
        try {
            const res = await fetch("/api/virustotal-cloud/disconnect", { method: "POST" });
            const data = await res.json();
            if (!res.ok || !data.success)
                throw new Error(data.error || "Could not remove the VirusTotal API key.");
            setVirusTotalApiKey("");
            setVirusTotalCloudStatus(data.virusTotalCloud);
            setSettings({ ...settings, virusTotalCloudEnabled: false, virusTotalAutoRefineEnabled: false, virusTotalResultsUploadUnknownEnabled: false, virusTotalShieldUploadUnknownEnabled: false });
            setNotice({ kind: "success", text: data.message || "VirusTotal Cloud Check disabled." });
        }
        catch (e: any) {
            setNotice({ kind: "error", text: e.message || "Could not remove the VirusTotal API key." });
        }
        finally {
            setVirusTotalPending(null);
        }
    };
    if (!settings)
        return <div className="p-8">{t("shield.loading")}</div>;
    const tamperProtectionOn = defenderStatus?.IsTamperProtected === true;
    const noticeClass = notice?.kind === "success"
        ? "bg-emerald-500/20 border-emerald-500/30 text-emerald-300"
        : notice?.kind === "warning"
            ? "bg-amber-500/15 border-amber-500/30 text-amber-200"
            : notice?.kind === "error"
                ? "bg-rose-500/15 border-rose-500/30 text-rose-200"
                : "bg-indigo-500/15 border-indigo-500/30 text-indigo-200";
    const toggleSection = (section: SettingsSection) => {
        setOpenSection(current => {
            const next = current === section ? null : section;
            pendingScrollSectionRef.current = next;
            return next;
        });
    };
    const scanIntensityDetails = (value: number) => {
        const cores = typeof navigator !== "undefined" && navigator.hardwareConcurrency ? navigator.hardwareConcurrency : 1;
        const allCores = Math.min(32, Math.max(1, cores));
        const halfCores = Math.min(allCores, Math.max(2, Math.ceil(cores * 0.5)));
        const threeQuarterCores = Math.min(allCores, Math.max(2, Math.ceil(cores * 0.75)));
        if (value <= 10)
            return "1-10: Extremely gentle. Idle priority, 1 worker, 100-file total batch window, 500 ms pause.";
        if (value <= 20)
            return "11-20: Very gentle. Idle priority, 1 worker, 250-file total batch window, 250 ms pause.";
        if (value <= 30)
            return "21-30: Gentle. Below-normal priority, 1 worker, 500-file total batch window, 150 ms pause.";
        if (value <= 40)
            return "31-40: Light. Below-normal priority, 1 worker, 1,000-file total batch window, 75 ms pause.";
        if (value <= 50)
            return "41-50: Balanced. Below-normal priority, 2 workers, 2,000-file total batch window split between workers, 25 ms pause.";
        if (value <= 60)
            return "51-60: Active. Normal priority, 2 workers, 3,000-file total batch window split between workers, no pause.";
        if (value <= 70)
            return `61-70: Fast. Normal priority, ${halfCores} workers, 5,000-file total batch window split between workers, no pause.`;
        if (value <= 80)
            return `71-80: Very fast. Normal priority, ${threeQuarterCores} workers, 10,000-file total batch window split between workers, no pause.`;
        if (value <= 90)
            return `81-90: Maximum minus one core. High priority, ${Math.max(1, allCores - 1)} workers, 15,000-file total batch window split between workers, no pause.`;
        return `91-100: Maximum. High priority, all ${allCores} logical cores, 25,000-file total batch window split between workers, no pause. The PC may be hard to use until the scan finishes.`;
    };
    const scanMemoryWarning = (value: number) => {
        const deviceMemory = typeof navigator !== "undefined" && "deviceMemory" in navigator ? Number((navigator as any).deviceMemory) : 0;
        if (settings.offloadToMemory || !deviceMemory || deviceMemory >= 8 || value <= 50)
            return "";
        return `RAM warning: this PC reports about ${deviceMemory} GB RAM. High parallel clamscan intensity can load signatures in multiple workers. Offload to memory uses clamdscan and is safer for RAM.`;
    };
    return (<div className="px-8 max-w-4xl mx-auto space-y-6 pb-20">
      <div ref={stickyHeaderRef} className="sticky top-0 z-30 -mx-8 px-8 py-5 bg-slate-950/95 backdrop-blur border-b border-slate-800/80 space-y-3">
        <header className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-white mb-1">{t("updates.settings")}</h1>
            <p className="text-slate-400">{t("settings.configure_clamav_paths_and_scanner_options")}</p>
          </div>
          <button onClick={() => saveSettings()} disabled={saving} className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors shrink-0">
            <Save className="w-4 h-4"/>
            {localizeText(saving ? "Saving..." : "Save Config")}
          </button>
        </header>
        {localizeText(notice && <div className={`p-3 border rounded-md text-sm ${noticeClass}`}>{localizeText(notice.text)}</div>)}
      </div>

      <div className="space-y-6">
        <LanguageSettings />
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button ref={element => { sectionHeaderRefs.current.system = element; }} type="button" onClick={() => toggleSection("system")} aria-expanded={openSection === "system"} className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${openSection === "system" ? "border-b border-slate-800" : ""}`}>
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-indigo-400"/>{t("settings.system_integration")}</div>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "system" ? "rotate-180" : ""}`}/>
          </button>
          {localizeText(openSection === "system" && (<div className="p-6 space-y-4">
            <div className="flex items-center justify-between py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">{t("settings.run_clamshield_on_startup")}</span>
                <span className="text-slate-500 text-xs">{t("settings.automatically_launch_clamshield_background_service_when_you_sign")}</span>
              </div>
              <input type="checkbox" checked={settings.runOnStartup || false} onChange={e => updateSettings({ ...settings, runOnStartup: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">{t("settings.start_minimized_to_tray")}</span>
                <span className="text-slate-500 text-xs">{t("settings.open_clamshield_as_a_tray_icon_without_showing_the_main_window")}</span>
              </div>
              <input type="checkbox" checked={settings.startMinimized || false} onChange={e => updateSettings({ ...settings, startMinimized: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">{t("settings.windows_context_menu")}</span>
                <span className="text-slate-500 text-xs">{t("settings.adds_clamshield_scan_and_exception_actions_to_file_explorer_right")}</span>
              </div>
              <input type="checkbox" checked={settings.windowsContextMenuEnabled === true} disabled={contextMenuPending} onChange={e => configureWindowsContextMenu(e.target.checked)} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"/>
            </div>

            <h3 className="text-slate-200 font-medium pt-2 block">{t("settings.windows_security")}</h3>
            <p className="text-sm text-slate-400">{t("settings.clamshield_runs_alongside_microsoft_defender_by_default_clamshiel")}</p>
            <div className={`flex items-center justify-between py-2 border-t border-slate-800 pt-4 ${tamperProtectionOn ? "opacity-60" : ""}`} title={tamperProtectionOn ? t("settings.open_windows_security_and_disable_tamper_protection_first") : undefined}>
              <div>
                <span className="text-slate-200 font-medium block">{t("settings.automatically_keep_defender_paused")}</span>
                <span className="text-slate-500 text-xs">{t("settings.optional_only_works_when_windows_permits_the_change_and_tamper_pr")}</span>
              </div>
              <input type="checkbox" checked={settings.autoDisableDefender === true} disabled={tamperProtectionOn} onChange={e => updateSettings({ ...settings, autoDisableDefender: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800 disabled:cursor-not-allowed"/>
            </div>
            {localizeText(settings.autoDisableDefender === true && (<div className="flex items-center justify-between">
                <label className="text-sm font-medium text-slate-400 block w-1/3">{t("settings.re_apply_every_minutes")}</label>
                <input type="number" min={1} max={1440} value={settings.defenderEnforceIntervalMinutes || 5} onChange={e => updateNumberSetting("defenderEnforceIntervalMinutes", e.target.value, 5, 1, 1440)} className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"/>
              </div>))}
            <div className="flex items-center justify-between py-2 border-t border-slate-800 pt-4">
              <div>
                <span className="text-slate-200 font-medium block">{t("settings.exclude_clamshield_yara_and_quarantine_from_defender")}</span>
                <span className="text-slate-500 text-xs">{t("settings.helps_prevent_duplicate_handling_of_rule_files_and_quarantined_it")}</span>
              </div>
              <input type="checkbox" checked={settings.defenderCompatibilityExclusionsEnabled === true} onChange={e => updateSettings({ ...settings, defenderCompatibilityExclusionsEnabled: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>
            <div className="flex items-start gap-2 bg-slate-800/50 p-3 rounded-lg border border-indigo-500/20 text-indigo-200/80 text-xs">
              <ShieldAlert className="w-4 h-4 shrink-0 text-indigo-400 mt-0.5"/>
              <p>
                <strong>{t("settings.windows_controls_this_setting")}</strong>{t("settings.tamper_protection_blocks_apps_from_changing_protected_microsoft_d")}</p>
            </div>
            {localizeText(tamperProtectionOn && (<div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-sm text-amber-100 space-y-3">
                <div className="flex items-start gap-3">
                  <ShieldAlert className="w-5 h-5 shrink-0 text-amber-400 mt-0.5"/>
                  <div>
                    <p className="font-semibold text-amber-300">{t("settings.action_required_before_defender_can_be_paused")}</p>
                    <ol className="mt-2 list-decimal list-inside space-y-1 text-amber-100/80">
                      <li>{t("settings.open_windows_security")}</li>
                      <li>{t("settings.select_virus_threat_protection_then_manage_settings")}</li>
                      <li>{t("settings.turn_tamper_protection_off")}</li>
                      <li>{t("settings.return_here_and_click_check_again")}</li>
                    </ol>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button onClick={openWindowsSecurity} className="px-3 py-2 bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-lg font-semibold transition-colors text-xs">{t("settings.open_tamper_protection_settings")}</button>
                  <button onClick={checkTamperProtection} disabled={defenderActionPending !== null} className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors text-xs">
                    <RefreshCw className={`w-3.5 h-3.5 ${defenderActionPending === "refresh" ? "animate-spin" : ""}`}/>
                    {localizeText(defenderActionPending === "refresh" ? "Checking..." : "Check again")}
                  </button>
                </div>
              </div>))}
            {localizeText(defenderStatus?.Supported !== false && (<div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">{t("settings.defender_real_time_protection")}</span>
                  <span className={defenderStatus?.RealTimeProtectionEnabled === false ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                    {localizeText(defenderStatus?.RealTimeProtectionEnabled === false
                    ? "Paused"
                    : defenderStatus?.RealTimeProtectionEnabled === true ? "Active" : "Unknown")}
                  </span>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">{t("settings.tamper_protection")}</span>
                  <span className={defenderStatus?.IsTamperProtected ? "text-amber-400 font-medium" : "text-slate-300 font-medium"}>
                    {localizeText(defenderStatus?.IsTamperProtected === null || defenderStatus?.IsTamperProtected === undefined
                    ? "Unknown"
                    : defenderStatus.IsTamperProtected ? "On" : "Off")}
                  </span>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">{t("settings.clamshield_mode")}</span>
                  <span className={defenderStatus?.RealTimeProtectionEnabled === false ? "text-emerald-400 font-medium" : "text-indigo-300 font-medium"}>
                    {localizeText(defenderStatus?.RealTimeProtectionEnabled === false ? "Defender paused" : "Side-by-side")}
                  </span>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">{t("settings.cloud_delivered_protection")}</span>
                  <span className={defenderStatus?.MAPSReporting === 0 ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                    {localizeText(defenderStatus?.MAPSReporting === 0
                    ? "Off"
                    : defenderStatus?.MAPSReporting === null || defenderStatus?.MAPSReporting === undefined ? "Unknown" : "On")}
                  </span>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">{t("settings.automatic_sample_submission")}</span>
                  <span className={defenderStatus?.SubmitSamplesConsent === 2 ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                    {localizeText(defenderStatus?.SubmitSamplesConsent === 2
                    ? "Never send"
                    : defenderStatus?.SubmitSamplesConsent === null || defenderStatus?.SubmitSamplesConsent === undefined ? "Unknown" : "Enabled or prompt")}
                  </span>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-slate-500 block mb-1">{t("settings.scheduled_defender_scans")}</span>
                  <span className={defenderStatus?.ScanScheduleDay === 8 ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                    {localizeText(defenderStatus?.ScanScheduleDay === 8
                    ? "Off"
                    : defenderStatus?.ScanScheduleDay === null || defenderStatus?.ScanScheduleDay === undefined ? "Unknown" : "Enabled")}
                  </span>
                </div>
              </div>))}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <div className="relative group">
                <button onClick={() => runDefenderAction("pause")} disabled={tamperProtectionOn || defenderActionPending !== null} className="px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:bg-slate-700 disabled:text-slate-400 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors text-sm">
                  {localizeText(defenderActionPending === "pause" ? "Pausing..." : "Pause Defender")}
                </button>
                {localizeText(tamperProtectionOn && (<div role="tooltip" className="pointer-events-none absolute left-1/2 bottom-full z-20 mb-2 w-64 -translate-x-1/2 rounded-lg border border-amber-500/30 bg-slate-950 px-3 py-2 text-center text-xs leading-relaxed text-amber-200 opacity-0 shadow-xl transition-opacity group-hover:opacity-100">{t("settings.open_windows_security_and_disable_tamper_protection_first")}<span className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-slate-950"/>
                  </div>))}
              </div>
              <button onClick={openWindowsSecurity} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg font-medium transition-colors text-sm">{t("settings.open_defender_settings")}</button>
              <button onClick={() => runDefenderAction("restore")} disabled={defenderActionPending !== null} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors text-sm">
                {localizeText(defenderActionPending === "restore" ? "Restoring..." : "Restore Defender")}
              </button>
            </div>
          </div>))}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button ref={element => { sectionHeaderRefs.current.cloud = element; }} type="button" onClick={() => toggleSection("cloud")} aria-expanded={openSection === "cloud"} className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${openSection === "cloud" ? "border-b border-slate-800" : ""}`}>
            <div className="flex items-center gap-2">
              <Cloud className="w-5 h-5 text-sky-400"/>{t("shield.cloud_checks")}</div>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "cloud" ? "rotate-180" : ""}`}/>
          </button>
          {localizeText(openSection === "cloud" && (<div className="p-6 space-y-5">
            <div className="flex items-start justify-between gap-6 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">{t("settings.virustotal_cloud_check")}</span>
                <div className="mt-2 flex flex-wrap items-center gap-3 text-xs">
                  <span className={virusTotalCloudStatus?.configured ? "text-emerald-300" : "text-amber-300"}>
                    {localizeText(virusTotalCloudStatus?.configured ? "API key saved locally in Windows secure storage." : "API key not configured.")}
                  </span>
                  {localizeText(!virusTotalCloudStatus?.configured && (<a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener noreferrer" className="text-sky-300 hover:text-sky-200">{t("settings.get_api_key")}</a>))}
                </div>
              </div>
              <input type="checkbox" checked={settings.virusTotalCloudEnabled === true} onChange={e => updateSettings({
                ...settings,
                virusTotalCloudEnabled: e.target.checked,
                virusTotalAutoRefineEnabled: e.target.checked ? settings.virusTotalAutoRefineEnabled === true : false,
                virusTotalResultsUploadUnknownEnabled: e.target.checked ? settings.virusTotalResultsUploadUnknownEnabled === true : false,
                virusTotalShieldBackgroundCheckEnabled: e.target.checked ? settings.virusTotalShieldBackgroundCheckEnabled === true : false,
                virusTotalShieldUploadUnknownEnabled: e.target.checked ? settings.virusTotalShieldUploadUnknownEnabled === true : false
            })} className="mt-1 w-5 h-5 rounded border-slate-600 text-sky-500 focus:ring-sky-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>
            <div className="flex items-start justify-between gap-6 border-b border-slate-800 pb-4">
              <div>
                <label htmlFor="virustotal-limit-warnings" className="text-slate-200 font-medium block">{t("settings.show_virustotal_limit_warnings")}</label>
                <span className="text-slate-500 text-xs">{t("settings.ask_before_checking_more_than_4_files_and_show_the_estimated_time")}</span>
              </div>
              <input id="virustotal-limit-warnings" type="checkbox" checked={settings.virusTotalShowLimitWarnings !== false} onChange={e => updateSettings({ ...settings, virusTotalShowLimitWarnings: e.target.checked })} className="mt-1 w-5 h-5 rounded border-slate-600 text-sky-500 focus:ring-sky-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>
            <div className="flex items-start justify-between gap-6 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">{t("settings.false_positive_refinement_via_virustotal")}</span>
                <span className="text-slate-500 text-xs">{t("settings.automatically_labels_new_results_findings_with_a_virustotal_verdi")}</span>
              </div>
              <input type="checkbox" checked={settings.virusTotalAutoRefineEnabled === true} disabled={settings.virusTotalCloudEnabled !== true} onChange={e => updateSettings({ ...settings, virusTotalAutoRefineEnabled: e.target.checked })} className="mt-1 w-5 h-5 rounded border-slate-600 text-sky-500 focus:ring-sky-500 focus:ring-offset-slate-900 bg-slate-800 disabled:opacity-50"/>
            </div>
            <div className={`space-y-3 border-b border-slate-800 pb-4 ${settings.virusTotalCloudEnabled === true ? "" : "opacity-60"}`}>
              <div className="flex items-start justify-between gap-6">
                <div>
                  <span className="text-slate-200 font-medium block">{t("settings.upload_results_files_without_a_vt_report")}</span>
                  <span className="text-slate-500 text-xs">{t("settings.only_after_virustotal_has_no_report_for_the_hash")}</span>
                </div>
                <input type="checkbox" checked={settings.virusTotalResultsUploadUnknownEnabled === true} disabled={settings.virusTotalCloudEnabled !== true} onChange={e => updateSettings({ ...settings, virusTotalResultsUploadUnknownEnabled: e.target.checked })} className="mt-1 w-5 h-5 rounded border-slate-600 text-sky-500 focus:ring-sky-500 focus:ring-offset-slate-900 bg-slate-800 disabled:opacity-50"/>
              </div>
              <div className="flex items-center justify-between gap-6">
                <label className="text-sm font-medium text-slate-400">{t("shield.max_upload_size_mb")}</label>
                <input type="number" min={1} max={32} value={settings.virusTotalResultsUploadMaxSizeMb || 20} disabled={settings.virusTotalCloudEnabled !== true || settings.virusTotalResultsUploadUnknownEnabled !== true} onChange={e => updateNumberSetting("virusTotalResultsUploadMaxSizeMb", e.target.value, 20, 1, 32)} className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-sky-500 disabled:cursor-not-allowed"/>
              </div>
            </div>
            <div className="grid md:grid-cols-[1fr_auto_auto] gap-3 items-end">
              <label className="block">
                <span className="text-xs font-medium text-slate-400">{t("settings.virustotal_api_key")}</span>
                <input type="password" value={virusTotalApiKey} onChange={e => setVirusTotalApiKey(e.target.value)} placeholder={virusTotalCloudStatus?.configured ? t("settings.leave_blank_to_keep_the_saved_key") : t("settings.paste_your_virustotal_api_key")} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-sky-500"/>
              </label>
              <button type="button" onClick={saveVirusTotalCloud} disabled={virusTotalPending !== null || (!virusTotalCloudStatus?.configured && !virusTotalApiKey.trim())} className="inline-flex items-center justify-center gap-2 px-4 py-2 bg-sky-700 hover:bg-sky-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors">
                {localizeText(virusTotalPending === "save" ? <RefreshCw className="w-4 h-4 animate-spin"/> : <KeyRound className="w-4 h-4"/>)}{t("shield.save")}</button>
              <button type="button" onClick={disconnectVirusTotalCloud} disabled={virusTotalPending !== null || !virusTotalCloudStatus?.configured} className="inline-flex items-center justify-center gap-2 px-4 py-2 bg-slate-800 hover:bg-rose-950/60 disabled:opacity-50 disabled:cursor-not-allowed text-slate-300 hover:text-rose-300 rounded-lg text-sm font-medium transition-colors">
                <Trash2 className="w-4 h-4"/>{t("settings.remove")}</button>
            </div>
          </div>))}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button ref={element => { sectionHeaderRefs.current.scanner = element; }} type="button" onClick={() => toggleSection("scanner")} aria-expanded={openSection === "scanner"} className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${openSection === "scanner" ? "border-b border-slate-800" : ""}`}>
            <span className="flex items-center gap-2">
              <Sliders className="w-5 h-5 text-indigo-400"/>{t("settings.scanner_options")}</span>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "scanner" ? "rotate-180" : ""}`}/>
          </button>
          {localizeText(openSection === "scanner" && (<div className="p-6 space-y-4">
            <div className="flex items-center justify-between py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">{t("settings.offload_clamshield_to_memory")}</span>
                <span className="text-slate-500 text-xs">{t("settings.larger_memory_footprint_1gb_ram_less_cpu_overhead")}</span>
              </div>
              <input type="checkbox" checked={settings.offloadToMemory || false} onChange={e => updateSettings({ ...settings, offloadToMemory: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>

            <div className="border-t border-slate-800 pt-4 space-y-3">
              <div className="flex items-center justify-between gap-6">
                <div className="w-1/3 pr-4">
                  <label className="text-sm font-medium text-slate-400 block">{t("settings.on_demand_intensity")}</label>
                  <span className="text-xs text-slate-500">{t("shield.current_value")}{localizeText(settings.manualScanIntensity || 81)}/100</span>
                </div>
                <input type="range" min={1} max={100} value={settings.manualScanIntensity || 81} onChange={e => updateNumberSetting("manualScanIntensity", e.target.value, 81, 1, 100)} className="w-2/3 accent-indigo-500"/>
              </div>
              <p className="text-xs text-slate-500 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                {localizeText(scanIntensityDetails(settings.manualScanIntensity || 81))}
              </p>
              {localizeText(scanMemoryWarning(settings.manualScanIntensity || 81) && (<p className="text-xs text-amber-200 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
                  {localizeText(scanMemoryWarning(settings.manualScanIntensity || 81))}
                </p>))}
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between gap-6">
                <div className="w-1/3 pr-4">
                  <label className="text-sm font-medium text-slate-400 block">{t("settings.scheduled_intensity")}</label>
                  <span className="text-xs text-slate-500">{t("shield.current_value")}{localizeText(settings.scheduledScanIntensity || 81)}/100</span>
                </div>
                <input type="range" min={1} max={100} value={settings.scheduledScanIntensity || 81} onChange={e => updateNumberSetting("scheduledScanIntensity", e.target.value, 81, 1, 100)} className="w-2/3 accent-indigo-500"/>
              </div>
              <p className="text-xs text-slate-500 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                {localizeText(scanIntensityDetails(settings.scheduledScanIntensity || 81))}
              </p>
              {localizeText(scanMemoryWarning(settings.scheduledScanIntensity || 81) && (<p className="text-xs text-amber-200 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
                  {localizeText(scanMemoryWarning(settings.scheduledScanIntensity || 81))}
                </p>))}
            </div>

            <div className="pt-4 border-t border-slate-800 space-y-4">
              <div>
                <h3 className="text-slate-200 font-medium">{t("settings.when_a_virus_is_found")}</h3>
                <p className="text-xs text-slate-500 mt-1">{t("settings.actions_and_final_warning_popup_for_on_demand_and_scheduled_scans")}</p>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-slate-300 text-sm mb-1 block">{t("settings.send_scanned_items_to")}</span>
                <select value={settings.scanDetectionAction || "results"} onChange={e => updateSettings({ ...settings, scanDetectionAction: e.target.value })} className="w-1/2 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500">
                  <option value="results">{t("settings.results_checklist")}</option>
                  <option value="quarantine">{t("results.quarantine")}</option>
                </select>
              </div>
              <div className="flex items-center justify-between py-2">
                <div>
                  <span className="text-slate-200 font-medium block">{t("settings.warn_me_with_a_popup_at_the_end_of_the_scan")}</span>
                  <span className="text-slate-500 text-xs">{t("settings.shows_a_summary_popup_after_a_scan_finishes_with_detections_and_w")}</span>
                </div>
                <input type="checkbox" checked={settings.scanCompletionPopupEnabled !== false} onChange={e => updateSettings({ ...settings, scanCompletionPopupEnabled: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-slate-800 pt-4">
              <label className="text-sm font-medium text-slate-400 block w-1/3">{t("settings.max_file_size_mb")}</label>
              <input type="number" value={settings.maxFileSize} onChange={e => updateNumberSetting("maxFileSize", e.target.value, 50, 1, 4096)} className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"/>
            </div>

            {localizeText(['scanArchives', 'recursive', 'followSymlinks'].map(key => (<div key={key} className="flex items-center justify-between py-2">
                <span className="text-slate-300 capitalize text-sm">{localizeText(key.replace(/([A-Z])/g, ' $1').trim())}</span>
                <input type="checkbox" checked={settings[key]} onChange={e => updateSettings({ ...settings, [key]: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
              </div>)))}

            <div className="pt-4 border-t border-slate-800 space-y-4">
              <div>
                <h3 className="text-slate-200 font-medium">{t("settings.yara_scanning")}</h3>
                <p className="text-xs text-slate-500 mt-1">{t("settings.runtime_limits_used_when_the_scanner_evaluates_files_with_local_y")}</p>
              </div>
              <div className="flex items-center justify-between gap-4 py-2">
                <div>
                  <span className="text-slate-200 font-medium block">{t("settings.enable_yara_scanning")}</span>
                  <span className="text-slate-500 text-xs">{t("settings.use_local_yara_rules_during_manual_scheduled_and_shield_scans")}</span>
                </div>
                <input type="checkbox" checked={settings.yaraEnabled !== false} onChange={e => updateSettings({ ...settings, yaraEnabled: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
              </div>
              <div className="grid sm:grid-cols-2 gap-4">
                <label className="block">
                  <span className="text-xs font-medium text-slate-400">{t("settings.timeout_seconds")}</span>
                  <input type="number" min={1} max={3600} value={settings.yaraTimeoutSeconds || 15} onChange={e => updateNumberSetting("yaraTimeoutSeconds", e.target.value, 15, 1, 3600)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"/>
                </label>
                <label className="block">
                  <span className="text-xs font-medium text-slate-400">{t("settings.max_file_size_mb_2cf191d")}</span>
                  <input type="number" min={1} max={4096} value={settings.yaraMaxFileSize || 50} onChange={e => updateNumberSetting("yaraMaxFileSize", e.target.value, 50, 1, 4096)} className="mt-2 w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"/>
                </label>
              </div>
            </div>
          </div>))}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button ref={element => { sectionHeaderRefs.current.diagnostics = element; }} type="button" onClick={() => toggleSection("diagnostics")} aria-expanded={openSection === "diagnostics"} className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${openSection === "diagnostics" ? "border-b border-slate-800" : ""}`}>
            <div className="flex items-center gap-2">
              <Bug className="w-5 h-5 text-indigo-400"/>{t("settings.diagnostics")}</div>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "diagnostics" ? "rotate-180" : ""}`}/>
          </button>
          {localizeText(openSection === "diagnostics" && (<div className="p-6 space-y-4">
            <div className="flex items-center justify-between py-2 border-b border-slate-800 pb-4">
              <div>
                <span className="text-slate-200 font-medium block">{t("settings.enable_debug_log")}</span>
                <span className="text-slate-500 text-xs">{t("settings.writes_extra_startup_popup_and_service_details_error_and_crash_lo")}</span>
              </div>
              <input type="checkbox" checked={settings.enableDebugLog === true} onChange={e => updateSettings({ ...settings, enableDebugLog: e.target.checked })} className="w-5 h-5 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"/>
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium text-slate-400 block w-1/3">{t("settings.delete_logs_after_days")}<span className="block text-xs font-normal text-slate-500 mt-1">{t("settings.default_is_7_days_logs_are_stored_under_c_programdata_clamshield")}</span>
              </label>
              <input type="number" min={1} max={365} value={settings.logRetentionDays || 7} onChange={e => updateNumberSetting("logRetentionDays", e.target.value, 7, 1, 365)} className="w-2/3 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"/>
            </div>
            <div className="text-xs text-slate-500 bg-slate-950/60 border border-slate-800 rounded-lg p-3">{t("settings.main_app_popup_renderer_and_service_errors_are_written_to_the_log")}</div>
          </div>))}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button ref={element => { sectionHeaderRefs.current.paths = element; }} type="button" onClick={() => toggleSection("paths")} aria-expanded={openSection === "paths"} className={`w-full px-6 py-4 flex items-center justify-between font-medium text-slate-200 hover:bg-slate-800/50 transition-colors ${openSection === "paths" ? "border-b border-slate-800" : ""}`}>
            <span className="flex items-center gap-2">
              <Folder className="w-5 h-5 text-indigo-400"/>{t("settings.clamav_paths")}</span>
            <ChevronDown className={`w-5 h-5 text-slate-500 transition-transform ${openSection === "paths" ? "rotate-180" : ""}`}/>
          </button>
          {localizeText(openSection === "paths" && (<div className="p-6 space-y-4">
            {localizeText(['clamavDir', 'clamscanPath', 'freshclamPath', 'freshclamConf', 'clamdPath', 'clamdscanPath', 'clamdConf', 'yaraDir', 'yaraPath', 'yaraRulesDir', 'yaraCustomRulesDir', 'yaraCacheDir', 'databaseDir', 'quarantineDir', 'logsDir'].map((key) => (<div key={key}>
                <label className="block text-sm font-medium text-slate-400 mb-1 capitalize">
                  {localizeText(key.replace(/([A-Z])/g, ' $1').trim())}
                </label>
                <input type="text" value={settings[key] || ""} onChange={e => updateSettings({ ...settings, [key]: e.target.value })} className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"/>
              </div>)))}
          </div>))}
        </section>

        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="w-full px-6 py-4 flex items-center gap-2 font-medium text-slate-200 border-b border-slate-800">
            <Heart className="w-5 h-5 text-rose-500"/>{t("settings.support_us")}</div>
          <div className="p-6 space-y-6">
            <div>
              <p className="text-sm text-slate-300 mb-4">{t("settings.enjoying_clamshield_consider_supporting_the_development_of_this_a")}</p>
              <div className="grid sm:grid-cols-3 gap-3">
                <a href="https://www.paypal.com/ncp/payment/LDBFB3RRB3E9J" target="_blank" rel="noopener noreferrer" className="flex items-center justify-center py-2 px-4 rounded-lg bg-[#0070ba] hover:bg-[#003087] text-white text-sm font-medium transition-colors">{t("settings.buy_me_a_coffee_5")}</a>
                <a href="https://www.paypal.com/ncp/payment/G5RNTC3UF58VU" target="_blank" rel="noopener noreferrer" className="flex items-center justify-center py-2 px-4 rounded-lg bg-[#0070ba] hover:bg-[#003087] text-white text-sm font-medium transition-colors">{t("settings.buy_me_a_beer_10")}</a>
                <a href="https://www.paypal.com/ncp/payment/4NP9RNUYRFRFA" target="_blank" rel="noopener noreferrer" className="flex items-center justify-center py-2 px-4 rounded-lg bg-[#0070ba] hover:bg-[#003087] text-white text-sm font-medium transition-colors">{t("settings.buy_me_a_meal_15")}</a>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800">
              <p className="text-sm text-slate-400 mb-3">{t("settings.we_also_recommend_supporting")}<strong className="text-slate-300">Sanesecurity</strong>{t("settings.who_provides_excellent_third_party_signatures_for_clamav_to_detec")}</p>
              <a href="https://sanesecurity.com/donate/" target="_blank" rel="noopener noreferrer" className="inline-flex items-center justify-center py-2 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium transition-colors border border-slate-700">{t("settings.donate_to_sanesecurity")}</a>
            </div>
            <div className="pt-4 border-t border-slate-800">
              <p className="text-sm text-slate-400 mb-3">{t("settings.securiteinfo_offers_hourly_clamav_signature_updates_through_a_sub")}</p>
              <a href="https://www.securiteinfo.com/clamav-antivirus/improve-detection-rate-of-zero-day-malwares-for-clamav.shtml" target="_blank" rel="noopener noreferrer" className="inline-flex items-center justify-center py-2 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium transition-colors border border-slate-700">{t("settings.subscribe_to_securiteinfo")}</a>
            </div>
          </div>
        </section>
      </div>
    </div>);
}
