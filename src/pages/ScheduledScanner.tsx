import { useEffect, useMemo, useState } from "react";
import PageHeader from "../components/PageHeader";
import {
  CalendarClock,
  Check,
  Clock3,
  Cpu,
  FolderPlus,
  HardDrive,
  Loader2,
  MousePointer2,
  Save,
  Trash2
} from "lucide-react";

type ScheduleFrequency = "weekly" | "monthly";

type ScheduledScanSettings = {
  scheduledScanEnabled: boolean;
  scheduledScanFrequency: ScheduleFrequency;
  scheduledScanWeekdays: number[];
  scheduledScanMonthDays: number[];
  scheduledScanTime: string;
  scheduledScanIdleOnly: boolean;
  scheduledScanIdleMinutes: number;
  scheduledScanFullDisk: boolean;
  scheduledScanDirectories: string[];
  scheduledScanMemory: boolean;
  lastScheduledScanAt?: string;
  lastScheduledScanResult?: string;
};

type ScheduledScanRuntime = {
  state?: string;
  message?: string;
  activeJobId?: string;
  currentTarget?: string;
  queueIndex?: number;
  totalTargets?: number;
  idleSeconds?: number;
  updatedAt?: number;
};

const defaultSchedule: ScheduledScanSettings = {
  scheduledScanEnabled: false,
  scheduledScanFrequency: "weekly",
  scheduledScanWeekdays: [0],
  scheduledScanMonthDays: [1],
  scheduledScanTime: "03:00",
  scheduledScanIdleOnly: true,
  scheduledScanIdleMinutes: 15,
  scheduledScanFullDisk: true,
  scheduledScanDirectories: [],
  scheduledScanMemory: false
};

const weekdays = [
  { value: 1, short: "Mon", long: "Monday" },
  { value: 2, short: "Tue", long: "Tuesday" },
  { value: 3, short: "Wed", long: "Wednesday" },
  { value: 4, short: "Thu", long: "Thursday" },
  { value: 5, short: "Fri", long: "Friday" },
  { value: 6, short: "Sat", long: "Saturday" },
  { value: 0, short: "Sun", long: "Sunday" }
];

function formatDuration(seconds: number) {
  const safe = Math.max(0, Math.round(seconds || 0));
  if (safe < 60) return `${safe}s`;
  const minutes = Math.floor(safe / 60);
  const remainder = safe % 60;
  return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
}

function formatDate(value?: string) {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Never" : date.toLocaleString();
}

function nextScheduledDate(settings: ScheduledScanSettings) {
  if (!settings.scheduledScanEnabled) return null;
  const [hours, minutes] = settings.scheduledScanTime.split(":").map(Number);
  const now = new Date();
  for (let offset = 0; offset <= 370; offset++) {
    const candidate = new Date(now);
    candidate.setDate(now.getDate() + offset);
    candidate.setHours(hours || 0, minutes || 0, 0, 0);
    if (candidate <= now) continue;
    const eligible = settings.scheduledScanFrequency === "monthly"
      ? settings.scheduledScanMonthDays.includes(candidate.getDate())
      : settings.scheduledScanWeekdays.includes(candidate.getDay());
    if (eligible) return candidate;
  }
  return null;
}

function stateClasses(state?: string) {
  if (state === "running") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  if (state === "waiting-idle" || state === "waiting-scan") return "border-amber-500/30 bg-amber-500/10 text-amber-200";
  if (state === "error" || state === "stopped") return "border-rose-500/30 bg-rose-500/10 text-rose-200";
  return "border-slate-700 bg-slate-800/60 text-slate-300";
}

export default function ScheduledScanner() {
  const [settings, setSettings] = useState<ScheduledScanSettings>(defaultSchedule);
  const [runtime, setRuntime] = useState<ScheduledScanRuntime>({});
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  const loadSchedule = async (initial = false) => {
    try {
      const response = await fetch("/api/scheduled-scan");
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not load the scheduled scanner.");
      setRuntime(data.runtime || {});
      if (initial) {
        setSettings({ ...defaultSchedule, ...(data.settings || {}) });
        setLoaded(true);
      } else {
        setSettings(current => ({
          ...current,
          lastScheduledScanAt: data.settings?.lastScheduledScanAt || "",
          lastScheduledScanResult: data.settings?.lastScheduledScanResult || ""
        }));
      }
    } catch (error: any) {
      if (initial) setMessage(error.message || "Could not load the scheduled scanner.");
    }
  };

  useEffect(() => {
    loadSchedule(true);
    const timer = window.setInterval(() => loadSchedule(false), 3000);
    return () => window.clearInterval(timer);
  }, []);

  const nextRun = useMemo(() => nextScheduledDate(settings), [settings]);
  const targetCount = (settings.scheduledScanFullDisk ? 1 : settings.scheduledScanDirectories.length)
    + (settings.scheduledScanMemory ? 1 : 0);

  const toggleNumber = (key: "scheduledScanWeekdays" | "scheduledScanMonthDays", value: number) => {
    setSettings(current => {
      const values = current[key];
      const next = values.includes(value) ? values.filter(item => item !== value) : [...values, value].sort((a, b) => a - b);
      return next.length > 0 ? { ...current, [key]: next } : current;
    });
  };

  const addDirectory = async () => {
    setMessage("");
    try {
      const response = await fetch("/api/select-folder");
      const data = await response.json();
      if (!response.ok || !data.path) return;
      setSettings(current => ({
        ...current,
        scheduledScanDirectories: Array.from(new Set([...current.scheduledScanDirectories, data.path]))
      }));
    } catch (error: any) {
      setMessage(error.message || "Could not open the folder selector.");
    }
  };

  const saveSchedule = async () => {
    if (targetCount === 0) {
      setMessage("Select at least one scan target.");
      return;
    }
    setSaving(true);
    setMessage("");
    try {
      const response = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scheduledScanEnabled: settings.scheduledScanEnabled,
          scheduledScanFrequency: settings.scheduledScanFrequency,
          scheduledScanWeekdays: settings.scheduledScanWeekdays,
          scheduledScanMonthDays: settings.scheduledScanMonthDays,
          scheduledScanTime: settings.scheduledScanTime,
          scheduledScanIdleOnly: settings.scheduledScanIdleOnly,
          scheduledScanIdleMinutes: 15,
          scheduledScanFullDisk: settings.scheduledScanFullDisk,
          scheduledScanDirectories: settings.scheduledScanDirectories,
          scheduledScanMemory: settings.scheduledScanMemory
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not save the scheduled scan.");
      setSettings(current => ({ ...current, ...(data.settings || {}) }));
      setMessage("Scheduled scanner saved.");
    } catch (error: any) {
      setMessage(error.message || "Could not save the scheduled scan.");
    } finally {
      setSaving(false);
    }
  };

  if (!loaded) {
    return <div className="p-8 flex items-center gap-3 text-slate-400"><Loader2 className="w-5 h-5 animate-spin" /> Loading scheduled scanner...</div>;
  }

  return (
    <div className="px-8 max-w-5xl mx-auto space-y-6 pb-20">
      <PageHeader
        title="Scheduled Scanner"
        description="Run saved scans automatically while ClamShield is running in the tray."
        actions={(
        <button
          onClick={saveSchedule}
          disabled={saving}
          className="inline-flex items-center gap-2 px-5 py-3 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium transition-colors disabled:opacity-50"
        >
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          {saving ? "Saving..." : "Save Schedule"}
        </button>
        )}
      />

      {message && (
        <div className={`px-4 py-3 rounded-lg border text-sm ${
          message.includes("saved") ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-amber-500/30 bg-amber-500/10 text-amber-200"
        }`}>
          {message}
        </div>
      )}

      <section className={`rounded-xl border p-5 ${stateClasses(runtime.state)}`}>
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-start gap-3">
            <CalendarClock className="w-6 h-6 shrink-0 mt-0.5" />
            <div>
              <h2 className="font-semibold text-white">Scheduler status</h2>
              <p className="text-sm mt-1 opacity-90">{runtime.message || "Waiting for scheduler status."}</p>
              {runtime.state === "running" && runtime.totalTargets ? (
                <p className="text-xs mt-1 opacity-70">Target {runtime.queueIndex} of {runtime.totalTargets}</p>
              ) : null}
            </div>
          </div>
          <div className="text-sm md:text-right">
            <p><span className="opacity-60">Next run:</span> {nextRun ? nextRun.toLocaleString() : "Disabled"}</p>
            <p className="mt-1"><span className="opacity-60">Last run:</span> {formatDate(settings.lastScheduledScanAt)}</p>
            {settings.lastScheduledScanResult && <p className="mt-1 opacity-80">{settings.lastScheduledScanResult}</p>}
          </div>
        </div>
      </section>

      <section className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
        <label className="flex items-center justify-between gap-6 cursor-pointer">
          <div>
            <h2 className="font-semibold text-white">Enable scheduled scanning</h2>
            <p className="text-sm text-slate-500 mt-1">ClamShield must remain running, but the main window may be hidden in the tray.</p>
          </div>
          <input
            type="checkbox"
            checked={settings.scheduledScanEnabled}
            onChange={event => setSettings(current => ({ ...current, scheduledScanEnabled: event.target.checked }))}
            className="w-5 h-5 accent-indigo-500"
          />
        </label>

        <div className="border-t border-slate-800 pt-5 space-y-4">
          <div className="flex flex-wrap gap-2">
            {(["weekly", "monthly"] as ScheduleFrequency[]).map(frequency => (
              <button
                key={frequency}
                onClick={() => setSettings(current => ({ ...current, scheduledScanFrequency: frequency }))}
                className={`px-4 py-2 rounded-lg text-sm font-medium capitalize border transition-colors ${
                  settings.scheduledScanFrequency === frequency
                    ? "bg-indigo-500/15 border-indigo-500/50 text-indigo-300"
                    : "bg-slate-950 border-slate-800 text-slate-400 hover:text-white"
                }`}
              >
                {frequency}
              </button>
            ))}
          </div>

          {settings.scheduledScanFrequency === "weekly" ? (
            <div>
              <label className="text-sm font-medium text-slate-300 block mb-2">Days of the week</label>
              <div className="grid grid-cols-4 sm:grid-cols-7 gap-2">
                {weekdays.map(day => {
                  const selected = settings.scheduledScanWeekdays.includes(day.value);
                  return (
                    <button
                      key={day.value}
                      title={day.long}
                      onClick={() => toggleNumber("scheduledScanWeekdays", day.value)}
                      className={`py-2 rounded-lg border text-sm transition-colors ${
                        selected
                          ? "bg-indigo-500/15 border-indigo-500/50 text-indigo-300"
                          : "bg-slate-950 border-slate-800 text-slate-500 hover:text-slate-200"
                      }`}
                    >
                      {day.short}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            <div>
              <label className="text-sm font-medium text-slate-300 block mb-2">Days of the month</label>
              <div className="grid grid-cols-7 sm:grid-cols-11 gap-2">
                {Array.from({ length: 31 }, (_, index) => index + 1).map(day => {
                  const selected = settings.scheduledScanMonthDays.includes(day);
                  return (
                    <button
                      key={day}
                      onClick={() => toggleNumber("scheduledScanMonthDays", day)}
                      className={`h-9 rounded-lg border text-xs transition-colors ${
                        selected
                          ? "bg-indigo-500/15 border-indigo-500/50 text-indigo-300"
                          : "bg-slate-950 border-slate-800 text-slate-500 hover:text-slate-200"
                      }`}
                    >
                      {day}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <label className="block max-w-xs">
            <span className="text-sm font-medium text-slate-300 flex items-center gap-2 mb-2"><Clock3 className="w-4 h-4" /> Start time</span>
            <input
              type="time"
              value={settings.scheduledScanTime}
              onChange={event => setSettings(current => ({ ...current, scheduledScanTime: event.target.value }))}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500"
            />
          </label>
        </div>
      </section>

      <section className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div>
          <h2 className="font-semibold text-white">What should be scanned?</h2>
          <p className="text-sm text-slate-500 mt-1">These choices are saved, so folders only need to be selected once.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <button
            onClick={() => setSettings(current => ({ ...current, scheduledScanFullDisk: !current.scheduledScanFullDisk }))}
            className={`text-left p-5 rounded-xl border transition-colors ${
              settings.scheduledScanFullDisk ? "bg-indigo-500/10 border-indigo-500/50" : "bg-slate-950 border-slate-800 hover:border-slate-700"
            }`}
          >
            <div className="flex items-start justify-between gap-4">
              <HardDrive className="w-8 h-8 text-indigo-400" />
              {settings.scheduledScanFullDisk && <Check className="w-5 h-5 text-emerald-400" />}
            </div>
            <h3 className="font-semibold text-white mt-4">Full disk scan</h3>
            <p className="text-xs text-slate-500 mt-1">Scan all local files. Saved directories are skipped to avoid scanning them twice.</p>
          </button>

          <button
            onClick={() => setSettings(current => ({ ...current, scheduledScanMemory: !current.scheduledScanMemory }))}
            className={`text-left p-5 rounded-xl border transition-colors ${
              settings.scheduledScanMemory ? "bg-indigo-500/10 border-indigo-500/50" : "bg-slate-950 border-slate-800 hover:border-slate-700"
            }`}
          >
            <div className="flex items-start justify-between gap-4">
              <Cpu className="w-8 h-8 text-indigo-400" />
              {settings.scheduledScanMemory && <Check className="w-5 h-5 text-emerald-400" />}
            </div>
            <h3 className="font-semibold text-white mt-4">Running process memory</h3>
            <p className="text-xs text-slate-500 mt-1">Scan executable images loaded by running processes, without a separate file target.</p>
          </button>
        </div>

        <div className={`rounded-xl border border-slate-800 bg-slate-950 p-4 space-y-3 ${settings.scheduledScanFullDisk ? "opacity-60" : ""}`}>
          <div className="flex items-center justify-between gap-4">
            <div>
              <h3 className="font-medium text-slate-200">Selected directories</h3>
              <p className="text-xs text-slate-500 mt-1">
                {settings.scheduledScanFullDisk ? "Retained for later, but not scanned separately while Full disk scan is selected." : "Each directory runs as a separate scan target."}
              </p>
            </div>
            <button
              onClick={addDirectory}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm transition-colors"
            >
              <FolderPlus className="w-4 h-4" />
              Add directory
            </button>
          </div>
          {settings.scheduledScanDirectories.length === 0 ? (
            <p className="text-sm text-slate-600">No directories selected.</p>
          ) : (
            <div className="space-y-2">
              {settings.scheduledScanDirectories.map(directory => (
                <div key={directory} className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs font-mono text-slate-300 truncate" title={directory}>{directory}</span>
                  <button
                    onClick={() => setSettings(current => ({
                      ...current,
                      scheduledScanDirectories: current.scheduledScanDirectories.filter(item => item !== directory)
                    }))}
                    className="p-1.5 rounded text-slate-500 hover:text-rose-300 hover:bg-rose-500/10 transition-colors shrink-0"
                    title="Remove directory"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      <section className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <label className="flex items-start justify-between gap-6 cursor-pointer">
          <div className="flex items-start gap-3">
            <MousePointer2 className="w-6 h-6 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="font-semibold text-white">Scan only if the computer is not being used</h2>
              <p className="text-sm text-slate-500 mt-1">
                Wait for 15 minutes of Windows keyboard and mouse inactivity. If activity resumes during the scan, ClamShield stops it.
              </p>
              <p className="text-xs text-slate-600 mt-2">
                Inactivity monitoring starts 15 minutes before the scheduled time and continues only while waiting for or running the scan.
              </p>
              {(runtime.state === "waiting-idle" || runtime.state === "running") && (
                <p className="text-xs text-slate-600 mt-1">Current inactivity: {formatDuration(runtime.idleSeconds || 0)}</p>
              )}
            </div>
          </div>
          <input
            type="checkbox"
            checked={settings.scheduledScanIdleOnly}
            onChange={event => setSettings(current => ({ ...current, scheduledScanIdleOnly: event.target.checked }))}
            className="w-5 h-5 accent-cyan-500 mt-1"
          />
        </label>
      </section>
    </div>
  );
}
