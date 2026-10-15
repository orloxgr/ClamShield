import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Cloud, FolderSearch, HardDrive, FileSearch, Loader2, Cpu, Play, Trash2 } from "lucide-react";
import { useScan } from "../context/ScanContext";
import PageHeader from "../components/PageHeader";

export default function Scan() {
  const { scanState, output, progressOutput, progress, resumableScan, startScan, attachScan, resumeScan, discardResumableScan, cancelScan } = useScan();
  const [searchParams, setSearchParams] = useSearchParams();
  const attachedJobIdRef = useRef<string | null>(null);
  const [virusTotalAllFiles, setVirusTotalAllFiles] = useState(() => {
    try { return localStorage.getItem("clamshield.onDemandVirusTotalAllFiles") === "true"; } catch { return false; }
  });
  const [cloudStatus, setCloudStatus] = useState<any>(null);
  const [cloudError, setCloudError] = useState("");
  const [cloudPending, setCloudPending] = useState(false);
  const [selectedCloudJobId, setSelectedCloudJobId] = useState("");
  const cloudReady = cloudStatus?.enabled === true && cloudStatus?.configured === true;
  const cloudJob = cloudStatus?.job;
  const scanOptions = { virusTotalAllFiles: virusTotalAllFiles && cloudReady };
  const refreshCloudStatus = useCallback(async () => {
    try {
      const response = await fetch("/api/virustotal/on-demand");
      if (!response.ok) throw new Error("Could not load VirusTotal scan status.");
      const data = await response.json();
      setCloudStatus({ ...data, job: data.jobs?.find((job: any) => job.jobId === selectedCloudJobId) || data.job });
    } catch (error: any) { setCloudError(error.message); }
  }, [selectedCloudJobId]);
  useEffect(() => {
    refreshCloudStatus();
    const timer = window.setInterval(refreshCloudStatus, 3000);
    return () => window.clearInterval(timer);
  }, [refreshCloudStatus]);
  const changeCloudState = async (state: "active" | "paused" | "cancelled") => {
    if (!cloudJob) return;
    setCloudPending(true);
    setCloudError("");
    try {
      const response = await fetch(`/api/virustotal/on-demand/${encodeURIComponent(cloudJob.jobId)}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ state })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not update cloud checks.");
      await refreshCloudStatus();
    } catch (error: any) { setCloudError(error.message); }
    finally { setCloudPending(false); }
  };
  const scannedFiles = Number(progress?.scannedFiles || 0);
  const totalFiles = Number(progress?.totalFiles || 0);
  const elapsedSeconds = Number(progress?.elapsedSeconds || 0);
  const heartbeatSeconds = Number(progress?.quietSeconds || 0);
  const percent = totalFiles > 0 ? Math.min(100, Math.round((scannedFiles / totalFiles) * 100)) : 0;
  const remainingSeconds = scanState === "running" && totalFiles > 0 && scannedFiles > 0 && elapsedSeconds > 0
    ? Math.max(0, Math.round((elapsedSeconds / scannedFiles) * (totalFiles - scannedFiles)))
    : null;
  const currentLabel = progress?.currentFile || (scanState === "done" ? progress?.phase || "Complete" : "Preparing...");
  const runningScanIsResumable = ["disk", "folder", "file"].includes(progress?.type || "");
  const formatDuration = (seconds: number) => {
    const safeSeconds = Math.max(0, Math.round(seconds));
    if (safeSeconds < 60) return `${safeSeconds}s`;
    const minutes = Math.floor(safeSeconds / 60);
    const remainder = safeSeconds % 60;
    if (minutes < 60) return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const minuteRemainder = minutes % 60;
    return minuteRemainder ? `${hours}h ${minuteRemainder}m` : `${hours}h`;
  };
  const formatProgressLine = (line: string) => {
    if (/^Infected files:/i.test(line)) {
      return `Infected files: ${Number(progress?.threatsFound || 0).toLocaleString()}`;
    }
    return line;
  };

  useEffect(() => {
    const requestedJobId = searchParams.get("jobId");
    if (!requestedJobId) return;
    if (attachedJobIdRef.current === requestedJobId) return;
    attachedJobIdRef.current = requestedJobId;
    attachScan(requestedJobId);
    setSearchParams({}, { replace: true });
  }, [attachScan, searchParams, setSearchParams]);

  const handleScanClick = async (type: string, target?: string) => {
    if (type === "folder" && !target) {
      try {
        const res = await fetch("/api/select-folder");
        const data = await res.json();
        const selectedPath = data.path;
        if (selectedPath) {
          startScan(type, selectedPath, scanOptions);
        }
      } catch (e) {
        console.error("Failed to select folder:", e);
      }
      return;
    }
    if (type === "file" && !target) {
      try {
        const res = await fetch("/api/select-file");
        const data = await res.json();
        const selectedPath = data.path;
        if (selectedPath) {
          startScan(type, selectedPath, scanOptions);
        }
      } catch (e) {
        console.error("Failed to select file:", e);
      }
      return;
    }

    startScan(type, target, scanOptions);
  };

  return (
    <div className="px-8 max-w-5xl mx-auto space-y-8 pb-20">
      <PageHeader title="On-Demand Scan" description="Manually check files, folders, or your entire system" />
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {[
          { id: "disk", name: "Full Scan", desc: "Scan all local drives", icon: HardDrive },
          { id: "folder", name: "Folder Scan", desc: "Select specific directory", icon: FolderSearch },
          { id: "file", name: "File Scan", desc: "Select a specific file", icon: FileSearch },
          { id: "memory", name: "Process Scan", desc: "Scan running process images", icon: Cpu },
        ].map(btn => (
          <button
            key={btn.id}
            onClick={() => handleScanClick(btn.id)}
            disabled={scanState === "running"}
            className="flex flex-col items-center justify-center p-6 bg-slate-900 border border-slate-800 rounded-xl hover:bg-slate-800 hover:border-slate-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed group"
          >
            <btn.icon className="w-10 h-10 text-indigo-400 mb-3 group-hover:scale-110 transition-transform" />
            <h3 className="font-semibold text-white">{btn.name}</h3>
            <p className="text-xs text-slate-400 mt-1 text-center">{btn.desc}</p>
          </button>
        ))}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-start gap-3 min-w-0">
            <Cloud className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
            <div>
              <label htmlFor="on-demand-virustotal" className="font-semibold text-white cursor-pointer">Check every file with VirusTotal</label>
              <p id="on-demand-virustotal-description" className="text-xs text-slate-400 mt-1">Checks every file, even when ClamAV and YARA find nothing. Files needing analysis are uploaded automatically.</p>
              {!cloudReady && <Link to="/settings" className="inline-block text-xs text-indigo-300 mt-2 hover:text-indigo-200">{cloudStatus ? "Enable VirusTotal and add your API key in Settings" : "Loading VirusTotal settings…"}</Link>}
            </div>
          </div>
          <input id="on-demand-virustotal" type="checkbox" role="switch" aria-describedby="on-demand-virustotal-description"
            checked={scanState === "running" && progress ? progress.virusTotalAllFiles === true : virusTotalAllFiles && cloudReady}
            disabled={!cloudReady || scanState === "running"}
            onChange={event => {
              setVirusTotalAllFiles(event.target.checked);
              try { localStorage.setItem("clamshield.onDemandVirusTotalAllFiles", String(event.target.checked)); } catch {}
            }} className="relative h-6 w-11 shrink-0 cursor-pointer appearance-none rounded-full bg-slate-700 transition-colors checked:bg-indigo-500 after:absolute after:left-1 after:top-1 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition-transform checked:after:translate-x-5 disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-indigo-400" />
        </div>
        {virusTotalAllFiles && cloudReady && <p className="text-xs text-slate-400">Every eligible file is queued. Cloud checks follow API limits and can continue after the local scan finishes.</p>}
        {cloudJob && (
          <div className="border-t border-slate-800 pt-4 space-y-2">
            {cloudStatus.jobs?.length > 1 && <select aria-label="VirusTotal scan queue" value={cloudJob.jobId}
              onChange={event => setSelectedCloudJobId(event.target.value)} className="w-full rounded bg-slate-950 border border-slate-700 px-2 py-1 text-xs text-slate-300">
              {cloudStatus.jobs.map((job: any) => <option key={job.jobId} value={job.jobId}>{job.target} · {job.status} · {job.pending.toLocaleString()} queued</option>)}
            </select>}
            <div className="flex flex-wrap items-center justify-between gap-3">
              <span className="text-sm font-medium text-slate-200">VirusTotal checks · {cloudJob.status === "active" ? cloudJob.requiresConfirmation ? "Awaiting confirmation" : cloudJob.enumerated ? "Queued / running" : "Collecting files" : cloudJob.status}</span>
              {["active", "paused"].includes(cloudJob.status) && <div className="flex gap-2">
                <button disabled={cloudPending || (cloudJob.status === "paused" && (!cloudReady || !cloudJob.enumerated))} onClick={() => changeCloudState(cloudJob.status === "active" ? "paused" : "active")} className="px-3 py-1 rounded bg-slate-800 text-xs text-slate-200 disabled:opacity-50">{cloudJob.status === "active" ? "Pause cloud checks" : "Resume cloud checks"}</button>
                <button disabled={cloudPending} onClick={() => changeCloudState("cancelled")} className="px-3 py-1 rounded bg-red-500/10 text-xs text-red-300 disabled:opacity-50">Cancel cloud checks</button>
              </div>}
            </div>
            <p className="text-xs text-slate-500 truncate" title={cloudJob.target}>{cloudJob.target}</p>
            <p className="text-xs text-slate-300">{cloudJob.checked.toLocaleString()} checked · {cloudJob.pending.toLocaleString()} queued · {cloudJob.detections.toLocaleString()} flagged · {(cloudJob.needsUpload ?? cloudJob.unknown).toLocaleString()} needs upload · {(cloudJob.analysing ?? 0).toLocaleString()} analysing · {cloudJob.skipped.toLocaleString()} skipped</p>
            {cloudJob.message && <p className="text-xs text-amber-300">{cloudJob.message}</p>}
            {cloudJob.status === "active" && !cloudReady && <p className="text-xs text-amber-300">Cloud checks are waiting for VirusTotal to be enabled and configured in Settings.</p>}
            {cloudJob.status === "active" && cloudStatus.nextAllowedAt > Date.now() && <p className="text-xs text-slate-500">Next cloud check after {new Date(cloudStatus.nextAllowedAt).toLocaleString()}.</p>}
            {cloudJob.detections > 0 && <Link to="/results" className="inline-block text-xs text-indigo-300 hover:text-indigo-200">Review VirusTotal findings in Results</Link>}
          </div>
        )}
        {cloudError && <p role="alert" className="text-xs text-red-300">{cloudError}</p>}
      </div>

      {resumableScan && scanState !== "running" && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-amber-200">Interrupted scan available</h2>
            <p className="text-xs text-amber-100/70 mt-1">
              {Number(resumableScan.scannedFiles || 0).toLocaleString()} / {Number(resumableScan.totalFiles || 0).toLocaleString()} files scanned
              {resumableScan.target ? ` in ${resumableScan.target}` : ""}.
            </p>
            {resumableScan.virusTotalAllFiles && <p className="text-xs text-amber-100/70 mt-1">VirusTotal checks for every file are enabled for this interrupted scan.</p>}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => resumeScan(scanOptions)}
              className="inline-flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded bg-emerald-500 text-slate-950 hover:bg-emerald-400 transition-colors"
            >
              <Play className="w-4 h-4" />
              Resume
            </button>
            <button
              onClick={discardResumableScan}
              className="inline-flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded bg-slate-800 text-slate-200 hover:bg-slate-700 transition-colors"
            >
              <Trash2 className="w-4 h-4" />
              Discard
            </button>
          </div>
        </div>
      )}

      {(scanState === "running" || scanState === "done") && (
        <div className="mt-8 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[32rem]">
          <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
            <span className="font-mono text-sm text-slate-300 flex items-center gap-2">
              {scanState === "running" ? <Loader2 className="w-4 h-4 animate-spin text-indigo-400" /> : null}
              Terminal Output
            </span>
            {scanState === "running" && (
              <button 
                onClick={cancelScan}
                className="text-xs px-3 py-1 bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded border border-red-500/20 transition-colors"
              >
                {runningScanIsResumable ? "Pause Scan" : "Cancel Scan"}
              </button>
            )}
          </div>
          {progress && (
            <div className="px-4 py-3 bg-slate-900/70 border-b border-slate-800 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>{progress.phase || "Scanning"}</span>
                <span>{scannedFiles.toLocaleString()} / {totalFiles ? totalFiles.toLocaleString() : "?"} files{totalFiles ? ` (${percent}%)` : ""}</span>
              </div>
              <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-500 transition-all duration-300"
                  style={{ width: `${percent}%` }}
                />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="min-w-0">
                  <span className="text-slate-500 block">Current</span>
                  <span className="text-slate-300 truncate block font-mono">{currentLabel}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Detections</span>
                  <span className="text-red-300 font-mono">{Number(progress.threatsFound || 0).toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Elapsed / Remaining / Last heartbeat</span>
                  <span className="text-slate-300 font-mono">
                    {formatDuration(elapsedSeconds)} / {remainingSeconds === null ? "~?" : `~${formatDuration(remainingSeconds)}`} / {formatDuration(heartbeatSeconds)} ago
                  </span>
                </div>
              </div>
            </div>
          )}
          <div className="flex-1 overflow-auto font-mono text-xs leading-relaxed">
            <div className="p-4 space-y-1 text-emerald-400/80">
              {output.map((line, i) => (
                <div key={i}>{line}</div>
              ))}
            </div>
            {progressOutput.length > 0 && (
              <div className="border-t border-slate-800 bg-slate-950/80 p-4 space-y-1 text-cyan-300/90">
                {progressOutput.map((line, i) => (
                  <div key={i}>{formatProgressLine(line)}</div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
