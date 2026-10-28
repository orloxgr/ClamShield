import { t, localizeText, useLanguage } from "../../../src/lib/i18n";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Cloud, FolderSearch, HardDrive, FileSearch, Loader2, Cpu, Play, Trash2 } from "lucide-react";
import { useScan } from "./ScanContext";
import PageHeader from "../../../src/components/PageHeader";
export default function Scan() {
    useLanguage();
    const { scanState, output, progressOutput, progress, resumableScan, startScan, attachScan, resumeScan, discardResumableScan, cancelScan } = useScan();
    const [searchParams, setSearchParams] = useSearchParams();
    const attachedJobIdRef = useRef<string | null>(null);
    const [virusTotalAllFiles, setVirusTotalAllFiles] = useState(() => {
        try {
            return localStorage.getItem("clamshield.onDemandVirusTotalAllFiles") === "true";
        }
        catch {
            return false;
        }
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
            if (!response.ok)
                throw new Error("Could not load VirusTotal scan status.");
            const data = await response.json();
            setCloudStatus({ ...data, job: data.jobs?.find((job: any) => job.jobId === selectedCloudJobId) || data.job });
        }
        catch (error: any) {
            setCloudError(error.message);
        }
    }, [selectedCloudJobId]);
    useEffect(() => {
        refreshCloudStatus();
        const timer = window.setInterval(refreshCloudStatus, 3000);
        return () => window.clearInterval(timer);
    }, [refreshCloudStatus]);
    const changeCloudState = async (state: "active" | "paused" | "cancelled") => {
        if (!cloudJob)
            return;
        setCloudPending(true);
        setCloudError("");
        try {
            const response = await fetch(`/api/virustotal/on-demand/${encodeURIComponent(cloudJob.jobId)}`, {
                method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ state })
            });
            const data = await response.json();
            if (!response.ok)
                throw new Error(data.error || "Could not update cloud checks.");
            await refreshCloudStatus();
        }
        catch (error: any) {
            setCloudError(error.message);
        }
        finally {
            setCloudPending(false);
        }
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
        if (safeSeconds < 60)
            return `${safeSeconds}s`;
        const minutes = Math.floor(safeSeconds / 60);
        const remainder = safeSeconds % 60;
        if (minutes < 60)
            return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
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
        if (!requestedJobId)
            return;
        if (attachedJobIdRef.current === requestedJobId)
            return;
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
            }
            catch (e) {
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
            }
            catch (e) {
                console.error("Failed to select file:", e);
            }
            return;
        }
        startScan(type, target, scanOptions);
    };
    return (<div className="px-8 max-w-5xl mx-auto space-y-8 pb-20">
      <PageHeader title={t("scan.on_demand_scan")} description={t("scan.manually_check_files_folders_or_your_entire_system")}/>
      {localizeText(searchParams.get("file") && <div className="space-y-3 rounded-xl border border-sky-500/30 bg-sky-500/5 p-4">
        <p className="text-sm font-medium text-slate-200">{t("scan.scan_the_current_file_again")}</p>
        <p className="break-all font-mono text-xs text-slate-400">{localizeText(searchParams.get("file"))}</p>
        <p className="text-xs text-slate-400">{t("scan.the_previous_detection_concerns_an_older_file_version_this_runs_a")}</p>
        <button disabled={scanState === "running"} onClick={() => startScan("file", searchParams.get("file")!, { virusTotalAllFiles: false })} className="rounded-lg bg-sky-700 px-4 py-2 text-sm text-white hover:bg-sky-600 disabled:opacity-50">{t("scan.scan_current_file")}</button>
        {localizeText(scanState === "running" && <p className="text-xs text-amber-200">{t("scan.a_scan_is_running_wait_for_it_to_finish_before_starting_this_file")}</p>)}
      </div>)}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {localizeText([
            { id: "disk", name: "Full Scan", desc: "Scan all local drives", icon: HardDrive },
            { id: "folder", name: "Folder Scan", desc: "Select specific directory", icon: FolderSearch },
            { id: "file", name: "File Scan", desc: "Select a specific file", icon: FileSearch },
            { id: "memory", name: "Process Scan", desc: "Scan running process images", icon: Cpu },
        ].map(btn => (<button key={btn.id} onClick={() => handleScanClick(btn.id)} disabled={scanState === "running"} className="flex flex-col items-center justify-center p-6 bg-slate-900 border border-slate-800 rounded-xl hover:bg-slate-800 hover:border-slate-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed group">
            <btn.icon className="w-10 h-10 text-indigo-400 mb-3 group-hover:scale-110 transition-transform"/>
            <h3 className="font-semibold text-white">{localizeText(btn.name)}</h3>
            <p className="text-xs text-slate-400 mt-1 text-center">{localizeText(btn.desc)}</p>
          </button>)))}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-start gap-3 min-w-0">
            <Cloud className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5"/>
            <div>
              <label htmlFor="on-demand-virustotal" className="font-semibold text-white cursor-pointer">{t("scan.check_every_file_with_virustotal")}</label>
              <p id="on-demand-virustotal-description" className="text-xs text-slate-400 mt-1">{t("scan.checks_every_file_even_when_clamav_and_yara_find_nothing_files_ne")}</p>
              {localizeText(!cloudReady && <Link to="/settings" className="inline-block text-xs text-indigo-300 mt-2 hover:text-indigo-200">{localizeText(cloudStatus ? "Enable VirusTotal and add your API key in Settings" : "Loading VirusTotal settings…")}</Link>)}
            </div>
          </div>
          <input id="on-demand-virustotal" type="checkbox" role="switch" aria-describedby="on-demand-virustotal-description" checked={scanState === "running" && progress ? progress.virusTotalAllFiles === true : virusTotalAllFiles && cloudReady} disabled={!cloudReady || scanState === "running"} onChange={event => {
            setVirusTotalAllFiles(event.target.checked);
            try {
                localStorage.setItem("clamshield.onDemandVirusTotalAllFiles", String(event.target.checked));
            }
            catch { }
        }} className="relative h-6 w-11 shrink-0 cursor-pointer appearance-none rounded-full bg-slate-700 transition-colors checked:bg-indigo-500 after:absolute after:left-1 after:top-1 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition-transform checked:after:translate-x-5 disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-indigo-400"/>
        </div>
        {localizeText(virusTotalAllFiles && cloudReady && <p className="text-xs text-slate-400">{t("scan.every_eligible_file_is_queued_cloud_checks_follow_api_limits_and")}</p>)}
        {localizeText(cloudJob && (<div className="border-t border-slate-800 pt-4 space-y-2">
            {localizeText(cloudStatus.jobs?.length > 1 && <select aria-label={t("scan.virustotal_scan_queue")} value={cloudJob.jobId} onChange={event => setSelectedCloudJobId(event.target.value)} className="w-full rounded bg-slate-950 border border-slate-700 px-2 py-1 text-xs text-slate-300">
              {localizeText(cloudStatus.jobs.map((job: any) => <option key={job.jobId} value={job.jobId}>{localizeText(job.target)} · {localizeText(job.status)} · {localizeText(job.pending.toLocaleString())}{t("scan.queued")}</option>))}
            </select>)}
            <div className="flex flex-wrap items-center justify-between gap-3">
              <span className="text-sm font-medium text-slate-200">{t("scan.virustotal_checks")}{localizeText(cloudJob.status === "active" ? cloudJob.requiresConfirmation ? "Awaiting confirmation" : cloudJob.enumerated ? "Queued / running" : "Collecting files" : cloudJob.status)}</span>
              {localizeText(["active", "paused"].includes(cloudJob.status) && <div className="flex gap-2">
                <button disabled={cloudPending || (cloudJob.status === "paused" && (!cloudReady || !cloudJob.enumerated))} onClick={() => changeCloudState(cloudJob.status === "active" ? "paused" : "active")} className="px-3 py-1 rounded bg-slate-800 text-xs text-slate-200 disabled:opacity-50">{localizeText(cloudJob.status === "active" ? "Pause cloud checks" : "Resume cloud checks")}</button>
                <button disabled={cloudPending} onClick={() => changeCloudState("cancelled")} className="px-3 py-1 rounded bg-red-500/10 text-xs text-red-300 disabled:opacity-50">{t("scan.cancel_cloud_checks")}</button>
              </div>)}
            </div>
            <p className="text-xs text-slate-500 truncate" title={cloudJob.target}>{localizeText(cloudJob.target)}</p>
            <p className="text-xs text-slate-300">{localizeText(cloudJob.checked.toLocaleString())}{t("scan.checked")}{localizeText(cloudJob.pending.toLocaleString())}{t("scan.queued_5398051")}{localizeText(cloudJob.detections.toLocaleString())}{t("scan.flagged")}{localizeText((cloudJob.needsUpload ?? cloudJob.unknown).toLocaleString())}{t("scan.needs_upload")}{localizeText((cloudJob.analysing ?? 0).toLocaleString())}{t("scan.analysing")}{localizeText(cloudJob.skipped.toLocaleString())}{t("scan.skipped")}</p>
            {localizeText(cloudJob.message && <p className="text-xs text-amber-300">{localizeText(cloudJob.message)}</p>)}
            {localizeText(cloudJob.status === "active" && !cloudReady && <p className="text-xs text-amber-300">{t("scan.cloud_checks_are_waiting_for_virustotal_to_be_enabled_and_configu")}</p>)}
            {localizeText(cloudJob.status === "active" && cloudStatus.nextAllowedAt > Date.now() && <p className="text-xs text-slate-500">{t("scan.next_cloud_check_after")}{localizeText(new Date(cloudStatus.nextAllowedAt).toLocaleString())}.</p>)}
            {localizeText(cloudJob.detections > 0 && <Link to="/results" className="inline-block text-xs text-indigo-300 hover:text-indigo-200">{t("scan.review_virustotal_findings_in_results")}</Link>)}
          </div>))}
        {localizeText(cloudError && <p role="alert" className="text-xs text-red-300">{localizeText(cloudError)}</p>)}
      </div>

      {localizeText(resumableScan && scanState !== "running" && (<div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-amber-200">{t("scan.interrupted_scan_available")}</h2>
            <p className="text-xs text-amber-100/70 mt-1">
              {localizeText(Number(resumableScan.scannedFiles || 0).toLocaleString())} / {localizeText(Number(resumableScan.totalFiles || 0).toLocaleString())}{t("scan.files_scanned")}{localizeText(resumableScan.target ? ` in ${resumableScan.target}` : "")}.
            </p>
            {localizeText(resumableScan.virusTotalAllFiles && <p className="text-xs text-amber-100/70 mt-1">{t("scan.virustotal_checks_for_every_file_are_enabled_for_this_interrupted")}</p>)}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => resumeScan(scanOptions)} className="inline-flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded bg-emerald-500 text-slate-950 hover:bg-emerald-400 transition-colors">
              <Play className="w-4 h-4"/>{t("scan.resume")}</button>
            <button onClick={discardResumableScan} className="inline-flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded bg-slate-800 text-slate-200 hover:bg-slate-700 transition-colors">
              <Trash2 className="w-4 h-4"/>{t("scan.discard")}</button>
          </div>
        </div>))}

      {localizeText((scanState === "running" || scanState === "done") && (<div className="mt-8 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[32rem]">
          <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
            <span className="font-mono text-sm text-slate-300 flex items-center gap-2">
              {localizeText(scanState === "running" ? <Loader2 className="w-4 h-4 animate-spin text-indigo-400"/> : null)}{t("scan.terminal_output")}</span>
            {localizeText(scanState === "running" && (<button onClick={cancelScan} className="text-xs px-3 py-1 bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded border border-red-500/20 transition-colors">
                {localizeText(runningScanIsResumable ? "Pause Scan" : "Cancel Scan")}
              </button>))}
          </div>
          {localizeText(progress && (<div className="px-4 py-3 bg-slate-900/70 border-b border-slate-800 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>{localizeText(progress.phase || "Scanning")}</span>
                <span>{localizeText(scannedFiles.toLocaleString())} / {localizeText(totalFiles ? totalFiles.toLocaleString() : "?")}{t("scan.files")}{localizeText(totalFiles ? ` (${percent}%)` : "")}</span>
              </div>
              <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-emerald-500 transition-all duration-300" style={{ width: `${percent}%` }}/>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="min-w-0">
                  <span className="text-slate-500 block">{t("scan.current")}</span>
                  <span className="text-slate-300 truncate block font-mono">{localizeText(currentLabel)}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">{t("scan.detections")}</span>
                  <span className="text-red-300 font-mono">{localizeText(Number(progress.threatsFound || 0).toLocaleString())}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">{t("scan.elapsed_remaining_last_heartbeat")}</span>
                  <span className="text-slate-300 font-mono">
                    {localizeText(formatDuration(elapsedSeconds))} / {localizeText(remainingSeconds === null ? "~?" : `~${formatDuration(remainingSeconds)}`)} / {localizeText(formatDuration(heartbeatSeconds))} ago
                  </span>
                </div>
              </div>
            </div>))}
          <div className="flex-1 overflow-auto font-mono text-xs leading-relaxed">
            <div className="p-4 space-y-1 text-emerald-400/80">
              {localizeText(output.map((line, i) => (<div key={i}>{localizeText(line)}</div>)))}
            </div>
            {localizeText(progressOutput.length > 0 && (<div className="border-t border-slate-800 bg-slate-950/80 p-4 space-y-1 text-cyan-300/90">
                {localizeText(progressOutput.map((line, i) => (<div key={i}>{localizeText(formatProgressLine(line))}</div>)))}
              </div>))}
          </div>
        </div>))}
    </div>);
}
