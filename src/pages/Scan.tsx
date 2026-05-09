import { useRef } from "react";
import { FolderSearch, HardDrive, FileSearch, Loader2, Cpu, Play, Trash2 } from "lucide-react";
import { useScan } from "../context/ScanContext";

export default function Scan() {
  const { scanState, output, progressOutput, progress, resumableScan, startScan, resumeScan, discardResumableScan, cancelScan } = useScan();
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

  const handleScanClick = async (type: string, target?: string) => {
    if (type === "folder" && !target) {
      try {
        const res = await fetch("/api/select-folder");
        const data = await res.json();
        const selectedPath = data.path;
        if (selectedPath) {
          startScan(type, selectedPath);
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
          startScan(type, selectedPath);
        }
      } catch (e) {
        console.error("Failed to select file:", e);
      }
      return;
    }

    startScan(type, target);
  };

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8">
      <header>
        <h1 className="text-3xl font-bold text-white mb-2">Scan your computer</h1>
        <p className="text-slate-400">Manually check files, folders, or your entire system</p>
      </header>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
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

      {resumableScan && scanState !== "running" && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-amber-200">Interrupted scan available</h2>
            <p className="text-xs text-amber-100/70 mt-1">
              {Number(resumableScan.scannedFiles || 0).toLocaleString()} / {Number(resumableScan.totalFiles || 0).toLocaleString()} files scanned
              {resumableScan.target ? ` in ${resumableScan.target}` : ""}.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={resumeScan}
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
