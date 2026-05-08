import { useRef } from "react";
import { FolderSearch, HardDrive, FileSearch, Loader2, Cpu } from "lucide-react";
import { useScan } from "../context/ScanContext";

export default function Scan() {
  const { scanState, output, progress, startScan, cancelScan } = useScan();
  const scannedFiles = Number(progress?.scannedFiles || 0);
  const totalFiles = Number(progress?.totalFiles || 0);
  const percent = totalFiles > 0 ? Math.min(100, Math.round((scannedFiles / totalFiles) * 100)) : 0;

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
                Cancel Scan
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
                  <span className="text-slate-300 truncate block font-mono">{progress.currentFile || "Preparing..."}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Detections</span>
                  <span className="text-red-300 font-mono">{Number(progress.threatsFound || 0).toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Elapsed / Quiet</span>
                  <span className="text-slate-300 font-mono">
                    {Number(progress.elapsedSeconds || 0).toLocaleString()}s / {Number(progress.quietSeconds || 0).toLocaleString()}s
                  </span>
                </div>
              </div>
            </div>
          )}
          <div className="flex-1 p-4 overflow-auto font-mono text-xs text-emerald-400/80 leading-relaxed space-y-1">
            {output.map((line, i) => (
              <div key={i}>{line}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
