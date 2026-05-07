import { useState, useRef, useEffect } from "react";
import { RefreshCw, Database, Loader2 } from "lucide-react";

const MAX_TERMINAL_LINES = 800;

function appendOutput(previous: string[], next: string[]) {
  return [...previous, ...next].slice(-MAX_TERMINAL_LINES);
}

export default function Updates() {
  const [updateState, setUpdateState] = useState<"idle" | "running" | "done">("idle");
  const [output, setOutput] = useState<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSimulated, setIsSimulated] = useState<boolean>(false);
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const runUpdate = async () => {
    setUpdateState("running");
    setOutput(["Triggering freshclam..."]);
    try {
      const res = await fetch("/api/update", { method: "POST" });
      const data = await res.json();
      
      if (!res.ok) {
        throw new Error(data.error || "Failed to start update.");
      }
      
      setJobId(data.jobId);
      setIsSimulated(!!data.simulated);
      
      if (data.simulated) {
        setOutput(prev => appendOutput(prev, ["Running in simulation mode...", "Checking for database updates..."]));
        setTimeout(() => {
          setOutput(prev => appendOutput(prev, ["main.cvd is up to date (version: 62, sigs: XXXXXX, f-level: 90)", "daily.cvd is up to date", "bytecode.cvd is up to date", "Database updated successfully."]));
          setUpdateState("done");
          setJobId(null);
        }, 2500);
      }
    } catch (e: any) {
      setOutput(prev => appendOutput(prev, [`Error: ${e.message}`]));
      setUpdateState("done");
      setJobId(null);
    }
  };

  useEffect(() => {
    if (updateState === "running" && jobId && !isSimulated) {
      pollIntervalRef.current = setInterval(async () => {
        try {
          const res = await fetch(`/api/scan/${jobId}`);
          if (res.ok) {
            const data = await res.json();
            if (data.logs && data.logs.length > 0) {
              setOutput(prev => appendOutput(prev, data.logs));
            }
            if (data.status === "done") {
              setUpdateState("done");
              setJobId(null);
              clearInterval(pollIntervalRef.current!);
              pollIntervalRef.current = null;
            }
          }
        } catch (e) {
          console.error("Failed to poll update status:", e);
        }
      }, 1000);
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [updateState, jobId, isSimulated]);

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <header>
        <h1 className="text-3xl font-bold text-white mb-2">Signature Updates</h1>
        <p className="text-slate-400">Keep your virus database current with freshclam</p>
      </header>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-full">
            <Database className="w-8 h-8" />
          </div>
          <div>
            <h3 className="font-semibold text-white text-lg">Virus Definitions</h3>
            <p className="text-slate-400 text-sm">Last checked: Recently</p>
          </div>
        </div>
        <button
          onClick={runUpdate}
          disabled={updateState === "running"}
          className="flex items-center gap-2 px-6 py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RefreshCw className={`w-5 h-5 ${updateState === "running" ? "animate-spin" : ""}`} />
          {updateState === "running" ? "Updating..." : "Update Now"}
        </button>
      </div>

      {(updateState === "running" || updateState === "done") && (
        <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-64">
           <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center gap-2">
            <span className="font-mono text-sm text-slate-300 flex items-center gap-2">
              {updateState === "running" ? <Loader2 className="w-4 h-4 animate-spin text-indigo-400" /> : null}
              FreshClam Output
            </span>
          </div>
          <div className="flex-1 p-4 overflow-auto font-mono text-xs text-emerald-400/80 leading-relaxed space-y-1 flex flex-col justify-end">
            {output.map((line, i) => <div key={i}>{line}</div>)}
          </div>
        </div>
      )}
    </div>
  );
}
