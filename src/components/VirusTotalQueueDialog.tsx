import { useEffect, useState } from "react";
import { Loader2, Search } from "lucide-react";
import Modal from "./Modal";
import { Link } from "react-router-dom";
import { formatSystemDateTime } from "../lib/dateFormat";

const sources: Record<string, string> = { all: "All", results: "Results", shield: "Shield", scan: "On-demand scans" };

export default function VirusTotalQueueDialog({ onClose }: { onClose: () => void }) {
  const [source, setSource] = useState("all"), [search, setSearch] = useState(""), [page, setPage] = useState(1);
  const [data, setData] = useState<any>(null), [error, setError] = useState(""), [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    let running = false;
    setLoading(true);
    const refresh = async () => {
      if (running) return;
      running = true;
      try {
        const query = new URLSearchParams({ source, search, page: String(page) });
        const response = await fetch(`/api/virustotal/queue?${query}`, { signal: controller.signal, cache: "no-store" });
        const next = await response.json();
        if (!response.ok) throw new Error(next.error || "Could not load the VirusTotal queue.");
        if (!controller.signal.aborted) { setData(next); setError(""); }
      } catch (e: any) { if (!controller.signal.aborted) setError(e.message); }
      finally { running = false; if (!controller.signal.aborted) setLoading(false); }
    };
    const initial = window.setTimeout(refresh, 150);
    const timer = window.setInterval(refresh, 3000);
    return () => { controller.abort(); window.clearTimeout(initial); window.clearInterval(timer); };
  }, [source, search, page]);
  const button = "rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs hover:bg-slate-700 disabled:opacity-40";
  return <Modal title="VirusTotal queue" onClose={onClose}>
    <div className="space-y-3 border-b border-slate-800 px-6 py-4">
      <p className="text-sm text-slate-400">Pending hash checks, file uploads and report follow-ups. A hash lookup does not upload the file.</p>
      <div className="flex gap-4 text-xs text-sky-300"><Link to="/settings" onClick={onClose}>Open Settings</Link><Link to="/results" onClick={onClose}>Review Results</Link></div>
      <div className="flex flex-wrap gap-2" aria-label="Queue source">
        {Object.entries(sources).map(([key, label]) => <button key={key} aria-pressed={source === key}
          className={`${button} ${source === key ? "border-indigo-400 text-indigo-200" : "text-slate-300"}`}
          onClick={() => { setSource(key); setPage(1); }}>
          {label}{data ? ` (${key === "all" ? data.totalPending : data.counts[key]})` : ""}
        </button>)}
      </div>
      <label className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2">
        <Search size={16} className="text-slate-400" />
        <input aria-label="Search queued files" placeholder="Search file name or path…" value={search}
          onChange={event => { setSearch(event.target.value); setPage(1); }} className="min-w-0 flex-1 bg-transparent text-sm outline-none" />
      </label>
      {data && <p className="text-xs text-slate-400">{data.totalPending} unfinished task(s) across all queues. A file can appear in more than one scan or queue. Updates every 3 seconds.</p>}
      {error && <p role="alert" className="rounded bg-red-500/10 p-2 text-sm text-red-200">{error} The list may be out of date.</p>}
      {data && !data.enabled && <p className="text-sm text-amber-200">Cloud checks are disabled. Open Settings to enable them, or review the files in Results.</p>}
      {data && data.enabled && !data.configured && <p className="text-sm text-amber-200">No API key is configured. Open Settings to add a key, or review the files in Results.</p>}
    </div>
    <div className="min-h-0 overflow-y-auto px-6 py-2" aria-busy={loading}>
      {loading ? <p role="status" className="flex items-center gap-2 py-8 text-slate-400"><Loader2 className="animate-spin" size={16} />Loading queue…</p>
        : !data?.items.length ? <p className="py-8 text-sm text-slate-400">{search || source !== "all" ? "No pending tasks match these filters." : "No pending VirusTotal tasks. Findings that need a decision remain in Results."}</p>
        : <div role="list" className="divide-y divide-slate-800">{data.items.map((item: any) => <article key={item.id} role="listitem" className="space-y-2 py-4">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <span className="min-w-0 break-all text-sm font-medium">{item.filePath?.split(/[\\/]/).pop() || "Unknown file"}</span>
            <span className={`rounded border px-2 py-1 text-xs ${item.active ? "border-cyan-500/40 text-cyan-200" : "border-amber-500/30 text-amber-200"}`}>{item.state}</span>
          </div>
          <p className="select-text break-all font-mono text-xs text-slate-400">{item.filePath}</p>
          <p className="text-xs text-slate-300">{item.submission}</p>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
            <span>{sources[item.source]}</span>
            {item.jobId && <span className="break-all">Scan: {item.jobId}</span>}
            {item.nextAttemptAt > Date.now() && <span>Next attempt: {formatSystemDateTime(item.nextAttemptAt)}</span>}
          </div>
          {item.message && <p className="break-words text-xs text-amber-200">{item.message}</p>}
          <Link className="inline-block text-xs text-sky-300" to={item.source === "scan" ? "/scan" : "/results"} onClick={onClose}>{item.source === "scan" ? "Manage scan" : "Review in Results"}</Link>
          {item.analysisId && <p className="select-text break-all text-xs text-slate-500">Analysis ID: {item.analysisId}</p>}
        </article>)}</div>}
    </div>
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 px-6 py-3 text-xs text-slate-400">
      <span>{data ? `${data.total} matching task(s) · Page ${data.page} of ${Math.max(1, Math.ceil(data.total / data.pageSize))}` : ""}</span>
      <div className="flex gap-2">
        <button className={button} disabled={loading || !data || data.page <= 1} onClick={() => setPage(Math.max(1, data.page - 1))}>Previous</button>
        <button className={button} disabled={loading || !data || data.page * data.pageSize >= data.total} onClick={() => setPage(data.page + 1)}>Next</button>
      </div>
    </div>
  </Modal>;
}
