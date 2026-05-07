import { AlertTriangle, Archive, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

export default function ResultsPage() {
  const [items, setItems] = useState<any[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [message, setMessage] = useState("");

  const fetchItems = async () => {
    try {
      const res = await fetch("/api/results");
      const data = await res.json();
      setItems(Array.isArray(data) ? data.sort((a: any, b: any) => Number(b.timestamp || 0) - Number(a.timestamp || 0)) : []);
    } catch {
      setItems([]);
    }
  };

  useEffect(() => {
    fetchItems();
  }, []);

  const handleAction = async (id: string, action: "quarantine" | "exception") => {
    setBusyId(id);
    setMessage("");
    try {
      const res = await fetch(`/api/results/${encodeURIComponent(id)}/action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action })
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Action failed.");
      setMessage(action === "quarantine" ? "Item moved to quarantine." : "Item added to exceptions.");
      fetchItems();
    } catch (e: any) {
      setMessage(e.message || "Action failed.");
    } finally {
      setBusyId(null);
    }
  };

  const quarantineAll = async () => {
    if (!items.length || !confirm("Quarantine all undecided suspicious files?")) return;
    setBulkBusy(true);
    setMessage("");
    try {
      const res = await fetch("/api/results/quarantine-all", { method: "POST" });
      const data = await res.json();
      if (!res.ok && res.status !== 207) throw new Error(data.error || "Bulk quarantine failed.");
      const missingCount = Array.isArray(data.errors) ? data.errors.filter((item: any) => String(item.error || "").includes("no longer available")).length : 0;
      setMessage(data.errors?.length
        ? `Quarantined ${data.quarantinedCount}. ${data.errors.length} item(s) could not be moved${missingCount ? `, ${missingCount} because the original file no longer exists` : ""}.`
        : `Quarantined ${data.quarantinedCount} item(s).`);
      fetchItems();
    } catch (e: any) {
      setMessage(e.message || "Bulk quarantine failed.");
    } finally {
      setBulkBusy(false);
    }
  };

  const clearMissing = async () => {
    setMessage("");
    try {
      const res = await fetch("/api/results/clear-missing", { method: "POST" });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Cleanup failed.");
      setMessage(`Removed ${data.removedCount} unavailable result item(s).`);
      fetchItems();
    } catch (e: any) {
      setMessage(e.message || "Cleanup failed.");
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      <header className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Results</h1>
          <p className="text-slate-400">Suspicious files waiting for your decision</p>
        </div>
        {items.length > 0 && (
          <div className="flex items-center gap-3">
            <button
              onClick={clearMissing}
              disabled={bulkBusy}
              className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-60 disabled:cursor-not-allowed text-slate-300 rounded-lg font-medium transition-colors border border-slate-700"
            >
              Clear unavailable
            </button>
            <button
              onClick={quarantineAll}
              disabled={bulkBusy}
              className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
            >
              <Archive className="w-4 h-4" />
              {bulkBusy ? "Quarantining..." : "Quarantine all"}
            </button>
          </div>
        )}
      </header>

      {message && (
        <div className="p-3 bg-slate-900 border border-slate-800 text-slate-300 rounded-md text-sm">
          {message}
        </div>
      )}

      {items.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 bg-emerald-500/10 text-emerald-400 rounded-full flex items-center justify-center mb-4">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-medium text-slate-200 mb-2">No undecided results</h3>
          <p className="text-slate-500 max-w-md">Manual scan detections and silent shield detections will appear here for review.</p>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-800/50 text-slate-400">
              <tr>
                <th className="px-6 py-4 font-medium">Detection</th>
                <th className="px-6 py-4 font-medium">File</th>
                <th className="px-6 py-4 font-medium">Source</th>
                <th className="px-6 py-4 font-medium">Date</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {items.map(item => (
                <tr key={item.id} className="hover:bg-slate-800/50 transition-colors">
                  <td className="px-6 py-4 font-medium text-red-400">
                    <span className="inline-flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      {item.threatName || "Unknown Threat"}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-slate-400 font-mono text-xs break-all">{item.originalPath}</td>
                  <td className="px-6 py-4 text-slate-400 capitalize">{item.source || "scan"}</td>
                  <td className="px-6 py-4">{new Date(item.timestamp).toLocaleString()}</td>
                  <td className="px-6 py-4">
                    <div className="flex justify-end gap-2">
                      <button
                        onClick={() => handleAction(item.id, "exception")}
                        disabled={busyId === item.id}
                        className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-60 text-slate-300 rounded text-xs font-medium transition-colors border border-slate-700"
                      >
                        Add to exceptions
                      </button>
                      <button
                        onClick={() => handleAction(item.id, "quarantine")}
                        disabled={busyId === item.id}
                        className="px-3 py-1.5 bg-red-600 hover:bg-red-500 disabled:opacity-60 text-white rounded text-xs font-medium transition-colors"
                      >
                        Quarantine
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
