import { ArchiveX, FolderOpen, RotateCcw, Trash2 } from "lucide-react";
import { useState, useEffect } from "react";
import PageHeader from "../components/PageHeader";

export default function Quarantine() {
  const [items, setItems] = useState<any[]>([]);
  const [restoringId, setRestoringId] = useState<string | null>(null);
  const [message, setMessage] = useState("");

  const fetchItems = () => {
    fetch("/api/quarantine").then(r => r.json()).then(data => {
      let fetchedItems = [];
      if (Array.isArray(data)) fetchedItems = data;
      else if (data && Array.isArray(data.items)) fetchedItems = data.items;
      
      // Sort newest first
      fetchedItems.sort((a: any, b: any) => (Number(b.timestamp) || new Date(b.date).getTime()) - (Number(a.timestamp) || new Date(a.date).getTime()));
      setItems(fetchedItems);
    }).catch(() => setItems([]));
  };

  useEffect(() => {
    fetchItems();
  }, []);

  const openQuarantine = async () => {
    await fetch("/api/open-quarantine");
  };

  const emptyQuarantine = async () => {
    if (confirm("Are you sure you want to empty the quarantine? This will permanently delete the files.")) {
      try {
        await fetch("/api/empty-quarantine", { method: "POST" });
        fetchItems();
      } catch (e) {
        console.error("Failed to empty quarantine", e);
      }
    }
  };

  const restoreAndAddException = async (item: any) => {
    if (!confirm("Restore this file to its original location and add it to exceptions? Only do this if you trust the file.")) {
      return;
    }
    setRestoringId(item.fileName);
    setMessage("");
    try {
      const res = await fetch(`/api/quarantine/${encodeURIComponent(item.fileName)}/restore-exception`, { method: "POST" });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || "Restore failed.");
      }
      setMessage(`Restored and added to exceptions: ${data.restoredPath}`);
      fetchItems();
    } catch (e: any) {
      setMessage(e.message || "Restore failed.");
    } finally {
      setRestoringId(null);
    }
  };

  return (
    <div className="px-8 max-w-5xl mx-auto space-y-8 pb-20">
      <PageHeader
        title="Quarantine"
        description="Isolated threats that cannot harm your system"
        actions={(
        <div className="flex items-center gap-3">
          {items.length > 0 && (
            <button 
              onClick={emptyQuarantine}
              className="flex items-center gap-2 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 rounded-lg transition-colors border border-red-500/20"
            >
              <Trash2 className="w-4 h-4" />
              <span>Empty Quarantine</span>
            </button>
          )}
          <button 
            onClick={openQuarantine}
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700 hover:border-slate-600"
          >
            <FolderOpen className="w-4 h-4" />
            <span>Open Folder</span>
          </button>
        </div>
        )}
      />

      {message && (
        <div className="p-3 bg-slate-900 border border-slate-800 text-slate-300 rounded-md text-sm">
          {message}
        </div>
      )}

      {items.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 bg-emerald-500/10 text-emerald-400 rounded-full flex items-center justify-center mb-4">
            <ArchiveX className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-medium text-slate-200 mb-2">Quarantine is empty</h3>
          <p className="text-slate-500 max-w-md">No threats have been quarantined yet. Your system looks clean.</p>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-800/50 text-slate-400">
              <tr>
                <th className="px-6 py-4 font-medium">Detection Name</th>
                <th className="px-6 py-4 font-medium">Original Location</th>
                <th className="px-6 py-4 font-medium">Date Caught</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {items.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/50 transition-colors">
                  <td className="px-6 py-4 font-medium text-red-400">{item.threatName}</td>
                  <td className="px-6 py-4 text-slate-400 font-mono text-xs">{item.originalPath}</td>
                  <td className="px-6 py-4">{new Date(item.date).toLocaleString()}</td>
                  <td className="px-6 py-4">
                    <div className="flex justify-end">
                      <button
                        onClick={() => restoreAndAddException(item)}
                        disabled={restoringId === item.fileName}
                        className="inline-flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-60 disabled:cursor-not-allowed text-slate-200 rounded text-xs font-medium transition-colors border border-slate-700"
                        title="Restore and add to exceptions"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        {restoringId === item.fileName ? "Restoring..." : "Restore + exception"}
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
