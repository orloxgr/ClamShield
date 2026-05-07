import { ArchiveX, FolderOpen, Trash2 } from "lucide-react";
import { useState, useEffect } from "react";

export default function Quarantine() {
  const [items, setItems] = useState<any[]>([]);

  const fetchItems = () => {
    fetch("/api/quarantine").then(r => r.json()).then(data => {
      let fetchedItems = [];
      if (Array.isArray(data)) fetchedItems = data;
      else if (data && Array.isArray(data.items)) fetchedItems = data.items;
      
      // Sort newest first
      fetchedItems.sort((a: any, b: any) => new Date(b.date).getTime() - new Date(a.date).getTime());
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

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8">
      <header className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Quarantine</h1>
          <p className="text-slate-400">Isolated threats that cannot harm your system</p>
        </div>
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
      </header>

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
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {items.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/50 transition-colors">
                  <td className="px-6 py-4 font-medium text-red-400">{item.threatName}</td>
                  <td className="px-6 py-4 text-slate-400 font-mono text-xs">{item.originalPath}</td>
                  <td className="px-6 py-4">{new Date(item.date).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
