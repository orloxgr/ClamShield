import { useState, useEffect } from "react";
import { ShieldCheck, Plus, Trash2, FolderPlus, FilePlus } from "lucide-react";

export default function ExceptionsPage() {
  const [exceptions, setExceptions] = useState<string[]>([]);
  const [addingError, setAddingError] = useState("");

  const fetchExceptions = async () => {
    try {
      const r = await fetch("/api/exceptions");
      const data = await r.json();
      if (Array.isArray(data)) setExceptions(data);
    } catch {
      setExceptions([]);
    }
  };

  useEffect(() => {
    fetchExceptions();
  }, []);

  const handleAdd = async (type: "file" | "folder") => {
    try {
      setAddingError("");
      const response = await fetch(`/api/select-${type}`);
      const data = await response.json();
      
      let selectedPath = data.path;
      if (!selectedPath) {
        selectedPath = window.prompt(`[Simulated] Enter a ${type} path manually:`, "C:\\TestPath\\" + type);
      }

      if (selectedPath) {
        if (exceptions.includes(selectedPath)) {
          setAddingError("Path is already in exceptions.");
          return;
        }
        const updated = [...exceptions, selectedPath];
        await fetch("/api/exceptions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ exceptions: updated })
        });
        fetchExceptions();
      }
    } catch (e: any) {
      setAddingError("Failed to add exception.");
    }
  };

  const removeException = async (path: string) => {
    try {
      const updated = exceptions.filter(e => e !== path);
      await fetch("/api/exceptions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ exceptions: updated })
      });
      fetchExceptions();
    } catch {
       // Ignore error
    }
  };

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8 animate-in slide-in-from-bottom-4 duration-500">
      <header className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Exceptions</h1>
          <p className="text-slate-400">Files and folders excluded from future scans</p>
        </div>
        <div className="flex gap-3">
            <button 
                onClick={() => handleAdd("file")}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700"
            >
                <FilePlus className="w-4 h-4" />
                <span>Add File</span>
            </button>
            <button 
                onClick={() => handleAdd("folder")}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700"
            >
                <FolderPlus className="w-4 h-4" />
                <span>Add Folder</span>
            </button>
        </div>
      </header>

      {addingError && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-lg text-sm">
          {addingError}
        </div>
      )}

      {exceptions.length === 0 ? (
        <div className="flex items-center justify-center p-12 mt-12 bg-slate-900 border border-slate-800 rounded-2xl flex-col text-center">
          <ShieldCheck className="w-16 h-16 text-slate-700 mb-4" />
          <h2 className="text-xl font-medium text-slate-300 mb-2">No Exceptions Added</h2>
          <p className="text-slate-500 max-w-md">
            Any files or directories you add here will be ignored by both the active Shield and manual scans.
          </p>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
          <div className="divide-y divide-slate-800">
            {exceptions.map((exc, idx) => (
              <div key={idx} className="flex justify-between items-center p-4 hover:bg-slate-800/50 transition-colors">
                <div className="min-w-0 pr-4">
                  <span className="font-mono text-sm text-slate-300 truncate block" title={exc}>{exc}</span>
                </div>
                <button
                    onClick={() => removeException(exc)}
                    className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors flex-shrink-0"
                    title="Remove exception"
                >
                    <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
