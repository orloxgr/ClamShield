import { useEffect, useState } from "react";
import { History, Search, ShieldAlert, Cpu, RefreshCw, CheckCircle2 } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import PageHeader from "../components/PageHeader";

export default function HistoryPage() {
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/history")
      .then(r => r.json())
      .then(data => {
        setHistory(data);
        setLoading(false);
      });
  }, []);

  const getIcon = (type: string) => {
    if (type.includes("scan")) return <Search className="w-4 h-4" />;
    if (type === "update") return <RefreshCw className="w-4 h-4" />;
    return <History className="w-4 h-4" />;
  };

  return (
    <div className="px-8 max-w-6xl mx-auto space-y-8 pb-20">
      <PageHeader title="History" description="Past scans, updates, and threat detections" />

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-400">Loading history...</div>
        ) : history.length === 0 ? (
          <div className="p-12 text-center text-slate-400">No activity recorded yet.</div>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-800/50 text-slate-400">
              <tr>
                <th className="px-6 py-4 font-medium">Event Type</th>
                <th className="px-6 py-4 font-medium">Target</th>
                <th className="px-6 py-4 font-medium">Date</th>
                <th className="px-6 py-4 font-medium text-right">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {history.map(item => (
                 <tr key={item.id} className="hover:bg-slate-800/20">
                    <td className="px-6 py-4 flex items-center gap-3">
                      <div className={`p-2 rounded-full ${item.threatsFound > 0 ? 'bg-red-500/10 text-red-400' : 'bg-slate-800 text-slate-400'}`}>
                        {getIcon(item.type)}
                      </div>
                      <span className="capitalize">{item.type.replace("-", " ")}</span>
                    </td>
                    <td className="px-6 py-4 truncate max-w-xs" title={item.target}>{item.target}</td>
                    <td className="px-6 py-4 text-slate-400 text-xs">
                      {formatDistanceToNow(new Date(item.date), {addSuffix: true})}
                    </td>
                    <td className="px-6 py-4 text-right">
                       {item.threatsFound > 0 ? (
                         <span className="inline-flex items-center gap-1 text-red-400 font-medium bg-red-400/10 px-2 py-1 rounded">
                           <ShieldAlert className="w-4 h-4" />
                           {item.threatsFound} Threats
                         </span>
                       ) : (
                         <span className="inline-flex items-center gap-1 text-emerald-400 bg-emerald-400/10 px-2 py-1 rounded">
                           <CheckCircle2 className="w-4 h-4" />
                           Clean
                         </span>
                       )}
                    </td>
                 </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
