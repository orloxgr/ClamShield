import { useEffect, useState } from "react";
import { History, Search, ShieldAlert, RefreshCw, CheckCircle2 } from "lucide-react";
import PageHeader from "../components/PageHeader";
import { formatSystemDateTime } from "../lib/dateFormat";

type PageSize = 50 | 100 | 200 | 500 | "all";

export default function HistoryPage() {
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [pageSize, setPageSize] = useState<PageSize>(50);
  const [page, setPage] = useState(1);

  useEffect(() => {
    fetch("/api/history")
      .then(r => r.json())
      .then(data => {
        setHistory(data);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    setPage(1);
  }, [pageSize, history.length]);

  const getIcon = (type: string) => {
    if (type.includes("scan")) return <Search className="w-4 h-4" />;
    if (type === "update") return <RefreshCw className="w-4 h-4" />;
    return <History className="w-4 h-4" />;
  };
  const resolvedPageSize = pageSize === "all" ? history.length || 1 : pageSize;
  const pageCount = pageSize === "all" ? 1 : Math.max(1, Math.ceil(history.length / resolvedPageSize));
  const currentPage = Math.min(page, pageCount);
  const pageStart = pageSize === "all" ? 0 : (currentPage - 1) * resolvedPageSize;
  const visibleHistory = pageSize === "all" ? history : history.slice(pageStart, pageStart + resolvedPageSize);
  const rangeStart = history.length === 0 ? 0 : pageStart + 1;
  const rangeEnd = pageSize === "all" ? history.length : Math.min(history.length, pageStart + resolvedPageSize);

  return (
    <div className="px-8 max-w-6xl mx-auto space-y-8 pb-20">
      <PageHeader title="History" description="Scan, update, and action history" />

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-400">Loading history...</div>
        ) : history.length === 0 ? (
          <div className="p-12 text-center text-slate-400">No activity recorded yet.</div>
        ) : (
          <>
          <div className="px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 text-sm">
            <span className="text-slate-400">
              Showing {rangeStart}-{rangeEnd} of {history.length}
            </span>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 text-slate-400">
                Rows
                <select
                  value={pageSize}
                  onChange={e => setPageSize(e.target.value === "all" ? "all" : Number(e.target.value) as PageSize)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                >
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                  <option value={200}>200</option>
                  <option value={500}>500</option>
                  <option value="all">All</option>
                </select>
              </label>
              {pageSize !== "all" && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage(current => Math.max(1, current - 1))}
                    disabled={currentPage <= 1}
                    className="px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 rounded-lg transition-colors"
                  >
                    Previous
                  </button>
                  <span className="text-slate-500 tabular-nums">Page {currentPage} / {pageCount}</span>
                  <button
                    onClick={() => setPage(current => Math.min(pageCount, current + 1))}
                    disabled={currentPage >= pageCount}
                    className="px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 rounded-lg transition-colors"
                  >
                    Next
                  </button>
                </div>
              )}
            </div>
          </div>
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
              {visibleHistory.map(item => (
                 <tr key={item.id} className="hover:bg-slate-800/20">
                    <td className="px-6 py-4 flex items-center gap-3">
                      <div className={`p-2 rounded-full ${item.threatsFound > 0 ? 'bg-red-500/10 text-red-400' : 'bg-slate-800 text-slate-400'}`}>
                        {getIcon(item.type)}
                      </div>
                      <span className="capitalize">{item.type.replace("-", " ")}</span>
                    </td>
                    <td className="px-6 py-4 truncate max-w-xs" title={item.target}>{item.target}</td>
                    <td className="px-6 py-4 text-slate-400 text-xs">
                      {formatSystemDateTime(item.date)}
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
          </>
        )}
      </div>
    </div>
  );
}
