import { useEffect, useState } from "react";
import { History, Search, ShieldAlert, RefreshCw, CheckCircle2, Trash2 } from "lucide-react";
import PageHeader from "../components/PageHeader";
import { formatSystemDateTime } from "../lib/dateFormat";

type PageSize = 50 | 100 | 200 | 500 | "all";

export default function HistoryPage() {
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [pageSize, setPageSize] = useState<PageSize>(50);
  const [page, setPage] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [dateFilter, setDateFilter] = useState("");
  const [selectedIds, setSelectedIds] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState<"delete" | null>(null);
  const [message, setMessage] = useState("");

  const fetchHistory = () => {
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
    if (dateFilter) params.set("date", dateFilter);
    fetch(`/api/history?${params.toString()}`)
      .then(r => r.json())
      .then(data => {
        const sourceItems = Array.isArray(data) ? data : data.items;
        const nextItems = Array.isArray(sourceItems) ? sourceItems : [];
        setHistory(nextItems);
        setTotalItems(Array.isArray(data) ? nextItems.length : Number(data.total || 0));
        setSelectedIds(prev => {
          const visible = new Set(nextItems.map((item: any) => String(item.id || "")));
          return Object.fromEntries(Object.entries(prev).filter(([id]) => visible.has(id)));
        });
      })
      .catch(() => {
        setHistory([]);
        setTotalItems(0);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchHistory();
  }, [page, pageSize, dateFilter]);

  useEffect(() => {
    setPage(1);
  }, [pageSize, dateFilter]);

  const getIcon = (type: string) => {
    if (type.includes("scan")) return <Search className="w-4 h-4" />;
    if (type === "update") return <RefreshCw className="w-4 h-4" />;
    return <History className="w-4 h-4" />;
  };
  const selectedItems = history.filter(item => selectedIds[item.id]);
  const selectedCount = selectedItems.length;
  const allVisibleSelected = history.length > 0 && history.every(item => selectedIds[item.id]);
  const resolvedPageSize = pageSize === "all" ? totalItems || 1 : pageSize;
  const pageCount = pageSize === "all" ? 1 : Math.max(1, Math.ceil(totalItems / resolvedPageSize));
  const currentPage = Math.min(page, pageCount);
  const rangeStart = totalItems === 0 ? 0 : pageSize === "all" ? 1 : (currentPage - 1) * resolvedPageSize + 1;
  const rangeEnd = pageSize === "all" ? totalItems : Math.min(totalItems, (currentPage - 1) * resolvedPageSize + resolvedPageSize);

  const toggleSelected = (id: string, checked: boolean) => {
    setSelectedIds(prev => {
      const next = { ...prev };
      if (checked) next[id] = true;
      else delete next[id];
      return next;
    });
  };

  const toggleSelectVisible = (checked: boolean) => {
    setSelectedIds(prev => {
      const next = { ...prev };
      history.forEach(item => {
        if (checked) next[item.id] = true;
        else delete next[item.id];
      });
      return next;
    });
  };

  const deleteSelected = async () => {
    if (selectedCount === 0) return;
    if (!confirm(`Delete ${selectedCount} selected history item(s)?`)) return;
    setBusy("delete");
    setMessage("");
    try {
      const response = await fetch("/api/history/delete-selected", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: selectedItems.map(item => item.id) })
      });
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || "Could not delete selected history.");
      setMessage(`Deleted ${data.deletedCount || 0} selected history item(s).`);
      setSelectedIds({});
      fetchHistory();
    } catch (e: any) {
      setMessage(e.message || "Could not delete selected history.");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="px-8 max-w-6xl mx-auto space-y-8 pb-20">
      <PageHeader
        title="History"
        description="Scan, update, and action history"
        actions={history.length > 0 ? (
          <div className="flex items-center gap-3">
            <span className="text-sm text-slate-400 tabular-nums">{selectedCount} selected</span>
            <button
              onClick={deleteSelected}
              disabled={selectedCount === 0 || busy !== null}
              className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
            >
              <Trash2 className="w-4 h-4" />
              {busy === "delete" ? "Deleting..." : "Delete selected"}
            </button>
          </div>
        ) : null}
      />

      {message && (
        <div className="p-3 bg-slate-900 border border-slate-800 text-slate-300 rounded-md text-sm">
          {message}
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-400">Loading history...</div>
        ) : totalItems === 0 ? (
          <div className="p-12 text-center text-slate-400">No activity recorded yet.</div>
        ) : (
          <>
          <div className="px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 text-sm">
            <span className="text-slate-400">
              Showing {rangeStart}-{rangeEnd} of {totalItems}
            </span>
            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-2 text-slate-400">
                Date
                <input
                  type="date"
                  value={dateFilter}
                  onChange={e => setDateFilter(e.target.value)}
                  className="date-picker-control bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
                />
              </label>
              {dateFilter && (
                <button onClick={() => setDateFilter("")} className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors">
                  Clear
                </button>
              )}
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
                <th className="px-6 py-4 font-medium">
                  <input
                    type="checkbox"
                    checked={allVisibleSelected}
                    onChange={e => toggleSelectVisible(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
                    title="Select visible history"
                  />
                </th>
                <th className="px-6 py-4 font-medium">Event Type</th>
                <th className="px-6 py-4 font-medium">Target</th>
                <th className="px-6 py-4 font-medium">Date</th>
                <th className="px-6 py-4 font-medium text-right">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {history.map(item => (
                 <tr key={item.id} className="hover:bg-slate-800/20">
                    <td className="px-6 py-4">
                      <input
                        type="checkbox"
                        checked={Boolean(selectedIds[item.id])}
                        onChange={e => toggleSelected(item.id, e.target.checked)}
                        className="w-4 h-4 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
                        title="Select history item"
                      />
                    </td>
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
