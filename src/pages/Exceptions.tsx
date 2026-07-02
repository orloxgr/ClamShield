import { useState, useEffect } from "react";
import { CheckCircle2, ShieldCheck, Trash2, FolderPlus, FilePlus, Send, Loader2 } from "lucide-react";
import PageHeader from "../components/PageHeader";
import { formatSystemDateTime } from "../lib/dateFormat";

type FalsePositiveChannel = "default" | "gmail" | "outlook";
type PageSize = 50 | 100 | 200 | 500 | "all";

const falsePositiveChannelNames: Record<FalsePositiveChannel, string> = {
  default: "report channel",
  gmail: "Gmail compose",
  outlook: "Outlook compose"
};

async function readJsonResponse(response: Response, fallback: string) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    throw new Error(fallback);
  }
}

export default function ExceptionsPage() {
  const [exceptions, setExceptions] = useState<Array<{ path: string, report: any | null }>>([]);
  const [totalItems, setTotalItems] = useState(0);
  const [pageSize, setPageSize] = useState<PageSize>(50);
  const [page, setPage] = useState(1);
  const [dateFilter, setDateFilter] = useState("");
  const [selectedPaths, setSelectedPaths] = useState<Record<string, boolean>>({});
  const [bulkBusy, setBulkBusy] = useState<"remove" | null>(null);
  const [addingError, setAddingError] = useState("");
  const [noticeKind, setNoticeKind] = useState<"error" | "info">("error");
  const [reportingTarget, setReportingTarget] = useState<{ path: string, channel: FalsePositiveChannel } | null>(null);
  const [preparedReports, setPreparedReports] = useState<Record<string, boolean>>({});

  const fetchExceptions = async () => {
    try {
      const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
      if (dateFilter) params.set("date", dateFilter);
      const r = await fetch(`/api/exceptions/reporting?${params.toString()}`);
      const data = await r.json();
      const sourceItems = Array.isArray(data) ? data : data.items;
      if (Array.isArray(sourceItems)) {
        setExceptions(sourceItems);
        setTotalItems(Array.isArray(data) ? sourceItems.length : Number(data.total || 0));
        setSelectedPaths(prev => {
          const visible = new Set(sourceItems.map((item: any) => String(item.path || "")));
          return Object.fromEntries(Object.entries(prev).filter(([itemPath]) => visible.has(itemPath)));
        });
        setPreparedReports(prev => {
          const next = { ...prev };
          sourceItems.forEach((item: any) => {
            if (item?.path && (item.report?.falsePositiveOpenedAt || item.report?.falsePositiveLastOpenedAt)) {
              next[item.path] = true;
            }
          });
          return next;
        });
      }
    } catch {
      setExceptions([]);
      setTotalItems(0);
    }
  };

  useEffect(() => {
    fetchExceptions();
  }, [page, pageSize, dateFilter]);

  useEffect(() => {
    setPage(1);
  }, [pageSize, dateFilter]);

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
        const allResponse = await fetch("/api/exceptions");
        const exceptionPaths = await allResponse.json();
        if (!Array.isArray(exceptionPaths)) throw new Error("Could not load existing exceptions.");
        if (exceptionPaths.includes(selectedPath)) {
          setNoticeKind("error");
          setAddingError("Path is already in exceptions.");
          return;
        }
        const updated = [...exceptionPaths, selectedPath];
        await fetch("/api/exceptions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ exceptions: updated })
        });
        fetchExceptions();
      }
    } catch (e: any) {
      setNoticeKind("error");
      setAddingError("Failed to add exception.");
    }
  };

  const removeException = async (path: string) => {
    try {
      const response = await fetch("/api/exceptions/delete-selected", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ paths: [path] })
      });
      const data = await readJsonResponse(response, "The server returned a non-JSON response while removing the exception. Please retry after the app finishes loading.");
      if (!response.ok || !data.success) throw new Error(data.error || "Could not remove exception.");
      fetchExceptions();
    } catch (e: any) {
      setNoticeKind("error");
      setAddingError(e.message || "Could not remove exception.");
    }
  };

  const selectedItems = exceptions.filter(item => selectedPaths[item.path]);
  const selectedCount = selectedItems.length;
  const allVisibleSelected = exceptions.length > 0 && exceptions.every(item => selectedPaths[item.path]);
  const pageCount = pageSize === "all" ? 1 : Math.max(1, Math.ceil(totalItems / pageSize));
  const currentPage = Math.min(page, pageCount);
  const rangeStart = totalItems === 0 ? 0 : pageSize === "all" ? 1 : (currentPage - 1) * pageSize + 1;
  const rangeEnd = pageSize === "all" ? totalItems : Math.min(totalItems, (currentPage - 1) * pageSize + pageSize);

  const toggleSelected = (path: string, checked: boolean) => {
    setSelectedPaths(prev => {
      const next = { ...prev };
      if (checked) next[path] = true;
      else delete next[path];
      return next;
    });
  };

  const toggleSelectVisible = (checked: boolean) => {
    setSelectedPaths(prev => {
      const next = { ...prev };
      exceptions.forEach(item => {
        if (checked) next[item.path] = true;
        else delete next[item.path];
      });
      return next;
    });
  };

  const removeSelected = async () => {
    if (selectedCount === 0) return;
    if (!confirm(`Remove ${selectedCount} selected exception(s)?`)) return;
    setBulkBusy("remove");
    setAddingError("");
    try {
      const response = await fetch("/api/exceptions/delete-selected", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ paths: selectedItems.map(item => item.path) })
      });
      const data = await readJsonResponse(response, "The server returned a non-JSON response while removing exceptions. Please retry after the app finishes loading.");
      if (!response.ok || !data.success) throw new Error(data.error || "Could not remove selected exceptions.");
      setNoticeKind("info");
      setAddingError(`Removed ${data.removedCount || 0} selected exception(s).`);
      setSelectedPaths({});
      fetchExceptions();
    } catch (e: any) {
      setNoticeKind("error");
      setAddingError(e.message || "Could not remove selected exceptions.");
    } finally {
      setBulkBusy(null);
    }
  };

  const reportFalsePositive = async (exceptionPath: string, channel: FalsePositiveChannel = "default") => {
    setReportingTarget({ path: exceptionPath, channel });
    setAddingError("");
    try {
      const response = await fetch("/api/exceptions/report-false-positive", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: exceptionPath, channel })
      });
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || "Could not prepare the false-positive report.");
      await navigator.clipboard?.writeText(data.details).catch(() => {});
      const targetUrl = channel === "gmail" ? data.emailUrls?.gmail : channel === "outlook" ? data.emailUrls?.outlook : data.url;
      if (!targetUrl) throw new Error(`${falsePositiveChannelNames[channel]} is not available for this provider.`);
      window.open(targetUrl, "_blank", "noopener,noreferrer");
      setPreparedReports(prev => ({ ...prev, [exceptionPath]: true }));
      setNoticeKind("info");
      setAddingError(
        `Opened ${channel === "default" ? data.provider.name : falsePositiveChannelNames[channel]}. Report details were copied to the clipboard.${
          data.requiresSample ? " Attach or upload the file only if you are comfortable sharing it with that provider." : ""
        }`
      );
    } catch (error: any) {
      setNoticeKind("error");
      setAddingError(error.message || "Could not prepare the false-positive report.");
    } finally {
      setReportingTarget(null);
    }
  };

  return (
    <div className="px-8 max-w-5xl mx-auto space-y-8 pb-20 animate-in slide-in-from-bottom-4 duration-500">
      <PageHeader
        title="Exceptions"
        description="Files and folders excluded from future scans"
        actions={(
        <div className="flex flex-wrap items-center gap-3">
            <span className="text-sm text-slate-400 tabular-nums">{selectedCount} selected</span>
            <button
                onClick={removeSelected}
                disabled={selectedCount === 0 || bulkBusy !== null}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
            >
                <Trash2 className="w-4 h-4" />
                <span>{bulkBusy === "remove" ? "Removing..." : "Remove selected"}</span>
            </button>
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
        )}
      />

      {addingError && (
        <div className={`p-4 rounded-lg text-sm border ${
          noticeKind === "info"
            ? "bg-indigo-500/10 border-indigo-500/20 text-indigo-200"
            : "bg-red-500/10 border-red-500/20 text-red-400"
        }`}>
          {addingError}
        </div>
      )}

      {totalItems === 0 ? (
        <div className="flex items-center justify-center p-12 mt-12 bg-slate-900 border border-slate-800 rounded-2xl flex-col text-center">
          <ShieldCheck className="w-16 h-16 text-slate-700 mb-4" />
          <h2 className="text-xl font-medium text-slate-300 mb-2">No Exceptions Added</h2>
          <p className="text-slate-500 max-w-md">
            Any files or directories you add here will be ignored by both the active Shield and manual scans.
          </p>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
          <div className="px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 text-sm">
            <span className="text-slate-400">Showing {rangeStart}-{rangeEnd} of {totalItems}</span>
            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-2 text-slate-400">
                Date
                <input type="date" value={dateFilter} onChange={e => setDateFilter(e.target.value)} className="date-picker-control bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500" />
              </label>
              {dateFilter && <button onClick={() => setDateFilter("")} className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors">Clear</button>}
              <label className="flex items-center gap-2 text-slate-400">
                Rows
                <select value={pageSize} onChange={e => setPageSize(e.target.value === "all" ? "all" : Number(e.target.value) as PageSize)} className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500">
                  <option value={50}>50</option><option value={100}>100</option><option value={200}>200</option><option value={500}>500</option><option value="all">All</option>
                </select>
              </label>
              {pageSize !== "all" && (
                <div className="flex items-center gap-2">
                  <button onClick={() => setPage(current => Math.max(1, current - 1))} disabled={currentPage <= 1} className="px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 rounded-lg transition-colors">Previous</button>
                  <span className="text-slate-500 tabular-nums">Page {currentPage} / {pageCount}</span>
                  <button onClick={() => setPage(current => Math.min(pageCount, current + 1))} disabled={currentPage >= pageCount} className="px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 rounded-lg transition-colors">Next</button>
                </div>
              )}
            </div>
          </div>
          <div className="px-4 py-3 border-b border-slate-800 bg-slate-800/30">
            <label className="inline-flex items-center gap-2 text-sm text-slate-400">
              <input type="checkbox" checked={allVisibleSelected} onChange={e => toggleSelectVisible(e.target.checked)} className="w-4 h-4 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" />
              Select visible
            </label>
          </div>
          <div className="divide-y divide-slate-800">
            {exceptions.map((exception, idx) => (
              <div key={idx} className="flex justify-between items-center p-4 hover:bg-slate-800/50 transition-colors">
                <div className="flex items-start gap-3 min-w-0 pr-4">
                  <input type="checkbox" checked={Boolean(selectedPaths[exception.path])} onChange={e => toggleSelected(exception.path, e.target.checked)} className="mt-1 w-4 h-4 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" />
                  <div className="min-w-0">
                  <span className="font-mono text-sm text-slate-300 truncate block" title={exception.path}>{exception.path}</span>
                  <span className="text-xs text-slate-600 mt-1 block">Added {formatSystemDateTime((exception as any).date || (exception as any).addedAt)}</span>
                  {exception.report && (
                    <span className="text-xs text-slate-500 mt-1 block">
                      {exception.report.threatName} · Report to {exception.report.provider.name}
                    </span>
                  )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {exception.report && (
                    <button
                      onClick={() => reportFalsePositive(exception.path)}
                      disabled={reportingTarget !== null}
                      className={`inline-flex items-center gap-2 px-3 py-2 text-xs hover:text-white disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors border ${
                        preparedReports[exception.path]
                          ? "text-emerald-200 bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/30"
                          : "text-indigo-300 bg-indigo-500/10 hover:bg-indigo-500/20 border-indigo-500/20"
                      }`}
                      title={
                        preparedReports[exception.path]
                          ? `Open the ${exception.report.provider.name} false-positive channel again`
                          : `Open the ${exception.report.provider.name} false-positive channel`
                      }
                    >
                      {reportingTarget?.path === exception.path && reportingTarget.channel === "default" ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : preparedReports[exception.path] ? (
                        <CheckCircle2 className="w-4 h-4" />
                      ) : (
                        <Send className="w-4 h-4" />
                      )}
                      {reportingTarget?.path === exception.path && reportingTarget.channel === "default" ? "Opening report..." : preparedReports[exception.path] ? "Report opened" : "Report false positive"}
                    </button>
                  )}
                  {exception.report?.provider?.method === "email" && (
                    <>
                      <button
                        onClick={() => reportFalsePositive(exception.path, "gmail")}
                        disabled={reportingTarget !== null}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-2 text-xs hover:text-white disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors border ${
                          preparedReports[exception.path]
                            ? "text-emerald-200 bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/30"
                            : "text-slate-300 bg-slate-800 hover:bg-slate-700 border-slate-700"
                        }`}
                        title="Open Gmail compose with the false-positive report"
                      >
                        {reportingTarget?.path === exception.path && reportingTarget.channel === "gmail" ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : preparedReports[exception.path] ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : null}
                        Gmail
                      </button>
                      <button
                        onClick={() => reportFalsePositive(exception.path, "outlook")}
                        disabled={reportingTarget !== null}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-2 text-xs hover:text-white disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors border ${
                          preparedReports[exception.path]
                            ? "text-emerald-200 bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/30"
                            : "text-slate-300 bg-slate-800 hover:bg-slate-700 border-slate-700"
                        }`}
                        title="Open Outlook compose with the false-positive report"
                      >
                        {reportingTarget?.path === exception.path && reportingTarget.channel === "outlook" ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : preparedReports[exception.path] ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : null}
                        Outlook
                      </button>
                    </>
                  )}
                  <button
                    onClick={() => removeException(exception.path)}
                    className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors flex-shrink-0"
                    title="Remove exception"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
