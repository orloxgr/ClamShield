import { AlertTriangle, Archive, CheckCircle2, Cloud, Loader2, SearchCheck, ShieldCheck, Trash2, UploadCloud } from "lucide-react";
import { useEffect, useState } from "react";
import DropdownSelect, { type DropdownOption } from "../components/DropdownSelect";
import PageHeader from "../components/PageHeader";
import { formatSystemDateTime } from "../lib/dateFormat";

type VirusTotalAction = "md5" | "upload" | "cloud";
type PageSize = 50 | 100 | 200 | 500 | "all";

export default function ResultsPage() {
  const [items, setItems] = useState<any[]>([]);
  const [totalItems, setTotalItems] = useState(0);
  const [loading, setLoading] = useState(true);
  const [pageSize, setPageSize] = useState<PageSize>(50);
  const [page, setPage] = useState(1);
  const [dateFilter, setDateFilter] = useState("");
  const [findingSourceFilter, setFindingSourceFilter] = useState("all");
  const [virusTotalRefinementFilter, setVirusTotalRefinementFilter] = useState("all");
  const [findingSourceOptions, setFindingSourceOptions] = useState<string[]>(["ClamAV", "SecuriteInfo", "SaneSecurity", "YARA"]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [bulkBusy, setBulkBusy] = useState<"exception" | "quarantine" | "clear" | "vt" | null>(null);
  const [message, setMessage] = useState("");
  const [selectedIds, setSelectedIds] = useState<Record<string, boolean>>({});
  const [virusTotalBusy, setVirusTotalBusy] = useState<{ id: string, action: VirusTotalAction } | null>(null);
  const [checkedVirusTotal, setCheckedVirusTotal] = useState<Record<string, Partial<Record<VirusTotalAction, boolean>>>>({});
  const [virusTotalCloudReports, setVirusTotalCloudReports] = useState<Record<string, any>>({});
  const selectedItems = items.filter(item => selectedIds[item.id]);
  const selectedCount = selectedItems.length;
  const selectedMissingCount = selectedItems.filter(item => item.available === false).length;
  const allVisibleSelected = items.length > 0 && items.every(item => selectedIds[item.id]);

  const markVirusTotalChecked = (id: string, action: VirusTotalAction) => {
    setCheckedVirusTotal(prev => ({
      ...prev,
      [id]: {
        ...prev[id],
        [action]: true
      }
    }));
  };

  const fetchItems = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(page),
        pageSize: String(pageSize)
      });
      if (dateFilter) params.set("date", dateFilter);
      if (findingSourceFilter !== "all") params.set("findingSource", findingSourceFilter);
      if (virusTotalRefinementFilter !== "all") params.set("virusTotalRefinement", virusTotalRefinementFilter);
      const res = await fetch(`/api/results?${params.toString()}`);
      const data = await res.json();
      const sourceItems = Array.isArray(data) ? data : data.items;
      const sorted = Array.isArray(sourceItems) ? sourceItems.sort((a: any, b: any) => Number(b.timestamp || 0) - Number(a.timestamp || 0)) : [];
      setItems(sorted);
      setTotalItems(Array.isArray(data) ? sorted.length : Number(data.total || 0));
      const optionSource = !Array.isArray(data) && Array.isArray(data.findingSourceOptions)
        ? data.findingSourceOptions
        : !Array.isArray(data) && Array.isArray(data.engineOptions) ? data.engineOptions : null;
      if (optionSource) {
        const nextOptions = optionSource
          .map((source: any) => String(source || "").trim())
          .filter(Boolean);
        if (findingSourceFilter !== "all" && !nextOptions.includes(findingSourceFilter)) nextOptions.push(findingSourceFilter);
        setFindingSourceOptions(nextOptions.length > 0 ? nextOptions : ["ClamAV", "SecuriteInfo", "SaneSecurity", "YARA"]);
      }
      setCheckedVirusTotal(prev => {
        const next = { ...prev };
        sorted.forEach((item: any) => {
          const checks = item.virusTotalChecks || {};
          if (item.id && (checks.md5 || checks.upload || checks.cloud)) {
            next[item.id] = {
              ...next[item.id],
              md5: Boolean(next[item.id]?.md5 || checks.md5),
              upload: Boolean(next[item.id]?.upload || checks.upload),
              cloud: Boolean(next[item.id]?.cloud || checks.cloud)
            };
          }
        });
        return next;
      });
      setSelectedIds(prev => {
        const visibleIds = new Set(sorted.map((item: any) => String(item.id || "")));
        return Object.fromEntries(Object.entries(prev).filter(([id]) => visibleIds.has(id)));
      });
    } catch {
      setItems([]);
      setTotalItems(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchItems();
  }, [page, pageSize, dateFilter, findingSourceFilter, virusTotalRefinementFilter]);

  useEffect(() => {
    setPage(1);
  }, [pageSize, dateFilter, findingSourceFilter, virusTotalRefinementFilter]);

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
      items.forEach(item => {
        if (!item.id) return;
        if (checked) next[item.id] = true;
        else delete next[item.id];
      });
      return next;
    });
  };

  const runSelectedAction = async (action: "quarantine" | "exception") => {
    if (selectedCount === 0) return;
    if (action === "quarantine" && !confirm(`Quarantine ${selectedCount} selected result item(s)?`)) return;
    setBulkBusy(action);
    setMessage("");
    try {
      const res = await fetch("/api/results/action-selected", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, ids: selectedItems.map(item => item.id) })
      });
      const data = await res.json();
      if (!res.ok && res.status !== 207) throw new Error(data.error || "Selected action failed.");
      setMessage(action === "quarantine"
        ? `Quarantined ${data.affectedCount || 0} selected item(s).${data.removedUnavailableCount ? ` Removed ${data.removedUnavailableCount} unavailable item(s).` : ""}${data.errors?.length ? ` ${data.errors.length} item(s) could not be moved.` : ""}`
        : `Added ${data.affectedCount || 0} selected item(s) to exceptions.${data.errors?.length ? ` ${data.errors.length} item(s) could not be added.` : ""}`);
      setSelectedIds({});
      fetchItems();
    } catch (e: any) {
      setMessage(e.message || "Selected action failed.");
    } finally {
      setBulkBusy(null);
    }
  };

  const clearSelectedUnavailable = async () => {
    if (selectedMissingCount === 0) return;
    setMessage("");
    setBulkBusy("clear");
    try {
      const res = await fetch("/api/results/clear-selected-unavailable", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: selectedItems.map(item => item.id) })
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Cleanup failed.");
      setMessage(`Removed ${data.removedCount} missing selected result item(s).`);
      setSelectedIds({});
      fetchItems();
    } catch (e: any) {
      setMessage(e.message || "Cleanup failed.");
    } finally {
      setBulkBusy(null);
    }
  };

  const recheckAllWithVirusTotal = async () => {
    if (totalItems === 0) return;
    setMessage("");
    setBulkBusy("vt");
    try {
      const res = await fetch("/api/results/virustotal-recheck-all", { method: "POST" });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Could not queue VirusTotal recheck.");
      setCheckedVirusTotal({});
      setVirusTotalCloudReports({});
      setItems(current => current.map(item => ({ ...item, virusTotalRefinement: null })));
      setMessage(data.message || "VirusTotal recheck queued.");
      fetchItems();
    } catch (e: any) {
      setMessage(e.message || "Could not queue VirusTotal recheck.");
    } finally {
      setBulkBusy(null);
    }
  };

  const checkMd5 = async (id: string) => {
    setBusyId(id);
    setVirusTotalBusy({ id, action: "md5" });
    setMessage("");
    try {
      const response = await fetch(`/api/results/${encodeURIComponent(id)}/virustotal-hash?algorithm=md5`);
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || "Could not prepare the VirusTotal report.");
      window.open(data.url, "_blank", "noopener,noreferrer");
      markVirusTotalChecked(id, "md5");
      setMessage("Opened the VirusTotal MD5 report.");
    } catch (error: any) {
      setMessage(error.message || "Could not open VirusTotal.");
    } finally {
      setVirusTotalBusy(null);
      setBusyId(null);
    }
  };

  const cloudCheck = async (id: string) => {
    setBusyId(id);
    setVirusTotalBusy({ id, action: "cloud" });
    setMessage("");
    try {
      const response = await fetch(`/api/results/${encodeURIComponent(id)}/virustotal-cloud`);
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || "Could not query VirusTotal Cloud Check.");
      setVirusTotalCloudReports(prev => ({ ...prev, [id]: data.report }));
      if (data.refinement) {
        setItems(current => current.map(item => item.id === id ? { ...item, virusTotalRefinement: data.refinement } : item));
      }
      markVirusTotalChecked(id, "cloud");
      setMessage(data.message || "VirusTotal Cloud Check completed.");
    } catch (error: any) {
      setMessage(error.message || "Could not query VirusTotal Cloud Check.");
    } finally {
      setVirusTotalBusy(null);
      setBusyId(null);
    }
  };

  const openUploadCheck = async (id: string) => {
    setBusyId(id);
    setVirusTotalBusy({ id, action: "upload" });
    setMessage("");
    try {
      const response = await fetch(`/api/results/${encodeURIComponent(id)}/virustotal-upload`);
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || "Could not prepare the VirusTotal upload check.");
      await navigator.clipboard?.writeText(data.filePath).catch(() => {});
      window.open(data.url, "_blank", "noopener,noreferrer");
      markVirusTotalChecked(id, "upload");
      setMessage("Opened VirusTotal and copied the file path.");
    } catch (error: any) {
      setMessage(error.message || "Could not open VirusTotal upload.");
    } finally {
      setVirusTotalBusy(null);
      setBusyId(null);
    }
  };

  const pageCount = pageSize === "all" ? 1 : Math.max(1, Math.ceil(totalItems / pageSize));
  const formatVirusTotalDate = (value: any) => value ? formatSystemDateTime(new Date(Number(value) * 1000).toISOString()) : "Unknown";
  const virusTotalVerdictClass = (report: any) => {
    const stats = report?.stats || {};
    if (Number(stats.malicious || 0) > 0) return "border-rose-500/30 bg-rose-500/10 text-rose-100";
    if (Number(stats.suspicious || 0) > 0) return "border-amber-500/30 bg-amber-500/10 text-amber-100";
    if (report?.found === false) return "border-slate-700 bg-slate-950/70 text-slate-300";
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-100";
  };
  const virusTotalRefinementClass = (refinement: any) => {
    const severity = refinement?.severity || "";
    if (severity === "good") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
    if (severity === "warning") return "border-amber-500/30 bg-amber-500/10 text-amber-300";
    if (severity === "danger") return "border-rose-500/30 bg-rose-500/10 text-rose-300";
    return "border-slate-700 bg-slate-950/70 text-slate-300";
  };
  const getVirusTotalReport = (item: any): any => virusTotalCloudReports[item.id] || item.virusTotalRefinement?.report || null;
  const currentPage = Math.min(page, pageCount);
  const rangeStart = totalItems === 0 ? 0 : pageSize === "all" ? 1 : (currentPage - 1) * pageSize + 1;
  const rangeEnd = pageSize === "all" ? totalItems : Math.min(totalItems, (currentPage - 1) * pageSize + pageSize);
  const hasActiveFilters = Boolean(dateFilter || findingSourceFilter !== "all" || virusTotalRefinementFilter !== "all");
  const pageSizeOptions: DropdownOption[] = [
    { value: "50", label: "50" },
    { value: "100", label: "100" },
    { value: "200", label: "200" },
    { value: "500", label: "500" },
    { value: "all", label: "All" }
  ];
  const findingSourceDropdownOptions: DropdownOption[] = [
    { value: "all", label: "All sources" },
    ...findingSourceOptions.map(source => ({ value: source, label: source }))
  ];
  const virusTotalRefinementOptions: DropdownOption[] = [
    { value: "all", label: "All VT labels" },
    { value: "unrefined", label: "Unrefined" },
    { value: "likely_false_positive", label: "Likely false positive" },
    { value: "needs_review", label: "Needs review" },
    { value: "confirmed_suspicious", label: "Confirmed suspicious" },
    { value: "confirmed_malicious", label: "Confirmed malicious" },
    { value: "unknown", label: "Unknown to VirusTotal" },
    { value: "error", label: "Refinement error" }
  ];

  return (
    <div className="px-8 max-w-6xl mx-auto space-y-8 pb-20">
      <PageHeader
        title="Results"
        description="Suspicious files waiting for your decision"
        actions={items.length > 0 ? (
          <div className="grid w-[26rem] max-w-full grid-cols-2 gap-2">
              <span className="col-span-2 text-right text-sm text-slate-400 tabular-nums">{selectedCount} selected</span>
              <button
                onClick={recheckAllWithVirusTotal}
                disabled={bulkBusy !== null || totalItems === 0}
                className="flex min-w-0 items-center justify-center gap-2 px-3 py-2 bg-sky-700 hover:bg-sky-600 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
              >
                <Cloud className="w-4 h-4 shrink-0" />
                <span className="truncate">{bulkBusy === "vt" ? "Queueing..." : "Recheck all with VT"}</span>
              </button>
              <button
                onClick={() => runSelectedAction("exception")}
                disabled={bulkBusy !== null || selectedCount === 0}
                className="flex min-w-0 items-center justify-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-60 disabled:cursor-not-allowed text-slate-300 rounded-lg font-medium transition-colors border border-slate-700"
              >
                <ShieldCheck className="w-4 h-4 shrink-0" />
                <span className="truncate">{bulkBusy === "exception" ? "Adding..." : "Add to exceptions"}</span>
              </button>
              <button
                onClick={clearSelectedUnavailable}
                disabled={bulkBusy !== null || selectedMissingCount === 0}
                title="Remove selected Results entries whose original file is no longer available."
                className="flex min-w-0 items-center justify-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-60 disabled:cursor-not-allowed text-slate-300 rounded-lg font-medium transition-colors border border-slate-700"
              >
                <Trash2 className="w-4 h-4 shrink-0" />
                <span className="truncate">{bulkBusy === "clear" ? "Removing..." : selectedMissingCount > 0 ? `Remove missing selected (${selectedMissingCount})` : "Remove missing selected"}</span>
              </button>
              <button
                onClick={() => runSelectedAction("quarantine")}
                disabled={bulkBusy !== null || selectedCount === 0}
                className="flex min-w-0 items-center justify-center gap-2 px-3 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
              >
                <Archive className="w-4 h-4 shrink-0" />
                <span className="truncate">{bulkBusy === "quarantine" ? "Quarantining..." : "Quarantine selected"}</span>
              </button>
          </div>
        ) : null}
      />

      {message && (
        <div className="p-3 bg-slate-900 border border-slate-800 text-slate-300 rounded-md text-sm">
          {message}
        </div>
      )}

      {loading ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-center">
          <Loader2 className="w-8 h-8 animate-spin text-indigo-400 mb-4" />
          <p className="text-slate-400">Loading results...</p>
        </div>
      ) : totalItems === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 bg-emerald-500/10 text-emerald-400 rounded-full flex items-center justify-center mb-4">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-medium text-slate-200 mb-2">{hasActiveFilters ? "No results for these filters" : "No undecided results"}</h3>
          <p className="text-slate-500 max-w-md">
            {hasActiveFilters ? "Pick another filter or clear filters to see all undecided results." : "Manual scan detections and silent shield detections will appear here for review."}
          </p>
          {hasActiveFilters && (
            <button
              onClick={() => {
                setDateFilter("");
                setFindingSourceFilter("all");
                setVirusTotalRefinementFilter("all");
              }}
              className="mt-4 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700"
            >
              Clear filters
            </button>
          )}
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
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
                <button
                  onClick={() => setDateFilter("")}
                  className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
                >
                  Clear
                </button>
              )}
              <label className="flex items-center gap-2 text-slate-400">
                VT
                <DropdownSelect
                  ariaLabel="Filter results by VirusTotal refinement"
                  value={virusTotalRefinementFilter}
                  options={virusTotalRefinementOptions}
                  onChange={setVirusTotalRefinementFilter}
                  align="right"
                />
              </label>
              <label className="flex items-center gap-2 text-slate-400">
                Rows
                <DropdownSelect
                  ariaLabel="Rows per page"
                  value={String(pageSize)}
                  options={pageSizeOptions}
                  onChange={value => setPageSize(value === "all" ? "all" : Number(value) as PageSize)}
                  align="right"
                />
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
          <table className="w-full table-fixed text-left text-sm">
            <colgroup>
              <col className="w-[5%]" />
              <col className="w-[53%]" />
              <col className="w-[12%]" />
              <col className="w-[12%]" />
              <col className="w-[18%]" />
            </colgroup>
            <thead className="bg-slate-800/50 text-slate-400">
              <tr>
                <th className="px-6 py-4 font-medium">
                  <input
                    type="checkbox"
                    checked={allVisibleSelected}
                    onChange={e => toggleSelectVisible(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
                    title="Select visible results"
                  />
                </th>
                <th className="px-6 py-4 font-medium">Detection</th>
                <th className="px-6 py-4 font-medium">
                  <div className="flex flex-col items-start gap-1">
                    <DropdownSelect
                      ariaLabel="Filter results by finding source"
                      value={findingSourceFilter}
                      options={findingSourceDropdownOptions}
                      onChange={setFindingSourceFilter}
                      compact
                      active={findingSourceFilter !== "all"}
                    />
                    {findingSourceFilter !== "all" && (
                      <span className="max-w-full truncate rounded bg-indigo-500/10 px-1.5 py-0.5 text-[11px] font-medium text-indigo-300">
                        {findingSourceFilter}
                      </span>
                    )}
                  </div>
                </th>
                <th className="px-6 py-4 font-medium">Scan</th>
                <th className="px-6 py-4 font-medium">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {items.map(item => (
                <tr key={item.id} className="hover:bg-slate-800/50 transition-colors">
                  <td className="px-6 py-4 align-top">
                    <input
                      type="checkbox"
                      checked={Boolean(selectedIds[item.id])}
                      onChange={e => toggleSelected(item.id, e.target.checked)}
                      className="mt-1 w-4 h-4 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800"
                      title="Select result"
                    />
                  </td>
                  <td className="px-6 py-4 font-medium text-red-400">
                    <span className="inline-flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      {item.threatName || "Unknown Threat"}
                    </span>
                    {item.virusTotalRefinement?.label && (
                      <span className={`ml-2 inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-medium ${virusTotalRefinementClass(item.virusTotalRefinement)}`}>
                        {item.virusTotalRefinement.label}
                      </span>
                    )}
                    <div
                      className="mt-2 max-w-full overflow-x-auto whitespace-nowrap font-mono text-xs font-normal text-slate-400 pb-1"
                      title={item.originalPath}
                    >
                      {item.originalPath}
                    </div>
                    <div className="mt-3 grid grid-cols-5 gap-2 max-w-3xl">
                      <button
                        onClick={() => cloudCheck(item.id)}
                        disabled={busyId === item.id || (item.available === false && !item.sha256)}
                        title={
                          checkedVirusTotal[item.id]?.cloud
                            ? "Run VirusTotal Cloud Check again."
                            : "Run VirusTotal Cloud Check."
                        }
                        className={`inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded text-[11px] font-medium transition-colors ${
                          checkedVirusTotal[item.id]?.cloud ? "bg-emerald-600 hover:bg-emerald-500" : "bg-sky-700 hover:bg-sky-600"
                        }`}
                      >
                        {virusTotalBusy?.id === item.id && virusTotalBusy.action === "cloud" ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : checkedVirusTotal[item.id]?.cloud ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : (
                          <Cloud className="w-3.5 h-3.5" />
                        )}
                        {virusTotalBusy?.id === item.id && virusTotalBusy.action === "cloud" ? "Checking..." : checkedVirusTotal[item.id]?.cloud ? "Cloud checked" : "Cloud check"}
                      </button>
                      <button
                        onClick={() => checkMd5(item.id)}
                        disabled={busyId === item.id || (item.available === false && !item.md5)}
                        title={
                          checkedVirusTotal[item.id]?.md5
                            ? "Open the VirusTotal MD5 report again."
                            : "Open the VirusTotal MD5 report."
                        }
                        className={`inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded text-[11px] font-medium transition-colors ${
                          checkedVirusTotal[item.id]?.md5 ? "bg-emerald-600 hover:bg-emerald-500" : "bg-indigo-600 hover:bg-indigo-500"
                        }`}
                      >
                        {virusTotalBusy?.id === item.id && virusTotalBusy.action === "md5" ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : checkedVirusTotal[item.id]?.md5 ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : (
                          <SearchCheck className="w-3.5 h-3.5" />
                        )}
                        {virusTotalBusy?.id === item.id && virusTotalBusy.action === "md5" ? "Opening..." : checkedVirusTotal[item.id]?.md5 ? "MD5 opened" : "MD5 check"}
                      </button>
                      <button
                        onClick={() => openUploadCheck(item.id)}
                        disabled={busyId === item.id || item.available === false}
                        title={
                          checkedVirusTotal[item.id]?.upload
                            ? "Open VirusTotal's upload page again. The full file path will be copied so you can paste it with Ctrl+V."
                            : "Opens VirusTotal's upload page. The full file path will be copied so you can paste it with Ctrl+V."
                        }
                        className={`inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded text-[11px] font-medium transition-colors ${
                          checkedVirusTotal[item.id]?.upload ? "bg-emerald-600 hover:bg-emerald-500" : "bg-sky-600 hover:bg-sky-500"
                        }`}
                      >
                        {virusTotalBusy?.id === item.id && virusTotalBusy.action === "upload" ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : checkedVirusTotal[item.id]?.upload ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : (
                          <UploadCloud className="w-3.5 h-3.5" />
                        )}
                        {virusTotalBusy?.id === item.id && virusTotalBusy.action === "upload" ? "Opening..." : checkedVirusTotal[item.id]?.upload ? "Upload opened" : "File upload check"}
                      </button>
                      <button
                        onClick={() => handleAction(item.id, "exception")}
                        disabled={busyId === item.id}
                        className="inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-60 disabled:cursor-not-allowed text-slate-300 rounded text-[11px] font-medium transition-colors border border-slate-700"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        Exception
                      </button>
                      <button
                        onClick={() => handleAction(item.id, "quarantine")}
                        disabled={busyId === item.id}
                        className="inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 bg-red-600 hover:bg-red-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded text-[11px] font-medium transition-colors"
                      >
                        <Archive className="w-3.5 h-3.5" />
                        Quarantine
                      </button>
                    </div>
                    {getVirusTotalReport(item) && (
                      <div className={`mt-3 max-w-3xl rounded-lg border p-3 text-xs ${virusTotalVerdictClass(getVirusTotalReport(item))}`}>
                        {getVirusTotalReport(item).found === false ? (
                          <div className="flex flex-wrap items-center justify-between gap-3">
                            <span>{getVirusTotalReport(item).message || "VirusTotal has no report for this hash."}</span>
                            <a href={getVirusTotalReport(item).url} target="_blank" rel="noopener noreferrer" className="text-sky-300 hover:text-sky-200">Open VT</a>
                          </div>
                        ) : (
                          <div className="space-y-2">
                            <div className="flex flex-wrap items-center justify-between gap-3">
                              <span className="font-medium">
                                VT: {getVirusTotalReport(item).stats?.malicious || 0} malicious, {getVirusTotalReport(item).stats?.suspicious || 0} suspicious, {getVirusTotalReport(item).stats?.harmless || 0} harmless, {getVirusTotalReport(item).stats?.undetected || 0} undetected
                              </span>
                              <a href={getVirusTotalReport(item).url} target="_blank" rel="noopener noreferrer" className="text-sky-300 hover:text-sky-200">Open VT</a>
                            </div>
                            <div className="text-slate-300">
                              {getVirusTotalReport(item).typeDescription || "Unknown type"} - Last analysis: {formatVirusTotalDate(getVirusTotalReport(item).lastAnalysisDate)}
                            </div>
                            {Array.isArray(getVirusTotalReport(item).detections) && getVirusTotalReport(item).detections.length > 0 && (
                              <div className="text-slate-300">
                                {getVirusTotalReport(item).detections.map((detection: any) => `${detection.engine}: ${detection.result || detection.category}`).join(" | ")}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4 text-slate-400">
                    <div className="flex flex-col gap-1">
                      <span>{item.findingSource || item.engine || "ClamAV"}</span>
                      {item.yaraRuleset && <span className="text-xs text-slate-500 capitalize">{item.yaraRuleset}</span>}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-slate-400 capitalize">{item.source || "scan"}</td>
                  <td className="px-6 py-4">
                    <div className="flex flex-col gap-1">
                      <span>{formatSystemDateTime(item.timestamp)}</span>
                      {item.available === false && <span className="text-xs text-amber-400">Original file unavailable</span>}
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
