import { t, localizeText, useLanguage } from "../../../src/lib/i18n";
import { ArchiveX, FolderOpen, RotateCcw, Trash2 } from "lucide-react";
import { useState, useEffect } from "react";
import PageHeader from "../../../src/components/PageHeader";
import { formatSystemDateTime } from "../../../src/lib/dateFormat";
type PageSize = 50 | 100 | 200 | 500 | "all";
export default function Quarantine() {
    useLanguage();
    const [items, setItems] = useState<any[]>([]);
    const [totalItems, setTotalItems] = useState(0);
    const [loading, setLoading] = useState(true);
    const [pageSize, setPageSize] = useState<PageSize>(50);
    const [page, setPage] = useState(1);
    const [dateFilter, setDateFilter] = useState("");
    const [selectedIds, setSelectedIds] = useState<Record<string, boolean>>({});
    const [bulkBusy, setBulkBusy] = useState<"restore" | "delete" | null>(null);
    const [restoringId, setRestoringId] = useState<string | null>(null);
    const [message, setMessage] = useState("");
    const fetchItems = () => {
        setLoading(true);
        const params = new URLSearchParams({
            page: String(page),
            pageSize: String(pageSize)
        });
        if (dateFilter)
            params.set("date", dateFilter);
        fetch(`/api/quarantine?${params.toString()}`).then(r => r.json()).then(data => {
            let fetchedItems = [];
            if (Array.isArray(data))
                fetchedItems = data;
            else if (data && Array.isArray(data.items))
                fetchedItems = data.items;
            // Sort newest first
            fetchedItems.sort((a: any, b: any) => (Number(b.timestamp) || new Date(b.date).getTime()) - (Number(a.timestamp) || new Date(a.date).getTime()));
            setItems(fetchedItems);
            setTotalItems(Array.isArray(data) ? fetchedItems.length : Number(data.total || 0));
            setSelectedIds(prev => {
                const visible = new Set(fetchedItems.map((item: any) => String(item.fileName || item.id || "")));
                return Object.fromEntries(Object.entries(prev).filter(([id]) => visible.has(id)));
            });
        }).catch(() => {
            setItems([]);
            setTotalItems(0);
        }).finally(() => setLoading(false));
    };
    useEffect(() => {
        fetchItems();
    }, [page, pageSize, dateFilter]);
    useEffect(() => {
        setPage(1);
    }, [pageSize, dateFilter]);
    const openQuarantine = async () => {
        await fetch("/api/open-quarantine");
    };
    const emptyQuarantine = async () => {
        if (confirm(t("quarantine.are_you_sure_you_want_to_empty_the_quarantine_this_will_permanent"))) {
            try {
                await fetch("/api/empty-quarantine", { method: "POST" });
                fetchItems();
            }
            catch (e) {
                console.error("Failed to empty quarantine", e);
            }
        }
    };
    const restoreAndAddException = async (item: any) => {
        if (!confirm(t("quarantine.restore_this_file_to_its_original_location_and_add_it_to_exceptio"))) {
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
        }
        catch (e: any) {
            setMessage(e.message || "Restore failed.");
        }
        finally {
            setRestoringId(null);
        }
    };
    const selectedItems = items.filter(item => selectedIds[item.fileName]);
    const selectedCount = selectedItems.length;
    const allVisibleSelected = items.length > 0 && items.every(item => selectedIds[item.fileName]);
    const toggleSelected = (fileName: string, checked: boolean) => {
        setSelectedIds(prev => {
            const next = { ...prev };
            if (checked)
                next[fileName] = true;
            else
                delete next[fileName];
            return next;
        });
    };
    const toggleSelectVisible = (checked: boolean) => {
        setSelectedIds(prev => {
            const next = { ...prev };
            items.forEach(item => {
                if (checked)
                    next[item.fileName] = true;
                else
                    delete next[item.fileName];
            });
            return next;
        });
    };
    const restoreSelected = async () => {
        if (selectedCount === 0)
            return;
        if (!confirm(t("quarantine.restore_selected_quarantined_file_s_and_add_them_to_exceptions_on", {
            selectedCount: String(selectedCount)
        })))
            return;
        setBulkBusy("restore");
        setMessage("");
        try {
            const res = await fetch("/api/quarantine/restore-selected-exception", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ fileNames: selectedItems.map(item => item.fileName) })
            });
            const data = await res.json();
            if (!res.ok && res.status !== 207)
                throw new Error(data.error || "Restore selected failed.");
            setMessage(`Restored ${data.restoredCount || 0} selected file(s).${data.errors?.length ? ` ${data.errors.length} item(s) could not be restored.` : ""}`);
            setSelectedIds({});
            fetchItems();
        }
        catch (e: any) {
            setMessage(e.message || "Restore selected failed.");
        }
        finally {
            setBulkBusy(null);
        }
    };
    const deleteSelected = async () => {
        if (selectedCount === 0)
            return;
        if (!confirm(t("quarantine.permanently_delete_selected_quarantined_file_s_this_cannot_be_und", {
            selectedCount: String(selectedCount)
        })))
            return;
        setBulkBusy("delete");
        setMessage("");
        try {
            const res = await fetch("/api/quarantine/delete-selected", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ fileNames: selectedItems.map(item => item.fileName) })
            });
            const data = await res.json();
            if (!res.ok && res.status !== 207)
                throw new Error(data.error || "Delete selected failed.");
            setMessage(`Deleted ${data.deletedCount || 0} selected quarantined file(s).${data.errors?.length ? ` ${data.errors.length} item(s) could not be deleted.` : ""}`);
            setSelectedIds({});
            fetchItems();
        }
        catch (e: any) {
            setMessage(e.message || "Delete selected failed.");
        }
        finally {
            setBulkBusy(null);
        }
    };
    const pageCount = pageSize === "all" ? 1 : Math.max(1, Math.ceil(totalItems / pageSize));
    const currentPage = Math.min(page, pageCount);
    const rangeStart = totalItems === 0 ? 0 : pageSize === "all" ? 1 : (currentPage - 1) * pageSize + 1;
    const rangeEnd = pageSize === "all" ? totalItems : Math.min(totalItems, (currentPage - 1) * pageSize + pageSize);
    return (<div className="px-8 max-w-5xl mx-auto space-y-8 pb-20">
      <PageHeader title={t("results.quarantine")} description={t("quarantine.isolated_threats_that_cannot_harm_your_system")} actions={(<div className="grid w-[26rem] max-w-full grid-cols-2 gap-2">
            <span className="col-span-2 text-right text-sm text-slate-400 tabular-nums">{localizeText(selectedCount)}{t("history.selected")}</span>
            <button onClick={restoreSelected} disabled={selectedCount === 0 || bulkBusy !== null} className="flex min-w-0 items-center justify-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-60 disabled:cursor-not-allowed text-slate-300 rounded-lg transition-colors border border-slate-700">
              <RotateCcw className="w-4 h-4 shrink-0"/>
              <span className="truncate">{localizeText(bulkBusy === "restore" ? "Restoring..." : "Restore selected")}</span>
            </button>
            <button onClick={deleteSelected} disabled={selectedCount === 0 || bulkBusy !== null} className="flex min-w-0 items-center justify-center gap-2 px-3 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-60 disabled:cursor-not-allowed text-white rounded-lg transition-colors">
              <Trash2 className="w-4 h-4 shrink-0"/>
              <span className="truncate">{localizeText(bulkBusy === "delete" ? "Deleting..." : "Delete selected")}</span>
            </button>
            {localizeText(totalItems > 0 && (<button onClick={emptyQuarantine} className="flex min-w-0 items-center justify-center gap-2 px-3 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 rounded-lg transition-colors border border-red-500/20">
                <Trash2 className="w-4 h-4 shrink-0"/>
                <span className="truncate">{t("quarantine.empty_quarantine")}</span>
              </button>))}
            <button onClick={openQuarantine} className="flex min-w-0 items-center justify-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700 hover:border-slate-600">
              <FolderOpen className="w-4 h-4 shrink-0"/>
              <span className="truncate">{t("quarantine.open_folder")}</span>
            </button>
        </div>)}/>

      {localizeText(message && (<div className="p-3 bg-slate-900 border border-slate-800 text-slate-300 rounded-md text-sm">
          {localizeText(message)}
        </div>))}

      {localizeText(loading ? (<div className="bg-slate-900 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 bg-slate-800 text-slate-500 rounded-full flex items-center justify-center mb-4">
            <ArchiveX className="w-8 h-8 animate-pulse"/>
          </div>
          <p className="text-slate-400">{t("quarantine.loading_quarantine")}</p>
        </div>) : totalItems === 0 ? (<div className="bg-slate-900 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 bg-emerald-500/10 text-emerald-400 rounded-full flex items-center justify-center mb-4">
            <ArchiveX className="w-8 h-8"/>
          </div>
          <h3 className="text-lg font-medium text-slate-200 mb-2">{t("quarantine.quarantine_is_empty")}</h3>
          <p className="text-slate-500 max-w-md">{t("quarantine.no_threats_have_been_quarantined_yet_your_system_looks_clean")}</p>
        </div>) : (<div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
            <span className="text-slate-400">{t("history.showing")}{localizeText(rangeStart)}-{localizeText(rangeEnd)}{t("history.of")}{localizeText(totalItems)}
            </span>
            <div className="flex flex-wrap items-center justify-end gap-2">
              <label className="flex items-center gap-2 text-slate-400">{t("history.date")}<input type="date" value={dateFilter} onChange={e => setDateFilter(e.target.value)} className="date-picker-control w-36 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-indigo-500"/>
              </label>
              {localizeText(dateFilter && (<button onClick={() => setDateFilter("")} className="px-2 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors">{t("history.clear")}</button>))}
              <label className="flex items-center gap-2 text-slate-400">{t("history.rows")}<select value={pageSize} onChange={e => setPageSize(e.target.value === "all" ? "all" : Number(e.target.value) as PageSize)} className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-indigo-500">
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                  <option value={200}>200</option>
                  <option value={500}>500</option>
                  <option value="all">{t("history.all")}</option>
                </select>
              </label>
              {localizeText(pageSize !== "all" && (<div className="flex items-center gap-2">
                  <button onClick={() => setPage(current => Math.max(1, current - 1))} disabled={currentPage <= 1} className="px-2 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 rounded-lg transition-colors">{t("history.previous")}</button>
                  <span className="text-slate-500 tabular-nums">{t("history.page")}{localizeText(currentPage)} / {localizeText(pageCount)}</span>
                  <button onClick={() => setPage(current => Math.min(pageCount, current + 1))} disabled={currentPage >= pageCount} className="px-2 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 rounded-lg transition-colors">{t("history.next")}</button>
                </div>))}
            </div>
          </div>
          <table className="w-full table-fixed text-left text-xs">
            <colgroup>
              <col className="w-11"/>
              <col className="w-[32%]"/>
              <col />
              <col className="w-32"/>
              <col className="w-36"/>
            </colgroup>
            <thead className="bg-slate-800/50 text-slate-400">
              <tr>
                <th className="px-3 py-3 font-medium">
                  <input type="checkbox" checked={allVisibleSelected} onChange={e => toggleSelectVisible(e.target.checked)} className="w-4 h-4 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" title={t("quarantine.select_visible_quarantine_items")}/>
                </th>
                <th className="px-3 py-3 font-medium">{t("quarantine.detection_name")}</th>
                <th className="px-3 py-3 font-medium">{t("quarantine.original_location")}</th>
                <th className="px-3 py-3 font-medium">{t("quarantine.date_caught")}</th>
                <th className="px-3 py-3 font-medium text-right">{t("quarantine.actions")}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {localizeText(items.map((item, idx) => (<tr key={idx} className="hover:bg-slate-800/50 transition-colors">
                  <td className="px-3 py-3">
                    <input type="checkbox" checked={Boolean(selectedIds[item.fileName])} onChange={e => toggleSelected(item.fileName, e.target.checked)} className="w-4 h-4 rounded border-slate-600 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-800" title={t("quarantine.select_quarantine_item")}/>
                  </td>
                  <td className="px-3 py-3 break-all text-[13px] leading-5 font-medium text-red-400">{localizeText(item.threatName)}</td>
                  <td className="min-w-0 px-3 py-3 text-slate-400 font-mono text-xs">
                    <div tabIndex={0} role="region" aria-label={t("quarantine.original_location_438f9e4", {
                    threatName: String(item.threatName)
                })} title={item.originalPath} className="max-w-full overflow-x-auto whitespace-nowrap pb-1.5 focus-visible:outline focus-visible:outline-1 focus-visible:outline-indigo-400">
                      {localizeText(item.originalPath)}
                    </div>
                  </td>
                  <td className="px-3 py-3 tabular-nums leading-5">{localizeText(formatSystemDateTime(item.date))}</td>
                  <td className="px-3 py-3">
                    <div className="flex justify-end">
                      <button onClick={() => restoreAndAddException(item)} disabled={restoringId === item.fileName} className="inline-flex max-w-full items-center gap-1.5 px-2 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-60 disabled:cursor-not-allowed text-slate-200 rounded text-xs font-medium transition-colors border border-slate-700" title={t("quarantine.restore_and_add_to_exceptions")}>
                        <RotateCcw className="w-3.5 h-3.5 shrink-0"/>
                        <span className="min-w-0 text-left leading-tight">{localizeText(restoringId === item.fileName ? "Restoring..." : "Restore + exception")}</span>
                      </button>
                    </div>
                  </td>
                </tr>)))}
            </tbody>
          </table>
        </div>))}
    </div>);
}
