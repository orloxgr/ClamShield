import { t, localizeText, useLanguage } from "../../../src/lib/i18n";
import { useEffect, useState } from "react";
import { FilePlus, FolderPlus, Search, Trash2, Download, Loader2, } from "lucide-react";
import PageHeader from "../../../src/components/PageHeader";
import DropdownSelect from "../../../src/components/DropdownSelect";
import Modal from "../../../src/components/Modal";
import { FilterField, ListPagination } from "../../../src/components/ListControls";
import ExceptionReportDialog, { ReportStatusBadge, } from "../../../src/components/ExceptionReportDialog";
import { exceptionApi, type ExceptionItem, itemStatus, originLabels, statusLabels, } from "../../../src/lib/exceptionReporting";
import { formatSystemDateTime } from "../../../src/lib/dateFormat";
const initialFilters = {
    search: "",
    provider: "all",
    origin: "all",
    status: "all",
    kind: "all",
    dateRange: "all",
    dateFrom: "",
    dateTo: "",
    sort: "newest",
};
const button = "inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40";
export default function ExceptionsPage() {
    useLanguage();
    const [items, setItems] = useState<ExceptionItem[]>([]), [total, setTotal] = useState(0), [totalAll, setTotalAll] = useState(0);
    const [filters, setFilters] = useState(initialFilters), [page, setPage] = useState(1), [pageSize, setPageSize] = useState<number | "all">(50);
    const [selected, setSelected] = useState<string[]>([]), [reload, setReload] = useState(0), [loading, setLoading] = useState(true);
    const [busy, setBusy] = useState(false), [notice, setNotice] = useState(""), [error, setError] = useState(false), [loadError, setLoadError] = useState("");
    const [dialog, setDialog] = useState<{
        item: ExceptionItem;
        details: boolean;
    } | null>(null), [removing, setRemoving] = useState<string[] | null>(null);
    useEffect(() => {
        const controller = new AbortController();
        setLoading(true);
        setLoadError("");
        const timer = window.setTimeout(async () => {
            try {
                const params = new URLSearchParams({
                    ...filters,
                    page: String(page),
                    pageSize: String(pageSize),
                });
                const response = await fetch(`/api/exceptions/reporting?${params}`, {
                    signal: controller.signal,
                });
                const data = await response.json();
                if (!response.ok)
                    throw new Error(data.error || "Could not load exceptions.");
                if (controller.signal.aborted)
                    return;
                setItems(data.items);
                setTotal(data.total);
                setTotalAll(data.totalAll);
                if (data.page !== page) {
                    setPage(data.page);
                    setSelected([]);
                }
            }
            catch (e: any) {
                if (!controller.signal.aborted)
                    setLoadError(e.message || "Could not load exceptions.");
            }
            finally {
                if (!controller.signal.aborted)
                    setLoading(false);
            }
        }, 180);
        return () => {
            controller.abort();
            window.clearTimeout(timer);
        };
    }, [filters, page, pageSize, reload]);
    const refresh = () => {
        setSelected([]);
        setReload((n) => n + 1);
    };
    const change = (key: keyof typeof initialFilters, value: string) => {
        setFilters((prev) => ({
            ...prev,
            [key]: value,
            ...(key === "dateRange" && value !== "custom"
                ? { dateFrom: "", dateTo: "" }
                : {}),
        }));
        setPage(1);
        setSelected([]);
    };
    const run = async (operation: () => Promise<void>) => {
        setBusy(true);
        setNotice("");
        setError(false);
        try {
            await operation();
        }
        catch (e: any) {
            setError(true);
            setNotice(e.message);
        }
        finally {
            setBusy(false);
        }
    };
    const add = (kind: "file" | "folder") => run(async () => {
        const data = await exceptionApi(`/api/select-${kind}`);
        const value = data.path ||
            (data.simulated ? window.prompt(`Enter an absolute ${kind} path`) : "");
        if (!value)
            return;
        await exceptionApi("/api/exceptions/add", { path: value, kind });
        setNotice("Added to exceptions. This path is excluded from manual scans and real-time protection.");
        refresh();
    });
    const beginRemoval = (paths: string[]) => {
        setNotice("");
        setError(false);
        setRemoving(paths);
    };
    const remove = () => run(async () => {
        const data = await exceptionApi("/api/exceptions/delete-selected", {
            paths: removing,
        });
        setRemoving(null);
        setNotice(`Removed ${data.removedCount} item(s) from exceptions. No files were deleted. These paths can be scanned again.`);
        refresh();
    });
    const exportReports = () => run(async () => {
        const includeSamples = window.confirm(t("exceptions.include_copies_of_the_selected_files_choose_cancel_to_export_repo"));
        const userNote = window.prompt("Optional note for the reports:", "") || "";
        const data = await exceptionApi("/api/exceptions/export-false-positives", { paths: selected, includeSamples, userNote });
        setNotice(`Exported ${data.itemCount} report(s): ${data.zipPath}. No reports were sent.`);
    });
    const updateReport = (value: string, report: any) => {
        setItems((prev) => prev.map((item) => (item.path === value ? { ...item, report } : item)));
        setDialog((prev) => prev && prev.item.path === value
            ? { ...prev, item: { ...prev.item, report } }
            : prev);
    };
    const select = (label: string, key: keyof typeof initialFilters, options: Array<[
        string,
        string
    ]>) => (<FilterField label={label}>
      <DropdownSelect ariaLabel={`Filter exceptions: ${label}`} value={filters[key]} options={options.map(([value, label]) => ({ value, label }))} onChange={(value) => change(key, value)} active={filters[key] !== "all" && key !== "sort"} fullWidth align={key === "sort" ? "right" : "left"}/>
    </FilterField>);
    const allSelected = items.length > 0 && items.every((item) => selected.includes(item.path));
    const activeFilters = Object.entries(filters).some(([key, value]) => key !== "sort" && value !== initialFilters[key]);
    return (<div className="mx-auto max-w-6xl space-y-5 px-8 pb-10">
      <PageHeader title={t("exceptions.exceptions")} description={t("exceptions.files_and_folders_excluded_from_manual_scans_and_real_time_protec")} actions={<div className="flex gap-2">
            <button className={button} disabled={busy} onClick={() => add("file")}>
              <FilePlus size={16}/>{t("exceptions.add_file")}</button>
            <button className={button} disabled={busy} onClick={() => add("folder")}>
              <FolderPlus size={16}/>{t("exceptions.add_folder")}</button>
          </div>}/>
      <div className="sticky top-0 z-20 space-y-3 border-b border-slate-800 bg-slate-950/95 py-3 backdrop-blur">
        {localizeText(notice && (<div role={error ? "alert" : "status"} className={`flex justify-between gap-3 rounded-lg border p-3 text-sm ${error ? "border-red-500/30 bg-red-950 text-red-200" : "border-amber-500/30 bg-amber-950 text-amber-100"}`}>
            <span className="break-all">{localizeText(notice)}</span>
            <button aria-label={t("exceptions.dismiss_notification")} onClick={() => setNotice("")}>
              ×
            </button>
          </div>))}
        <label className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3">
          <Search size={17} className="text-slate-400"/>
          <input aria-label={t("exceptions.search_exceptions")} placeholder={t("exceptions.search_file_name_path_or_detection")} value={filters.search} onChange={(e) => change("search", e.target.value)} className="w-full bg-transparent py-2 text-sm outline-none"/>
        </label>
        <div className="exceptions-filter-toolbar">
          <div className="exceptions-filter-row">
            {localizeText(select("Provider", "provider", [
            ["all", "All providers"],
            ...[
                "ClamAV",
                "SaneSecurity",
                "SecuriteInfo",
                "YARA Forge",
                "Unknown",
            ].map((v) => [v, v] as [
                string,
                string
            ]),
        ]))}
            {localizeText(select("Added from", "origin", [
            ["all", "All origins"],
            ...Object.entries(originLabels),
        ]))}
            {localizeText(select("Report status", "status", [
            ["all", "All report statuses"],
            ...Object.entries(statusLabels),
        ]))}
            {localizeText(select("Type", "kind", [
            ["all", "All types"],
            ["file", "Files"],
            ["folder", "Folders"],
            ["unknown", "Unknown"],
        ]))}
            {localizeText(select("Date added", "dateRange", [
            ["all", "All dates"],
            ["today", "Today"],
            ["7", "Last 7 days"],
            ["30", "Last 30 days"],
            ["custom", "Custom range"],
        ]))}
            {localizeText(select("Sort", "sort", [
            ["newest", "Newest added first"],
            ["oldest", "Oldest added first"],
            ["path", "Path A–Z"],
        ]))}
          </div>
          {localizeText(filters.dateRange === "custom" && (<div className="mt-2 flex flex-wrap items-end gap-2">
              <FilterField label={t("exceptions.from")}>
                <input aria-label={t("exceptions.date_added_from")} type="date" value={filters.dateFrom} onChange={(e) => change("dateFrom", e.target.value)} className="date-picker-control rounded border border-slate-700 bg-slate-900 p-2 text-sm"/>
              </FilterField>
              <FilterField label={t("exceptions.to")}>
                <input aria-label={t("exceptions.date_added_to")} type="date" value={filters.dateTo} onChange={(e) => change("dateTo", e.target.value)} className="date-picker-control rounded border border-slate-700 bg-slate-900 p-2 text-sm"/>
              </FilterField>
            </div>))}
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-slate-400">
          <div className="flex items-center gap-3">
            <span aria-live="polite">
              {localizeText(loading
            ? "Loading exceptions…"
            : `Showing ${total} of ${totalAll} exceptions`)}
            </span>
            {localizeText(activeFilters && (<button className="text-xs text-indigo-300 hover:text-indigo-200" onClick={() => {
                setFilters(initialFilters);
                setPage(1);
                setSelected([]);
            }}>{t("results.clear_filters")}</button>))}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={allSelected} disabled={loading || busy || !items.length || !!loadError} onChange={(e) => setSelected(e.target.checked ? items.map((item) => item.path) : [])}/>{t("exceptions.select_this_page")}</label>
            <span>{localizeText(selected.length)}{t("history.selected")}</span>
            <button disabled={!selected.length} onClick={() => setSelected([])}>{t("exceptions.clear_selection")}</button>
            <button className={button} disabled={!selected.length || busy || loading || !!loadError} onClick={() => beginRemoval(selected)}>
              <Trash2 size={15}/>{t("exceptions.remove_from_exceptions")}</button>
            <button className={button} disabled={!items.some((item) => selected.includes(item.path) && item.report) ||
            busy ||
            loading ||
            !!loadError} onClick={exportReports}>
              <Download size={15}/>{t("exceptions.export_selected_reports")}</button>
          </div>
        </div>
      </div>
      {localizeText(loadError ? (<div role="alert" className="rounded-lg border border-red-500/30 p-5 text-red-200">
          {localizeText(loadError)}
          <button className={`${button} ml-3`} onClick={refresh}>{t("exceptions.retry")}</button>
        </div>) : (<div className="rounded-xl border border-slate-800 bg-slate-900">
          {localizeText(loading && (<div role="status" className="flex items-center gap-2 p-5 text-slate-400">
              <Loader2 className="animate-spin" size={16}/>{t("exceptions.loading")}</div>))}
          {localizeText(!loading && !items.length && (<p className="p-10 text-center text-slate-400">
              {localizeText(activeFilters
                    ? "No exceptions match these filters. Change or clear the filters above."
                    : "No exceptions added.")}
            </p>))}
          {localizeText(!loading &&
                items.map((item) => (<div key={item.path} className="flex flex-wrap items-center gap-4 border-b border-slate-800 p-4 last:border-b-0">
                <input aria-label={t("exceptions.select", {
                    path: String(item.path)
                })} type="checkbox" checked={selected.includes(item.path)} disabled={busy} onChange={(e) => setSelected((prev) => e.target.checked
                        ? [...prev, item.path]
                        : prev.filter((value) => value !== item.path))}/>
                <div className="min-w-0 flex-1 basis-64">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="break-all font-medium">
                      {localizeText(item.path.split(/[\\/]/).pop() || item.path)}
                    </span>
                    <span className="rounded border border-indigo-500/30 px-2 py-0.5 text-xs text-indigo-200">
                      {localizeText(item.providerName)}
                    </span>
                    <span className="text-xs text-slate-500">{localizeText(item.kind)}</span>
                  </div>
                  <p className="mt-1 select-text break-all text-xs text-slate-400">
                    {localizeText(item.path)}
                  </p>
                  {localizeText(item.report && (<p className="mt-1 break-all text-xs text-slate-300">
                      {localizeText(item.report.threatName)}
                    </p>))}
                  <p className="mt-2 text-xs text-slate-500">
                    {localizeText(originLabels[item.origin] || "Unknown")} ·{localizeText(" ")}
                    {localizeText(formatSystemDateTime(item.addedAt, "Date unavailable"))}
                  </p>
                </div>
                <div className="flex flex-col items-start gap-2">
                  <ReportStatusBadge status={itemStatus(item)}/>
                  <div className="flex flex-wrap gap-2">
                    <button className={button} onClick={() => setDialog({ item, details: true })}>{t("exceptions.details")}</button>
                    {localizeText(item.report && (<button className={button} onClick={() => setDialog({ item, details: false })}>{t("exceptions.report_false_positive")}</button>))}
                    <button className={button} disabled={busy} aria-label={t("exceptions.remove_from_exceptions_3d118d9", {
                        path: String(item.path)
                    })} onClick={() => beginRemoval([item.path])}>
                      <Trash2 size={16}/>
                    </button>
                  </div>
                </div>
              </div>)))}
          <ListPagination page={page} pageSize={pageSize} total={total} onPage={(value) => {
                setPage(value);
                setSelected([]);
            }} onPageSize={(value) => {
                setPageSize(value);
                setPage(1);
                setSelected([]);
            }}/>
        </div>))}
      {localizeText(dialog && (<ExceptionReportDialog item={dialog.item} detailsOnly={dialog.details} onClose={() => {
                setDialog(null);
                refresh();
            }} onUpdate={updateReport}/>))}
      {localizeText(removing && (<Modal title={t("exceptions.remove_from_exceptions")} onClose={() => setRemoving(null)} busy={busy}>
          <div className="space-y-3 overflow-y-auto p-6">
            <p>{t("exceptions.remove")}{localizeText(removing.length)}{t("exceptions.selected_item_s_from_exceptions")}</p>
            <p className="text-slate-300">{t("exceptions.these_files_and_folders_will_no_longer_be_excluded_from_scans_no")}</p>
            <ul className="max-h-40 overflow-auto text-xs text-slate-400">
              {localizeText(removing.map((value) => (<li className="break-all py-1" key={value}>
                  {localizeText(value)}
                </li>)))}
            </ul>
            {localizeText(error && notice && (<p role="alert" className="text-red-200">
                {localizeText(notice)}
              </p>))}
          </div>
          <div className="flex justify-end gap-2 border-t border-slate-800 p-4">
            <button className={button} disabled={busy} onClick={() => setRemoving(null)}>{t("results.cancel")}</button>
            <button className="rounded-lg bg-red-600 px-4 py-2 text-sm text-white hover:bg-red-500 disabled:opacity-40" disabled={busy} onClick={remove}>
              {localizeText(busy ? "Removing…" : "Remove from exceptions")}
            </button>
          </div>
        </Modal>))}
    </div>);
}
