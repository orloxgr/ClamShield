import { t, localizeText, useLanguage } from "../lib/i18n";
import { type ReactNode } from "react";
import DropdownSelect from "./DropdownSelect";
export function FilterField({ label, children, }: {
    label: string;
    children: ReactNode;
}) {
    useLanguage();
    return (<div className="flex min-w-0 flex-col gap-1">
      <span className="text-xs text-slate-400">{localizeText(label)}</span>
      {localizeText(children)}
    </div>);
}
export function ListPagination({ page, pageSize, total, onPage, onPageSize, }: {
    page: number;
    pageSize: number | "all";
    total: number;
    onPage: (page: number) => void;
    onPageSize: (size: number | "all") => void;
}) {
    useLanguage();
    const pages = pageSize === "all" ? 1 : Math.max(1, Math.ceil(total / pageSize));
    const start = total
        ? pageSize === "all"
            ? 1
            : (page - 1) * pageSize + 1
        : 0;
    const end = pageSize === "all" ? total : Math.min(total, page * pageSize);
    return (<div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 p-4 text-sm text-slate-400">
      <span>
        {localizeText(start)}–{localizeText(end)}{t("history.of")}{localizeText(total)}
      </span>
      <div className="flex flex-wrap items-center gap-3">
        <span>{t("common.list_controls.rows_per_page")}</span>
        <DropdownSelect ariaLabel="Rows per page" value={String(pageSize)} options={[50, 100, 200, 500, "all"].map((n) => ({
            value: String(n),
            label: n === "all" ? "All" : String(n),
        }))} onChange={(v) => onPageSize(v === "all" ? "all" : Number(v))}/>
        <button className="disabled:opacity-40" disabled={page <= 1} onClick={() => onPage(page - 1)}>{t("history.previous")}</button>
        <span>
          {localizeText(page)} / {localizeText(pages)}
        </span>
        <button className="disabled:opacity-40" disabled={page >= pages} onClick={() => onPage(page + 1)}>{t("history.next")}</button>
      </div>
    </div>);
}
