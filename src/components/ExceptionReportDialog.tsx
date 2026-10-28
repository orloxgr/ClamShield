import { t, localizeText, useLanguage } from "../lib/i18n";
import { useEffect, useState } from "react";
import Modal from "./Modal";
import { exceptionApi, type ExceptionItem, itemStatus, originLabels, openReportUrl, statusLabels, } from "../lib/exceptionReporting";
import { formatSystemDateTime } from "../lib/dateFormat";
export function ReportStatusBadge({ status }: {
    status: string;
}) {
    useLanguage();
    return (<span className={`inline-block rounded-full border px-2 py-1 text-xs ${status === "sent" ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200" : status === "unconfirmed" ? "border-amber-500/30 bg-amber-500/10 text-amber-200" : "border-slate-700 bg-slate-800 text-slate-300"}`}>
      {localizeText(statusLabels[status])}
    </span>);
}
export default function ExceptionReportDialog({ item, detailsOnly = false, onClose, onUpdate, }: {
    item: ExceptionItem;
    detailsOnly?: boolean;
    onClose: () => void;
    onUpdate: (path: string, report: any) => void;
}) {
    useLanguage();
    const [preview, setPreview] = useState<any>(null), [subject, setSubject] = useState(""), [body, setBody] = useState("");
    const [status, setStatus] = useState(itemStatus(item)), [sentAt, setSentAt] = useState(item.report?.reportSentAt);
    const [notice, setNotice] = useState(""), [error, setError] = useState(false), [busy, setBusy] = useState(false);
    useEffect(() => {
        if (detailsOnly || !item.report)
            return;
        let cancelled = false;
        exceptionApi("/api/exceptions/report-false-positive", { path: item.path })
            .then((data) => {
            if (!cancelled) {
                setPreview(data);
                setSubject(data.subject);
                setBody(data.details);
            }
        })
            .catch((e) => {
            if (!cancelled) {
                setError(true);
                setNotice(e.message);
            }
        });
        return () => {
            cancelled = true;
        };
    }, [item.path, detailsOnly]);
    const update = async (action: string) => {
        const data = await exceptionApi("/api/exceptions/report-status", {
            path: item.path,
            action,
        });
        setStatus(data.reportStatus);
        setSentAt(data.reportSentAt);
        onUpdate(item.path, {
            ...item.report,
            reportStatus: data.reportStatus,
            reportSentAt: data.reportSentAt,
        });
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
    const copy = (value: string, name: string, prepare = false) => run(async () => {
        if (!navigator.clipboard)
            throw new Error("Clipboard is unavailable. Select and copy the text below manually.");
        await navigator.clipboard.writeText(value);
        setNotice(`${name} copied. No report has been sent by ClamShield.`);
        if (prepare) {
            try {
                await update("prepare");
            }
            catch {
                throw new Error(`${name} copied, but its status could not be saved. Retry the action to save it.`);
            }
        }
    });
    const open = (channel: string) => run(async () => {
        const provider = preview.provider;
        const url = provider.method === "email"
            ? channel === "gmail"
                ? `https://mail.google.com/mail/?${new URLSearchParams({ view: "cm", fs: "1", to: provider.email, su: subject, body })}`
                : channel === "outlook"
                    ? `https://outlook.live.com/mail/0/deeplink/compose?${new URLSearchParams({ to: provider.email, subject, body })}`
                    : `mailto:${provider.email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`
            : provider.method === "github"
                ? `${provider.url}?${new URLSearchParams({ title: subject, body })}`
                : provider.url;
        await openReportUrl(url);
        setNotice("Requested opening the report channel. Complete submission with the provider, then mark it as sent. No file was attached automatically.");
        try {
            await update("prepare");
        }
        catch {
            throw new Error("The report channel was opened, but its status could not be saved.");
        }
    });
    const report = preview?.report || item.report;
    const button = "rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700 disabled:opacity-40";
    return (<Modal title={detailsOnly ? t("common.exception_report_dialog.exception_details") : t("exceptions.report_false_positive")} onClose={onClose} busy={busy}>
      <div className="border-b border-slate-800 px-6 py-3" aria-live="polite">
        <ReportStatusBadge status={status}/>
        {localizeText(sentAt && status === "sent" && (<span className="ml-2 text-xs text-slate-400">
            {localizeText(formatSystemDateTime(sentAt))}
          </span>))}
        {localizeText(status === "unconfirmed" && (<p className="mt-2 text-sm text-amber-200">{t("common.exception_report_dialog.clamshield_cannot_verify_submission_complete_the_report_with_the")}</p>))}
        {localizeText(status === "sent" && (<p className="mt-2 text-xs text-slate-400">{t("common.exception_report_dialog.you_confirmed_sending_this_report_provider_receipt_acceptance_and")}</p>))}
        {localizeText(notice && (<p role={error ? "alert" : "status"} className={`mt-2 rounded-lg p-3 text-sm ${error ? "bg-red-500/15 text-red-200" : "bg-amber-500/10 text-amber-200"}`}>
            {localizeText(notice)}
          </p>))}
      </div>
      <div className="space-y-5 overflow-y-auto px-6 py-4">
        <dl className="grid grid-cols-[7rem_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
          {localizeText(Object.entries({
            File: item.path.split(/[\\/]/).pop(),
            Path: item.path,
            Provider: item.providerName,
            Engine: report?.engine,
            Detection: report?.threatName,
            "SHA-256": report?.sha256,
            "Detected at": formatSystemDateTime(report?.detectedAt, "Unavailable"),
            "Detection source": report?.source,
            "Added from": originLabels[item.origin] || "Unknown",
            "Date added": formatSystemDateTime(item.addedAt, "Unavailable"),
            Type: item.kind,
        }).map(([key, value]) => (<div key={key} className="contents">
              <dt className="text-slate-400">{localizeText(key)}</dt>
              <dd className="select-text break-all">
                {localizeText(value || "Unavailable")}
              </dd>
            </div>)))}
        </dl>
        <button className={button} disabled={busy} onClick={() => copy(Object.entries({
            Path: item.path,
            Provider: item.providerName,
            Detection: report?.threatName,
            Engine: report?.engine,
            "SHA-256": report?.sha256,
        })
            .map(([k, v]) => `${k}: ${v || "Unavailable"}`)
            .join("\n"), "Detection details")}>{t("common.exception_report_dialog.copy_detection_details")}</button>
        {localizeText(!detailsOnly && !preview && !notice && (<p role="status">{t("common.exception_report_dialog.preparing_report_preview")}</p>))}
        {localizeText(!detailsOnly && preview && (<>
            {localizeText(preview.provider.method === "email" && (<div>
                <label className="text-sm text-slate-400" htmlFor="report-to">{t("exceptions.to")}</label>
                <div className="mt-1 flex gap-2">
                  <input id="report-to" readOnly value={preview.provider.email} className="min-w-0 flex-1 rounded border border-slate-700 bg-slate-900 p-2"/>
                  <button className={button} disabled={busy} onClick={() => copy(preview.provider.email, "Recipient")}>{t("common.exception_report_dialog.copy")}</button>
                </div>
              </div>))}
            <div>
              <label className="text-sm text-slate-400" htmlFor="report-subject">{t("common.exception_report_dialog.subject")}</label>
              <div className="mt-1 flex gap-2">
                <input id="report-subject" value={subject} onChange={(e) => setSubject(e.target.value)} className="min-w-0 flex-1 rounded border border-slate-700 bg-slate-900 p-2"/>
                <button className={button} disabled={busy} onClick={() => copy(subject, "Subject")}>{t("common.exception_report_dialog.copy")}</button>
              </div>
            </div>
            <div>
              <label className="text-sm text-slate-400" htmlFor="report-body">
                {localizeText(preview.provider.method === "email"
                ? "Message"
                : "Report details")}
              </label>
              <textarea id="report-body" rows={9} value={body} onChange={(e) => setBody(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-900 p-3 text-sm"/>
              <button className={button} disabled={busy} onClick={() => copy(body, "Report details", true)}>{t("common.exception_report_dialog.copy_report_details")}</button>
            </div>
            <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">{t("common.exception_report_dialog.no_file_has_been_sent_or_attached_by_clamshield")}{localizeText(" ")}
              {localizeText(preview.requiresSample
                ? "Attach or upload the sample yourself only if you agree to share it. "
                : "")}
              {localizeText(preview.provider.id === "securiteinfo"
                ? "If sharing a sample, use a password-protected ZIP with password infectedsecuriteinfo. "
                : "")}{t("common.exception_report_dialog.follow_the_provider_s_submission_instructions")}</p>
            <div className="flex flex-wrap gap-2">
              <button className={button} disabled={busy} onClick={() => open("default")}>
                {localizeText(preview.provider.method === "email"
                ? "Open default email app"
                : preview.provider.method === "github"
                    ? "Open GitHub issue"
                    : "Open report form")}
              </button>
              {localizeText(preview.provider.method === "email" && (<>
                  <button className={button} disabled={busy} onClick={() => open("gmail")}>{t("common.exception_report_dialog.gmail")}</button>
                  <button className={button} disabled={busy} onClick={() => open("outlook")}>{t("common.exception_report_dialog.outlook")}</button>
                  <button className={button} disabled={busy} onClick={() => copy(`To: ${preview.provider.email}\nSubject: ${subject}\n\n${body}`, "Entire report", true)}>{t("common.exception_report_dialog.copy_entire_report")}</button>
                </>))}
            </div>
          </>))}
      </div>
      <div className="flex flex-wrap justify-end gap-2 border-t border-slate-800 px-6 py-4">
        {localizeText(!detailsOnly &&
            status !== "not_reported" &&
            status !== "not_applicable" && (<button className={button} disabled={busy} onClick={() => run(async () => {
                await update("reset");
                setNotice("Report status reset. The exception and detection details were kept.");
            })}>{t("common.exception_report_dialog.reset_report_status")}</button>))}
        {localizeText(!detailsOnly && status === "unconfirmed" && (<button className={`${button} text-emerald-200`} disabled={busy} onClick={() => run(async () => {
                await update("sent");
                setNotice("Marked as sent by you. Provider receipt is not verified.");
            })}>{t("common.exception_report_dialog.mark_as_sent")}</button>))}
        <button className={button} disabled={busy} onClick={onClose}>{t("common.exception_report_dialog.close")}</button>
      </div>
    </Modal>);
}
