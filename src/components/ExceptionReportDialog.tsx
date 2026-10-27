import { useEffect, useState } from "react";
import Modal from "./Modal";
import {
  exceptionApi,
  type ExceptionItem,
  itemStatus,
  originLabels,
  openReportUrl,
  statusLabels,
} from "../lib/exceptionReporting";
import { formatSystemDateTime } from "../lib/dateFormat";

export function ReportStatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-block rounded-full border px-2 py-1 text-xs ${status === "sent" ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200" : status === "unconfirmed" ? "border-amber-500/30 bg-amber-500/10 text-amber-200" : "border-slate-700 bg-slate-800 text-slate-300"}`}
    >
      {statusLabels[status]}
    </span>
  );
}

export default function ExceptionReportDialog({
  item,
  detailsOnly = false,
  onClose,
  onUpdate,
}: {
  item: ExceptionItem;
  detailsOnly?: boolean;
  onClose: () => void;
  onUpdate: (path: string, report: any) => void;
}) {
  const [preview, setPreview] = useState<any>(null),
    [subject, setSubject] = useState(""),
    [body, setBody] = useState("");
  const [status, setStatus] = useState(itemStatus(item)),
    [sentAt, setSentAt] = useState(item.report?.reportSentAt);
  const [notice, setNotice] = useState(""),
    [error, setError] = useState(false),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    if (detailsOnly || !item.report) return;
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
    } catch (e: any) {
      setError(true);
      setNotice(e.message);
    } finally {
      setBusy(false);
    }
  };
  const copy = (value: string, name: string, prepare = false) =>
    run(async () => {
      if (!navigator.clipboard)
        throw new Error(
          "Clipboard is unavailable. Select and copy the text below manually.",
        );
      await navigator.clipboard.writeText(value);
      setNotice(`${name} copied. No report has been sent by ClamShield.`);
      if (prepare) {
        try {
          await update("prepare");
        } catch {
          throw new Error(
            `${name} copied, but its status could not be saved. Retry the action to save it.`,
          );
        }
      }
    });
  const open = (channel: string) =>
    run(async () => {
      const provider = preview.provider;
      const url =
        provider.method === "email"
          ? channel === "gmail"
            ? `https://mail.google.com/mail/?${new URLSearchParams({ view: "cm", fs: "1", to: provider.email, su: subject, body })}`
            : channel === "outlook"
              ? `https://outlook.live.com/mail/0/deeplink/compose?${new URLSearchParams({ to: provider.email, subject, body })}`
              : `mailto:${provider.email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`
          : provider.method === "github"
            ? `${provider.url}?${new URLSearchParams({ title: subject, body })}`
            : provider.url;
      await openReportUrl(url);
      setNotice(
        "Requested opening the report channel. Complete submission with the provider, then mark it as sent. No file was attached automatically.",
      );
      try {
        await update("prepare");
      } catch {
        throw new Error(
          "The report channel was opened, but its status could not be saved.",
        );
      }
    });
  const report = preview?.report || item.report;
  const button =
    "rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700 disabled:opacity-40";
  return (
    <Modal
      title={detailsOnly ? "Exception details" : "Report false positive"}
      onClose={onClose}
      busy={busy}
    >
      <div className="border-b border-slate-800 px-6 py-3" aria-live="polite">
        <ReportStatusBadge status={status} />
        {sentAt && status === "sent" && (
          <span className="ml-2 text-xs text-slate-400">
            {formatSystemDateTime(sentAt)}
          </span>
        )}
        {status === "unconfirmed" && (
          <p className="mt-2 text-sm text-amber-200">
            ClamShield cannot verify submission. Complete the report with the
            provider, then mark it as sent.
          </p>
        )}
        {status === "sent" && (
          <p className="mt-2 text-xs text-slate-400">
            You confirmed sending this report. Provider receipt, acceptance and
            signature correction are not verified.
          </p>
        )}
        {notice && (
          <p
            role={error ? "alert" : "status"}
            className={`mt-2 rounded-lg p-3 text-sm ${error ? "bg-red-500/15 text-red-200" : "bg-amber-500/10 text-amber-200"}`}
          >
            {notice}
          </p>
        )}
      </div>
      <div className="space-y-5 overflow-y-auto px-6 py-4">
        <dl className="grid grid-cols-[7rem_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
          {Object.entries({
            File: item.path.split(/[\\/]/).pop(),
            Path: item.path,
            Provider: item.providerName,
            Engine: report?.engine,
            Detection: report?.threatName,
            "SHA-256": report?.sha256,
            "Detected at": formatSystemDateTime(
              report?.detectedAt,
              "Unavailable",
            ),
            "Detection source": report?.source,
            "Added from": originLabels[item.origin] || "Unknown",
            "Date added": formatSystemDateTime(item.addedAt, "Unavailable"),
            Type: item.kind,
          }).map(([key, value]) => (
            <div key={key} className="contents">
              <dt className="text-slate-400">{key}</dt>
              <dd className="select-text break-all">
                {value || "Unavailable"}
              </dd>
            </div>
          ))}
        </dl>
        <button
          className={button}
          disabled={busy}
          onClick={() =>
            copy(
              Object.entries({
                Path: item.path,
                Provider: item.providerName,
                Detection: report?.threatName,
                Engine: report?.engine,
                "SHA-256": report?.sha256,
              })
                .map(([k, v]) => `${k}: ${v || "Unavailable"}`)
                .join("\n"),
              "Detection details",
            )
          }
        >
          Copy detection details
        </button>
        {!detailsOnly && !preview && !notice && (
          <p role="status">Preparing report preview…</p>
        )}
        {!detailsOnly && preview && (
          <>
            {preview.provider.method === "email" && (
              <div>
                <label className="text-sm text-slate-400" htmlFor="report-to">
                  To
                </label>
                <div className="mt-1 flex gap-2">
                  <input
                    id="report-to"
                    readOnly
                    value={preview.provider.email}
                    className="min-w-0 flex-1 rounded border border-slate-700 bg-slate-900 p-2"
                  />
                  <button
                    className={button}
                    disabled={busy}
                    onClick={() => copy(preview.provider.email, "Recipient")}
                  >
                    Copy
                  </button>
                </div>
              </div>
            )}
            <div>
              <label
                className="text-sm text-slate-400"
                htmlFor="report-subject"
              >
                Subject
              </label>
              <div className="mt-1 flex gap-2">
                <input
                  id="report-subject"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="min-w-0 flex-1 rounded border border-slate-700 bg-slate-900 p-2"
                />
                <button
                  className={button}
                  disabled={busy}
                  onClick={() => copy(subject, "Subject")}
                >
                  Copy
                </button>
              </div>
            </div>
            <div>
              <label className="text-sm text-slate-400" htmlFor="report-body">
                {preview.provider.method === "email"
                  ? "Message"
                  : "Report details"}
              </label>
              <textarea
                id="report-body"
                rows={9}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                className="mt-1 w-full rounded border border-slate-700 bg-slate-900 p-3 text-sm"
              />
              <button
                className={button}
                disabled={busy}
                onClick={() => copy(body, "Report details", true)}
              >
                Copy report details
              </button>
            </div>
            <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
              No file has been sent or attached by ClamShield.{" "}
              {preview.requiresSample
                ? "Attach or upload the sample yourself only if you agree to share it. "
                : ""}
              {preview.provider.id === "securiteinfo"
                ? "If sharing a sample, use a password-protected ZIP with password infectedsecuriteinfo. "
                : ""}
              Follow the provider’s submission instructions.
            </p>
            <div className="flex flex-wrap gap-2">
              <button
                className={button}
                disabled={busy}
                onClick={() => open("default")}
              >
                {preview.provider.method === "email"
                  ? "Open default email app"
                  : preview.provider.method === "github"
                    ? "Open GitHub issue"
                    : "Open report form"}
              </button>
              {preview.provider.method === "email" && (
                <>
                  <button
                    className={button}
                    disabled={busy}
                    onClick={() => open("gmail")}
                  >
                    Gmail
                  </button>
                  <button
                    className={button}
                    disabled={busy}
                    onClick={() => open("outlook")}
                  >
                    Outlook
                  </button>
                  <button
                    className={button}
                    disabled={busy}
                    onClick={() =>
                      copy(
                        `To: ${preview.provider.email}\nSubject: ${subject}\n\n${body}`,
                        "Entire report",
                        true,
                      )
                    }
                  >
                    Copy entire report
                  </button>
                </>
              )}
            </div>
          </>
        )}
      </div>
      <div className="flex flex-wrap justify-end gap-2 border-t border-slate-800 px-6 py-4">
        {!detailsOnly &&
          status !== "not_reported" &&
          status !== "not_applicable" && (
            <button
              className={button}
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await update("reset");
                  setNotice(
                    "Report status reset. The exception and detection details were kept.",
                  );
                })
              }
            >
              Reset report status
            </button>
          )}
        {!detailsOnly && status === "unconfirmed" && (
          <button
            className={`${button} text-emerald-200`}
            disabled={busy}
            onClick={() =>
              run(async () => {
                await update("sent");
                setNotice(
                  "Marked as sent by you. Provider receipt is not verified.",
                );
              })
            }
          >
            Mark as sent
          </button>
        )}
        <button className={button} disabled={busy} onClick={onClose}>
          Close
        </button>
      </div>
    </Modal>
  );
}
