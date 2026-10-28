import { t, localizeText, useLanguage } from "../../../src/lib/i18n";
import { useEffect, useRef, useState } from "react";
export default function VirusTotalLimitWarning() {
    useLanguage();
    const [warning, setWarning] = useState<any>(null);
    const [pending, setPending] = useState(false);
    const [error, setError] = useState("");
    const dialogRef = useRef<HTMLDialogElement>(null);
    const answeredRef = useRef(new Set<string>());
    const submittingRef = useRef(false);
    useEffect(() => {
        let stopped = false;
        let fetching = false;
        const poll = async () => {
            if (fetching || submittingRef.current)
                return;
            fetching = true;
            try {
                // This endpoint reads local queue/quota state; it makes no VirusTotal requests.
                const response = await fetch("/api/virustotal/on-demand/limit-warning");
                if (!response.ok)
                    return;
                const data = await response.json();
                if (!stopped && !submittingRef.current) {
                    setWarning(data.warning && !answeredRef.current.has(data.warning.jobId) ? data.warning : null);
                }
            }
            catch { /* Leave gated work waiting and retry when the local service responds. */ }
            finally {
                fetching = false;
            }
        };
        poll();
        const timer = window.setInterval(poll, 3000);
        return () => { stopped = true; window.clearInterval(timer); };
    }, []);
    useEffect(() => {
        setError("");
        if (warning && dialogRef.current && !dialogRef.current.open)
            dialogRef.current.showModal();
    }, [warning?.jobId]);
    const respond = async (proceed: boolean) => {
        if (!warning || submittingRef.current)
            return;
        submittingRef.current = true;
        setPending(true);
        setError("");
        try {
            const response = await fetch(`/api/virustotal/on-demand/${encodeURIComponent(warning.jobId)}/confirm`, {
                method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ proceed })
            });
            if (!response.ok && response.status !== 409) {
                const data = await response.json();
                throw new Error(data.error || "Could not update VirusTotal checks. Please try again.");
            }
            answeredRef.current.add(warning.jobId);
            setWarning(null);
        }
        catch (error: any) {
            setError(error.message || "Could not update VirusTotal checks. Please try again.");
        }
        finally {
            submittingRef.current = false;
            setPending(false);
        }
    };
    if (!warning)
        return null;
    return (<dialog ref={dialogRef} aria-labelledby="vt-limit-title" aria-describedby="vt-limit-description" onCancel={event => { event.preventDefault(); if (!pending)
        respond(false); }} className="m-auto w-[calc(100%_-_2rem)] max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 text-slate-200 shadow-2xl backdrop:bg-black/70">
      <h2 id="vt-limit-title" className="text-lg font-semibold text-white">{t("common.virus_total_limit_warning.virustotal_scan_estimate")}</h2>
      <p id="vt-limit-description" className="mt-3 text-sm leading-relaxed">
        {localizeText(warning.durationMs === null
            ? `Checking ${warning.files.toLocaleString()} files will have to wait ${warning.duration} because of VirusTotal API limits.`
            : `Checking ${warning.files.toLocaleString()} files is estimated to take about ${warning.duration} because of VirusTotal API limits.`)}
        {localizeText(" ")}{t("common.virus_total_limit_warning.do_you_want_to_proceed")}</p>
      <p className="mt-2 text-xs text-slate-400">{t("common.virus_total_limit_warning.uploads_and_analysis_can_add_time_local_scanning_continues_either")}</p>
      {localizeText(error && <p role="alert" className="mt-3 text-sm text-red-300">{localizeText(error)}</p>)}
      <div className="mt-6 flex flex-wrap justify-end gap-3">
        <button type="button" disabled={pending} onClick={() => respond(false)} className="rounded-lg bg-slate-800 px-4 py-2 text-sm font-medium hover:bg-slate-700 disabled:opacity-50">{t("common.virus_total_limit_warning.local_scan_only")}</button>
        <button type="button" disabled={pending} onClick={() => respond(true)} className="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-400 disabled:opacity-50">{t("common.virus_total_limit_warning.continue_with_virustotal")}</button>
      </div>
    </dialog>);
}
