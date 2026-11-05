import { useEffect, useState } from "react";
import { ExternalLink, Loader2, X } from "lucide-react";
import { localizeText, t, useLanguage } from "../lib/i18n";
import { availableSecuriteInfoDatabases, saneSecurityDatabaseCatalog, securiteInfoDatabaseCatalog, type SignatureDatabaseCatalog } from "../../shared/signatureDatabases";
import UpdateJobProgress from "./UpdateJobProgress";

export type SignatureProvider = "securiteinfo" | "sanesecurity";

type SignatureProviderDialogProps = {
    provider: SignatureProvider; status: any; onClose: () => void; onChanged: () => void;
};

export default function SignatureProviderDialog(props: SignatureProviderDialogProps) {
    useLanguage();
    const { provider, status, onClose } = props;
    const current = provider === "securiteinfo" ? status?.securiteInfo : status?.saneSecurity;
    useEffect(() => {
        if (current) return;
        const close = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
        window.addEventListener("keydown", close);
        return () => window.removeEventListener("keydown", close);
    }, [current, onClose]);
    // Mount the editor only after status arrives. Its initial state must never be
    // guessed from missing data, or overwritten by subsequent status polling.
    if (current) return <LoadedSignatureProviderDialog key={provider} {...props}/>;
    return <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6">
        <section role="dialog" aria-modal="true" aria-busy="true" aria-labelledby="signature-provider-title" className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl">
            <header className="flex items-center justify-between gap-4 px-6 py-4 border-b border-slate-800">
                <h2 id="signature-provider-title" className="text-xl font-semibold text-white">{localizeText(provider === "securiteinfo" ? "Manage SecuriteInfo" : "Manage SaneSecurity")}</h2>
                <button onClick={onClose} aria-label={t(provider === "securiteinfo" ? "dashboard.close_securiteinfo" : "dashboard.close_sanesecurity")} className="p-2 text-slate-400 hover:text-white rounded-lg"><X className="w-5 h-5"/></button>
            </header>
            <p role="status" className="flex items-center gap-2 p-6 text-slate-400"><Loader2 className="w-4 h-4 animate-spin"/>{t("shield.loading")}</p>
        </section>
    </div>;
}

function LoadedSignatureProviderDialog({ provider, status, onClose, onChanged }: SignatureProviderDialogProps) {
    useLanguage();
    const isSecuriteInfo = provider === "securiteinfo";
    const name = isSecuriteInfo ? "SecuriteInfo" : "SaneSecurity";
    const current = (isSecuriteInfo ? status?.securiteInfo : status?.saneSecurity) || {};
    const catalog: SignatureDatabaseCatalog = isSecuriteInfo ? securiteInfoDatabaseCatalog : saneSecurityDatabaseCatalog;
    const [plan, setPlan] = useState(current.plan === "paid" ? "paid" : "basic");
    const available = isSecuriteInfo ? availableSecuriteInfoDatabases(plan) : catalog.map(([file]) => file);
    const [selected, setSelected] = useState<string[]>(() => current.connected && Array.isArray(current.selectedDatabases)
        ? [...current.selectedDatabases] : [...available]);
    const [setupText, setSetupText] = useState("");
    const [busy, setBusy] = useState(false);
    const [message, setMessage] = useState("");
    const [error, setError] = useState("");
    const [job, setJob] = useState<{ jobId: string; simulated?: boolean } | null>(null);
    const updating = isSecuriteInfo ? status?.isSignatureUpdateRunning : status?.isSaneSecurityUpdateRunning;
    const disabled = busy || updating;
    const effectiveSelection = selected.filter(file => available.includes(file));
    useEffect(() => {
        const close = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) onClose(); };
        window.addEventListener("keydown", close);
        return () => window.removeEventListener("keydown", close);
    }, [busy, onClose]);
    const request = async (url: string, body: any) => {
        const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Could not save provider settings.");
        return data;
    };
    const save = async (update: boolean) => {
        setBusy(true); setError(""); setMessage("");
        let saved = false;
        try {
            await request(`/api/${provider}/configure`, { databases: effectiveSelection, ...(isSecuriteInfo ? { plan, setupText } : {}) });
            saved = true; setSetupText(""); onChanged();
            setMessage("Database selection saved.");
            if (update && effectiveSelection.length > 0) {
                const data = await request(isSecuriteInfo ? "/api/update" : "/api/update-sanesecurity", isSecuriteInfo ? { target: "securiteinfo" } : {});
                setJob({ jobId: data.jobId, simulated: data.simulated });
                setMessage("Database selection saved. Signature update started."); onChanged();
            }
        } catch (e: any) {
            setError((saved ? localizeText("Database selection saved. Update could not start.") + " " : "") + localizeText(e.message));
        } finally { setBusy(false); }
    };
    const disconnect = async () => {
        if (!window.confirm(t(isSecuriteInfo ? "dashboard.disconnect_securiteinfo_and_remove_its_downloaded_signature_files" : "dashboard.disconnect_sanesecurity_and_remove_its_downloaded_signature_files"))) return;
        setBusy(true); setError("");
        try { await request(`/api/${provider}/disconnect`, { removeDatabases: true }); onChanged(); onClose(); }
        catch (e: any) { setError(e.message); }
        finally { setBusy(false); }
    };
    return <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6">
        <section role="dialog" aria-modal="true" aria-labelledby="signature-provider-title" className="w-full max-w-3xl max-h-[90vh] flex flex-col bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl">
            <header className="flex items-center justify-between gap-4 px-6 py-4 border-b border-slate-800">
                <h2 id="signature-provider-title" className="text-xl font-semibold text-white">{localizeText(isSecuriteInfo ? "Manage SecuriteInfo" : "Manage SaneSecurity")}</h2>
                <button onClick={onClose} disabled={busy} aria-label={t(isSecuriteInfo ? "dashboard.close_securiteinfo" : "dashboard.close_sanesecurity")} className="p-2 text-slate-400 hover:text-white rounded-lg"><X className="w-5 h-5"/></button>
            </header>
            <div className="overflow-y-auto min-h-0 p-6 space-y-5">
                <p className="text-sm text-slate-400">{localizeText(isSecuriteInfo ? "Select the SecuriteInfo databases used by ClamAV. A SecuriteInfo account is required." : "Select the SaneSecurity databases used by ClamAV. No account is required.")}</p>
                {isSecuriteInfo && <>
                    <label className="block text-sm text-slate-300">{t("dashboard.account_plan")}
                        <select value={plan} disabled={disabled} onChange={event => {
                            setPlan(event.target.value); setSelected(availableSecuriteInfoDatabases(event.target.value));
                        }} className="ml-3 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2">
                            <option value="basic">{t("dashboard.basic_free")}</option><option value="paid">{t("updates.paid")}</option>
                        </select>
                    </label>
                    <label className="block text-sm text-slate-300">{localizeText(current.connected ? "Replace account token (optional)" : "Paste your SecuriteInfo DatabaseCustomURL")}
                        <input type="password" value={setupText} disabled={disabled} onChange={event => setSetupText(event.target.value)} autoComplete="off" className="mt-2 w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2 text-sm"/>
                    </label>
                </>}
                <div>
                    <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                        <h3 className="font-medium text-slate-200">{localizeText("Signature databases")} ({effectiveSelection.length}/{available.length})</h3>
                        <div className="flex gap-3 text-sm text-cyan-300">
                            <button disabled={disabled} onClick={() => setSelected([...available])}>{localizeText("Select all databases")}</button>
                            <button disabled={disabled} onClick={() => setSelected([])}>{localizeText("Deselect all databases")}</button>
                        </div>
                    </div>
                    <p className="text-xs text-slate-400 mb-3">{localizeText("Save to remove deselected databases. Save & Update also downloads newly selected databases. Active scans finish before in-memory databases reload.")}</p>
                    <div className="divide-y divide-slate-800 border border-slate-800 rounded-xl overflow-hidden">
                        {catalog.map(([file, description]) => {
                            const permitted = available.includes(file);
                            return <label key={file} className={`flex items-start gap-3 px-4 py-3 bg-slate-950/40 ${permitted ? "" : "opacity-50"}`}>
                                <input type="checkbox" aria-label={file} checked={permitted && selected.includes(file)} disabled={disabled || !permitted} onChange={event => setSelected(previous => event.target.checked ? [...previous, file] : previous.filter(item => item !== file))} className="mt-1 shrink-0 w-4 h-4 accent-cyan-500"/>
                                <span className="min-w-0"><code className="text-xs text-slate-200 break-all">{file}</code><span className="block text-xs text-slate-400 mt-1">{localizeText(description)}</span>
                                    {!permitted && <span className="block text-xs text-amber-300 mt-1">{t("updates.available_for_paid_securiteinfo_plans")}</span>}
                                </span>
                            </label>;
                        })}
                    </div>
                </div>
                <a href={isSecuriteInfo ? "https://www.securiteinfo.com/clients/customers/" : "https://sanesecurity.com/usage/signatures/"} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-sm text-cyan-400"><ExternalLink className="w-4 h-4"/>{t("dashboard.signature_information")}</a>
                {message && <p role="status" className="text-sm text-cyan-300">{localizeText(message)}</p>}
                {error && <p role="alert" className="text-sm text-rose-300">{localizeText(error)}</p>}
                <UpdateJobProgress jobId={job?.jobId || (isSecuriteInfo && status?.signatureUpdateTarget === "securiteinfo" ? status.signatureUpdateJobId : !isSecuriteInfo ? status?.saneSecurityUpdateJobId : null)} title={`${name} Output`} simulated={job?.simulated} onFinished={onChanged}/>
            </div>
            <footer className="flex flex-wrap items-center justify-end gap-3 border-t border-slate-800 px-6 py-4">
                {current.connected && <button onClick={disconnect} disabled={disabled} className="mr-auto text-sm text-slate-400 hover:text-rose-300 disabled:opacity-50">{t("dashboard.disconnect")}</button>}
                <button onClick={() => save(false)} disabled={disabled || (isSecuriteInfo && !current.connected && !setupText.trim())} className="px-4 py-2 bg-slate-800 text-white rounded-lg text-sm disabled:opacity-50">{localizeText("Save")}</button>
                <button onClick={() => save(true)} disabled={disabled || (isSecuriteInfo && !current.connected && !setupText.trim())} className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-700 text-white rounded-lg text-sm disabled:opacity-50">{busy && <Loader2 className="w-4 h-4 animate-spin"/>}{localizeText("Save & Update")}</button>
            </footer>
        </section>
    </div>;
}
