import { localizeText } from "../../../src/lib/i18n";
import { useEffect, useState } from "react";
import { applyLanguage, getLanguage, t, useLanguage } from "../../../src/lib/i18n";
export default function LanguageSettings() {
    useLanguage();
    const [data, setData] = useState<any>({ languages: [{ code: "en", name: "English" }], errors: [], directories: [] });
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    const refresh = async () => {
        setBusy(true);
        setError("");
        try {
            const response = await fetch("/api/languages", { cache: "no-store" });
            if (!response.ok)
                throw new Error(t("common.language_settings.could_not_read_installed_languages"));
            const next = await response.json();
            setData(next);
            const selected = await fetch("/api/languages/current", { cache: "no-store" });
            if (selected.ok)
                await applyLanguage(await selected.json());
        }
        catch (e: any) {
            setError(e.message);
        }
        finally {
            setBusy(false);
        }
    };
    useEffect(() => { refresh(); }, []);
    const select = async (code: string) => {
        setBusy(true);
        setError("");
        try {
            const response = await fetch("/api/languages", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) });
            const result = await response.json();
            if (!response.ok)
                throw new Error(result.error || t("common.language_settings.could_not_change_the_language"));
            await applyLanguage(result.language);
            setData(result);
        }
        catch (e: any) {
            setError(e.message);
        }
        finally {
            setBusy(false);
        }
    };
    return <section className="space-y-3 rounded-xl border border-slate-800 bg-slate-900 p-6" aria-label={t("settings.language")}>
    <div className="flex flex-wrap items-center justify-between gap-3">
      <label className="text-sm font-medium" htmlFor="application-language">{t("settings.language")}</label>
      <div className="flex flex-wrap gap-2">
        <select aria-label={t("settings.language")} id="application-language" value={getLanguage().code} disabled={busy} onChange={event => select(event.target.value)} className="max-w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
          {localizeText(data.languages.map((language: any) => <option key={language.code} value={language.code}>{localizeText(language.name)}</option>))}
        </select>
        <button disabled={busy} onClick={refresh} className="rounded border border-slate-700 px-3 py-2 text-xs disabled:opacity-50">{t("settings.language_refresh")}</button>
      </div>
    </div>
    <p className="text-xs text-slate-400">{t("settings.language_help")}</p>
    <a className="inline-block text-xs text-sky-300" href="/api/languages/template" download="es.json">{t("common.language_settings.download_translation_template")}</a>
    {localizeText(error && <p role="alert" className="text-sm text-rose-300 break-words">{localizeText(error)}</p>)}
    {localizeText(data.errors?.map((item: any, index: number) => <p key={index} role="alert" className="text-xs text-amber-300 break-words">{localizeText(item.file)}: {localizeText(item.error)}</p>))}
    {localizeText(data.directories?.map((directory: string) => <p key={directory} className="break-all text-xs text-slate-500">{localizeText(directory)}</p>))}
  </section>;
}
