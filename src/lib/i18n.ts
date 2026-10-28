import { useSyncExternalStore } from "react";
import { englishPack, getLanguage, getRevision, localizeText, setLanguage, subscribeLanguage, t, type LanguagePack } from "../../shared/localization/runtime";
export { t, localizeText, getLanguage };
export const getLocale = () => getLanguage().code === "en" ? undefined : getLanguage().code;
export function useLanguage() { useSyncExternalStore(subscribeLanguage, getRevision, getRevision); return getLanguage(); }
export async function applyLanguage(pack: LanguagePack) {
  setLanguage(pack);
  document.documentElement.lang = getLanguage().code;
  document.documentElement.dir = getLanguage().direction;
  await (window as any).clamshieldLanguage?.refresh?.().catch(() => {});
}
export async function initializeLanguage() {
  try {
    const response = await fetch("/api/languages/current", { cache: "no-store" });
    if (!response.ok) throw new Error("Language unavailable.");
    await applyLanguage(await response.json());
  } catch { setLanguage(englishPack); }
}
