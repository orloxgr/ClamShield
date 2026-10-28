import { LanguageFiles, readLanguagePreference } from "./files";
import path from 'node:path';
import { writeShellLanguage } from './shell';
import { englishPack, setLanguage, t, englishText, localizeText, getLanguage } from "./runtime";
export { t, englishText, localizeText, getLanguage };
let loadedCode = "", reader: LanguageFiles | undefined;
export function desktopLanguage(directories: string[], preference: string, refresh = false) {
  const code = readLanguagePreference(preference);
  if (!reader || refresh || code !== loadedCode) {
    reader = new LanguageFiles(directories); reader.refresh();
    const pack = reader.current(code); setLanguage(pack); loadedCode = code;
    try { writeShellLanguage(pack, path.join(path.dirname(preference), 'language-labels')); } catch { /* Presentation only; the scanners remain independent. */ }
    return pack;
  }
  return reader.current(code) || englishPack;
}
