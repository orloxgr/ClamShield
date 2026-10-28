import { englishText } from "./runtime";
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from 'node:crypto';
import { englishPack, validateLanguagePack, type LanguagePack } from "./runtime";
export const maxLanguageBytes = 2 * 1024 * 1024;
const filename = /^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*\.json$/;
const inside = (folder: string, file: string) => { const relative = path.relative(folder, file); return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative); };
export function writeLanguageText(file: string, text: string, maxBytes: number) {
    if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('Language output exceeds its limit');
    const directory = path.dirname(file);
    fs.mkdirSync(directory, { recursive: true });
    if (fs.lstatSync(directory).isSymbolicLink()) throw new Error('Language output directory links are not allowed');
    const temporary = path.join(directory, '.language-' + randomUUID() + '.tmp');
    let created = false;
    try {
        const fd = fs.openSync(temporary, 'wx', 0o600); created = true;
        try { fs.writeFileSync(fd, text, 'utf8'); } finally { fs.closeSync(fd); }
        // Replace the directory entry, rather than following an existing file link.
        fs.renameSync(temporary, file);
    } finally { if (created && fs.existsSync(temporary)) fs.unlinkSync(temporary); }
}
// No imports, scripts, URLs, HTML parsing or executable callbacks from a language pack.
export function readBoundedJson(file: string, maxBytes = maxLanguageBytes): unknown {
    if (fs.lstatSync(file).isSymbolicLink())
        throw new Error(englishText("backend.languages.symbolic_links_are_not_language_files"));
    const fd = fs.openSync(file, "r");
    try {
        const stat = fs.fstatSync(fd);
        if (!stat.isFile() || stat.size > maxBytes)
            throw new Error(englishText("backend.languages.language_file_is_too_large_or_is_not_a_regular_file"));
        const buffer = Buffer.alloc(Math.min(stat.size + 1, maxBytes + 1));
        let read = 0;
        while (read < buffer.length) {
            const n = fs.readSync(fd, buffer, read, buffer.length - read, null);
            if (!n)
                break;
            read += n;
        }
        if (read > maxBytes || fs.fstatSync(fd).size > maxBytes)
            throw new Error(englishText("backend.languages.language_file_is_too_large"));
        const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, read)).replace(/^\uFEFF/, "");
        return JSON.parse(text);
    }
    finally {
        fs.closeSync(fd);
    }
}
export class LanguageFiles {
    private packs = new Map<string, LanguagePack>();
    private errors: Array<{
        file: string;
        error: string;
    }> = [];
    constructor(readonly directories: string[]) {
        if (directories.some(folder => !path.isAbsolute(folder)))
            throw new Error(englishText("backend.languages.language_directories_must_be_absolute"));
    }
    refresh() {
        this.packs.clear();
        this.errors = [];
        this.packs.set("en", englishPack);
        let visited = 0, bytes = 0;
        for (const folder of this.directories) {
          try {
            if (!fs.existsSync(folder))
                continue;
            if (fs.lstatSync(folder).isSymbolicLink()) {
                this.errors.push({ file: folder, error: englishText("backend.languages.language_directory_links_are_not_allowed") });
                continue;
            }
            const root = fs.realpathSync(folder);
            const entries = [];
            const directory = fs.opendirSync(folder);
            try {
                for (let entry; (entry = directory.readSync());) {
                    if (entries.length >= 256) throw new Error(englishText('languages.directory_limit'));
                    entries.push(entry);
                }
            } finally { directory.closeSync(); }
            for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
                if (!entry.name.endsWith(".json") || ["en.json", "template.json"].includes(entry.name))
                    continue;
                if (++visited > 64) {
                    this.errors.push({ file: folder, error: englishText("backend.languages.at_most_64_language_files_can_be_loaded") });
                    break;
                }
                try {
                    if (!filename.test(entry.name) || !entry.isFile() || entry.isSymbolicLink())
                        throw new Error(englishText("backend.languages.expected_a_regular_language_code_json_file"));
                    const file = path.join(folder, entry.name), resolved = fs.realpathSync(file);
                    if (!inside(root, resolved))
                        throw new Error(englishText("backend.languages.language_file_is_outside_its_directory"));
                    bytes += fs.statSync(file).size;
                    if (bytes > 16 * 1024 * 1024) throw new Error(englishText('languages.total_size_limit'));
                    const pack = validateLanguagePack(readBoundedJson(file));
                    if (entry.name !== `${pack.language.code}.json` || pack.language.code === "en")
                        throw new Error(englishText("backend.languages.filename_must_match_the_language_code"));
                    if (this.packs.has(pack.language.code))
                        throw new Error(englishText("backend.languages.duplicate_language_code"));
                    this.packs.set(pack.language.code, pack);
                }
                catch (error: any) {
                    this.errors.push({ file: entry.name, error: String(error?.message || "Invalid language file.").slice(0, 500) });
                }
            }
          } catch (error: any) {
            this.errors.push({ file: folder, error: String(error?.message || 'Invalid language directory.').slice(0, 500) });
          }
        }
        return this.list();
    }
    list() { return { languages: [...this.packs.values()].map(pack => pack.language), errors: [...this.errors], directories: [...this.directories] }; }
    get(code: unknown) { return typeof code === "string" ? this.packs.get(code) || null : null; }
    current(code: unknown) { return this.get(code) || englishPack; }
}
export function readLanguagePreference(file: string) {
    try {
        const value: any = readBoundedJson(file, 256);
        return value && typeof value.code === "string" && /^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(value.code) ? value.code : "en";
    }
    catch {
        return "en";
    }
}
