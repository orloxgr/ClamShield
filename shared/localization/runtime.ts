import english from "../../languages/en.json";
export type Parameters = Record<string, string | number | boolean | null | undefined>;
export type LanguageEntry = {
    english: string;
    translation: string;
    maxChars: number;
    optionalParameters?: string[];
    plural?: string;
    forms?: Record<string, string>;
};
export type LanguagePack = {
    schemaVersion: number;
    language: {
        code: string;
        name: string;
        direction: "ltr" | "rtl";
        englishName?: string;
        status?: "source" | "auto" | "reviewed";
        reviewers?: string[];
    };
    strings: Record<string, LanguageEntry>;
};
const canonical = english as LanguagePack;
const own = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key);
const forbidden = new Set(["__proto__", "prototype", "constructor"]);
const control = /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/;
const token = /\{\{([a-zA-Z][a-zA-Z0-9_]*)\}\}/g;
const count = (text: string) => Array.from(text).length;
const placeholders = (text: string) => [...text.matchAll(token)].map(match => match[1]).sort();
const object = (v: unknown): v is Record<string, any> => Boolean(v && typeof v === "object" && !Array.isArray(v));
export function validateLanguagePack(input: unknown): LanguagePack {
    const rejectKeys = (value: unknown, depth = 0) => {
        if (depth > 7)
            throw new Error(englishText("backend.languages.language_json_is_nested_too_deeply"));
        if (!value || typeof value !== "object")
            return;
        if (Array.isArray(value)) {
            if (value.length > 32)
                throw new Error(englishText("backend.languages.language_array_is_too_large"));
            for (const v of value)
                rejectKeys(v, depth + 1);
            return;
        }
        for (const [key, v] of Object.entries(value)) {
            if (forbidden.has(key))
                throw new Error(englishText("backend.languages.forbidden_language_property"));
            rejectKeys(v, depth + 1);
        }
    };
    rejectKeys(input);
    if (!object(input) || input.schemaVersion !== 1 || !object(input.language) || !object(input.strings))
        throw new Error(englishText("backend.languages.expected_language_schemaversion_1_language_metadata_and_strings"));
    if (Object.keys(input).some(k => !["schemaVersion", "language", "strings"].includes(k)))
        throw new Error(englishText("backend.languages.unexpected_language_document_property"));
    const meta = input.language;
    if (typeof meta.code !== "string" || !/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(meta.code) || meta.code.length > 35)
        throw new Error(englishText("backend.languages.invalid_language_code"));
    try {
        Intl.getCanonicalLocales(meta.code);
    }
    catch {
        throw new Error(englishText("backend.languages.invalid_language_locale"));
    }
    if (typeof meta.name !== "string" || !meta.name.trim() || count(meta.name) > 60 || control.test(meta.name))
        throw new Error(englishText("backend.languages.invalid_language_name"));
    if (!["ltr", "rtl"].includes(meta.direction) || Object.keys(meta).some(k => !["code", "name", "direction", "englishName", "status", "reviewers"].includes(k)))
        throw new Error(englishText("backend.languages.invalid_language_metadata"));
    if (meta.englishName !== undefined && (typeof meta.englishName !== 'string' || !meta.englishName.trim() || count(meta.englishName) > 60 || control.test(meta.englishName)))
        throw new Error(englishText('languages.invalid_english_name'));
    const status = meta.status ?? (meta.code === 'en' ? 'source' : 'auto');
    if (!['source', 'auto', 'reviewed'].includes(status) || (status === 'source' && meta.code !== 'en') || (meta.code === 'en' && status !== 'source'))
        throw new Error(englishText('languages.invalid_review_status'));
    if (meta.reviewers !== undefined && (!Array.isArray(meta.reviewers) || meta.reviewers.length > 8 || meta.reviewers.some((name: unknown) => typeof name !== 'string' || !name.trim() || count(name) > 60 || control.test(name))))
        throw new Error(englishText('languages.invalid_reviewers'));
    if (status === 'reviewed' && !meta.reviewers?.length)
        throw new Error(englishText('languages.review_requires_name'));
    if (Object.keys(input.strings).length > 8192)
        throw new Error(englishText("backend.languages.too_many_language_strings"));
    const strings: Record<string, LanguageEntry> = Object.create(null);
    for (const [key, raw] of Object.entries(input.strings)) {
        if (!own(canonical.strings, key))
            throw new Error(englishText("backend.languages.unknown_string", {
                key: String(key)
            }));
        const definition = canonical.strings[key];
        if (!object(raw) || Object.keys(raw).some(k => !["english", "translation", "maxChars", "optionalParameters", "plural", "forms"].includes(k)))
            throw new Error(englishText("backend.languages.invalid_entry", {
                key: String(key)
            }));
        if (raw.english !== definition.english || raw.maxChars !== definition.maxChars)
            throw new Error(englishText("backend.languages.english_text_or_maxchars_changed", {
                key: String(key)
            }));
        if (JSON.stringify(raw.optionalParameters || []) !== JSON.stringify(definition.optionalParameters || []) || raw.plural !== definition.plural)
            throw new Error(englishText("backend.languages.placeholder_metadata_changed", {
                key: String(key)
            }));
        const checkText = (text: unknown) => {
            if (typeof text !== "string" || count(text) > definition.maxChars || control.test(text))
                throw new Error(englishText("backend.languages.invalid_or_overlong_translation_max_characters", {
                    key: String(key),
                    maxChars: String(definition.maxChars)
                }));
            if (!text)
                return "";
            const expected = placeholders(definition.english), actual = placeholders(text);
            // These optional parameters are authored English plural suffixes.
            // Other languages may omit them without dropping any actual values.
            const required = expected.filter(p => !(definition.optionalParameters || []).includes(p));
            if (actual.some(p => !expected.includes(p)) || required.some(p => !actual.includes(p)))
                throw new Error(englishText("backend.languages.placeholders_must_be_preserved", {
                    key: String(key)
                }));
            return text;
        };
        const translation = checkText(raw.translation);
        let forms: Record<string, string> | undefined;
        if (raw.forms !== undefined) {
            if (!definition.plural || !object(raw.forms) || !own(raw.forms, "other"))
                throw new Error(englishText("backend.languages.plural_forms_require_an_other_form", {
                    key: String(key)
                }));
            forms = Object.create(null);
            for (const [form, text] of Object.entries(raw.forms)) {
                if (!["zero", "one", "two", "few", "many", "other"].includes(form))
                    throw new Error(englishText("backend.languages.invalid_plural_form", {
                        key: String(key)
                    }));
                forms[form] = checkText(text);
            }
        }
        strings[key] = { ...definition, translation, ...(forms ? { forms } : {}) };
    }
    if (status === 'reviewed' && (Object.keys(strings).length !== Object.keys(canonical.strings).length || Object.values(strings).some(entry => !entry.translation && !entry.forms?.other)))
        throw new Error(englishText('languages.review_requires_complete_translation'));
    return { schemaVersion: 1, language: { code: meta.code, name: meta.name, direction: meta.direction,
        ...(meta.englishName !== undefined ? { englishName: meta.englishName } : {}), status,
        ...(meta.reviewers !== undefined ? { reviewers: [...meta.reviewers] } : {}) }, strings };
}

export function languageLabel(language: LanguagePack['language']) {
    let englishName = language.englishName;
    if (!englishName) {
        try { englishName = new Intl.DisplayNames(['en'], { type: 'language' }).of(language.code); } catch { /* Display metadata only. */ }
    }
    const english = englishName || language.code;
    const name = english === language.name ? english : `${english} — ${language.name}`;
    if (language.code === 'en') return name;
    const credit = language.status === 'reviewed' && language.reviewers?.length ? language.reviewers.join(', ') : 'auto';
    return `${name} (${credit})`;
}
export const englishPack = canonical;
let active: LanguagePack = canonical;
let revision = 0;
const listeners = new Set<() => void>();
export const getLanguage = () => active.language;
export const getRevision = () => revision;
export const subscribeLanguage = (callback: () => void) => { listeners.add(callback); return () => { listeners.delete(callback); }; };
export function setLanguage(pack: unknown) {
    active = validateLanguagePack(pack);
    revision++;
    for (const listener of listeners)
        listener();
}
export function englishText(key: string, params: Parameters = {}) { return render(canonical, key, params); }
export function t(key: string, params: Parameters = {}) { return render(active, key, params); }
export function translate(pack: LanguagePack, key: string, params: Parameters = {}) { return render(pack, key, params); }
function render(pack: LanguagePack, key: string, params: Parameters) {
    const definition = canonical.strings[key];
    if (!definition)
        return key;
    const translated = pack.strings[key];
    let text = translated?.translation || definition.english;
    if (translated?.forms && definition.plural && Number.isFinite(Number(params[definition.plural]))) {
        const form = new Intl.PluralRules(pack.language.code).select(Number(params[definition.plural]));
        text = translated.forms[form] || translated.forms.other || text;
    }
    return text.replace(token, (_match, name) => {
        const value = params[name];
        return ["string", "number", "boolean"].includes(typeof value) ? String(value).slice(0, 8192) : "";
    });
}
const exact = new Map<string, string>();
const patterns: Array<{
    key: string;
    parts: string[];
    names: string[];
}> = [];
for (const [key, entry] of Object.entries(canonical.strings)) {
    const matches = [...entry.english.matchAll(token)];
    if (!matches.length) {
        if (!exact.has(entry.english))
            exact.set(entry.english, key);
        continue;
    }
    const parts = entry.english.split(token).filter((_v, i) => i % 2 === 0);
    if (matches.length <= 8 && parts.join("").length >= 12 && parts.slice(1, -1).every(Boolean))
        patterns.push({ key, parts, names: matches.map(m => m[1]) });
}
// Bounded literal matching. Regexes are never made from language-file content.
export function messageDescriptor(value: unknown): {
    key: string;
    params: Parameters;
} | null {
    if (typeof value !== "string" || value.length > 16384)
        return null;
    const key = exact.get(value);
    if (key)
        return { key, params: {} };
    for (const pattern of patterns) {
        if (!value.startsWith(pattern.parts[0]) || !value.endsWith(pattern.parts.at(-1)!))
            continue;
        let at = pattern.parts[0].length, valid = true;
        const params: Parameters = Object.create(null);
        for (let i = 0; i < pattern.names.length; i++) {
            const next = pattern.parts[i + 1];
            const end = i === pattern.names.length - 1 ? value.length - next.length : value.indexOf(next, at);
            if (end < at) {
                valid = false;
                break;
            }
            params[pattern.names[i]] = value.slice(at, end);
            at = end + next.length;
        }
        if (valid && at === value.length)
            return { key: pattern.key, params };
    }
    return null;
}
export function localizeText<T>(value: T): T {
    if (typeof value !== "string")
        return value;
    const descriptor = messageDescriptor(value);
    return (descriptor ? t(descriptor.key, descriptor.params) : value) as T;
}
