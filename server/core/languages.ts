import { englishText } from "../../shared/localization/runtime";
import path from "node:path";
import { LanguageFiles, writeLanguageText } from "../../shared/localization/files";
import { englishPack, messageDescriptor } from "../../shared/localization/runtime";
import { programDataDir, runtimeDir } from "./paths";
import { getInstalledAppDir } from "../platform/contextMenu";
import { saveConfig } from "../../modules/settings/server/service";
import type { ApplicationContext } from "./applicationContext";
import { writeShellLanguage } from '../../shared/localization/shell';
import { setPresentationLanguage } from '../../shared/localization/presentation';
import { configureLegacyContextMenuRegistry } from '../platform/contextMenu';
export function registerLanguageRoutes(app: any, context: Pick<ApplicationContext, 'settings'>, options: {
    directories?: string[]; preference?: string;
    persistSettings?: typeof saveConfig;
    onChanged?: (pack: typeof englishPack) => Promise<void>;
} = {}) {
    const installation = /clamshield\.exe$/i.test(process.execPath) ? getInstalledAppDir()
        : path.basename(runtimeDir) === 'dist' ? path.dirname(runtimeDir) : getInstalledAppDir();
    const files = new LanguageFiles(options.directories || [path.resolve(installation, "languages"), path.join(programDataDir, "languages")]);
    files.refresh();
    const preference = options.preference || path.join(programDataDir, "language.json");
    const current = () => files.current(context.settings.languageCode || "en");
    const refresh = () => { const result = files.refresh(); setPresentationLanguage(current()); return result; };
    setPresentationLanguage(current());
    const persistDesktopChoice = async () => {
        // Only a validated language code is written. Language files never control a path or command.
        writeLanguageText(preference, JSON.stringify({ code: current().language.code }), 256);
        writeShellLanguage(current(), path.join(path.dirname(preference), 'language-labels'));
    };
    persistDesktopChoice().catch(() => { });
    app.get("/api/languages", (_req: any, res: any) => res.json({ ...refresh(), selected: current().language.code }));
    app.get("/api/languages/current", (_req: any, res: any) => res.json(current()));
    app.post("/api/languages", async (req: any, res: any) => {
        try {
            refresh();
            const selected = files.get(req.body?.code);
            if (!selected)
                return res.status(400).json({ error: englishText("backend.core.choose_a_valid_installed_language_file") });
            await (options.persistSettings || saveConfig)({ ...context.settings, languageCode: selected.language.code }, { keys: ["languageCode"] });
            context.settings = { ...context.settings, languageCode: selected.language.code };
            setPresentationLanguage(selected);
            await persistDesktopChoice();
            await options.onChanged?.(selected);
            if (!options.directories && context.settings.windowsContextMenuEnabled === true)
                await configureLegacyContextMenuRegistry(true, context.settings);
            res.json({ success: true, language: selected, ...files.list() });
        }
        catch {
            res.status(400).json({ error: englishText("backend.core.could_not_save_the_language_preference") });
        }
    });
    app.get("/api/languages/template", (_req: any, res: any) => {
        const template = { ...englishPack, language: { code: "es", name: "Español", direction: "ltr" },
            strings: Object.fromEntries(Object.entries(englishPack.strings).map(([key, entry]) => [key, { ...entry, translation: "" }])) };
        res.type("application/json").attachment("es.json").send(JSON.stringify(template, null, 2));
    });
}
// Messages remain English at rest and protocol identifiers are never translated.
export function describePresentationFields(value: any, depth = 0): any {
    if (depth > 8 || !value || typeof value !== "object")
        return value;
    if (Array.isArray(value))
        return value.map(item => describePresentationFields(item, depth + 1));
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value)))
        return value;
    const result = { ...value };
    for (const [key, field] of Object.entries(value)) {
        if (["message", "error", "label", "title", "subtitle", "reason"].includes(key) && typeof field === "string") {
            const descriptor = messageDescriptor(field);
            if (descriptor)
                result[`${key}I18n`] = descriptor;
        }
        else if (field && typeof field === "object")
            result[key] = describePresentationFields(field, depth + 1);
    }
    return result;
}
