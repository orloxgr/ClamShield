import { englishText } from "../../../shared/localization/runtime";
import { yaraForgeRulesDir } from "../../../server/core/paths";
import { yaraForgePackages } from "../../../server/core/utils";
import { walkFiles } from "../../../server/scanning/targets";
import fs from "fs/promises";
import path from "path";
export function normalizeYaraRuleset(value: any) {
    return Object.prototype.hasOwnProperty.call(yaraForgePackages, value) ? value : "core";
}
export function getYaraRulesFile(settings: any) {
    const ruleset = normalizeYaraRuleset(settings.yaraRuleset);
    return path.join(settings.yaraRulesDir || yaraForgeRulesDir, yaraForgePackages[ruleset].fileName);
}
export async function findLargestYaraFile(rootPath: string): Promise<string | null> {
    let best: {
        filePath: string;
        size: number;
    } | null = null;
    for await (const filePath of walkFiles(rootPath)) {
        const ext = path.extname(filePath).toLowerCase();
        if (ext !== ".yar" && ext !== ".yara")
            continue;
        try {
            const stat = await fs.stat(filePath);
            if (!best || stat.size > best.size) {
                best = { filePath, size: stat.size };
            }
        }
        catch (e: any) {
            console.debug(englishText("backend.yara.unable_to_inspect_candidate_yara_rules_file"), filePath, e?.message || e);
        }
    }
    return best?.filePath || null;
}
export async function countYaraRules(filePath: string) {
    try {
        const content = await fs.readFile(filePath, "utf8");
        return (content.match(/^\s*(?:private\s+|global\s+)*rule\s+[A-Za-z0-9_]+/gm) || []).length;
    }
    catch {
        return 0;
    }
}
