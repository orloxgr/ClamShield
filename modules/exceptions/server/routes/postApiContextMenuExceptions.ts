import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { normalizeContextMenuTargets } from "../../../../server/scanning/targets";
import { addHistory } from "../../../history/server/storage";
import { normalizeCachePath } from "../../../shield/server/cache";
import { getExceptions, saveExceptions } from "../service";
export function registerPostApiContextMenuExceptions(app: any, context: ApplicationContext) {
    app.post("/api/context-menu/exceptions", async (req, res) => {
        try {
            const targets = normalizeContextMenuTargets(req.body?.targets);
            if (targets.length === 0) {
                return res.status(400).json({ success: false, error: englishText("backend.exceptions.no_valid_context_menu_targets_were_provided") });
            }
            const exceptions = await getExceptions();
            const existing = new Set(exceptions.map(item => normalizeCachePath(item)).filter(Boolean));
            let addedCount = 0;
            for (const targetPath of targets) {
                const normalized = normalizeCachePath(targetPath);
                if (!normalized || existing.has(normalized))
                    continue;
                exceptions.push(targetPath);
                existing.add(normalized);
                addedCount++;
            }
            if (addedCount > 0)
                await saveExceptions(exceptions, "manual");
            await addHistory({
                type: "context-menu-exceptions",
                target: targets.length === 1 ? targets[0] : `${targets.length} selected items`,
                result: 0,
                threatsFound: 0,
                scannedFiles: 0,
                duration: 1,
                actionTaken: addedCount > 0
                    ? englishText("backend.exceptions.added_item_to_exceptions", {
                        addedCount: String(addedCount),
                        value2: String(addedCount === 1 ? "" : englishText("dns.s"))
                    }) : englishText("backend.exceptions.already_in_exceptions")
            }).catch(() => { });
            res.json({ success: true, addedCount, totalTargets: targets.length });
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || String(e) });
        }
    });
}
