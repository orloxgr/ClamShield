import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getQuarantineMap } from "../storage";
import { addHistory } from "../../../history/server/storage";
import { saveQuarantineMap } from "../storage";
import fs from "fs/promises";
import path from "path";
export function registerPostApiQuarantineDeleteSelected(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/quarantine/delete-selected", async (req, res) => {
        try {
            const fileNames = Array.isArray(req.body?.fileNames)
                ? req.body.fileNames.map((item: any) => String(item || "")).filter(Boolean)
                : [];
            if (fileNames.length === 0)
                return res.status(400).json({ success: false, error: englishText("backend.exceptions.no_quarantine_items_selected") });
            const qMap = await getQuarantineMap();
            const errors: any[] = [];
            let deletedCount = 0;
            for (const fileName of fileNames) {
                const safeName = path.basename(fileName);
                if (safeName !== fileName) {
                    errors.push({ fileName, error: englishText("backend.quarantine.invalid_quarantine_item") });
                    continue;
                }
                try {
                    await fs.unlink(path.join(context.settings.quarantineDir, safeName));
                    delete qMap[safeName];
                    deletedCount++;
                }
                catch (e: any) {
                    errors.push({ fileName, error: e.message || String(e) });
                }
            }
            await saveQuarantineMap(qMap);
            await addHistory({
                type: "quarantine-delete-selected",
                target: "Selected quarantine items",
                result: errors.length === 0 ? 0 : 1,
                threatsFound: 0,
                scannedFiles: fileNames.length,
                duration: 0,
                actionTaken: englishText("backend.quarantine.deleted_selected_quarantined_file", {
                    deletedCount: String(deletedCount),
                    value2: String(deletedCount === 1 ? "" : englishText("dns.s"))
                })
            });
            res.status(errors.length === 0 ? 200 : 207).json({ success: errors.length === 0, deletedCount, errors });
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || String(e) });
        }
    });
}
