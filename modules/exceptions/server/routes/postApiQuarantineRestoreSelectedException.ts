import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { restoreQuarantinedFileAndAddException } from "../../../quarantine/server/storage";
export function registerPostApiQuarantineRestoreSelectedException(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/quarantine/restore-selected-exception", async (req, res) => {
        try {
            const fileNames = Array.isArray(req.body?.fileNames)
                ? req.body.fileNames.map((item: any) => String(item || "")).filter(Boolean)
                : [];
            if (fileNames.length === 0)
                return res.status(400).json({ success: false, error: englishText("backend.exceptions.no_quarantine_items_selected") });
            const restored: any[] = [];
            const errors: any[] = [];
            for (const fileName of fileNames) {
                try {
                    const result = await restoreQuarantinedFileAndAddException(context.settings, fileName);
                    restored.push({ fileName, ...result });
                }
                catch (e: any) {
                    errors.push({ fileName, error: e.message || String(e) });
                }
            }
            res.status(errors.length === 0 ? 200 : 207).json({
                success: errors.length === 0,
                restoredCount: restored.length,
                restored,
                errors
            });
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || String(e) });
        }
    });
}
