import { ApplicationContext } from "../../../../server/core/applicationContext";
import { restoreQuarantinedFileAndAddException } from "../../../quarantine/server/storage";
export function registerPostApiQuarantineFileNameRestoreException(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/quarantine/:fileName/restore-exception", async (req, res) => {
        try {
            const result = await restoreQuarantinedFileAndAddException(context.settings, req.params.fileName);
            res.json({ success: true, ...result });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e.message });
        }
    });
}
