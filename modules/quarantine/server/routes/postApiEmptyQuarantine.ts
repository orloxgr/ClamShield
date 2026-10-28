import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saveQuarantineMap } from "../storage";
import fs from "fs/promises";
import path from "path";
export function registerPostApiEmptyQuarantine(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/empty-quarantine", async (req, res) => {
        try {
            const files = await fs.readdir(context.settings.quarantineDir);
            for (const file of files) {
                try {
                    await fs.unlink(path.join(context.settings.quarantineDir, file));
                }
                catch (e) {
                    console.error("Cannot delete quarantine file:", file);
                }
            }
            await saveQuarantineMap({});
            res.json({ success: true });
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
