import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { ensureAppStateReady } from "../../../../server/core/database/migrations";
import { getAppStateDb } from "../../../../server/core/database/schema";
import { normalizedStatePath } from "../../../../server/core/database/values";
import { insertExceptionRow } from "../rows";
import path from "path";
export function registerPostApiExceptionsAdd(app: any, context: ApplicationContext) {
    app.post("/api/exceptions/add", async (req, res) => {
        try {
            const value = String(req.body?.path || "").trim();
            if (!value || !path.isAbsolute(value))
                throw new Error("Select an absolute file or folder path.");
            await ensureAppStateReady();
            const db = getAppStateDb();
            if (db.prepare("SELECT 1 FROM exceptions WHERE normalized_path = ?").get(normalizedStatePath(value)))
                throw new Error(englishText("backend.exceptions.path_is_already_in_exceptions"));
            insertExceptionRow(db, value, Date.now(), { origin: "manual", kind: ["file", "folder"].includes(req.body?.kind) ? req.body.kind : "unknown" });
            res.json({ success: true });
        }
        catch (e: any) {
            res.status(400).json({ error: e.message });
        }
    });
}
