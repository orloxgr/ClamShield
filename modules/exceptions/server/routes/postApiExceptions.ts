import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saveExceptions } from "../service";
export function registerPostApiExceptions(app: any, context: ApplicationContext) {
    app.post("/api/exceptions", async (req, res) => {
        try {
            const list = req.body.exceptions;
            if (Array.isArray(list)) {
                await saveExceptions(list, "manual");
                res.json({ success: true });
            }
            else {
                res.status(400).json({ error: englishText("backend.exceptions.invalid_array") });
            }
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
