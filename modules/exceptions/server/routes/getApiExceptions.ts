import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getExceptions } from "../service";
export function registerGetApiExceptions(app: any, context: ApplicationContext) {
    app.get("/api/exceptions", async (req, res) => {
        try {
            res.json(await getExceptions());
        }
        catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });
}
