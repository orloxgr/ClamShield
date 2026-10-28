import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getExceptionItemsPage } from "../service";
export function registerGetApiExceptionsReporting(app: any, context: ApplicationContext) {
    app.get("/api/exceptions/reporting", async (req, res) => {
        try {
            const page = Math.max(1, Math.floor(Number(req.query.page) || 1));
            const pageSize = req.query.pageSize === "all" ? null : Math.max(1, Math.min(500, Math.floor(Number(req.query.pageSize) || 50)));
            res.json(await getExceptionItemsPage({ ...req.query, limit: pageSize, offset: pageSize ? (page - 1) * pageSize : 0 }));
        }
        catch (e: any) {
            res.status(400).json({ error: e.message });
        }
    });
}
