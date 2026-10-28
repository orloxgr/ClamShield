import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getHistory, getHistoryPage } from "../storage";
export function registerGetApiHistory(app: any, context: ApplicationContext) {
    app.get("/api/history", async (req, res) => {
        const hasPagedQuery = req.query.page !== undefined || req.query.pageSize !== undefined || req.query.date !== undefined;
        if (!hasPagedQuery) {
            res.json(await getHistory());
            return;
        }
        const requestedPageSize = String(req.query.pageSize || "50").toLowerCase();
        const page = Math.max(1, Math.floor(Number(req.query.page || 1) || 1));
        const pageSize = requestedPageSize === "all"
            ? null
            : Math.max(1, Math.min(500, Math.floor(Number(requestedPageSize) || 50)));
        const offset = pageSize ? (page - 1) * pageSize : 0;
        const paged = await getHistoryPage({
            limit: pageSize,
            offset,
            date: typeof req.query.date === "string" ? req.query.date : ""
        });
        res.json({ items: paged.items, total: paged.total, page, pageSize: pageSize || "all" });
    });
}
