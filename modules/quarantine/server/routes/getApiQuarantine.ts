import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getLocalDateRangeMs } from "../../../history/server/storage";
import { getQuarantineItems } from "../storage";
export function registerGetApiQuarantine(app: any, context: Pick<ApplicationContext, "settings">) {
    app.get("/api/quarantine", async (req, res) => {
        try {
            const items = await getQuarantineItems(context.settings.quarantineDir);
            const hasPagedQuery = req.query.page !== undefined || req.query.pageSize !== undefined || req.query.date !== undefined;
            if (!hasPagedQuery) {
                res.json(items);
                return;
            }
            const dateRange = getLocalDateRangeMs(req.query.date);
            const filteredItems = dateRange
                ? items.filter((item: any) => Number(item.timestamp || 0) >= dateRange.start && Number(item.timestamp || 0) <= dateRange.end)
                : items;
            const requestedPageSize = String(req.query.pageSize || "50").toLowerCase();
            const page = Math.max(1, Math.floor(Number(req.query.page || 1) || 1));
            const pageSize = requestedPageSize === "all"
                ? null
                : Math.max(1, Math.min(500, Math.floor(Number(requestedPageSize) || 50)));
            const offset = pageSize ? (page - 1) * pageSize : 0;
            res.json({
                items: pageSize ? filteredItems.slice(offset, offset + pageSize) : filteredItems,
                total: filteredItems.length,
                page,
                pageSize: pageSize || "all"
            });
        }
        catch (e: any) {
            console.error(englishText("backend.quarantine.error_reading_quarantine_dir"), e);
            res.status(500).json({ error: e.message, items: [] });
        }
    });
}
