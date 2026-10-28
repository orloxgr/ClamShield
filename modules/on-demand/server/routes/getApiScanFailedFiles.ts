import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getScanFailedFilesPage } from "../../../results/server/storage";
export function registerGetApiScanFailedFiles(app: any, context: ApplicationContext) {
    app.get("/api/scan/failed-files", async (req, res) => {
        try {
            const requestedPageSize = String(req.query.pageSize || "100").toLowerCase();
            const page = Math.max(1, Math.floor(Number(req.query.page || 1) || 1));
            const pageSize = requestedPageSize === "all"
                ? null
                : Math.max(1, Math.min(500, Math.floor(Number(requestedPageSize) || 100)));
            const offset = pageSize ? (page - 1) * pageSize : 0;
            const paged = await getScanFailedFilesPage({
                limit: pageSize,
                offset,
                status: typeof req.query.status === "string" ? req.query.status : "pending"
            });
            res.json({ items: paged.items, total: paged.total, page, pageSize: pageSize || "all" });
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || String(e) });
        }
    });
}
