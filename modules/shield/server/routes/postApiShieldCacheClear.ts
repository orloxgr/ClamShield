import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerPostApiShieldCacheClear(app: any, context: Pick<ApplicationContext, "shieldScanCache">) {
app.post("/api/shield-cache/clear", async (req, res) => {
    context.shieldScanCache.clear();
    res.json({ success: true, shieldCacheCount: 0 });
});
}
