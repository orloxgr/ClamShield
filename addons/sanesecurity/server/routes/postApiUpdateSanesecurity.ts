import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerPostApiUpdateSanesecurity(app: any, context: Pick<ApplicationContext, "startSaneSecurityUpdate">) {
app.post("/api/update-sanesecurity", async (_req, res) => {
    try {
        const jobId = await context.startSaneSecurityUpdate("manual");
        res.json({ jobId, status: "started" });
    }
    catch (e: any) {
        const message = e?.message || String(e);
        res.status(/already running/i.test(message) ? 409 : 400).json({ error: message });
    }
});
}
