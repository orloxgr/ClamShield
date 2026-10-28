import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerGetApiEvents(app: any, context: Pick<ApplicationContext, "eventClients" | "sendApiEventToClient" | "pendingThreats" | "getResultsReminderPayload">) {
    app.get("/api/events", async (req, res) => {
        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache, no-transform");
        res.setHeader("Connection", "keep-alive");
        res.flushHeaders?.();
        context.eventClients.add(res);
        context.sendApiEventToClient(res, "connected", { ok: true });
        for (const threat of context.pendingThreats) {
            context.sendApiEventToClient(res, "threat", threat);
        }
        try {
            context.sendApiEventToClient(res, "results-reminder", await context.getResultsReminderPayload());
        }
        catch (e) {
            console.warn(englishText("backend.dashboard.failed_to_send_initial_results_reminder_event"), e);
        }
        const keepAlive = setInterval(() => {
            try {
                res.write(":keepalive\n\n");
            }
            catch {
                clearInterval(keepAlive);
                context.eventClients.delete(res);
            }
        }, 25000);
        keepAlive.unref?.();
        req.on("close", () => {
            clearInterval(keepAlive);
            context.eventClients.delete(res);
        });
    });
}
