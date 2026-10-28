import { ApplicationContext } from "../../../../server/core/applicationContext";
import express from "express";
export function registerGetApiScanJobIdEvents(app: any, context: Pick<ApplicationContext, "jobEventClients" | "activeJobs" | "sendJobEventToClient">) {
    app.get("/api/scan/:jobId/events", (req, res) => {
        const jobId = req.params.jobId;
        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache, no-transform");
        res.setHeader("Connection", "keep-alive");
        res.flushHeaders?.();
        let clients = context.jobEventClients.get(jobId);
        if (!clients) {
            clients = new Set<express.Response>();
            context.jobEventClients.set(jobId, clients);
        }
        clients.add(res);
        const job = context.activeJobs[jobId];
        context.sendJobEventToClient(res, {
            status: job?.status || "missing",
            logs: job?.logs || [],
            progress: job?.progress || null,
            result: job?.result
        });
        const keepAlive = setInterval(() => {
            try {
                res.write(":keepalive\n\n");
            }
            catch {
                clearInterval(keepAlive);
                clients?.delete(res);
            }
        }, 25000);
        keepAlive.unref?.();
        req.on("close", () => {
            clearInterval(keepAlive);
            clients?.delete(res);
            if (clients && clients.size === 0)
                context.jobEventClients.delete(jobId);
        });
    });
}
