import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saveConfig } from "../../../settings/server/service";
export function registerPostApiScheduledScanRuntime(app: any, context: Pick<ApplicationContext, "scheduledScanRuntime" | "settings" | "sendScanSummary">) {
    app.post("/api/scheduled-scan/runtime", async (req, res) => {
        const body = req.body || {};
        const allowedStates = new Set(["idle", "disabled", "waiting-idle", "waiting-scan", "running", "stopped", "complete", "error"]);
        context.scheduledScanRuntime = {
            state: allowedStates.has(body.state) ? body.state : context.scheduledScanRuntime.state,
            message: String(body.message || context.scheduledScanRuntime.message || "").slice(0, 500),
            activeJobId: String(body.activeJobId || "").slice(0, 100),
            currentTarget: String(body.currentTarget || "").slice(0, 1000),
            queueIndex: Math.max(0, Math.round(Number(body.queueIndex || 0))),
            totalTargets: Math.max(0, Math.round(Number(body.totalTargets || 0))),
            idleSeconds: Math.max(0, Math.round(Number(body.idleSeconds || 0))),
            updatedAt: Date.now()
        };
        const runtimeSettingsKeys = new Set<string>();
        if (typeof body.lastRunKey === "string" && body.lastRunKey) {
            context.settings.lastScheduledScanRunKey = body.lastRunKey.slice(0, 200);
            runtimeSettingsKeys.add("lastScheduledScanRunKey");
        }
        if (typeof body.lastRunAt === "string") {
            context.settings.lastScheduledScanAt = body.lastRunAt.slice(0, 100);
            runtimeSettingsKeys.add("lastScheduledScanAt");
        }
        if (typeof body.lastResult === "string") {
            context.settings.lastScheduledScanResult = body.lastResult.slice(0, 500);
            runtimeSettingsKeys.add("lastScheduledScanResult");
        }
        if (body.persist === true && runtimeSettingsKeys.size > 0) {
            await saveConfig(context.settings, { keys: runtimeSettingsKeys });
        }
        if (body.persist === true && context.scheduledScanRuntime.state === "complete" && String(context.settings.lastScheduledScanResult || "").toLowerCase().includes("detections")) {
            context.sendScanSummary({
                title: englishText("backend.on_demand.scheduled_scan_found_threats"),
                message: context.settings.lastScheduledScanResult,
                detail: context.scheduledScanRuntime.message || englishText("backend.scheduler.scheduled_scan_completed"),
                target: context.scheduledScanRuntime.currentTarget || "Scheduled scan",
                action: context.settings.scanDetectionAction === "quarantine" ? "quarantine" : "results"
            });
        }
        else if (body.persist === true && (context.scheduledScanRuntime.state === "stopped" || context.scheduledScanRuntime.state === "error")) {
            context.sendScanSummary({
                title: englishText("backend.scheduler.scheduled_scan_stopped"),
                message: context.settings.lastScheduledScanResult || context.scheduledScanRuntime.message || englishText("backend.scheduler.scheduled_scan_stopped_e813068"),
                detail: context.scheduledScanRuntime.message || "",
                target: context.scheduledScanRuntime.currentTarget || "Scheduled scan",
                action: "results"
            });
        }
        res.json({ success: true, runtime: context.scheduledScanRuntime });
    });
}
