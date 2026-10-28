import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { writeAppLog } from "../../../../server/core/logging";
import { runtimeState } from "../../../../server/core/runtimeState";
export function registerPostApiClientLog(app: any, context: ApplicationContext) {
    app.post("/api/client-log", (req, res) => {
        const level = typeof req.body?.level === "string" ? req.body.level : "error";
        const message = req.body?.message || englishText("backend.dashboard.renderer_log");
        if (runtimeState.debugLoggingEnabled || level === "fatal" || level === "error") {
            writeAppLog("renderer.log", level, [message, req.body?.details || {}]);
        }
        res.json({ success: true });
    });
}
