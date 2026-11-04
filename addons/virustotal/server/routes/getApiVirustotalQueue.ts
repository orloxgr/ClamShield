import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { loadVirusTotalApiKey } from "../account";
import { getVirusTotalShieldUploadMaxBytes } from "../requests";
import fs from "node:fs/promises";
export function registerGetApiVirustotalQueue(app: any, context: ApplicationContext) {
    app.post("/api/virustotal/queue/shield/action", async (req, res) => {
        const { id, action } = req.body || {};
        if (typeof id !== "string" || !id.startsWith("shield:") || !["recheck", "upload", "remove"].includes(action))
            return res.status(400).json({ error: englishText("vt.queue.update_failed") });
        const key = id.slice(7), task = context.virusTotalShieldQueue.get(key);
        if (!task) return res.status(404).json({ error: englishText("vt.queue.update_failed") });
        // Only waiting tasks may be changed; an active request owns its evidence.
        if (!task.blockedReason) return res.status(409).json({ error: englishText("vt.queue.update_failed") });
        try {
            if (action === "remove") {
                context.virusTotalShieldQueue.delete(key);
                return res.json({ success: true });
            }
            if (context.settings.virusTotalCloudEnabled !== true || !await loadVirusTotalApiKey())
                return res.status(409).json({ error: englishText("vt.queue.enable_cloud") });
            if (action === "upload") {
                if (task.blockedReason !== "upload" || !/^[a-f0-9]{64}$/i.test(task.sha256 || ""))
                    return res.status(409).json({ error: englishText("vt.queue.recheck_first") });
                const stat = await fs.stat(task.filePath).catch(() => null);
                if (!stat?.isFile() || stat.size <= 0 || stat.size > getVirusTotalShieldUploadMaxBytes(context.settings))
                    return res.status(409).json({ error: englishText("vt.queue.upload_unavailable") });
            }
            // A concurrent button request must not replace a task already changed.
            if (context.virusTotalShieldQueue.get(key) !== task)
                return res.status(409).json({ error: englishText("vt.queue.update_failed") });
            context.virusTotalShieldQueue.set(key, { ...task, blockedReason: undefined, message: "", notBefore: 0,
                forceCloudCheck: true, recheckHash: action === "recheck", pendingUploadHash: action === "upload" ? task.sha256 : "" });
            context.scheduleShieldVirusTotalCheck();
            res.json({ success: true });
        } catch {
            res.status(500).json({ error: englishText("vt.queue.update_failed") });
        }
    });
    app.get("/api/virustotal/queue", async (req, res) => {
        try {
            res.json(runtimeState.virusTotalQueueViewHandler!(req.query, Boolean(await loadVirusTotalApiKey())));
        }
        catch (e: any) {
            res.status(500).json({ error: englishText("common.virus_total_queue_dialog.could_not_load_the_virustotal_queue") });
        }
    });
}
