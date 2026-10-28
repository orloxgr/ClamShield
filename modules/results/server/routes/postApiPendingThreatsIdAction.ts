import { englishText } from "../../../../shared/localization/runtime";
import { normalizeYaraRuleset } from "../../../../engines/yara/server/rules";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getExceptions, rememberExceptionDetection, saveExceptions } from "../../../exceptions/server/service";
import { getQuarantineMap } from "../../../quarantine/server/storage";
import { quarantineFile } from "../../../quarantine/server/files";
import { saveQuarantineMap } from "../../../quarantine/server/storage";
import { addScanResult } from "../storage";
export function registerPostApiPendingThreatsIdAction(app: any, context: Pick<ApplicationContext, "pendingThreats" | "pendingThreatStore" | "pendingThreatActions" | "settings" | "sendApiEvent">) {
    app.post("/api/pending-threats/:id/action", async (req, res) => {
        const threatId = req.params.id;
        const action = req.body.action; // "quarantine" | "exception" | "results"
        if (!["quarantine", "exception", "results"].includes(action)) {
            return res.status(400).json({ success: false, error: englishText("backend.results.invalid_threat_action") });
        }
        const threat = context.pendingThreats.find(t => t.id === threatId);
        if (!threat) {
            return res.json(context.pendingThreatStore.wasResolved(threatId)
                ? { success: true, alreadyResolved: true }
                : { success: false, error: englishText("backend.results.this_alert_is_no_longer_available_review_the_latest_detections_in") });
        }
        try {
            if (context.pendingThreatActions.has(threatId)) {
                return res.status(409).json({ success: false, error: englishText("backend.results.an_action_is_already_in_progress_for_this_file") });
            }
            const task = (async () => {
                if (action === "quarantine") {
                    const quarantined = await quarantineFile(threat.originalPath, threat.threatName, context.settings.quarantineDir);
                    Object.assign(quarantined.metadata, { detections: threat.detections });
                    const qMap = await getQuarantineMap();
                    qMap[quarantined.fileName] = quarantined.metadata;
                    await saveQuarantineMap(qMap);
                }
                else if (action === "exception") {
                    const exceptions = await getExceptions();
                    if (!exceptions.includes(threat.originalPath)) {
                        exceptions.push(threat.originalPath);
                        await saveExceptions(exceptions);
                    }
                    await rememberExceptionDetection(threat, "shield");
                }
                else if (action === "results") {
                    for (const detection of threat.detections || [threat]) {
                        await addScanResult({
                            source: "shield",
                            scanType: "shield",
                            target: threat.originalPath,
                            originalPath: threat.originalPath,
                            threatName: detection.threatName,
                            engine: detection.engine || (String(detection.threatName || "").startsWith("YARA:") ? "YARA" : "ClamAV"),
                            yaraRuleset: detection.engine === "YARA" ? normalizeYaraRuleset(context.settings.yaraRuleset) : undefined
                        });
                    }
                }
                context.pendingThreatStore.resolve(threatId);
                context.sendApiEvent("threat-resolved", { id: threatId });
            })();
            context.pendingThreatActions.set(threatId, task);
            try {
                await task;
            }
            finally {
                context.pendingThreatActions.delete(threatId);
            }
            res.json({ success: true });
        }
        catch (e: any) {
            console.error(englishText("backend.results.failed_to_apply_pending_threat_action"), e?.message || e);
            res.status(400).json({
                success: false,
                code: e?.code === "ENOENT" ? "FILE_UNAVAILABLE" : "ACTION_FAILED",
                error: e?.code === "ENOENT"
                    ? englishText("backend.results.the_file_is_no_longer_at_this_location_it_may_have_been_moved_del") : e?.message || englishText("backend.results.threat_action_failed")
            });
        }
    });
}
