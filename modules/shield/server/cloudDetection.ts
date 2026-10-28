import { englishText } from "../../../shared/localization/runtime";
import { buildVirusTotalRefinement, buildVirusTotalThreatName } from "../../../addons/virustotal/server/refinement";
import { flushPendingClamdDatabaseReload } from "../../../engines/clamav/server/daemon";
import { getExceptions, isExcluded } from "../../exceptions/server/service";
import { getQuarantineMap } from "../../quarantine/server/storage";
import { quarantineFile } from "../../quarantine/server/files";
import { saveQuarantineMap } from "../../quarantine/server/storage";
import { addScanResult } from "../../results/server/storage";
import { normalizeShieldDetectionAction, shieldActionKind, shieldActionNotifies } from "./actions";
import { shouldSkipBuiltInScanPath } from "../../../server/scanning/targets";
import { ScanProgress } from "../../../server/scanning/types";
import { ApplicationContext } from "../../../server/core/applicationContext";
import { sleep } from "../../../server/core/utils";
import express from "express";
export function createHandleVirusTotalShieldDetection(context: Pick<ApplicationContext, "settings" | "sendApiEvent" | "queuePendingThreat">) {
    return async (filePath: string, report: any) => {
        const exceptions = await getExceptions();
        if (shouldSkipBuiltInScanPath(context.settings, filePath) || isExcluded(filePath, exceptions))
            return "Ignored";
        const threatName = buildVirusTotalThreatName(report);
        const refinement = buildVirusTotalRefinement(report);
        const action = normalizeShieldDetectionAction(context.settings.actionOnDetection || (context.settings.autoQuarantine ? "quarantine_silent" : "ask"));
        const actionKind = shieldActionKind(action);
        if (actionKind === "quarantine") {
            try {
                const quarantined = await quarantineFile(filePath, threatName, context.settings.quarantineDir);
                const qMap = await getQuarantineMap();
                qMap[quarantined.fileName] = quarantined.metadata;
                await saveQuarantineMap(qMap);
                if (shieldActionNotifies(action)) {
                    context.sendApiEvent("threat", {
                        id: Date.now().toString() + Math.random().toString(36).substring(7),
                        originalPath: filePath,
                        threatName,
                        engine: "VirusTotal",
                        mode: "notice",
                        title: englishText("backend.core.threat_quarantined"),
                        subtitle: englishText("backend.core.clamshield_shield_quarantined_this_file"),
                        timestamp: Date.now()
                    });
                }
                return "Quarantined";
            }
            catch (e: any) {
                console.warn(englishText("backend.core.virustotal_shield_quarantine_failed"), e?.message || e);
                return "Quarantine Failed";
            }
        }
        if (actionKind === "ask") {
            const pendingThreat = {
                id: Date.now().toString() + Math.random().toString(36).substring(7),
                originalPath: filePath,
                threatName,
                engine: "VirusTotal",
                timestamp: Date.now()
            };
            await context.queuePendingThreat(pendingThreat);
            return "Pending";
        }
        await addScanResult({
            source: "shield",
            scanType: "shield",
            target: filePath,
            originalPath: filePath,
            threatName,
            engine: "VirusTotal",
            sha256: report?.hash || "",
            virusTotalRefinement: refinement
        });
        if (shieldActionNotifies(action)) {
            context.sendApiEvent("threat", {
                id: Date.now().toString() + Math.random().toString(36).substring(7),
                originalPath: filePath,
                threatName,
                engine: "VirusTotal",
                mode: "notice",
                title: englishText("backend.core.threat_sent_to_results"),
                subtitle: englishText("backend.core.clamshield_shield_saved_this_detection_for_review"),
                timestamp: Date.now()
            });
        }
        return "Sent to Results";
    };
}
