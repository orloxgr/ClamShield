import { englishText } from "../../../shared/localization/runtime";
import { getExceptions, isExcluded } from "../../../modules/exceptions/server/service";
import { getQuarantineMap } from "../../../modules/quarantine/server/storage";
import { quarantineFile } from "../../../modules/quarantine/server/files";
import { saveQuarantineMap } from "../../../modules/quarantine/server/storage";
import { addScanResult } from "../../../modules/results/server/storage";
import { normalizeShieldDetectionAction, shieldActionKind, shieldActionNotifies } from "../../../modules/shield/server/actions";
import { displayFileName } from "../../../server/core/utils";
import { shouldSkipBuiltInScanPath } from "../../../server/scanning/targets";
import { normalizeYaraRuleset } from "./rules";
export function parseYaraMatchLine(line: string) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.toLowerCase().startsWith("error:") || trimmed.includes(": error:"))
        return null;
    const match = trimmed.match(/^([A-Za-z0-9_.@$-]+)(?:\s+\[[^\]]+\])?\s+(.+)$/);
    if (!match)
        return null;
    const originalPath = match[2].trim();
    if (!originalPath || originalPath.startsWith("["))
        return null;
    return {
        ruleName: match[1],
        originalPath
    };
}
export async function handleYaraDetection(settings: any, detection: any, options: any) {
    const exceptions = await getExceptions();
    if (shouldSkipBuiltInScanPath(settings, detection.originalPath)) {
        options.appendJobLogs(options.jobId, [
            `YARA threat found: ${displayFileName(detection.originalPath)}`,
            "Action: Ignored because this path is excluded from provider-safety scans"
        ]);
        return "Ignored";
    }
    if (isExcluded(detection.originalPath, exceptions)) {
        options.appendJobLogs(options.jobId, [
            `YARA threat found: ${displayFileName(detection.originalPath)}`,
            "Action: Ignored because it is in Exceptions"
        ]);
        return "Ignored";
    }
    const threatName = `YARA: ${detection.ruleNames.join(", ")}`;
    if (options.action === "quarantine") {
        try {
            const quarantined = await quarantineFile(detection.originalPath, threatName, settings.quarantineDir);
            const qMap = await getQuarantineMap();
            qMap[quarantined.fileName] = quarantined.metadata;
            await saveQuarantineMap(qMap);
            options.appendJobLogs(options.jobId, [
                `YARA threat found: ${displayFileName(detection.originalPath)}`,
                "Action: Quarantined"
            ]);
            return "Quarantined";
        }
        catch (e: any) {
            options.appendJobLogs(options.jobId, [`YARA quarantine failed for ${displayFileName(detection.originalPath)}: ${e.message}`]);
            return "Quarantine Failed";
        }
    }
    const shieldAction = normalizeShieldDetectionAction(options.action);
    const shieldKind = shieldActionKind(shieldAction);
    if (shieldKind === "quarantine") {
        try {
            const quarantined = await quarantineFile(detection.originalPath, threatName, settings.quarantineDir);
            const qMap = await getQuarantineMap();
            qMap[quarantined.fileName] = quarantined.metadata;
            await saveQuarantineMap(qMap);
            options.appendJobLogs(options.jobId, [
                `YARA threat found: ${displayFileName(detection.originalPath)}`,
                "Action: Quarantined"
            ]);
            if (shieldActionNotifies(shieldAction) && typeof options.notifyThreat === "function") {
                options.notifyThreat({
                    id: Date.now().toString() + Math.random().toString(36).substring(7),
                    originalPath: detection.originalPath,
                    threatName,
                    engine: "YARA",
                    mode: "notice",
                    title: englishText("backend.core.threat_quarantined"),
                    subtitle: englishText("backend.core.clamshield_shield_quarantined_this_file"),
                    timestamp: Date.now()
                });
            }
            return "Quarantined";
        }
        catch (e: any) {
            options.appendJobLogs(options.jobId, [`YARA quarantine failed for ${displayFileName(detection.originalPath)}: ${e.message}`]);
            return "Quarantine Failed";
        }
    }
    if (shieldKind === "ask" && Array.isArray(options.pendingThreats)) {
        const pendingThreat = {
            id: Date.now().toString() + Math.random().toString(36).substring(7),
            originalPath: detection.originalPath,
            threatName,
            engine: "YARA",
            timestamp: Date.now()
        };
        await options.queuePendingThreat(pendingThreat);
        options.appendJobLogs(options.jobId, [
            `YARA threat found: ${displayFileName(detection.originalPath)}`,
            "Action: Waiting for your decision"
        ]);
        return "Pending";
    }
    await addScanResult({
        source: options.source,
        scanType: options.scanType,
        target: options.target,
        originalPath: detection.originalPath,
        threatName,
        engine: "YARA",
        yaraRuleset: normalizeYaraRuleset(settings.yaraRuleset)
    });
    options.appendJobLogs(options.jobId, [
        `YARA threat found: ${displayFileName(detection.originalPath)}`,
        "Action: Sent to Results"
    ]);
    if (shieldKind === "results" && shieldActionNotifies(shieldAction) && typeof options.notifyThreat === "function") {
        options.notifyThreat({
            id: Date.now().toString() + Math.random().toString(36).substring(7),
            originalPath: detection.originalPath,
            threatName,
            engine: "YARA",
            mode: "notice",
            title: englishText("backend.core.threat_sent_to_results"),
            subtitle: englishText("backend.core.clamshield_shield_saved_this_detection_for_review"),
            timestamp: Date.now()
        });
    }
    return "Sent to Results";
}
