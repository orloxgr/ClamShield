import { englishText } from "../../../shared/localization/runtime";
import { normalizePositiveNumber } from "../../../modules/settings/server/validation";
import { titleCase } from "../../../server/core/utils";
import { handleYaraDetection, parseYaraMatchLine } from "./detections";
import { ensureYaraEngine } from "./install";
import { getYaraRulesFile, normalizeYaraRuleset } from "./rules";
import { createYaraTargetList } from "./targets";
import { spawn } from "child_process";
import { existsSync } from "fs";
import fs from "fs/promises";
import path from "path";
export async function runYaraScanForTargets(settings: any, targets: string[], options: any) {
    if (settings.yaraEnabled === false)
        return { matches: 0, ignoredMatches: 0, actionTaken: englishText("backend.yara.none") };
    const job = options.activeJobs[options.jobId];
    if (!job)
        return { matches: 0, ignoredMatches: 0, actionTaken: englishText("backend.yara.none") };
    const rulesFile = getYaraRulesFile(settings);
    if (!existsSync(rulesFile)) {
        options.appendJobLogs(options.jobId, [
            `YARA skipped: ${path.basename(rulesFile)} is missing. Use Updates -> Update YARA Rules.`
        ]);
        return { matches: 0, ignoredMatches: 0, actionTaken: englishText("backend.yara.none") };
    }
    let yaraPath: string;
    try {
        yaraPath = await ensureYaraEngine(settings, message => console.debug(englishText("backend.yara.yara", {
            message: String(message)
        })));
    }
    catch (e: any) {
        options.appendJobLogs(options.jobId, [`YARA skipped: ${e.message}`]);
        return { matches: 0, ignoredMatches: 0, actionTaken: englishText("backend.yara.none") };
    }
    const { listPath, count, unreadablePathCount } = await createYaraTargetList(settings, targets, (indexed) => {
        console.debug(englishText("backend.yara.yara_target_list_indexed_files", {
            indexed: String(indexed)
        }));
    });
    if (unreadablePathCount > 0) {
        options.appendJobLogs(options.jobId, [
            `YARA skipped ${unreadablePathCount} unreadable target path${unreadablePathCount === 1 ? "" : "s"}.`
        ]);
    }
    if (count === 0) {
        await fs.unlink(listPath).catch(() => { });
        options.appendJobLogs(options.jobId, ["YARA skipped: no eligible files after exclusions and size limits."]);
        return { matches: 0, ignoredMatches: 0, actionTaken: englishText("backend.yara.none") };
    }
    const maxBytes = normalizePositiveNumber(settings.yaraMaxFileSize, 50, 1, 4096) * 1024 * 1024;
    const timeoutSeconds = normalizePositiveNumber(settings.yaraTimeoutSeconds, 15, 1, 3600);
    const args = [
        "--no-warnings",
        "--fast-scan",
        `--timeout=${timeoutSeconds}`,
        `--skip-larger=${maxBytes}`,
        "--scan-list",
        rulesFile,
        listPath
    ];
    options.appendJobLogs(options.jobId, [
        "YARA scan started",
        `YARA ruleset: ${titleCase(normalizeYaraRuleset(settings.yaraRuleset))}`,
        `YARA scanned files: ${count}`
    ]);
    const stdoutLines: string[] = [];
    const child = spawn(yaraPath, args, { windowsHide: true });
    job.process = child;
    let openErrorCount = 0;
    const exitCode = await new Promise<number>((resolve) => {
        let settled = false;
        let timedOut = false;
        const finish = (code: number) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timeout);
            resolve(code);
        };
        const timeout = setTimeout(() => {
            timedOut = true;
            options.appendJobLogs(options.jobId, [
                `YARA timed out after ${timeoutSeconds + 30}s. ClamAV scan results are still valid.`
            ]);
            try {
                child.kill();
            }
            catch { }
            setTimeout(() => finish(-2), 5000).unref?.();
        }, (timeoutSeconds + 30) * 1000);
        timeout.unref?.();
        child.stdout.on("data", data => {
            const lines = data.toString().split("\n").map((line: string) => line.trim()).filter(Boolean);
            stdoutLines.push(...lines);
            if (lines.length)
                console.debug(englishText("backend.yara.yara_output"), lines);
        });
        child.stderr.on("data", data => {
            const lines = data.toString().split("\n").map((line: string) => line.trim()).filter(Boolean);
            const visibleLines: string[] = [];
            for (const line of lines) {
                if (/error scanning .*could not open file/i.test(line)) {
                    openErrorCount++;
                }
                else {
                    visibleLines.push(line);
                }
            }
            if (visibleLines.length)
                console.debug(englishText("backend.yara.yara_stderr"), visibleLines);
        });
        child.on("error", error => {
            options.appendJobLogs(options.jobId, [`YARA process error: ${error.message}`]);
            finish(-1);
        });
        child.on("close", code => finish(timedOut ? -2 : (code ?? 0)));
    });
    await fs.unlink(listPath).catch(() => { });
    if (job.process === child)
        job.process = null;
    // yara exits 0 or 1 on its own. Anything else (for example 0xC0000135 when a DLL is missing) means
    // it never scanned, and reporting "YARA matches: 0" would read as a clean result.
    if (exitCode !== 0 && exitCode !== 1 && exitCode !== -1 && exitCode !== -2) {
        const hex = `0x${(exitCode >>> 0).toString(16).toUpperCase()}`;
        const reason = (exitCode >>> 0) === 0xC0000135 ? " A required DLL is missing (usually the Microsoft Visual C++ runtime)." : "";
        options.appendJobLogs(options.jobId, [`YARA did not run (exit code ${hex}).${reason} ClamAV scan results are still valid.`]);
        console.warn(englishText("backend.yara.yara_exited_with_without_scanning", {
            hex: String(hex)
        }));
        return { matches: 0, ignoredMatches: 0, actionTaken: englishText("backend.yara.none") };
    }
    if (openErrorCount > 0) {
        options.appendJobLogs(options.jobId, [
            `YARA skipped ${openErrorCount} file${openErrorCount === 1 ? "" : "s"} it could not open. ClamAV scan results are still valid.`
        ]);
    }
    const detectionsByPath = new Map<string, {
        originalPath: string;
        ruleNames: Set<string>;
    }>();
    for (const line of stdoutLines) {
        const match = parseYaraMatchLine(line);
        if (!match)
            continue;
        const normalizedPath = path.resolve(match.originalPath).toLowerCase();
        if (!detectionsByPath.has(normalizedPath)) {
            detectionsByPath.set(normalizedPath, { originalPath: match.originalPath, ruleNames: new Set() });
        }
        detectionsByPath.get(normalizedPath)!.ruleNames.add(match.ruleName);
    }
    let actionTaken = "None";
    let activeMatches = 0;
    let ignoredMatches = 0;
    for (const detection of detectionsByPath.values()) {
        const result = await handleYaraDetection(settings, {
            originalPath: detection.originalPath,
            ruleNames: Array.from(detection.ruleNames).slice(0, 8)
        }, options);
        if (result === "Ignored") {
            ignoredMatches++;
        }
        else {
            activeMatches++;
            actionTaken = result;
        }
    }
    options.appendJobLogs(options.jobId, [
        ignoredMatches > 0
            ? `YARA matches: ${activeMatches} active, ${ignoredMatches} ignored by exclusions`
            : `YARA matches: ${activeMatches}`
    ]);
    return { matches: activeMatches, ignoredMatches, actionTaken };
}
