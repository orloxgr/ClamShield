import { normalizeCachePath } from "../../../modules/shield/server/cache";
import { isNoisyClamFileLine, parseClamOutputPath } from "./arguments";

export function isLockedOrUnstableClamLine(line: string) {
    return /File path check failure|Can't get file status|Can't open file(?: or directory)?|Can't access file|Can't fstat descriptor|Access denied|Permission denied/i.test(line);
}

export function isImportantClamOutputLine(line: string) {
    if (!line)
        return false;
    if (/^-{3,}\s*SCAN SUMMARY\s*-{3,}$/i.test(line))
        return true;
    if (/^(Scanned files|Infected files|Total errors|Time):/i.test(line))
        return true;
    if (/^(ERROR|LibClamAV Error|Process error):/i.test(line))
        return true;
    if (isLockedOrUnstableClamLine(line))
        return true;
    if (line.includes(" ERROR") && !isNoisyClamFileLine(line))
        return true;
    return false;
}

export function extractClamFailedFilePath(line: string) {
    const trimmed = String(line || "").trim();
    const directAccessMatch = trimmed.match(/^ERROR:\s+Can't access file\s+(.+)$/i);
    if (directAccessMatch)
        return directAccessMatch[1].trim();
    const openFileMatch = trimmed.match(/^(?:LibClamAV\s+)?(?:Warning|Error):\s+Can't open file\s+(.+?)(?::\s*\d+)?$/i);
    if (openFileMatch)
        return openFileMatch[1].trim();
    const pathCheckMatch = trimmed.match(/File path check failure for:\s+(.+)$/i);
    if (pathCheckMatch)
        return pathCheckMatch[1].trim();
    const statusMatch = trimmed.match(/^(.+?):\s+Can't get file status(?:\s+ERROR)?$/i);
    if (statusMatch)
        return statusMatch[1].trim();
    if (isLockedOrUnstableClamLine(trimmed)) {
        const outputPath = parseClamOutputPath(trimmed);
        if (outputPath && !/^ERROR$/i.test(outputPath))
            return outputPath.trim();
    }
    return "";
}

export function uniqueFailedFilePathsFromClamLines(lines: string[]) {
    const seen = new Set<string>();
    const paths: string[] = [];
    for (const line of lines) {
        const failedPath = extractClamFailedFilePath(line);
        const key = normalizeCachePath(failedPath);
        if (!failedPath || !key || seen.has(key))
            continue;
        seen.add(key);
        paths.push(failedPath);
    }
    return paths;
}
