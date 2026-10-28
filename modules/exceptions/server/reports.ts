import { englishText } from "../../../shared/localization/runtime";
import path from "path";
export function getFalsePositiveProvider(report: any) {
    const threatName = String(report?.threatName || "");
    const engine = String(report?.engine || "");
    if (/^yara:/i.test(threatName) || engine.toLowerCase() === "yara") {
        return {
            id: "yara-forge",
            name: "YARA Forge",
            method: "github",
            url: "https://github.com/YARAHQ/yara-forge/issues/new"
        };
    }
    if (/securiteinfo\.com(?:[._-]|$)|^securiteinfo[._-]/i.test(threatName)) {
        return {
            id: "securiteinfo",
            name: "SecuriteInfo",
            method: "email",
            email: "webmaster@securiteinfo.com",
            url: "https://www.securiteinfo.com/services-cybersecurite/contacter-securiteinfo.shtml"
        };
    }
    if (/^sanesecurity[._-]/i.test(threatName)) {
        return {
            id: "sanesecurity",
            name: "SaneSecurity",
            method: "email",
            email: "false_positive@sanesecurity.org.uk",
            url: "https://sanesecurity.com/support/false-positives/"
        };
    }
    return {
        id: "clamav",
        name: englishText("backend.exceptions.clamav_cisco_talos"),
        method: "form",
        url: "https://www.clamav.net/reports/fp"
    };
}
export function falsePositiveProviderFolderName(provider: any) {
    const id = String(provider?.id || "unknown");
    if (id === "clamav")
        return "ClamAV";
    if (id === "securiteinfo")
        return "SecuriteInfo";
    if (id === "sanesecurity")
        return "SaneSecurity";
    if (id === "yara-forge")
        return "YARA";
    return id.replace(/[^a-z0-9._-]+/gi, "-") || "Unknown";
}
export function csvCell(value: any) {
    const text = String(value ?? "");
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}
export function safeExportFileName(value: string) {
    return String(value || "file")
        .replace(/[<>:"/\\|?*\x00-\x1F]+/g, "_")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 120) || "file";
}
export function detectionSignatureName(threatName: any) {
    return String(threatName || "Unknown Threat").replace(/\.UNOFFICIAL$/i, "");
}
export function buildFalsePositiveManifestRows(items: any[]) {
    const headers = [
        "provider",
        "signature",
        "detection",
        "original_path",
        "file_name",
        "available",
        "size_bytes",
        "md5",
        "sha1",
        "sha256",
        "scan_origin",
        "scan_type",
        "target",
        "detected_at",
        "engine",
        "yara_ruleset",
        "sample_file"
    ];
    const lines = [headers.map(csvCell).join(",")];
    for (const item of items) {
        const provider = getFalsePositiveProvider(item);
        lines.push([
            provider.name,
            detectionSignatureName(item.threatName),
            item.threatName || "",
            item.originalPath || "",
            path.basename(String(item.originalPath || "")),
            item.available === false ? "no" : "yes",
            item.sizeBytes || "",
            item.md5 || "",
            item.sha1 || "",
            item.sha256 || "",
            item.source || "",
            item.scanType || "",
            item.target || "",
            item.timestamp ? new Date(Number(item.timestamp)).toISOString() : "",
            item.engine || "",
            item.yaraRuleset || "",
            item.sampleFile || ""
        ].map(csvCell).join(","));
    }
    return `${lines.join("\n")}\n`;
}
export function buildFalsePositiveProviderReport(provider: any, items: any[], options: any) {
    const lines = [
        `# ClamShield False Positive Export - ${provider.name}`,
        "",
        `Generated: ${new Date().toISOString()}`,
        `ClamShield version: ${process.env.npm_package_version || "unknown"}`,
        `Items: ${items.length}`,
        `Samples included: ${options.includeSamples ? "yes" : "no"}`,
        ""
    ];
    if (options.userNote) {
        lines.push("## User note", "", String(options.userNote), "");
    }
    lines.push("## Submission guidance");
    if (provider.id === "clamav") {
        lines.push("Submit false positives through the ClamAV/Cisco Talos false-positive flow. Include the exact detection name, hashes, and sample only if you are comfortable sharing it.", "ClamAV states submitted files are retained, so review samples before sending.");
    }
    else if (provider.id === "securiteinfo") {
        lines.push("Use SecuriteInfo's contact channel for false positives. Include the SecuriteInfo signature name, hashes, and a sample or SHA-256 when appropriate.");
    }
    else if (provider.id === "sanesecurity") {
        lines.push("SaneSecurity asks for the signature name and, for email detections, the raw message including headers where possible.");
    }
    else if (provider.id === "yara-forge") {
        lines.push("Open a YARA Forge GitHub issue with the matching rule name, ruleset, file hash, file type/path context, and a minimal reproducer or sample if shareable.");
    }
    lines.push("", "## Items");
    for (const item of items) {
        lines.push("", `### ${item.threatName || "Unknown Threat"}`, "", `- Signature: ${detectionSignatureName(item.threatName)}`, `- File: ${item.originalPath || "Unavailable"}`, `- SHA-256: ${item.sha256 || "Unavailable"}`, `- MD5: ${item.md5 || "Unavailable"}`, `- Scan origin: ${item.source || "scan"}`, `- Detected at: ${item.timestamp ? new Date(Number(item.timestamp)).toISOString() : "Unknown"}`, item.sampleFile ? `- Included sample: ${item.sampleFile}` : "- Included sample: no");
        if (item.yaraRuleset)
            lines.push(`- YARA ruleset: ${item.yaraRuleset}`);
    }
    lines.push("");
    return `${lines.join("\n")}\n`;
}
export function buildYaraGithubIssue(items: any[], options: any) {
    const lines = [
        "## False positive report from ClamShield",
        "",
        `Generated: ${new Date().toISOString()}`,
        `ClamShield version: ${process.env.npm_package_version || "unknown"}`,
        ""
    ];
    if (options.userNote)
        lines.push("### User note", "", String(options.userNote), "");
    lines.push("### Matches");
    for (const item of items) {
        lines.push("", `- Rule/signature: \`${detectionSignatureName(item.threatName).replace(/^YARA:\s*/i, "")}\``, `  - File path: \`${item.originalPath || "Unavailable"}\``, `  - SHA-256: \`${item.sha256 || "Unavailable"}\``, `  - Ruleset: \`${item.yaraRuleset || "unknown"}\``, `  - Sample included in local export: ${item.sampleFile ? "yes" : "no"}`);
    }
    lines.push("", "### Expected result", "", "These file(s) should not match the listed YARA rule(s).", "");
    return `${lines.join("\n")}\n`;
}
