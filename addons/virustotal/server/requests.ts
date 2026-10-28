import { englishText } from "../../../shared/localization/runtime";
import { normalizeNumberSetting } from "../../../modules/settings/server/validation";
import { assertVirusTotalQuotaAvailable, recordVirusTotalLookupSafely, reserveVirusTotalLookupSlot, waitForVirusTotalLookupSlot } from "./account";
import axios from "axios";
import fs from "fs/promises";
import path from "path";
export function createVirusTotalNoReport(hash: string) {
    return {
        found: false,
        hash,
        url: `https://www.virustotal.com/gui/file/${hash}/detection`,
        message: englishText("backend.virustotal.hash_lookup_completed_virustotal_returned_no_report_for_this_hash")
    };
}
export function summarizeVirusTotalFileReport(hash: string, payload: any) {
    const attributes = payload?.data?.attributes || {};
    const stats = attributes.last_analysis_stats || {};
    const detections = Object.values(attributes.last_analysis_results || {})
        .filter((item: any) => ["malicious", "suspicious"].includes(String(item?.category || "").toLowerCase()))
        .map((item: any) => ({
        engine: String(item?.engine_name || ""),
        category: String(item?.category || ""),
        result: String(item?.result || "")
    }))
        .filter((item: any) => item.engine || item.result)
        .slice(0, 8);
    return {
        found: true,
        hash,
        url: `https://www.virustotal.com/gui/file/${hash}/detection`,
        stats: {
            malicious: Number(stats.malicious || 0),
            suspicious: Number(stats.suspicious || 0),
            harmless: Number(stats.harmless || 0),
            undetected: Number(stats.undetected || 0),
            timeout: Number(stats.timeout || 0),
            failure: Number(stats.failure || 0)
        },
        reputation: Number(attributes.reputation || 0),
        typeDescription: String(attributes.type_description || attributes.type_tag || ""),
        meaningfulName: String(attributes.meaningful_name || ""),
        firstSubmissionDate: attributes.first_submission_date || null,
        lastAnalysisDate: attributes.last_analysis_date || null,
        threatVerdict: String(attributes.threat_verdict || ""),
        threatSeverity: attributes.threat_severity || null,
        tags: Array.isArray(attributes.tags) ? attributes.tags.slice(0, 8) : [],
        detections
    };
}
export async function fetchVirusTotalFileReport(apiKey: string, sha256: string) {
    try {
        await assertVirusTotalQuotaAvailable();
        reserveVirusTotalLookupSlot();
        const vtRes = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`, {
            headers: { "x-apikey": apiKey },
            timeout: 30000
        });
        await recordVirusTotalLookupSafely(apiKey);
        return summarizeVirusTotalFileReport(sha256, vtRes.data);
    }
    catch (e: any) {
        if (e?.response) {
            await recordVirusTotalLookupSafely(apiKey);
        }
        const status = e?.response?.status;
        if (status === 404)
            return createVirusTotalNoReport(sha256);
        if (status === 401 || status === 403) {
            const error: any = new Error(englishText("backend.virustotal.virustotal_rejected_the_api_key_check_the_key_in_settings"));
            error.status = status;
            throw error;
        }
        if (status === 429) {
            const error: any = new Error(englishText("backend.virustotal.virustotal_rate_limit_reached_automatic_refinement_will_pause_and"));
            error.status = status;
            throw error;
        }
        if (e?.localRateLimit || e?.localQuotaLimit)
            throw e;
        throw new Error(e?.message || englishText("backend.virustotal.virustotal_cloud_check_failed"));
    }
}
export function getVirusTotalShieldUploadMaxBytes(settings: any) {
    const maxMb = normalizeNumberSetting("virusTotalShieldUploadMaxSizeMb", settings?.virusTotalShieldUploadMaxSizeMb);
    return Math.max(1, Math.min(32, Math.round(Number(maxMb || 20)))) * 1024 * 1024;
}
export function getVirusTotalResultsUploadMaxBytes(settings: any) {
    const maxMb = normalizeNumberSetting("virusTotalResultsUploadMaxSizeMb", settings?.virusTotalResultsUploadMaxSizeMb);
    return Math.max(1, Math.min(32, Math.round(Number(maxMb || 20)))) * 1024 * 1024;
}
export function formatVirusTotalUploadSize(bytes: number) {
    return `${(Math.max(0, bytes) / (1024 * 1024)).toFixed(1).replace(/\.0$/, "")} MB`;
}
export async function uploadVirusTotalFile(apiKey: string, filePath: string, options: {
    waitForSlot?: boolean;
} = {}) {
    await assertVirusTotalQuotaAvailable();
    if (options.waitForSlot)
        await waitForVirusTotalLookupSlot();
    else
        reserveVirusTotalLookupSlot();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120000);
    try {
        const data = await fs.readFile(filePath);
        const form = new FormData();
        form.append("file", new Blob([data as any]), path.basename(filePath) || "file");
        const response = await fetch("https://www.virustotal.com/api/v3/files", {
            method: "POST",
            headers: { "x-apikey": apiKey },
            body: form as any,
            signal: controller.signal
        });
        await recordVirusTotalLookupSafely(apiKey);
        if (response.status === 401 || response.status === 403) {
            const error: any = new Error(englishText("backend.virustotal.virustotal_rejected_the_api_key_check_the_key_in_settings"));
            error.status = response.status;
            throw error;
        }
        if (response.status === 429) {
            const error: any = new Error(englishText("backend.virustotal.virustotal_rate_limit_reached_automatic_checks_will_pause_and_try"));
            error.status = response.status;
            throw error;
        }
        if (!response.ok) {
            const errorText = await response.text().catch(() => "");
            throw new Error(errorText || englishText("backend.virustotal.virustotal_upload_failed_with_status", {
                status: String(response.status)
            }));
        }
        const payload = await response.json();
        return {
            analysisId: String((payload as any)?.data?.id || ""),
            payload
        };
    }
    catch (e: any) {
        if (e?.localRateLimit || e?.localQuotaLimit)
            throw e;
        if (e?.name === "AbortError")
            throw new Error(englishText("backend.virustotal.virustotal_upload_timed_out"));
        throw e;
    }
    finally {
        clearTimeout(timeout);
    }
}
