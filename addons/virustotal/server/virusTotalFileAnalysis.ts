import { englishText } from "../../../shared/localization/runtime";
import { openAsBlob } from "node:fs";
import { stat } from "node:fs/promises";
import path from "node:path";
const apiBase = "https://www.virustotal.com/api/v3";
type Dependencies = {
    reserveSlot: (wait: boolean) => Promise<void>;
    checkQuota: () => Promise<void>;
    recordRequest: (apiKey: string, exempt: boolean) => Promise<void>;
    fetch?: typeof fetch;
    openFile?: (filePath: string) => Promise<Blob>;
};
// Upload only after a missing-hash response; analysis polling uses the contributing key.
export class VirusTotalFileAnalysis {
    constructor(private deps: Dependencies) { }
    private async request(apiKey: string, url: string, options: {
        method?: string;
        body?: FormData;
        exempt: boolean;
        wait?: boolean;
        canContinue?: () => Promise<boolean>;
    }) {
        if (!options.exempt)
            await this.deps.checkQuota();
        await this.deps.reserveSlot(options.wait === true);
        if (options.canContinue && !await options.canContinue()) {
            throw new Error(englishText("backend.virusTotalFileAnalysis.ts.virustotal_upload_stopped_before_submission"));
        }
        const response = await (this.deps.fetch || fetch)(url, {
            method: options.method || "GET", body: options.body,
            headers: { "x-apikey": apiKey }, signal: AbortSignal.timeout(options.body ? 10 * 60000 : 30000),
            redirect: "error"
        });
        const missingAnalysis = !options.body && response.status === 404 && url.includes("/analyses/");
        await this.deps.recordRequest(apiKey, options.exempt && (response.ok || missingAnalysis));
        if (!response.ok) {
            const message = response.status === 401 || response.status === 403
                ? englishText("backend.virustotal.virustotal_rejected_the_api_key_check_the_key_in_settings") : response.status === 429 ? englishText("backend.virusTotalFileAnalysis.ts.virustotal_rate_limit_reached_cloud_checks_will_retry_later") : englishText("backend.virusTotalFileAnalysis.ts.virustotal_failed_http", {
                value1: String(options.body ? englishText("backend.virusTotalFileAnalysis.ts.upload") : englishText("backend.virusTotalFileAnalysis.ts.request")),
                status: String(response.status)
            });
            const retryAfter = response.headers.get("retry-after");
            const retryAt = retryAfter && (/^\d+$/.test(retryAfter) ? Date.now() + Number(retryAfter) * 1000 : Date.parse(retryAfter));
            throw Object.assign(new Error(message), {
                status: response.status, analysisMissing: missingAnalysis,
                fileError: Boolean(options.body && [400, 413, 415, 422].includes(response.status)),
                nextAllowedAt: retryAt && Number.isFinite(retryAt) ? Math.max(Date.now() + 1000, retryAt) : undefined
            });
        }
        return response.json();
    }
    async upload(apiKey: string, filePath: string, canContinue: () => Promise<boolean>) {
        const size = (await stat(filePath)).size;
        if (size > 650 * 1024 * 1024) {
            throw Object.assign(new Error(englishText("backend.virusTotalFileAnalysis.ts.upload_skipped_file_exceeds_virustotal_s_650_mb_upload_limit")), { fileError: true });
        }
        const file = await (this.deps.openFile || openAsBlob)(filePath);
        let url = `${apiBase}/files`;
        if (size > 32 * 1024 * 1024) {
            const payload = await this.request(apiKey, `${apiBase}/files/upload_url`, { exempt: false, canContinue });
            const target = new URL(payload?.data);
            if (target.protocol !== "https:" || !["www.virustotal.com", "virustotal.com"].includes(target.hostname) || target.username || target.password || (target.port && target.port !== "443")) {
                throw new Error(englishText("backend.virusTotalFileAnalysis.ts.virustotal_returned_an_invalid_upload_url"));
            }
            url = target.href;
        }
        const body = new FormData();
        body.append("file", file, path.basename(filePath));
        const payload = await this.request(apiKey, url, {
            method: "POST", body, exempt: true, wait: size > 32 * 1024 * 1024, canContinue
        });
        const id = payload?.data?.id;
        if (typeof id !== "string" || !id.trim())
            throw new Error(englishText("backend.virusTotalFileAnalysis.ts.virustotal_did_not_return_an_analysis_id"));
        return id;
    }
    async analysis(apiKey: string, analysisId: string, hash: string) {
        const payload = await this.request(apiKey, `${apiBase}/analyses/${encodeURIComponent(analysisId)}`, { exempt: true });
        const attributes = payload?.data?.attributes;
        if (["queued", "in-progress"].includes(attributes?.status))
            return null;
        if (attributes?.status !== "completed" || !attributes?.stats || !attributes?.results) {
            throw new Error(englishText("backend.virusTotalFileAnalysis.ts.virustotal_returned_an_incomplete_analysis_response_waiting_to_re"));
        }
        if (payload?.meta?.file_info?.sha256 && payload.meta.file_info.sha256 !== hash) {
            throw Object.assign(new Error(englishText("backend.virusTotalFileAnalysis.ts.file_changed_during_upload_the_virustotal_analysis_belongs_to_dif")), { fileError: true, fileChanged: true });
        }
        return { data: { attributes: {
                    last_analysis_stats: attributes.stats, last_analysis_results: attributes.results,
                    last_analysis_date: attributes.date
                } } };
    }
}
