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
    constructor(private deps: Dependencies) {}

    private async request(apiKey: string, url: string, options: {
        method?: string; body?: FormData; exempt: boolean; wait?: boolean; canContinue?: () => Promise<boolean>;
    }) {
        if (!options.exempt) await this.deps.checkQuota();
        await this.deps.reserveSlot(options.wait === true);
        if (options.canContinue && !await options.canContinue()) {
            throw new Error("VirusTotal upload stopped before submission.");
        }
        const response = await (this.deps.fetch || fetch)(url, {
            method: options.method || "GET", body: options.body,
            headers: { "x-apikey": apiKey }, signal: AbortSignal.timeout(options.body ? 10 * 60_000 : 30_000),
            redirect: "error"
        });
        const missingAnalysis = !options.body && response.status === 404 && url.includes("/analyses/");
        await this.deps.recordRequest(apiKey, options.exempt && (response.ok || missingAnalysis));
        if (!response.ok) {
            const message = response.status === 401 || response.status === 403
                ? "VirusTotal rejected the API key. Check the key in Settings."
                : response.status === 429 ? "VirusTotal rate limit reached. Cloud checks will retry later."
                : `VirusTotal ${options.body ? "upload" : "request"} failed (HTTP ${response.status}).`;
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
            throw Object.assign(new Error("Upload skipped: file exceeds VirusTotal's 650 MB upload limit."), { fileError: true });
        }
        const file = await (this.deps.openFile || openAsBlob)(filePath);
        let url = `${apiBase}/files`;
        if (size > 32 * 1024 * 1024) {
            const payload = await this.request(apiKey, `${apiBase}/files/upload_url`, { exempt: false, canContinue });
            const target = new URL(payload?.data);
            if (target.protocol !== "https:" || !["www.virustotal.com", "virustotal.com"].includes(target.hostname) || target.username || target.password || (target.port && target.port !== "443")) {
                throw new Error("VirusTotal returned an invalid upload URL.");
            }
            url = target.href;
        }
        const body = new FormData();
        body.append("file", file, path.basename(filePath));
        const payload = await this.request(apiKey, url, {
            method: "POST", body, exempt: true, wait: size > 32 * 1024 * 1024, canContinue
        });
        const id = payload?.data?.id;
        if (typeof id !== "string" || !id.trim()) throw new Error("VirusTotal did not return an analysis ID.");
        return id;
    }

    async analysis(apiKey: string, analysisId: string, hash: string) {
        const payload = await this.request(apiKey, `${apiBase}/analyses/${encodeURIComponent(analysisId)}`, { exempt: true });
        const attributes = payload?.data?.attributes;
        if (["queued", "in-progress"].includes(attributes?.status)) return null;
        if (attributes?.status !== "completed" || !attributes?.stats || !attributes?.results) {
            throw new Error("VirusTotal returned an incomplete analysis response; waiting to retry.");
        }
        if (payload?.meta?.file_info?.sha256 && payload.meta.file_info.sha256 !== hash) {
            throw Object.assign(new Error("File changed during upload; the VirusTotal analysis belongs to different content."), { fileError: true });
        }
        return { data: { attributes: {
            last_analysis_stats: attributes.stats, last_analysis_results: attributes.results,
            last_analysis_date: attributes.date
        } } };
    }
}
