import { englishText } from "../../../../shared/localization/runtime";
import { getVirusTotalRefinementStatus } from "../../../../addons/virustotal/server/refinement";
import { isVirusTotalAutoRefinementCandidate } from "../../../../addons/virustotal/server/status";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { cleanupBuiltInExcludedScanResults } from "../cleanup";
import { getScanResultFindingSourceOptions, getScanResults, getScanResultsPage } from "../storage";
import { existsSync } from "fs";
export function registerGetApiResults(app: any, context: Pick<ApplicationContext, "settings">) {
    app.get("/api/results", async (req, res) => {
        try {
            const hasPagedQuery = req.query.page !== undefined || req.query.pageSize !== undefined || req.query.date !== undefined || req.query.engine !== undefined || req.query.findingSource !== undefined || req.query.virusTotalRefinement !== undefined;
            if (!runtimeState.scanResultsCleanupTimer) {
                runtimeState.scanResultsCleanupTimer = setTimeout(() => {
                    runtimeState.scanResultsCleanupTimer = null;
                    cleanupBuiltInExcludedScanResults(context.settings)
                        .catch(e => console.warn(englishText("backend.results.deferred_scan_results_cleanup_failed"), e?.message || e));
                }, 1000);
            }
            if (!hasPagedQuery) {
                const results = await getScanResults();
                res.json(results.map((result: any) => ({
                    ...result,
                    virusTotalQueued: context.settings.virusTotalCloudEnabled === true && isVirusTotalAutoRefinementCandidate(result, context.settings) && !getVirusTotalRefinementStatus(result),
                    available: Boolean(result.originalPath && existsSync(result.originalPath))
                })));
                return;
            }
            const requestedPageSize = String(req.query.pageSize || "50").toLowerCase();
            const page = Math.max(1, Math.floor(Number(req.query.page || 1) || 1));
            const date = typeof req.query.date === "string" ? req.query.date : "";
            const pageSize = requestedPageSize === "all"
                ? null
                : Math.max(1, Math.min(500, Math.floor(Number(requestedPageSize) || 50)));
            const offset = pageSize ? (page - 1) * pageSize : 0;
            const findingSource = typeof req.query.findingSource === "string"
                ? req.query.findingSource
                : typeof req.query.engine === "string" ? req.query.engine : "";
            const virusTotalRefinement = typeof req.query.virusTotalRefinement === "string"
                ? req.query.virusTotalRefinement
                : "all";
            const [paged, findingSourceOptions] = await Promise.all([
                getScanResultsPage({
                    limit: pageSize,
                    offset,
                    date,
                    findingSource,
                    virusTotalRefinement
                }),
                getScanResultFindingSourceOptions({ date })
            ]);
            res.json({
                items: paged.items.map((result: any) => ({
                    ...result,
                    virusTotalQueued: context.settings.virusTotalCloudEnabled === true && isVirusTotalAutoRefinementCandidate(result, context.settings) && !getVirusTotalRefinementStatus(result),
                    available: Boolean(result.originalPath && existsSync(result.originalPath))
                })),
                total: paged.total,
                page,
                pageSize: pageSize || "all",
                findingSourceOptions,
                engineOptions: findingSourceOptions
            });
        }
        catch (e: any) {
            console.error(englishText("backend.results.failed_to_load_scan_results"), e?.message || e);
            res.status(500).json({ error: e?.message || englishText("backend.results.could_not_load_scan_results"), items: [], total: 0 });
        }
    });
}
