import { englishText } from "../../../shared/localization/runtime";
import { ensureAppStateReady } from "../../../server/core/database/migrations";
import { getAppStateDb } from "../../../server/core/database/schema";
import { escapeSqlLike, normalizedStatePath, runAppStateTransaction } from "../../../server/core/database/values";
import { getClamShieldScanExclusionPaths } from "../../../server/scanning/exclusions";
import path from "path";
export async function cleanupBuiltInExcludedScanResults(settings: any) {
    await ensureAppStateReady();
    const excludedPaths = getClamShieldScanExclusionPaths(settings)
        .map(normalizedStatePath)
        .filter(Boolean);
    if (excludedPaths.length === 0)
        return 0;
    const db = getAppStateDb();
    let removedCount = 0;
    try {
        runAppStateTransaction(db, () => {
            const deletePath = db.prepare(`
                DELETE FROM scan_results
                WHERE normalized_path = ?
                   OR normalized_path LIKE ? ESCAPE '\\'
            `);
            for (const excludedPath of excludedPaths) {
                const result: any = deletePath.run(excludedPath, `${escapeSqlLike(excludedPath)}${escapeSqlLike(path.sep)}%`);
                removedCount += Number(result?.changes || 0);
            }
        });
        if (removedCount > 0) {
            console.log(englishText("backend.results.removed_scan_result_s_from_built_in_provider_safety_exclusions", {
                removedCount: String(removedCount)
            }));
        }
    }
    catch (e: any) {
        console.warn(englishText("backend.results.failed_to_remove_built_in_excluded_scan_results"), e?.message || e);
        return 0;
    }
    return removedCount;
}
