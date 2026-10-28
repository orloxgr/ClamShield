import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getResolvedSystemPaths } from "../../../../server/platform/paths";
export function registerGetApiSystemPaths(app: any, context: ApplicationContext) {
    app.get("/api/system-paths", async (req, res) => {
        try {
            res.json(await getResolvedSystemPaths());
        }
        catch (e: any) {
            res.status(500).json({ error: e.message || englishText("backend.settings.failed_to_resolve_system_paths") });
        }
    });
}
