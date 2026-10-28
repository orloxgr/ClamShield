import { englishText } from "../../../../shared/localization/runtime";
import { markVirusTotalCheckOpened } from "../../../../addons/virustotal/server/account";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getScanResults, saveScanResults } from "../storage";
import { existsSync } from "fs";
export function registerGetApiResultsIdVirustotalUpload(app: any, context: ApplicationContext) {
    app.get("/api/results/:id/virustotal-upload", async (req, res) => {
        try {
            const results = await getScanResults();
            const result = results.find((item: any) => item.id === req.params.id);
            if (!result)
                throw new Error(englishText("backend.results.result_not_found"));
            if (!result.originalPath || !existsSync(result.originalPath)) {
                throw new Error(englishText("backend.results.the_original_file_is_unavailable_so_it_cannot_be_uploaded_for_a_s"));
            }
            markVirusTotalCheckOpened(result, "upload");
            await saveScanResults(results);
            res.json({
                success: true,
                filePath: result.originalPath,
                url: "https://www.virustotal.com/gui/home/upload",
                uploaded: false,
                message: englishText("backend.results.clamshield_opens_virustotal_s_upload_page_only_the_user_must_choo")
            });
        }
        catch (e: any) {
            res.status(400).json({ success: false, error: e?.message || String(e) });
        }
    });
}
