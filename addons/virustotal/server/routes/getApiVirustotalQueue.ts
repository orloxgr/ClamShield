import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
import { loadVirusTotalApiKey } from "../account";
export function registerGetApiVirustotalQueue(app: any, context: ApplicationContext) {
    app.get("/api/virustotal/queue", async (req, res) => {
        try {
            res.json(runtimeState.virusTotalQueueViewHandler!(req.query, Boolean(await loadVirusTotalApiKey())));
        }
        catch (e: any) {
            res.status(500).json({ error: englishText("common.virus_total_queue_dialog.could_not_load_the_virustotal_queue") });
        }
    });
}
