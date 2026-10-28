import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeDir } from "../../../../server/core/paths";
import { existsSync } from "fs";
import path from "path";
export function registerGetScanSummaryHtml(app: any, context: ApplicationContext) {
    app.get('/scan-summary.html', (req, res) => {
        const isProd = process.env.NODE_ENV === "production";
        const summaryPath = isProd
            ? path.join(runtimeDir, "..", "public", "scan-summary.html")
            : path.join(runtimeDir, "public", "scan-summary.html");
        if (existsSync(summaryPath)) {
            res.sendFile(summaryPath);
        }
        else {
            res.status(404).send("Scan summary not found");
        }
    });
}
