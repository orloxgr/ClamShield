import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeDir } from "../../../../server/core/paths";
import { existsSync } from "fs";
import path from "path";
export function registerGetAlertHtml(app: any, context: ApplicationContext) {
    app.get('/alert.html', (req, res) => {
        const isProd = process.env.NODE_ENV === "production";
        const alertPath = isProd
            ? path.join(runtimeDir, "..", "public", "alert.html")
            : path.join(runtimeDir, "public", "alert.html");
        if (existsSync(alertPath)) {
            res.sendFile(alertPath);
        }
        else {
            res.status(404).send("Alert not found");
        }
    });
}
