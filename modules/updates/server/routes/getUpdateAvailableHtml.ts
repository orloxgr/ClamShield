import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeDir } from "../../../../server/core/paths";
import { existsSync } from "fs";
import path from "path";
export function registerGetUpdateAvailableHtml(app: any, context: ApplicationContext) {
    app.get('/update-available.html', (req, res) => {
        const isProd = process.env.NODE_ENV === "production";
        const updatePath = isProd
            ? path.join(runtimeDir, "..", "public", "update-available.html")
            : path.join(runtimeDir, "public", "update-available.html");
        if (existsSync(updatePath)) {
            res.sendFile(updatePath);
        }
        else {
            res.status(404).send("Update popup not found");
        }
    });
}
