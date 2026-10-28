import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeDir } from "../../../../server/core/paths";
import { existsSync } from "fs";
import path from "path";
export function registerGetResultsReminderHtml(app: any, context: ApplicationContext) {
    app.get('/results-reminder.html', (req, res) => {
        const isProd = process.env.NODE_ENV === "production";
        const reminderPath = isProd
            ? path.join(runtimeDir, "..", "public", "results-reminder.html")
            : path.join(runtimeDir, "public", "results-reminder.html");
        if (existsSync(reminderPath)) {
            res.sendFile(reminderPath);
        }
        else {
            res.status(404).send("Reminder not found");
        }
    });
}
