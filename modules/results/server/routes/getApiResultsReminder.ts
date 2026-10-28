import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerGetApiResultsReminder(app: any, context: Pick<ApplicationContext, "getResultsReminderPayload">) {
    app.get("/api/results-reminder", async (req, res) => {
        res.json(await context.getResultsReminderPayload());
    });
}
