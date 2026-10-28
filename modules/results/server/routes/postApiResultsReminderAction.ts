import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { getResultsReminderState, getResultsReminderSummary, saveResultsReminderState } from "../storage";
export function registerPostApiResultsReminderAction(app: any, context: ApplicationContext) {
    app.post("/api/results-reminder/action", async (req, res) => {
        const action = req.body.action;
        const reminder = await getResultsReminderSummary();
        const latestTimestamp = reminder.latestTimestamp;
        const state = await getResultsReminderState();
        if (action === "remind-10") {
            state.remindUntil = Date.now() + 10 * 60 * 1000;
        }
        else if (action === "remind-60") {
            state.remindUntil = Date.now() + 60 * 60 * 1000;
        }
        else if (action === "forget") {
            state.forgottenUntil = latestTimestamp;
            state.remindUntil = 0;
        }
        else if (action === "open") {
            state.remindUntil = Date.now() + 10 * 60 * 1000;
        }
        else {
            return res.status(400).json({ success: false, error: englishText("backend.results.invalid_reminder_action") });
        }
        await saveResultsReminderState(state);
        res.json({ success: true, openResults: action === "open" });
    });
}
