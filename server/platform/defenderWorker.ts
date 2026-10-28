import { englishText } from "../../shared/localization/runtime";
import { normalizePositiveNumber } from "../../modules/settings/server/validation";
import { ApplicationContext } from "../core/applicationContext";
import { autoDisableDefender } from "./defender";
export function createScheduleDefenderEnforcement(context: Pick<ApplicationContext, "defenderTimer" | "settings">) {
    return async (runNow = true) => {
        if (context.defenderTimer)
            clearInterval(context.defenderTimer);
        if (!context.settings.autoDisableDefender)
            return;
        if (runNow) {
            autoDisableDefender().catch(e => console.warn(englishText("backend.platform.initial_defender_pause_failed"), e.message));
        }
        const intervalMinutes = normalizePositiveNumber(context.settings.defenderEnforceIntervalMinutes, 5, 1, 1440);
        context.defenderTimer = setInterval(() => {
            autoDisableDefender().catch(e => console.warn(englishText("backend.platform.scheduled_defender_pause_failed"), e.message));
        }, intervalMinutes * 60 * 1000);
        context.defenderTimer.unref?.();
    };
}
