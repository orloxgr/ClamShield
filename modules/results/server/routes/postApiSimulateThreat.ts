import { ApplicationContext } from "../../../../server/core/applicationContext";
import { runtimeState } from "../../../../server/core/runtimeState";
export function registerPostApiSimulateThreat(app: any, context: Pick<ApplicationContext, "pendingThreatStore">) {
    app.post("/api/simulate-threat", (req, res) => {
        const pendingThreat = {
            id: Date.now().toString() + Math.random().toString(36).substring(7),
            originalPath: "C:\\TestPath\\fake-virus.exe",
            threatName: "Win32.Test.SimulatedThreat.A",
            timestamp: Date.now()
        };
        const pending = context.pendingThreatStore.register(pendingThreat, null);
        if (pending && runtimeState.pendingThreatHandler)
            runtimeState.pendingThreatHandler(pending);
        res.json({ success: true });
    });
}
