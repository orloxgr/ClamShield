import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerGetApiPendingThreats(app: any, context: Pick<ApplicationContext, "pendingThreats">) {
    app.get("/api/pending-threats", (req, res) => {
        res.json(context.pendingThreats);
    });
}
