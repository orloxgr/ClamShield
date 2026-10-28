import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerGetApiReady(app: any, context: ApplicationContext) {
    // API Routes
    app.get("/api/ready", (_req, res) => res.json({ ready: true }));
}
