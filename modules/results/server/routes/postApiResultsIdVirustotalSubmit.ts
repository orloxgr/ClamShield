import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerPostApiResultsIdVirustotalSubmit(app: any, context: Pick<ApplicationContext, "checkResultWithVirusTotal">) {
    app.post("/api/results/:id/virustotal-submit", context.checkResultWithVirusTotal);
}
