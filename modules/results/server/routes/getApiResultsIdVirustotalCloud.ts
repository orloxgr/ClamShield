import { ApplicationContext } from "../../../../server/core/applicationContext";
export function registerGetApiResultsIdVirustotalCloud(app: any, context: Pick<ApplicationContext, "checkResultWithVirusTotal">) {
    app.get("/api/results/:id/virustotal-cloud", context.checkResultWithVirusTotal);
}
