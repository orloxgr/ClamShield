// HTTP entry points for this feature. Business services and workers live alongside them.
export { registerGetApiVirustotalCloudStatus } from "./routes/getApiVirustotalCloudStatus";
export { registerPostApiVirustotalCloudUsageRefresh } from "./routes/postApiVirustotalCloudUsageRefresh";
export { registerPostApiVirustotalCloudUsageSettings } from "./routes/postApiVirustotalCloudUsageSettings";
export { registerPostApiVirustotalCloudConfigure } from "./routes/postApiVirustotalCloudConfigure";
export { registerPostApiVirustotalCloudDisconnect } from "./routes/postApiVirustotalCloudDisconnect";
export { registerGetApiVirustotalQueue } from "./routes/getApiVirustotalQueue";
export { registerGetApiVirustotalRefinementStatus } from "./routes/getApiVirustotalRefinementStatus";
export { registerGetApiVirustotalOnDemandLimitWarning } from "./routes/getApiVirustotalOnDemandLimitWarning";
export { registerPostApiVirustotalOnDemandJobIdConfirm } from "./routes/postApiVirustotalOnDemandJobIdConfirm";
export { registerGetApiVirustotalOnDemand } from "./routes/getApiVirustotalOnDemand";
export { registerPostApiVirustotalOnDemandJobId } from "./routes/postApiVirustotalOnDemandJobId";
