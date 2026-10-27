export type ExceptionItem = {
  path: string;
  addedAt: number;
  kind: string;
  origin: string;
  providerName: string;
  report: any | null;
};
export const statusLabels: Record<string, string> = {
  not_reported: "Not reported",
  unconfirmed: "Submission unconfirmed",
  sent: "Reported by you",
  not_applicable: "Not applicable",
};
export const originLabels: Record<string, string> = {
  manual: "Manually added",
  scan: "Scan results",
  shield: "Real-time Shield",
  unknown: "Unknown",
};
export function itemStatus(item: ExceptionItem) {
  return (
    item.report?.reportStatus ||
    (item.report ? "not_reported" : "not_applicable")
  );
}
export async function exceptionApi(url: string, body?: any) {
  const response = await fetch(
    url,
    body === undefined
      ? undefined
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
  );
  const data = await response.json().catch(() => {
    throw new Error(
      "The service returned an unreadable response. Please retry.",
    );
  });
  if (!response.ok || data.success === false)
    throw new Error(data.error || "The operation failed.");
  return data;
}
export async function openReportUrl(url: string) {
  const desktop = (window as any).clamshieldDesktop;
  if (desktop) return desktop.openExternal(url);
  const opened = window.open(url, "_blank");
  if (!opened)
    throw new Error(
      "The browser blocked the report window. Allow popups and retry, or copy the report.",
    );
  opened.opener = null;
}
