export function reportUiFailure(input: {
  stage: string;
  code: string;
  message: string;
  details?: any;
}) {
  const record = {
    ...input,
    time: new Date().toISOString(),
    id: crypto.randomUUID(),
  };
  window.dispatchEvent(
    new CustomEvent("clamshield-ui-failure", { detail: record }),
  );
  const desktop = (window as any).clamshieldDesktop;
  if (desktop) desktop.reportError(input).catch(() => {});
  else
    fetch("/api/client-log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        level: "error",
        message: "Interface failure",
        details: record,
      }),
      keepalive: true,
    }).catch(() => {});
}
