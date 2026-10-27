const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("clamshieldDesktop", {
  openExternal: (url) => ipcRenderer.invoke("clamshield-open-external", url),
  reportError: (error) => ipcRenderer.invoke("clamshield-ui-error", error),
  copyDiagnostics: () => ipcRenderer.invoke("clamshield-copy-diagnostics"),
  openLogs: () => ipcRenderer.invoke("clamshield-open-logs"),
  retry: () => ipcRenderer.invoke("clamshield-retry-ui"),
  uiReady: () => ipcRenderer.invoke("clamshield-ui-ready"),
});
// These listeners exist before any application script or React code runs.
let failed = false;
function report(payload) {
  if (failed || location.protocol === "data:" || location.protocol === "file:")
    return;
  failed = true;
  ipcRenderer.invoke("clamshield-ui-error", payload).catch(() => {
    failed = false;
  });
}
window.addEventListener(
  "error",
  (event) => {
    const target = event.target;
    if (
      target &&
      (target.tagName === "SCRIPT" ||
        (target.tagName === "LINK" && target.rel === "stylesheet"))
    ) {
      report({
        stage: "Loading interface resources",
        code: "RESOURCE_LOAD_FAILED",
        message:
          "A required interface script or stylesheet could not be loaded.",
        details: target.src || target.href,
      });
    } else if (event.message) {
      report({
        stage: "Running interface",
        code: "JAVASCRIPT_ERROR",
        message: event.message,
        details: event.error?.stack || `${event.filename}:${event.lineno}`,
      });
    }
  },
  true,
);
window.addEventListener("unhandledrejection", (event) =>
  report({
    stage: "Running interface",
    code: "UNHANDLED_REJECTION",
    message: event.reason?.message || String(event.reason),
    details: event.reason?.stack,
  }),
);
