import { t, localizeText } from "../lib/i18n";
import React, { type ReactNode } from "react";
import { reportUiFailure } from "../lib/uiDiagnostics";
export default class UiErrorBoundary extends React.Component<{
    children: ReactNode;
}, {
    failure: any;
    notice: string;
}> {
    state = { failure: null as any, notice: "" };
    static getDerivedStateFromError(error: Error) {
        return {
            failure: {
                stage: "Rendering interface",
                code: "REACT_RENDER_ERROR",
                message: error.message,
            },
        };
    }
    receive = (event: Event) => this.setState({ failure: (event as CustomEvent).detail });
    componentDidMount() {
        window.addEventListener("clamshield-ui-failure", this.receive);
        document.documentElement.dataset.clamshieldUiReady = "true";
        (window as any).clamshieldDesktop?.uiReady().catch((error: any) => {
            console.warn("Could not acknowledge interface readiness:", error.message);
        });
    }
    componentWillUnmount() {
        window.removeEventListener("clamshield-ui-failure", this.receive);
    }
    componentDidCatch(error: Error, info: React.ErrorInfo) {
        reportUiFailure({
            stage: "Rendering interface",
            code: "REACT_RENDER_ERROR",
            message: error.message,
            details: { stack: error.stack, componentStack: info.componentStack },
        });
    }
    render() {
        const { failure, notice } = this.state;
        if (!failure)
            return this.props.children;
        const action = async (name: string) => {
            try {
                const desktop = (window as any).clamshieldDesktop;
                if (desktop)
                    await desktop[name]();
                else if (name === "retry")
                    window.location.reload();
                else if (name === "copyDiagnostics")
                    await navigator.clipboard.writeText(JSON.stringify(failure, null, 2));
                else
                    throw new Error("Logs are stored on the computer running ClamShield, normally C:\\ProgramData\\ClamShield\\logs.");
                this.setState({
                    notice: name === "copyDiagnostics" ? "Diagnostics copied." : "Requested.",
                });
            }
            catch (error: any) {
                this.setState({ notice: error.message });
            }
        };
        return (<main className="flex h-screen items-center justify-center overflow-auto bg-slate-950 p-8 text-slate-200">
        <div className="w-full max-w-2xl space-y-4 rounded-xl border border-amber-500/40 bg-slate-900 p-6">
          <h1 className="text-2xl font-semibold text-amber-100">{t("common.ui_error_boundary.clamshield_could_not_load")}</h1>
          <p>{localizeText(failure.message)}</p>
          <p className="text-sm text-slate-400">{t("common.ui_error_boundary.protection_status_could_not_be_verified_from_this_screen")}</p>
          <p className="text-sm">{t("common.ui_error_boundary.stage")}{localizeText(failure.stage)}{t("common.ui_error_boundary.error")}{localizeText(failure.code)}
          </p>
          {localizeText(failure.time && (<p className="text-xs text-slate-400">
              {localizeText(failure.time)} · {localizeText(failure.id)}
            </p>))}
          <div className="flex flex-wrap gap-2">
            {localizeText([
                ["retry", "Retry"],
                ["copyDiagnostics", "Copy diagnostics"],
                ["openLogs", "Open logs folder"],
            ].map(([name, label]) => (<button key={name} className="rounded border border-slate-600 bg-slate-800 px-3 py-2" onClick={() => action(name)}>
                {localizeText(label)}
              </button>)))}
          </div>
          <p role="status" className="text-sm text-amber-200">
            {localizeText(notice)}
          </p>
          <details>
            <summary>{t("common.ui_error_boundary.technical_details")}</summary>
            <pre className="mt-2 max-h-60 overflow-auto whitespace-pre-wrap break-all text-xs">
              {localizeText(JSON.stringify(failure, null, 2))}
            </pre>
          </details>
        </div>
      </main>);
    }
}
