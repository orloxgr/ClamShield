import { t, localizeText, useLanguage } from "../lib/i18n";
export default function StartupShell({ retrying, onRetry }: {
    retrying?: boolean;
    onRetry?: () => void;
}) {
    useLanguage();
    return (<div className="startup-shell" aria-busy="true">
      <aside className="startup-sidebar" aria-label={t("common.startup_shell.clamshield_navigation")} aria-disabled="true">
        <div className="startup-brand"><img src="/shield.svg" width={32} height={32} alt="" aria-hidden="true"/>ClamShield</div>
        <div className="startup-nav">{localizeText(["Dashboard", "Shield", "On-Demand Scan", "Scheduled Scanner", "Results", "Exceptions", "Quarantine", "DNS Protection", "Updates", "History", "Settings"].map(label => <div key={label}>{localizeText(label)}</div>))}</div>
        <div className="startup-footer">{t("navigation.made_by_byron_iniotakis")}</div>
      </aside>
      <main className="startup-main">
        <header className="startup-header"><h1>ClamShield</h1><p>{t("dashboard.system_protection_overview")}</p></header>
        <div className="startup-content"><section className="startup-loading" role="status" aria-live="polite">
          <span className="startup-spinner" aria-hidden="true"/>
          <h2>{t("common.startup_shell.loading_clamshield")}</h2>
          <p>{localizeText(retrying ? "Waiting for the local service. Retrying…" : "Loading your protection status…")}</p>
          {localizeText(retrying && onRetry && <button type="button" onClick={onRetry}>{t("common.startup_shell.retry_now")}</button>)}
        </section></div>
      </main>
    </div>);
}
