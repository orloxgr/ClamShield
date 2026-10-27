export default function StartupShell({ retrying, onRetry }: { retrying?: boolean; onRetry?: () => void }) {
  return (
    <div className="startup-shell" aria-busy="true">
      <aside className="startup-sidebar" aria-label="ClamShield navigation" aria-disabled="true">
        <div className="startup-brand"><img src="/shield.svg" width={32} height={32} alt="" aria-hidden="true" />ClamShield</div>
        <div className="startup-nav">{["Dashboard", "Shield", "On-Demand Scan", "Scheduled Scanner", "Results", "Exceptions", "Quarantine", "DNS Protection", "Updates", "History", "Settings"].map(label => <div key={label}>{label}</div>)}</div>
        <div className="startup-footer">Made by Byron Iniotakis</div>
      </aside>
      <main className="startup-main">
        <header className="startup-header"><h1>ClamShield</h1><p>System protection overview</p></header>
        <div className="startup-content"><section className="startup-loading" role="status" aria-live="polite">
          <span className="startup-spinner" aria-hidden="true" />
          <h2>Loading ClamShield…</h2>
          <p>{retrying ? "Waiting for the local service. Retrying…" : "Loading your protection status…"}</p>
          {retrying && onRetry && <button type="button" onClick={onRetry}>Retry now</button>}
        </section></div>
      </main>
    </div>
  );
}
