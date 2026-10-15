export default function StartupShell({ retrying, onRetry }: { retrying?: boolean; onRetry?: () => void }) {
  return (
    <div className="startup-shell" aria-busy="true">
      <aside className="startup-sidebar" aria-label="ClamShield navigation" aria-disabled="true">
        <div className="startup-brand"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true"><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z" /></svg>ClamShield</div>
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
