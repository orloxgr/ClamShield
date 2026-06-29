import { useEffect, useState } from "react";
import { Shield, ShieldAlert, Cpu, Database, Clock, Activity, FileWarning, DownloadCloud, Loader2, ExternalLink, X, RefreshCw } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import PageHeader from "../components/PageHeader";

export default function Dashboard() {
  const [status, setStatus] = useState<any>(null);
  const [securiteInfoDialogOpen, setSecuriteInfoDialogOpen] = useState(false);
  const [securiteInfoSetupUrl, setSecuriteInfoSetupUrl] = useState("");
  const [securiteInfoPlan, setSecuriteInfoPlan] = useState<"basic" | "paid">("basic");
  const [securiteInfoIncludePua, setSecuriteInfoIncludePua] = useState(false);
  const [securiteInfoBusy, setSecuriteInfoBusy] = useState(false);
  const [securiteInfoMessage, setSecuriteInfoMessage] = useState("");
  const [saneSecurityDialogOpen, setSaneSecurityDialogOpen] = useState(false);
  const [saneSecurityProfile, setSaneSecurityProfile] = useState<"malware" | "complete">("malware");
  const [saneSecurityBusy, setSaneSecurityBusy] = useState(false);
  const [saneSecurityMessage, setSaneSecurityMessage] = useState("");

  const fetchStatus = () => {
    fetch("/api/status").then(r => r.json()).then(setStatus);
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  const installEngine = async () => {
    try {
      await fetch("/api/install-engine", { method: "POST" });
      fetchStatus();
    } catch (e) {
      console.error(e);
    }
  };

  const connectSecuriteInfo = async () => {
    setSecuriteInfoBusy(true);
    setSecuriteInfoMessage("");
    try {
      const configureRes = await fetch("/api/securiteinfo/configure", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          setupText: securiteInfoSetupUrl,
          plan: securiteInfoPlan,
          includePua: securiteInfoIncludePua
        })
      });
      const configureData = await configureRes.json();
      if (!configureRes.ok) throw new Error(configureData.error || "Could not connect SecuriteInfo.");
      fetchStatus();

      const updateRes = await fetch("/api/update", { method: "POST" });
      const updateData = await updateRes.json();
      if (!updateRes.ok) throw new Error(updateData.error || "Connected, but the signature update could not start.");

      setSecuriteInfoSetupUrl("");
      setSecuriteInfoDialogOpen(false);
      setSecuriteInfoMessage("SecuriteInfo connected. The signature update has started; detailed progress is available on Updates.");
      fetchStatus();
    } catch (e: any) {
      setSecuriteInfoMessage(e.message || "Could not connect SecuriteInfo.");
    } finally {
      setSecuriteInfoBusy(false);
    }
  };

  const updateSecuriteInfo = async () => {
    setSecuriteInfoBusy(true);
    setSecuriteInfoMessage("");
    try {
      const settingsRes = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          securiteInfoPlan,
          securiteInfoIncludePua
        })
      });
      const settingsData = await settingsRes.json();
      if (!settingsRes.ok) throw new Error(settingsData.error || "Could not save SecuriteInfo settings.");

      const res = await fetch("/api/update", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not start the signature update.");
      setSecuriteInfoMessage("SecuriteInfo settings saved. Signature update started. Open Updates to view detailed FreshClam output.");
      fetchStatus();
    } catch (e: any) {
      setSecuriteInfoMessage(e.message || "Could not start the signature update.");
    } finally {
      setSecuriteInfoBusy(false);
    }
  };

  const disconnectSecuriteInfo = async () => {
    if (!window.confirm("Disconnect SecuriteInfo and remove its downloaded signature files?")) return;
    setSecuriteInfoBusy(true);
    setSecuriteInfoMessage("");
    try {
      const res = await fetch("/api/securiteinfo/disconnect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ removeDatabases: true })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not disconnect SecuriteInfo.");
      setSecuriteInfoMessage("SecuriteInfo disconnected and its signature files were removed.");
      fetchStatus();
    } catch (e: any) {
      setSecuriteInfoMessage(e.message || "Could not disconnect SecuriteInfo.");
    } finally {
      setSecuriteInfoBusy(false);
    }
  };

  const configureSaneSecurity = async () => {
    setSaneSecurityBusy(true);
    setSaneSecurityMessage("");
    try {
      const configureRes = await fetch("/api/sanesecurity/configure", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile: saneSecurityProfile })
      });
      const configureData = await configureRes.json();
      if (!configureRes.ok) throw new Error(configureData.error || "Could not configure SaneSecurity.");

      const updateRes = await fetch("/api/update-sanesecurity", { method: "POST" });
      const updateData = await updateRes.json();
      if (!updateRes.ok) throw new Error(updateData.error || "Configured, but the signature update could not start.");

      setSaneSecurityMessage(
        "Installation started. The first setup downloads the helper tools before verifying and installing the databases. Detailed progress is available on Updates."
      );
      fetchStatus();
    } catch (e: any) {
      setSaneSecurityMessage(e.message || "Could not configure SaneSecurity.");
    } finally {
      setSaneSecurityBusy(false);
    }
  };

  const updateSaneSecurity = async () => {
    setSaneSecurityBusy(true);
    setSaneSecurityMessage("");
    try {
      const res = await fetch("/api/update-sanesecurity", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not start the SaneSecurity update.");
      setSaneSecurityMessage("SaneSecurity update started. Detailed progress is available on Updates.");
      fetchStatus();
    } catch (e: any) {
      setSaneSecurityMessage(e.message || "Could not start the SaneSecurity update.");
    } finally {
      setSaneSecurityBusy(false);
    }
  };

  const disconnectSaneSecurity = async () => {
    if (!window.confirm("Disconnect SaneSecurity and remove its downloaded signature files?")) return;
    setSaneSecurityBusy(true);
    setSaneSecurityMessage("");
    try {
      const res = await fetch("/api/sanesecurity/disconnect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ removeDatabases: true })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not disconnect SaneSecurity.");
      setSaneSecurityMessage("SaneSecurity disconnected and its signature databases were removed.");
      fetchStatus();
    } catch (e: any) {
      setSaneSecurityMessage(e.message || "Could not disconnect SaneSecurity.");
    } finally {
      setSaneSecurityBusy(false);
    }
  };

  if (!status) return <div className="p-8">Loading...</div>;

  const isProtected = status.settings?.shieldEnabled && !status.isSimulated;
  const securiteInfo = status.securiteInfo || {};
  const securiteInfoInstalled = securiteInfo.connected && Number(securiteInfo.installedCount || 0) > 0;
  const saneSecurity = status.saneSecurity || {};
  const saneSecurityInstalled = saneSecurity.connected && Number(saneSecurity.installedCount || 0) > 0;
  const formatUpdateDate = (value: any) => value ? new Date(value).toLocaleString() : "Never";
  const openSecuriteInfoDialog = () => {
    setSecuriteInfoPlan(securiteInfo.plan === "paid" ? "paid" : "basic");
    setSecuriteInfoIncludePua(securiteInfo.includePua === true);
    setSecuriteInfoMessage("");
    setSecuriteInfoDialogOpen(true);
  };

  return (
    <div className="px-8 max-w-6xl mx-auto space-y-8 pb-20">
      <PageHeader title="Dashboard" description="System protection overview" />

      {/* Main Status card */}
      <div className={`p-8 rounded-2xl border flex items-center gap-6 ${isProtected ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-red-500/10 border-red-500/20'}`}>
        <div className={`p-4 rounded-full ${isProtected ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
          {isProtected ? <Shield className="w-12 h-12" /> : <ShieldAlert className="w-12 h-12" />}
        </div>
        <div className="flex-1">
          <h2 className="text-2xl font-semibold text-white mb-1">
            {isProtected ? "You're Protected" : status.isSimulated ? "Engine Missing" : "Shield is OFF"}
          </h2>
          <p className={isProtected ? "text-emerald-400/80" : "text-red-400/80"}>
            {isProtected 
              ? "Your system is being monitored in real-time." 
              : status.isSimulated 
                ? "ClamAV engine is not installed. Background scanning is disabled." 
                : "Real-time protection is disabled. Enable it in Shield settings."}
          </p>
        </div>
      </div>

      {status.isSimulated && status.platform === "win32" && (
        <div className="p-6 bg-indigo-500/10 border border-indigo-500/20 rounded-xl flex items-center justify-between">
            <div>
              <h3 className="font-semibold text-indigo-300 text-lg flex items-center gap-2">
                <DownloadCloud className="w-5 h-5" />
                Download Windows Engine
              </h3>
              <p className="text-slate-400 text-sm mt-1">
                {status.isInstalling 
                  ? "Downloading and installing official ClamAV 64-bit engine automatically..." 
                  : "ClamAV engine is missing. We can download and configure it for you automatically."}
              </p>
              {status.isInstalling && (
                <p className="text-indigo-400 text-sm mt-2 font-mono flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  {status.installProgress}
                </p>
              )}
            </div>
            {!status.isInstalling && (
              <button 
                onClick={installEngine}
                className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded-lg transition-colors"
              >
                Install ClamAV Engine
              </button>
            )}
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <h3 className="font-medium text-slate-300 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-indigo-400" />
            Engine Info
          </h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">Version</span>
              <span className="font-medium text-slate-200">{status.stats.engineVersion}</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">YARA Engine</span>
              <span className={status.hasYaraEngine ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                {status.hasYaraEngine ? "Installed" : "Not installed"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500">YARA Rules</span>
              <span className={status.hasYaraRules ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                {status.hasYaraRules
                  ? `${status.stats.yaraRuleset || "core"} · ${status.stats.yaraRuleCount || 0} rules`
                  : "Missing"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50 gap-4">
              <span className="text-slate-500">ClamAV signatures</span>
              <span className="font-medium text-slate-200 text-right">{formatUpdateDate(status.stats.lastUpdate)}</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50 gap-4">
              <span className="text-slate-500">SecuriteInfo</span>
              {securiteInfoInstalled ? (
                <div className="flex items-center gap-3">
                  <span className="font-medium text-slate-200 text-right">{formatUpdateDate(securiteInfo.lastUpdated)}</span>
                  <button
                    onClick={openSecuriteInfoDialog}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium"
                  >
                    Manage
                  </button>
                </div>
              ) : (
                <button
                  onClick={openSecuriteInfoDialog}
                  className="px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg text-xs font-medium transition-colors"
                >
                  {securiteInfo.connected ? "Finish setup" : "Install"}
                </button>
              )}
            </div>
            <div className="flex justify-between items-center py-2 gap-4">
              <span className="text-slate-500">SaneSecurity</span>
              {saneSecurityInstalled ? (
                <div className="flex items-center gap-3">
                  <span className="font-medium text-slate-200 text-right">{formatUpdateDate(saneSecurity.lastUpdated)}</span>
                  <button
                    onClick={() => {
                      setSaneSecurityProfile(saneSecurity.profile === "complete" ? "complete" : "malware");
                      setSaneSecurityMessage("");
                      setSaneSecurityDialogOpen(true);
                    }}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium"
                  >
                    Manage
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => {
                    setSaneSecurityProfile(saneSecurity.profile === "complete" ? "complete" : "malware");
                    setSaneSecurityMessage("");
                    setSaneSecurityDialogOpen(true);
                  }}
                  className="px-3 py-1.5 bg-violet-700 hover:bg-violet-600 text-white rounded-lg text-xs font-medium transition-colors"
                >
                  {saneSecurity.connected ? "Finish setup" : "Install"}
                </button>
              )}
            </div>
            {status.isSimulated && (
              <div className="mt-4 p-3 bg-amber-500/10 border border-amber-500/20 rounded-md text-amber-400 text-xs text-center flex flex-col gap-2">
                <span>Running in Simulated Mode (ClamAV not detected on path)</span>
                <button 
                  onClick={() => fetch('/api/simulate-threat', { method: 'POST' })}
                  className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 rounded border border-amber-500/30 transition-colors"
                >
                  Trigger Test Threat Modal
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <h3 className="font-medium text-slate-300 flex items-center gap-2">
            <Activity className="w-5 h-5 text-indigo-400" />
            Recent Activity
          </h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500 flex items-center gap-2"><Clock className="w-4 h-4"/> Last Scan</span>
              <span className="font-medium text-slate-200">
                {status.stats.lastScan ? formatDistanceToNow(new Date(status.stats.lastScan), {addSuffix: true}) : "Never"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500 flex items-center gap-2"><Database className="w-4 h-4"/> Signatures Updated</span>
              <span className="font-medium text-slate-200">
                {status.stats.lastUpdate ? formatDistanceToNow(new Date(status.stats.lastUpdate), {addSuffix: true}) : "Never"}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-500 flex items-center gap-2"><FileWarning className="w-4 h-4"/> Quarantined Items</span>
              <span className="font-medium text-slate-200">{status.stats.quarantineCount} files</span>
            </div>
          </div>
        </div>
      </div>

      {securiteInfoDialogOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6">
          <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl">
            <div className="sticky top-0 z-10 bg-slate-900 flex items-center justify-between gap-4 px-6 py-4 border-b border-slate-800">
              <div className="min-w-0">
                <h2 className="text-xl font-semibold text-white">
                  {securiteInfo.connected ? "Manage SecuriteInfo" : "Install SecuriteInfo Signatures"}
                </h2>
                <p className="text-xs text-slate-500 mt-1">Your private token is encrypted by Windows and is never returned by the ClamShield API.</p>
              </div>
              <button
                onClick={() => setSecuriteInfoDialogOpen(false)}
                className="shrink-0 p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-5">
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 space-y-2">
                <p className="text-sm text-slate-300">
                  SecuriteInfo is an optional third-party ClamAV signature source. A free account is required.
                </p>
                <p className="text-xs text-slate-500">
                  Basic installs <code className="text-cyan-300">securiteinfo.ign2</code> and{" "}
                  <code className="text-cyan-300">securiteinfoold.hdb</code>. Paid plans add the remaining supported databases, including 0-hour signatures. PUA signatures are off by default; mailserver spam-domain signatures are not used for Windows scans.
                </p>
                <p className="text-xs text-slate-500">
                  SecuriteInfo reports over 90% and up to 99% zero-day detection in its published measurements. This is a provider claim, not a guarantee by ClamShield.
                </p>
                {securiteInfo.connected && (
                  <p className="text-xs text-emerald-400">
                    Connected as {securiteInfo.plan === "paid" ? "Paid" : "Basic"} - {securiteInfo.installedCount || 0}/{securiteInfo.expectedCount || 0} databases installed{securiteInfo.plan === "paid" ? ` - PUA ${securiteInfo.includePua ? "on" : "off"}` : ""}
                  </p>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Account plan</label>
                <div className="grid sm:grid-cols-2 gap-3">
                  <button
                    onClick={() => {
                      setSecuriteInfoPlan("basic");
                      setSecuriteInfoIncludePua(false);
                    }}
                    className={`text-left p-4 rounded-xl border transition-colors ${
                      securiteInfoPlan === "basic"
                        ? "border-cyan-500 bg-cyan-500/10"
                        : "border-slate-700 bg-slate-950/40 hover:border-slate-600"
                    }`}
                  >
                    <span className="block text-white font-medium">Basic (free)</span>
                    <span className="block text-slate-500 text-xs mt-1">
                      Downloads <code>securiteinfo.ign2</code> and <code>securiteinfoold.hdb</code>.
                    </span>
                  </button>
                  <button
                    onClick={() => setSecuriteInfoPlan("paid")}
                    className={`text-left p-4 rounded-xl border transition-colors ${
                      securiteInfoPlan === "paid"
                        ? "border-cyan-500 bg-cyan-500/10"
                        : "border-slate-700 bg-slate-950/40 hover:border-slate-600"
                    }`}
                  >
                    <span className="block text-white font-medium">Paid</span>
                    <span className="block text-slate-500 text-xs mt-1">Downloads supported paid databases, including 0-hour signatures. PUA signatures are optional; mailserver spam-domain signatures are disabled.</span>
                  </button>
                </div>
              </div>
              <label className={`flex items-start justify-between gap-4 rounded-xl border p-4 ${
                securiteInfoPlan === "paid"
                  ? "border-amber-500/30 bg-amber-500/10 cursor-pointer"
                  : "border-slate-800 bg-slate-950/40 opacity-60"
              }`}>
                <div className="space-y-1">
                  <span className="text-sm font-medium text-slate-200 flex items-center gap-2">
                    <FileWarning className="w-4 h-4 text-amber-300" />
                    Include PUA and vulnerability signatures
                  </span>
                  <span className="block text-xs text-amber-100/80">
                    Caution: <code>{securiteInfo.puaDatabase || "securiteinfo-pua-app-and-vulnerabilities.ndb"}</code> detects potentially unwanted applications and vulnerable components. It may generate many false positives.
                  </span>
                  {securiteInfoPlan !== "paid" && (
                    <span className="block text-xs text-slate-500">Available for paid SecuriteInfo plans.</span>
                  )}
                </div>
                <input
                  type="checkbox"
                  checked={securiteInfoPlan === "paid" && securiteInfoIncludePua}
                  disabled={securiteInfoPlan !== "paid"}
                  onChange={event => setSecuriteInfoIncludePua(event.target.checked)}
                  className="mt-1 w-5 h-5 rounded border-slate-600 text-amber-500 focus:ring-amber-500 focus:ring-offset-slate-900 bg-slate-800"
                />
              </label>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Paste any one of your <code className="text-cyan-300">DatabaseCustomURL</code> lines
                </label>
                <input
                  type="password"
                  value={securiteInfoSetupUrl}
                  onChange={event => setSecuriteInfoSetupUrl(event.target.value)}
                  placeholder="DatabaseCustomURL https://www.securiteinfo.com/get/signatures/…/securiteinfo.ign2"
                  autoComplete="off"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <p className="text-xs text-slate-500 mt-2">
                  Both URLs contain the same private account token. Paste either one and ClamShield adds the correct database URLs automatically. Do not share it publicly.
                </p>
              </div>
              {securiteInfoMessage && (
                <div className="p-3 rounded-lg border border-cyan-500/20 bg-cyan-500/10 text-cyan-200 text-sm">
                  {securiteInfoMessage}
                </div>
              )}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <a
                  href="https://www.securiteinfo.com/clients/customers/signup"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 text-sm text-cyan-400 hover:text-cyan-300"
                >
                  <ExternalLink className="w-4 h-4" />
                  Requires a free SecuriteInfo account
                </a>
                <div className="flex flex-wrap gap-2 justify-end">
                  {securiteInfo.connected && (
                    <>
                      <button
                        onClick={updateSecuriteInfo}
                        disabled={securiteInfoBusy || status.isSignatureUpdateRunning}
                        className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
                      >
                        <RefreshCw className={`w-4 h-4 ${status.isSignatureUpdateRunning ? "animate-spin" : ""}`} />
                        {status.isSignatureUpdateRunning ? "Updating..." : "Save & Update"}
                      </button>
                      <button
                        onClick={disconnectSecuriteInfo}
                        disabled={securiteInfoBusy}
                        className="px-4 py-2.5 bg-slate-800 hover:bg-rose-950/60 disabled:opacity-50 text-slate-300 hover:text-rose-300 rounded-lg text-sm font-medium transition-colors"
                      >
                        Disconnect
                      </button>
                    </>
                  )}
                  <button
                    onClick={connectSecuriteInfo}
                    disabled={securiteInfoBusy || status.isSignatureUpdateRunning || !securiteInfoSetupUrl.trim()}
                    className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
                  >
                    {securiteInfoBusy && <Loader2 className="w-4 h-4 animate-spin" />}
                    {securiteInfo.connected ? "Replace & Update" : "Connect & Update"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {saneSecurityDialogOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-6">
          <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl">
            <div className="sticky top-0 bg-slate-900 flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div>
                <h2 className="text-xl font-semibold text-white">
                  {saneSecurity.connected ? "Manage SaneSecurity" : "Install SaneSecurity Signatures"}
                </h2>
                <p className="text-xs text-slate-500 mt-1">Public third-party signatures for ClamAV. No account is required.</p>
              </div>
              <button
                onClick={() => setSaneSecurityDialogOpen(false)}
                className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-5">
              <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-4 space-y-2">
                <p className="text-sm text-slate-300">
                  ClamShield downloads the databases from SaneSecurity's public rsync mirrors and verifies every file with SaneSecurity's official GPG key before ClamAV is allowed to load it.
                </p>
                <p className="text-xs text-slate-500">
                  First-time setup downloads an official signed Cygwin helper of approximately 185 MB for rsync and GnuPG. The helper is stored inside ClamShield data, creates no shortcuts, and requires outbound TCP port 873.
                </p>
                <p className="text-xs text-amber-300/80">
                  Third-party signatures can improve detection but may also increase false positives. ClamShield does not guarantee SaneSecurity's availability or detection results.
                </p>
                {saneSecurity.connected && (
                  <p className="text-xs text-emerald-400">
                    {saneSecurity.profile === "complete" ? "Complete" : "Malware Protection"} · {saneSecurity.installedCount || 0}/{saneSecurity.expectedCount || 0} databases installed
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Signature profile</label>
                <div className="grid sm:grid-cols-2 gap-3">
                  <button
                    onClick={() => setSaneSecurityProfile("malware")}
                    className={`text-left p-4 rounded-xl border transition-colors ${
                      saneSecurityProfile === "malware"
                        ? "border-violet-500 bg-violet-500/10"
                        : "border-slate-700 bg-slate-950/40 hover:border-slate-600"
                    }`}
                  >
                    <span className="block text-white font-medium">Malware Protection</span>
                    <span className="block text-slate-500 text-xs mt-1">
                      Installs 9 malware, phishing, macro, hash, whitelist, and exploit-focused databases.
                    </span>
                  </button>
                  <button
                    onClick={() => setSaneSecurityProfile("complete")}
                    className={`text-left p-4 rounded-xl border transition-colors ${
                      saneSecurityProfile === "complete"
                        ? "border-violet-500 bg-violet-500/10"
                        : "border-slate-700 bg-slate-950/40 hover:border-slate-600"
                    }`}
                  >
                    <span className="block text-white font-medium">Complete</span>
                    <span className="block text-slate-500 text-xs mt-1">
                      Installs 20 databases, adding spam, scam, URL, attachment, image, and spear-phishing signatures.
                    </span>
                  </button>
                </div>
              </div>

              {saneSecurityMessage && (
                <div className="p-3 rounded-lg border border-violet-500/20 bg-violet-500/10 text-violet-200 text-sm">
                  {saneSecurityMessage}
                </div>
              )}

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex flex-wrap gap-4">
                  <a
                    href={saneSecurity.usageUrl || "https://sanesecurity.com/usage/signatures/"}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-sm text-violet-400 hover:text-violet-300"
                  >
                    <ExternalLink className="w-4 h-4" />
                    Signature information
                  </a>
                  <a
                    href={saneSecurity.donateUrl || "https://sanesecurity.com/donate/"}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-slate-300"
                  >
                    <ExternalLink className="w-4 h-4" />
                    Support SaneSecurity
                  </a>
                </div>
                <div className="flex flex-wrap gap-2 justify-end">
                  {saneSecurity.connected && (
                    <>
                      <button
                        onClick={updateSaneSecurity}
                        disabled={saneSecurityBusy || status.isSaneSecurityUpdateRunning}
                        className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
                      >
                        <RefreshCw className={`w-4 h-4 ${status.isSaneSecurityUpdateRunning ? "animate-spin" : ""}`} />
                        {status.isSaneSecurityUpdateRunning ? "Updating..." : "Update now"}
                      </button>
                      <button
                        onClick={disconnectSaneSecurity}
                        disabled={saneSecurityBusy || status.isSaneSecurityUpdateRunning}
                        className="px-4 py-2.5 bg-slate-800 hover:bg-rose-950/60 disabled:opacity-50 text-slate-300 hover:text-rose-300 rounded-lg text-sm font-medium transition-colors"
                      >
                        Disconnect
                      </button>
                    </>
                  )}
                  <button
                    onClick={configureSaneSecurity}
                    disabled={saneSecurityBusy || status.isSaneSecurityUpdateRunning}
                    className="inline-flex items-center gap-2 px-5 py-2.5 bg-violet-700 hover:bg-violet-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
                  >
                    {(saneSecurityBusy || status.isSaneSecurityUpdateRunning) && <Loader2 className="w-4 h-4 animate-spin" />}
                    {saneSecurity.connected ? "Save & Update" : "Install & Update"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
