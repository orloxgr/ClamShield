import { useEffect, useState } from "react";
import { ExternalLink, Globe2, Loader2, Network, RefreshCw, RotateCcw, ShieldCheck, TriangleAlert } from "lucide-react";
import PageHeader from "../components/PageHeader";

type DnsProfile = {
  id: string;
  provider: string;
  name: string;
  description: string;
  ipv4: string[];
  ipv6: string[];
  websiteUrl: string;
  category: "security" | "family" | "privacy";
};

export default function DnsProtection() {
  const [status, setStatus] = useState<any>(null);
  const [selectedProfile, setSelectedProfile] = useState("");
  const [busy, setBusy] = useState<"apply" | "restore" | "refresh" | null>(null);
  const [message, setMessage] = useState("");

  const refreshStatus = async (initial = false) => {
    if (!initial) setBusy("refresh");
    try {
      const response = await fetch("/api/dns-protection/status");
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not read Windows DNS settings.");
      setStatus(data);
      setSelectedProfile(current => current || data.activeProfileId || data.profiles?.[0]?.id || "");
    } catch (error: any) {
      setMessage(error.message || "Could not read Windows DNS settings.");
    } finally {
      if (!initial) setBusy(null);
    }
  };

  useEffect(() => {
    refreshStatus(true);
  }, []);

  const applyProtection = async () => {
    if (!selectedProfile) return;
    setBusy("apply");
    setMessage("");
    try {
      const response = await fetch("/api/dns-protection/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profileId: selectedProfile })
      });
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || "Windows did not apply the DNS profile.");
      setStatus(data.status);
      setMessage(data.warning || "DNS protection applied to active internet adapters. The previous resolver list was saved for restoration.");
    } catch (error: any) {
      setMessage(error.message || "Could not apply DNS protection.");
    } finally {
      setBusy(null);
    }
  };

  const restoreDns = async () => {
    if (!confirm("Restore the DNS resolver list that was saved before ClamShield enabled DNS protection?")) return;
    setBusy("restore");
    setMessage("");
    try {
      const response = await fetch("/api/dns-protection/restore", { method: "POST" });
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || "Windows did not restore the previous DNS settings.");
      setStatus(data.status);
      setMessage("Previous DNS resolver settings restored.");
    } catch (error: any) {
      setMessage(error.message || "Could not restore the previous DNS settings.");
    } finally {
      setBusy(null);
    }
  };

  if (!status) {
    return <div className="p-8 flex items-center gap-3 text-slate-400"><Loader2 className="w-5 h-5 animate-spin" /> Loading DNS protection...</div>;
  }

  const profiles: DnsProfile[] = Array.isArray(status.profiles) ? status.profiles : [];
  const selected = profiles.find(profile => profile.id === selectedProfile);
  const dnsActive = Boolean(status.applied);
  const dnsPartial = Boolean(status.partiallyApplied);
  const statusTitle = dnsActive
    ? dnsPartial
      ? `${status.activeProfileName} is partially active`
      : `${status.activeProfileName} is active`
    : "Windows DNS protection is not active";
  const statusDescription = dnsPartial
    ? `${status.partialAdapterCount || status.matchingAdapterCount || 0} of ${status.adapters?.length || 0} active internet adapters report this DNS profile. VPNs, virtual adapters, IPv6 policy, or router-managed DNS can report differently.`
    : `${status.adapters?.length || 0} active internet adapter${status.adapters?.length === 1 ? "" : "s"} detected.${status.backupAvailable ? " Previous DNS settings are available for restoration." : ""}`;

  return (
    <div className="px-8 max-w-6xl mx-auto space-y-6 pb-20">
      <PageHeader
        title="DNS Protection"
        description="Block malicious or unwanted domains before the connection reaches your browser."
        actions={(
          <button
            onClick={() => refreshStatus()}
            disabled={busy !== null}
            className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 rounded-lg border border-slate-700"
          >
            <RefreshCw className={`w-4 h-4 ${busy === "refresh" ? "animate-spin" : ""}`} />
            Refresh
          </button>
        )}
      />

      {message && (
        <div className="p-4 rounded-xl border border-indigo-500/30 bg-indigo-500/10 text-indigo-100 text-sm">
          {message}
        </div>
      )}

      <section className={`rounded-xl border p-5 ${
        dnsPartial
          ? "border-amber-500/30 bg-amber-500/10"
          : dnsActive
            ? "border-emerald-500/30 bg-emerald-500/10"
            : "border-slate-800 bg-slate-900"
      }`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
          <div className="flex items-start gap-4">
            <div className={`p-3 rounded-full ${
              dnsPartial
                ? "bg-amber-500/15 text-amber-300"
                : dnsActive
                  ? "bg-emerald-500/15 text-emerald-400"
                  : "bg-slate-800 text-slate-400"
            }`}>
              {dnsActive ? <ShieldCheck className="w-7 h-7" /> : <Globe2 className="w-7 h-7" />}
            </div>
            <div>
              <h2 className="font-semibold text-white text-lg">
                {statusTitle}
              </h2>
              <p className="text-sm text-slate-400 mt-1">
                {statusDescription}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={applyProtection}
              disabled={busy !== null || !selectedProfile}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg font-medium"
            >
              {busy === "apply" ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
              {status.enabled ? "Switch profile" : "Enable protection"}
            </button>
            <button
              onClick={restoreDns}
              disabled={busy !== null || !status.backupAvailable}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded-lg border border-slate-700"
            >
              {busy === "restore" ? <Loader2 className="w-4 h-4 animate-spin" /> : <RotateCcw className="w-4 h-4" />}
              Restore previous DNS
            </button>
          </div>
        </div>
      </section>

      {(status.domainJoined || status.adapters?.length === 0) && (
        <div className="flex items-start gap-3 p-4 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-100 text-sm">
          <TriangleAlert className="w-5 h-5 shrink-0 mt-0.5 text-amber-400" />
          <p>
            {status.domainJoined
              ? "This computer is joined to an organization domain. Changing DNS can break company resources or be overwritten by policy."
              : "No active adapter with an internet gateway was found. Connect to a network and refresh before enabling DNS protection."}
          </p>
        </div>
      )}

      <section>
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-white">Choose a filtering profile</h2>
          <p className="text-sm text-slate-500 mt-1">All profiles below are public and require no account or registration.</p>
        </div>
        <div className="grid md:grid-cols-2 gap-4">
          {profiles.map(profile => {
            const selectedNow = selectedProfile === profile.id;
            return (
              <button
                key={profile.id}
                onClick={() => setSelectedProfile(profile.id)}
                className={`text-left rounded-xl border p-5 transition-colors ${
                  selectedNow
                    ? "border-emerald-500 bg-emerald-500/10"
                    : "border-slate-800 bg-slate-900 hover:border-slate-700"
                }`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <span className="text-xs uppercase tracking-wide text-slate-500">{profile.provider}</span>
                    <h3 className="font-semibold text-white mt-1">{profile.name}</h3>
                  </div>
                  <span className={`px-2 py-1 rounded text-[10px] uppercase tracking-wide ${
                    profile.category === "family"
                      ? "bg-violet-500/15 text-violet-300"
                      : profile.category === "privacy"
                        ? "bg-cyan-500/15 text-cyan-300"
                        : "bg-emerald-500/15 text-emerald-300"
                  }`}>
                    {profile.category}
                  </span>
                </div>
                <p className="text-sm text-slate-400 mt-3">{profile.description}</p>
                <div className="mt-4 font-mono text-xs text-slate-500 space-y-1">
                  <p>IPv4: {profile.ipv4.join(" · ")}</p>
                  <p>IPv6: {profile.ipv6.join(" · ")}</p>
                </div>
              </button>
            );
          })}
        </div>
      </section>

      {selected && (
        <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h2 className="font-medium text-white">Selected: {selected.provider} {selected.name}</h2>
            <p className="text-sm text-slate-500 mt-1">ClamShield applies both IPv4 and IPv6 resolvers to each active adapter to avoid an IPv6 filtering bypass.</p>
          </div>
          <a
            href={selected.websiteUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 text-sm text-indigo-400 hover:text-indigo-300 shrink-0"
          >
            Provider documentation
            <ExternalLink className="w-4 h-4" />
          </a>
        </section>
      )}

      <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center gap-2 font-medium text-slate-200">
          <Network className="w-5 h-5 text-indigo-400" />
          Active adapters
        </div>
        <div className="divide-y divide-slate-800">
          {(status.adapters || []).map((adapter: any) => {
            const adapterState = adapter.dnsProtectionApplied
              ? { label: "Protected", className: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30" }
              : adapter.dnsProtectionPartial
                ? { label: "Partial", className: "bg-amber-500/10 text-amber-300 border-amber-500/30" }
                : { label: "Different DNS", className: "bg-slate-800 text-slate-400 border-slate-700" };
            return (
            <div key={adapter.interfaceIndex} className="px-5 py-4 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <p className="text-slate-200 font-medium">{adapter.interfaceAlias}</p>
                  {status.enabled && (
                    <span className={`text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full border ${adapterState.className}`}>
                      {adapterState.label}
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-500 mt-1">Interface {adapter.interfaceIndex}</p>
              </div>
              <div className="font-mono text-xs text-slate-400 lg:text-right">
                <p>IPv4: {adapter.ipv4?.length ? adapter.ipv4.join(" · ") : "Automatic / unavailable"}</p>
                <p className="mt-1">IPv6: {adapter.ipv6?.length ? adapter.ipv6.join(" · ") : "Automatic / unavailable"}</p>
              </div>
            </div>
            );
          })}
        </div>
      </section>

      <div className="text-xs text-slate-500 leading-relaxed">
        DNS filtering does not inspect files and cannot replace ClamAV, YARA, browser security, or safe browsing habits. VPNs, browsers with their own Secure DNS setting, and captive portals may bypass or temporarily conflict with Windows DNS settings.
      </div>
    </div>
  );
}
