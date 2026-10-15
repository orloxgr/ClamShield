import { useEffect, useRef, useState } from "react";
import { Loader2 } from "lucide-react";

export default function UpdateJobProgress({ jobId, title, simulated = false, onFinished }: {
  jobId: string | null; title: string; simulated?: boolean; onFinished?: () => void;
}) {
  const [lines, setLines] = useState<string[]>([]);
  const [state, setState] = useState("connecting");
  const outputRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (jobId) panelRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [jobId]);

  useEffect(() => {
    setLines([]);
    setState("connecting");
    if (!jobId) return;
    if (simulated) {
      setLines(["Simulation mode: no signature download was performed."]);
      setState("complete");
      return;
    }
    let stopped = false, finished = false, firstEvent = true, polling = false;
    let fallback: number | undefined;
    const source = new EventSource(`/api/scan/${encodeURIComponent(jobId)}/events`);
    const stopPolling = () => { if (fallback !== undefined) window.clearInterval(fallback); fallback = undefined; };
    const consume = (data: any, snapshot: boolean) => {
      if (stopped || finished) return;
      const next = Array.isArray(data.logs) ? data.logs.map(String).slice(-800) : [];
      setLines(previous => snapshot ? next : [...previous, ...next].slice(-800));
      if (data.status === "missing") {
        setState("unavailable");
      } else if (data.status === "done") {
        setState(typeof data.result === "number" && data.result !== 0 ? "failed" : "complete");
      } else {
        setState("updating");
        return;
      }
      finished = true;
      source.close(); stopPolling(); onFinished?.();
    };
    const poll = async () => {
      if (polling || stopped || finished) return;
      polling = true;
      try {
        const response = await fetch(`/api/scan/${encodeURIComponent(jobId)}?peek=1`, { cache: "no-store" });
        if (response.status === 404) consume({ status: "missing" }, true);
        else if (response.ok) consume(await response.json(), true);
      } catch { /* Keep the last output visible while the connection recovers. */ }
      finally { polling = false; }
    };
    source.onopen = () => { firstEvent = true; stopPolling(); };
    source.addEventListener("job", event => {
      try { consume(JSON.parse((event as MessageEvent).data), firstEvent); firstEvent = false; }
      catch { setState("reconnecting"); }
    });
    source.onerror = () => {
      if (stopped || finished) return;
      setState("reconnecting");
      if (fallback === undefined) { poll(); fallback = window.setInterval(poll, 3000); }
    };
    return () => { stopped = true; source.close(); stopPolling(); };
  }, [jobId, simulated, onFinished]);

  useEffect(() => {
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [lines]);

  if (!jobId) return null;
  const active = ["connecting", "updating", "reconnecting"].includes(state);
  const label = { connecting: "Connecting…", updating: "Updating…", reconnecting: "Reconnecting…", complete: "Complete", failed: "Failed", unavailable: "Log no longer available" }[state];
  return (
    <section ref={panelRef} className="overflow-hidden rounded-xl border border-slate-700 bg-slate-950" aria-label={`${title} progress`}>
      <div className="flex items-center justify-between gap-3 border-b border-slate-800 bg-slate-900 px-4 py-3">
        <span className="text-sm font-medium text-slate-200">{title}</span>
        <span role="status" className={`flex items-center gap-2 text-xs ${state === "failed" ? "text-red-300" : "text-slate-400"}`}>
          {active && <Loader2 className="h-4 w-4 animate-spin" />}{label}
        </span>
      </div>
      <div ref={outputRef} role="log" aria-label={`${title} log`} aria-live="polite"
        className="h-52 overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-xs leading-relaxed text-emerald-300/90">
        {lines.length ? lines.map((line, index) => <div key={index}>{line}</div>) : "Waiting for update output…"}
      </div>
    </section>
  );
}
