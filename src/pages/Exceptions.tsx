import { useState, useEffect } from "react";
import { CheckCircle2, ShieldCheck, Trash2, FolderPlus, FilePlus, Send, Loader2 } from "lucide-react";
import PageHeader from "../components/PageHeader";

type FalsePositiveChannel = "default" | "gmail" | "outlook";

const falsePositiveChannelNames: Record<FalsePositiveChannel, string> = {
  default: "report channel",
  gmail: "Gmail compose",
  outlook: "Outlook compose"
};

export default function ExceptionsPage() {
  const [exceptions, setExceptions] = useState<Array<{ path: string, report: any | null }>>([]);
  const [addingError, setAddingError] = useState("");
  const [noticeKind, setNoticeKind] = useState<"error" | "info">("error");
  const [reportingTarget, setReportingTarget] = useState<{ path: string, channel: FalsePositiveChannel } | null>(null);
  const [preparedReports, setPreparedReports] = useState<Record<string, boolean>>({});

  const fetchExceptions = async () => {
    try {
      const r = await fetch("/api/exceptions/reporting");
      const data = await r.json();
      if (Array.isArray(data)) {
        setExceptions(data);
        setPreparedReports(prev => {
          const next = { ...prev };
          data.forEach((item: any) => {
            if (item?.path && (item.report?.falsePositiveOpenedAt || item.report?.falsePositiveLastOpenedAt)) {
              next[item.path] = true;
            }
          });
          return next;
        });
      }
    } catch {
      setExceptions([]);
    }
  };

  useEffect(() => {
    fetchExceptions();
  }, []);

  const handleAdd = async (type: "file" | "folder") => {
    try {
      setAddingError("");
      const response = await fetch(`/api/select-${type}`);
      const data = await response.json();
      
      let selectedPath = data.path;
      if (!selectedPath) {
        selectedPath = window.prompt(`[Simulated] Enter a ${type} path manually:`, "C:\\TestPath\\" + type);
      }

      if (selectedPath) {
        const exceptionPaths = exceptions.map(item => item.path);
        if (exceptionPaths.includes(selectedPath)) {
          setNoticeKind("error");
          setAddingError("Path is already in exceptions.");
          return;
        }
        const updated = [...exceptionPaths, selectedPath];
        await fetch("/api/exceptions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ exceptions: updated })
        });
        fetchExceptions();
      }
    } catch (e: any) {
      setNoticeKind("error");
      setAddingError("Failed to add exception.");
    }
  };

  const removeException = async (path: string) => {
    try {
      const updated = exceptions.map(item => item.path).filter(item => item !== path);
      await fetch("/api/exceptions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ exceptions: updated })
      });
      fetchExceptions();
    } catch {
       // Ignore error
    }
  };

  const reportFalsePositive = async (exceptionPath: string, channel: FalsePositiveChannel = "default") => {
    setReportingTarget({ path: exceptionPath, channel });
    setAddingError("");
    try {
      const response = await fetch("/api/exceptions/report-false-positive", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: exceptionPath, channel })
      });
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || "Could not prepare the false-positive report.");
      await navigator.clipboard?.writeText(data.details).catch(() => {});
      const targetUrl = channel === "gmail" ? data.emailUrls?.gmail : channel === "outlook" ? data.emailUrls?.outlook : data.url;
      if (!targetUrl) throw new Error(`${falsePositiveChannelNames[channel]} is not available for this provider.`);
      window.open(targetUrl, "_blank", "noopener,noreferrer");
      setPreparedReports(prev => ({ ...prev, [exceptionPath]: true }));
      setNoticeKind("info");
      setAddingError(
        `Opened ${channel === "default" ? data.provider.name : falsePositiveChannelNames[channel]}. Report details were copied to the clipboard.${
          data.requiresSample ? " Attach or upload the file only if you are comfortable sharing it with that provider." : ""
        }`
      );
    } catch (error: any) {
      setNoticeKind("error");
      setAddingError(error.message || "Could not prepare the false-positive report.");
    } finally {
      setReportingTarget(null);
    }
  };

  return (
    <div className="px-8 max-w-5xl mx-auto space-y-8 pb-20 animate-in slide-in-from-bottom-4 duration-500">
      <PageHeader
        title="Exceptions"
        description="Files and folders excluded from future scans"
        actions={(
        <div className="flex gap-3">
            <button 
                onClick={() => handleAdd("file")}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700"
            >
                <FilePlus className="w-4 h-4" />
                <span>Add File</span>
            </button>
            <button 
                onClick={() => handleAdd("folder")}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700"
            >
                <FolderPlus className="w-4 h-4" />
                <span>Add Folder</span>
            </button>
        </div>
        )}
      />

      {addingError && (
        <div className={`p-4 rounded-lg text-sm border ${
          noticeKind === "info"
            ? "bg-indigo-500/10 border-indigo-500/20 text-indigo-200"
            : "bg-red-500/10 border-red-500/20 text-red-400"
        }`}>
          {addingError}
        </div>
      )}

      {exceptions.length === 0 ? (
        <div className="flex items-center justify-center p-12 mt-12 bg-slate-900 border border-slate-800 rounded-2xl flex-col text-center">
          <ShieldCheck className="w-16 h-16 text-slate-700 mb-4" />
          <h2 className="text-xl font-medium text-slate-300 mb-2">No Exceptions Added</h2>
          <p className="text-slate-500 max-w-md">
            Any files or directories you add here will be ignored by both the active Shield and manual scans.
          </p>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
          <div className="divide-y divide-slate-800">
            {exceptions.map((exception, idx) => (
              <div key={idx} className="flex justify-between items-center p-4 hover:bg-slate-800/50 transition-colors">
                <div className="min-w-0 pr-4">
                  <span className="font-mono text-sm text-slate-300 truncate block" title={exception.path}>{exception.path}</span>
                  {exception.report && (
                    <span className="text-xs text-slate-500 mt-1 block">
                      {exception.report.threatName} · Report to {exception.report.provider.name}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {exception.report && (
                    <button
                      onClick={() => reportFalsePositive(exception.path)}
                      disabled={reportingTarget !== null}
                      className={`inline-flex items-center gap-2 px-3 py-2 text-xs hover:text-white disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors border ${
                        preparedReports[exception.path]
                          ? "text-emerald-200 bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/30"
                          : "text-indigo-300 bg-indigo-500/10 hover:bg-indigo-500/20 border-indigo-500/20"
                      }`}
                      title={
                        preparedReports[exception.path]
                          ? `Open the ${exception.report.provider.name} false-positive channel again`
                          : `Open the ${exception.report.provider.name} false-positive channel`
                      }
                    >
                      {reportingTarget?.path === exception.path && reportingTarget.channel === "default" ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : preparedReports[exception.path] ? (
                        <CheckCircle2 className="w-4 h-4" />
                      ) : (
                        <Send className="w-4 h-4" />
                      )}
                      {reportingTarget?.path === exception.path && reportingTarget.channel === "default" ? "Opening report..." : preparedReports[exception.path] ? "Report opened" : "Report false positive"}
                    </button>
                  )}
                  {exception.report?.provider?.method === "email" && (
                    <>
                      <button
                        onClick={() => reportFalsePositive(exception.path, "gmail")}
                        disabled={reportingTarget !== null}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-2 text-xs hover:text-white disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors border ${
                          preparedReports[exception.path]
                            ? "text-emerald-200 bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/30"
                            : "text-slate-300 bg-slate-800 hover:bg-slate-700 border-slate-700"
                        }`}
                        title="Open Gmail compose with the false-positive report"
                      >
                        {reportingTarget?.path === exception.path && reportingTarget.channel === "gmail" ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : preparedReports[exception.path] ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : null}
                        Gmail
                      </button>
                      <button
                        onClick={() => reportFalsePositive(exception.path, "outlook")}
                        disabled={reportingTarget !== null}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-2 text-xs hover:text-white disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors border ${
                          preparedReports[exception.path]
                            ? "text-emerald-200 bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/30"
                            : "text-slate-300 bg-slate-800 hover:bg-slate-700 border-slate-700"
                        }`}
                        title="Open Outlook compose with the false-positive report"
                      >
                        {reportingTarget?.path === exception.path && reportingTarget.channel === "outlook" ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : preparedReports[exception.path] ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : null}
                        Outlook
                      </button>
                    </>
                  )}
                  <button
                    onClick={() => removeException(exception.path)}
                    className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors flex-shrink-0"
                    title="Remove exception"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
