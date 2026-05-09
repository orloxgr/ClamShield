import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';

type ScanState = "idle" | "running" | "done";

interface ScanContextType {
  scanState: ScanState;
  output: string[];
  progressOutput: string[];
  jobId: string | null;
  progress: any | null;
  resumableScan: any | null;
  startScan: (type: string, target?: string) => Promise<void>;
  resumeScan: () => Promise<void>;
  discardResumableScan: () => Promise<void>;
  cancelScan: () => void;
  resetScan: () => void;
}

const ScanContext = createContext<ScanContextType | null>(null);
const MAX_TERMINAL_LINES = 800;
const MAX_PROGRESS_LINES = 80;
const MAX_TERMINAL_LINE_LENGTH = 2000;

function normalizeOutputLines(next: string[]) {
  return next.map(line => {
    const text = typeof line === "string" ? line : (JSON.stringify(line) ?? String(line));
    return text.length > MAX_TERMINAL_LINE_LENGTH ? `${text.slice(0, MAX_TERMINAL_LINE_LENGTH)}...` : text;
  });
}

function isProgressLine(line: string) {
  return /^-{3,}\s*SCAN (SUMMARY|PROGRESS)\s*-{3,}$/i.test(line) ||
    /^(Scanned files|Infected files|Total errors|Time):/i.test(line) ||
    /^Batch \d+\/\d+(?::|\s+complete\b)/i.test(line) ||
    /^(YARA )?Threat found:/i.test(line) ||
    /^Action:/i.test(line) ||
    /^Quarantine failed/i.test(line) ||
    /File path check failure|Can't get file status|Can't open file or directory|Access denied/i.test(line) ||
    /^YARA (scan started|ruleset:|scanned files:|skipped|process error|matches:)/i.test(line) ||
    /^(Scan complete|Updating real-time protection cache|Protection cache)/i.test(line);
}

function fileNameFromPath(filePath: string) {
  const parts = filePath.split(/[\\/]/).filter(Boolean);
  return parts.at(-1) || filePath || "Unknown file";
}

function normalizeProgressLine(line: string) {
  if (/^-{3,}\s*SCAN SUMMARY\s*-{3,}$/i.test(line)) return "----------- SCAN PROGRESS -----------";
  if (/^Time:/i.test(line)) return line.replace(/^Time:/i, "Time per batch:");
  const unreadableMatch = line.match(/^(.+?):\s+(File path check failure|Can't get file status|Can't open file or directory|Access denied)/i);
  if (unreadableMatch) return `Skipped unreadable file: ${fileNameFromPath(unreadableMatch[1])}`;
  return line;
}

function progressLineKey(line: string) {
  if (/^-{3,}\s*SCAN PROGRESS\s*-{3,}$/i.test(line)) return "header";
  if (/^Batch \d+\/\d+/i.test(line)) return "batch";
  if (/^(YARA )?Threat found:/i.test(line)) return "threat";
  if (/^Action:/i.test(line)) return "action";
  if (/^Quarantine failed/i.test(line)) return "action";
  if (/^Skipped unreadable file:/i.test(line)) return "fileWarning";
  if (/^Scanned files:/i.test(line)) return "scanned";
  if (/^Infected files:/i.test(line)) return "infected";
  if (/^Total errors:/i.test(line)) return "errors";
  if (/^Time per batch:/i.test(line)) return "time";
  if (/^YARA scan started/i.test(line)) return "yaraStatus";
  if (/^YARA ruleset:/i.test(line)) return "yaraRuleset";
  if (/^YARA scanned files:/i.test(line)) return "yaraScanned";
  if (/^YARA skipped/i.test(line)) return "yaraStatus";
  if (/^YARA process error/i.test(line)) return "yaraStatus";
  if (/^YARA matches:/i.test(line)) return "yaraMatches";
  if (/^Scan complete/i.test(line)) return "complete";
  if (/^(Updating real-time protection cache|Protection cache)/i.test(line)) return "cache";
  return line;
}

function upsertProgressLine(previousProgress: string[], line: string) {
  const key = progressLineKey(line);
  const existingIndex = previousProgress.findIndex(existing => progressLineKey(existing) === key);
  if (existingIndex >= 0) {
    const next = [...previousProgress];
    next[existingIndex] = line;
    return next;
  }
  return [...previousProgress, line].slice(-MAX_PROGRESS_LINES);
}

function appendScanOutput(previous: string[], previousProgress: string[], next: string[]) {
  let output = previous;
  let progressOutput = previousProgress;
  for (const line of normalizeOutputLines(next)) {
    if (isProgressLine(line)) {
      const normalizedLine = normalizeProgressLine(line);
      if (/^-{3,}\s*SCAN PROGRESS\s*-{3,}$/i.test(normalizedLine)) {
        progressOutput = [normalizedLine];
      } else {
        progressOutput = upsertProgressLine(progressOutput, normalizedLine);
      }
    } else {
      output = [...output, line].slice(-MAX_TERMINAL_LINES);
    }
  }
  return { output, progressOutput };
}

function scanLabel(type: string) {
  if (type === "memory") return "process";
  if (type === "disk") return "full";
  return type;
}

function canResumeScanType(type?: string) {
  return type === "disk" || type === "folder" || type === "file";
}

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [output, setOutput] = useState<string[]>([]);
  const [progressOutput, setProgressOutput] = useState<string[]>([]);
  const progressOutputRef = useRef<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  const [progress, setProgress] = useState<any | null>(null);
  const [resumableScan, setResumableScan] = useState<any | null>(null);
  const [isSimulated, setIsSimulated] = useState<boolean>(false);
  const eventSourceRef = useRef<EventSource | null>(null);

  const closeJobStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  };

  const refreshResumableScan = useCallback(async () => {
    try {
      const res = await fetch("/api/scan/resumable");
      if (!res.ok) return;
      const data = await res.json();
      setResumableScan(data.available ? data.progress : null);
    } catch (e) {
      console.error("Failed to load resumable scan:", e);
    }
  }, []);

  const startScan = async (type: string, target?: string) => {
    closeJobStream();
    setScanState("running");
    setOutput([`Starting ${scanLabel(type)} scan...`, target ? `Target: ${target}` : ''].filter(Boolean));
    setProgressOutput([]);
    progressOutputRef.current = [];
    setProgress(null);
    setJobId(null);
    if (canResumeScanType(type)) setResumableScan(null);
    
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, target })
      });
      const data = await res.json();
      
      if (!res.ok) {
        throw new Error(data.error || "An unknown error occurred");
      }
      setJobId(data.jobId);
      setIsSimulated(!!data.simulated);

      if (data.simulated) {
        setOutput(prev => [...prev, "Running in simulation mode. Wait 3 seconds..."].slice(-MAX_TERMINAL_LINES));
        setTimeout(() => {
          setOutput(prev => {
            const next = appendScanOutput(prev, progressOutputRef.current, ["Scan complete. Simulated results saved.", "----------- SCAN SUMMARY -----------", "Scanned files: 1240", "Infected files: 0"]);
            progressOutputRef.current = next.progressOutput;
            setProgressOutput(next.progressOutput);
            return next.output;
          });
          setProgress({ scannedFiles: 1240, totalFiles: 1240, phase: "Complete", status: "done", currentFile: "Complete" });
          setScanState("done");
          setJobId(null);
        }, 3000);
      }
    } catch (e: any) {
      setOutput(prev => [...prev, `Error: ${e.message}`].slice(-MAX_TERMINAL_LINES));
      setScanState("done");
      setJobId(null);
    }
  };

  const resumeScan = async () => {
    if (!resumableScan?.jobId) return;
    closeJobStream();
    setScanState("running");
    setOutput([`Resuming ${scanLabel(resumableScan.type)} scan...`, resumableScan.target ? `Target: ${resumableScan.target}` : ''].filter(Boolean));
    setProgressOutput([]);
    progressOutputRef.current = [];
    setProgress(resumableScan);
    setJobId(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resumeJobId: resumableScan.jobId })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to resume scan");
      }
      setResumableScan(null);
      setJobId(data.jobId);
      setIsSimulated(!!data.simulated);
      if (data.progress) setProgress(data.progress);
    } catch (e: any) {
      setOutput(prev => [...prev, `Error: ${e.message}`].slice(-MAX_TERMINAL_LINES));
      setScanState("done");
      setJobId(null);
      refreshResumableScan();
    }
  };

  const discardResumableScan = async () => {
    if (!resumableScan?.jobId) return;
    try {
      await fetch(`/api/scan/${encodeURIComponent(resumableScan.jobId)}/discard`, { method: "POST" });
      setResumableScan(null);
    } catch (e) {
      console.error("Failed to discard resumable scan:", e);
    }
  };

  const cancelScan = async () => {
    if (jobId) {
      try {
        await fetch(`/api/scan/${jobId}/cancel`, { method: "POST" });
      } catch (e) {
        console.error("Failed to cancel scan", e);
      }
    }
    setScanState("done");
    const resumable = canResumeScanType(progress?.type);
    setOutput(prev => [...prev, resumable ? "Scan paused. You can resume it later." : "Scan cancelled by user."].slice(-MAX_TERMINAL_LINES));
    setProgress(prev => prev ? { ...prev, status: resumable ? "paused" : "done", phase: resumable ? "Paused" : "Cancelled", currentFile: resumable ? "Paused" : "Cancelled" } : prev);
    setJobId(null);
    closeJobStream();
    refreshResumableScan();
  };

  const resetScan = () => {
    closeJobStream();
    setScanState("idle");
    setOutput([]);
    setProgressOutput([]);
    progressOutputRef.current = [];
    setJobId(null);
    setProgress(null);
  };

  // Server-Sent Events keep scan output/progress live without polling.
  useEffect(() => {
    if (scanState === "running" && jobId && !isSimulated) {
      const source = new EventSource(`/api/scan/${encodeURIComponent(jobId)}/events`);
      eventSourceRef.current = source;

      const handleJobEvent = (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          if (data.progress) {
            setProgress(data.progress);
          }
          if (Array.isArray(data.logs) && data.logs.length > 0) {
            setOutput(prev => {
              const next = appendScanOutput(prev, progressOutputRef.current, data.logs);
              progressOutputRef.current = next.progressOutput;
              setProgressOutput(next.progressOutput);
              return next.output;
            });
          }
          if (data.status === "done" || data.status === "missing") {
            setScanState("done");
            setJobId(null);
            closeJobStream();
            setTimeout(() => refreshResumableScan(), 250);
          }
        } catch (e) {
          console.error("Failed to process scan event:", e);
        }
      };

      source.addEventListener("job", handleJobEvent);
      source.onerror = () => {
        console.error("Scan event stream disconnected; waiting for reconnect.");
      };
    }

    return () => {
      closeJobStream();
    };
  }, [scanState, jobId, isSimulated, refreshResumableScan]);

  useEffect(() => {
    refreshResumableScan();
  }, [refreshResumableScan]);

  return (
    <ScanContext.Provider value={{ scanState, output, progressOutput, jobId, progress, resumableScan, startScan, resumeScan, discardResumableScan, cancelScan, resetScan }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error("useScan must be used within a ScanProvider");
  }
  return context;
}
