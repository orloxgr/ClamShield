import React, { createContext, useContext, useState, useEffect, useRef } from 'react';

type ScanState = "idle" | "running" | "done";

interface ScanContextType {
  scanState: ScanState;
  output: string[];
  jobId: string | null;
  startScan: (type: string, target?: string) => Promise<void>;
  cancelScan: () => void;
  resetScan: () => void;
}

const ScanContext = createContext<ScanContextType | null>(null);
const MAX_TERMINAL_LINES = 800;

function appendOutput(previous: string[], next: string[]) {
  return [...previous, ...next].slice(-MAX_TERMINAL_LINES);
}

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [output, setOutput] = useState<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSimulated, setIsSimulated] = useState<boolean>(false);
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const startScan = async (type: string, target?: string) => {
    setScanState("running");
    setOutput([`Initiating ${type} scan...`, target ? `Target: ${target}` : '']);
    
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

      setOutput(prev => appendOutput(prev, [`Job created with ID: ${data.jobId}`]));
      setJobId(data.jobId);
      setIsSimulated(!!data.simulated);

      if (data.simulated) {
        setOutput(prev => appendOutput(prev, ["Running in simulation mode. Wait 3 seconds..."]));
        setTimeout(() => {
          setOutput(prev => appendOutput(prev, ["Scan complete. Simulated results saved.", "----------- SCAN SUMMARY -----------", "Known viruses: 12345", "Engine version: Simulated", `Target: ${target || type}`, "Scanned directories: 50", "Scanned files: 1240", "Infected files: 0"]));
          setScanState("done");
          setJobId(null);
        }, 3000);
      }
    } catch (e: any) {
      setOutput(prev => appendOutput(prev, [`Error: ${e.message}`]));
      setScanState("done");
      setJobId(null);
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
    setOutput(prev => appendOutput(prev, ["Scan cancelled by user."]));
    setJobId(null);
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  };

  const resetScan = () => {
    setScanState("idle");
    setOutput([]);
    setJobId(null);
  };

  // Polling hook
  useEffect(() => {
    if (scanState === "running" && jobId && !isSimulated) {
      pollIntervalRef.current = setInterval(async () => {
        try {
          const res = await fetch(`/api/scan/${jobId}`);
          if (res.ok) {
            const data = await res.json();
            if (data.logs && data.logs.length > 0) {
              setOutput(prev => appendOutput(prev, data.logs));
            }
            if (data.status === "done") {
              setScanState("done");
              setJobId(null);
              clearInterval(pollIntervalRef.current!);
              pollIntervalRef.current = null;
            }
          }
        } catch (e) {
          console.error("Failed to poll scan status:", e);
        }
      }, 1000);
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [scanState, jobId, isSimulated]);

  return (
    <ScanContext.Provider value={{ scanState, output, jobId, startScan, cancelScan, resetScan }}>
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
