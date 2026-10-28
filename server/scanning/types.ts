

export type ScanProgress = {
    jobId: string;
    type: string;
    target: string;
    status: string;
    phase: string;
    totalFiles: number;
    scannedFiles: number;
    currentFile: string;
    startedAt: number;
    updatedAt: number;
    completedAt?: number;
    threatsFound: number;
    errorsFound: number;
    result?: number;
    actionTaken: string;
    elapsedSeconds?: number;
    quietSeconds?: number;
    virusTotalAllFiles?: boolean;
};
