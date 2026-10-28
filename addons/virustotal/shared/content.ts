// Recognise old persisted errors too, so upgrading immediately fixes their guidance.
export function isVirusTotalContentChange(value: any) {
  return value?.fileChanged === true || value?.virusTotalChecks?.resultsBlockedReason === "content_changed" ||
    /^File (?:changed during upload|content changed since the detection)/i.test(String(value?.message || value?.virusTotalRefinement?.message || ""));
}

export const virusTotalContentChangedMessage = "The VirusTotal analysis belongs to a different version of this file and cannot assess the current file. Scan the current file again, or remove this old finding from Results. Removing a finding does not delete the file or add an exception.";
