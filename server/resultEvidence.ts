// A new local detection at the same path may concern different bytes.
export function freshScanEvidence(result: any, existing: any) {
  if (result?.virusTotalRefinement) return {};
  if (/^[a-f0-9]{64}$/i.test(result?.sha256 || "") && result.sha256 === existing?.sha256) return {};
  return { sha256: "", sha1: "", md5: "", virusTotalChecks: {}, virusTotalRefinement: null };
}
