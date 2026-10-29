import { readBackendSource, serverTestContext } from "./testSupport";
import assert from "node:assert/strict";
import test from "node:test";
import { advanceVirusTotalResult, nextVirusTotalResultAttempt } from "../addons/virustotal/server/virusTotalResultWorkflow";
import { describeVirusTotalResult } from "../addons/virustotal/shared/state";
import fs from "node:fs";
import vm from "node:vm";
import ts from "../scripts/test-source.cjs";

const hash = "abc";
function fixture() {
  const item: any = { id: "result", sha256: hash };
  let now = 1000, uploads = 0, lookups = 0, polls = 0;
  let allowed = false, report: any = null, analysisError: any = null, uploadError: any = null;
  const saved: any[] = [];
  const deps = {
    now: () => now,
    lookup: async () => { lookups++; return { found: false, hash }; },
    upload: async () => { uploads++; if (uploadError) throw uploadError; return "analysis-1"; },
    analysis: async (id: string, fileHash: string) => { polls++; assert.equal(id, "analysis-1"); assert.equal(fileHash, hash); if (analysisError) throw analysisError; return report; },
    eligibility: async (explicit: boolean) => ({ allowed: explicit || allowed, reason: "disabled", message: "Automatic uploads are off. Choose Upload for analysis or quarantine the file." }),
    classify: (value: any) => ({ status: "likely_false_positive", label: "Likely false positive", report: value }),
    persist: async () => { saved.push(JSON.parse(JSON.stringify(item))); }
  };
  return { item, deps, saved, advance: (explicit = false) => advanceVirusTotalResult(item, hash, deps, explicit),
    allow: () => { allowed = true; }, time: (value: number) => { now = value; },
    complete: () => { report = { found: true, hash, stats: { undetected: 62 } }; },
    failPoll: (error: any) => { analysisError = error; }, failUpload: (error: any) => { uploadError = error; },
    counts: () => ({ uploads, lookups, polls }) };
}

test("missing hash report requires an explicit next step without uploading when consent is off", async () => {
  const f = fixture(); await f.advance();
  assert.equal(f.item.virusTotalRefinement.status, "upload_required");
  assert.equal(describeVirusTotalResult(f.item).action, "upload");
  assert.equal(nextVirusTotalResultAttempt(f.item), 0);
  assert.equal(f.counts().uploads, 0);
  assert.match(f.item.virusTotalRefinement.message, /Upload for analysis or quarantine/);
});

test("explicit upload with automatic uploads off persists the accepted ID and monitors its actual analysis", async () => {
  const f = fixture(); await f.advance(); await f.advance(true);
  assert.equal(f.item.virusTotalRefinement.status, "awaiting_analysis");
  assert.equal(f.saved.at(-1).virusTotalChecks.resultsUploadAnalysisId, "analysis-1");
  // Ten pending responses, including after serialising/reloading the saved record.
  for (let i = 0; i < 10; i++) { f.time((i + 1) * 100_000); await f.advance(); }
  assert.deepEqual(f.counts(), { uploads: 1, lookups: 1, polls: 10 });
  assert.ok(nextVirusTotalResultAttempt(JSON.parse(JSON.stringify(f.item))) > 0);
  f.complete(); await f.advance();
  assert.equal(f.item.virusTotalRefinement.status, "likely_false_positive");
  assert.equal(nextVirusTotalResultAttempt(f.item), 0);
});

test("automatic uploads have a visible queued stage and consent is checked again before submission", async () => {
  const f = fixture(); f.allow(); await f.advance();
  assert.equal(f.item.virusTotalRefinement.status, "upload_queued");
  assert.ok(nextVirusTotalResultAttempt(f.item) > 0); assert.equal(f.counts().uploads, 0);
  f.deps.eligibility = async () => ({ allowed: false, reason: "disabled", message: "Uploads are off. Choose Upload for analysis or quarantine." });
  await f.advance(); assert.equal(f.item.virusTotalRefinement.status, "upload_required");
  assert.equal(f.counts().uploads, 0);
});

test("legacy submissions stopped after five attempts resume via analysis ID without another upload", async () => {
  const f = fixture();
  f.item.virusTotalRefinement = { status: "unknown", report: { found: false } };
  f.item.virusTotalChecks = { resultsUploadedUnknownHash: hash, resultsUploadAnalysisId: "analysis-1", resultsUploadCheckAfter: 1, resultsUploadFollowupCount: 5 };
  assert.equal(nextVirusTotalResultAttempt(f.item), 1);
  await f.advance(); assert.deepEqual(f.counts(), { uploads: 0, lookups: 0, polls: 1 });
  assert.equal(describeVirusTotalResult(f.item).label, "Awaiting analysis");
});

test("rate limits preserve submission evidence and expose an automatic retry time", async () => {
  const f = fixture(); await f.advance(); await f.advance(true);
  f.failPoll(Object.assign(new Error("Rate limit reached"), { status: 429, nextAllowedAt: 2_000_000 }));
  await f.advance();
  assert.equal(f.item.virusTotalRefinement.status, "retry_pending");
  assert.equal(nextVirusTotalResultAttempt(f.item), 2_000_000);
  assert.equal(f.item.virusTotalChecks.resultsUploadAnalysisId, "analysis-1");
  f.failPoll(null); f.complete(); await f.advance();
  assert.equal(f.counts().uploads, 1); assert.equal(nextVirusTotalResultAttempt(f.item), 0);
});

test("an upload rate limit retries the pending upload without losing explicit permission", async () => {
  const f = fixture(); await f.advance();
  f.failUpload(Object.assign(new Error("Rate limited"), { status: 429 }));
  await f.advance(true); assert.equal(f.item.virusTotalRefinement.status, "retry_pending");
  assert.equal(f.item.virusTotalChecks.resultsUploadRequestedHash, hash);
  f.failUpload(null); await f.advance();
  assert.equal(f.item.virusTotalRefinement.status, "awaiting_analysis");
  assert.equal(f.counts().lookups, 1);
});

test("rejected API keys stop retrying and direct the user to Settings", async () => {
  const f = fixture(); await f.advance(); await f.advance(true);
  f.failPoll(Object.assign(new Error("API key rejected"), { status: 403 })); await f.advance();
  assert.equal(nextVirusTotalResultAttempt(f.item), 0);
  assert.equal(describeVirusTotalResult(f.item).action, "settings");
  assert.match(f.item.virusTotalRefinement.message, /Settings/);
});

test("expired analysis IDs fall back to a hash lookup and require a decision before resubmission", async () => {
  const f = fixture(); f.allow(); await f.advance(); await f.advance();
  f.failPoll(Object.assign(new Error("Analysis expired"), { analysisMissing: true }));
  await f.advance(); assert.equal(f.item.virusTotalRefinement.status, "retry_pending");
  await f.advance(); assert.equal(f.item.virusTotalRefinement.status, "upload_required");
  assert.equal(nextVirusTotalResultAttempt(f.item), 0); assert.equal(f.counts().uploads, 1);
  await f.advance(true); assert.equal(f.counts().uploads, 2);
});

test("unavailable files remain actionable without a retry loop or false verdict", async () => {
  const f = fixture(); await f.advance();
  f.deps.eligibility = async () => ({ allowed: false, reason: "unavailable", message: "Restore the file to upload, or remove the finding if the file is gone." });
  await f.advance(true);
  assert.equal(f.item.virusTotalRefinement.status, "upload_required");
  assert.match(describeVirusTotalResult(f.item).message, /Restore.*remove/);
  assert.equal(f.counts().uploads, 0);
});

test("unrequested and completed findings never become automatic pending tasks", () => {
  assert.equal(nextVirusTotalResultAttempt({}), 0);
  assert.equal(nextVirusTotalResultAttempt({ sha256: hash }), 0);
  assert.equal(nextVirusTotalResultAttempt({ sha256: "changed", virusTotalChecks: { resultsUploadedUnknownHash: hash } }), 0);
});

test("rechecking a completed submission refreshes the hash report instead of repeating an old analysis", async () => {
  const f = fixture(); await f.advance(); await f.advance(true); f.complete(); await f.advance();
  f.deps.lookup = async () => ({ found: true, hash, stats: { malicious: 15 } });
  f.deps.classify = report => ({ status: "confirmed_malicious", label: "Malicious", report });
  await f.advance();
  assert.equal(f.item.virusTotalRefinement.status, "confirmed_malicious");
  assert.equal(f.counts().polls, 1); assert.equal(f.counts().uploads, 1);
});

test("production verdicts require a report and completed engines, with no terminal unknown verdict", () => {
  const source = readBackendSource();
  const tree = ts.createSourceFile("server.ts", source, ts.ScriptTarget.Latest, true);
  const node = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === "classifyVirusTotalRefinement");
  assert.ok(node);
  const context = serverTestContext({});
  vm.runInContext(ts.transpile(node.getText(tree)), context);
  const classify = context.classifyVirusTotalRefinement;
  assert.equal(classify({ found: false }).status, "upload_required");
  assert.equal(classify({ found: true, stats: {} }).status, "needs_review");
  assert.equal(classify({ found: true, stats: { undetected: 62 } }).status, "likely_false_positive");
  assert.equal(classify({ found: true, stats: { malicious: 2 } }).status, "needs_review");
  assert.equal(classify({ found: true, stats: { malicious: 3 } }).label, "Suspicious");
  assert.equal(classify({ found: true, stats: { malicious: 10 } }).label, "Malicious");
});

test("content mismatches require a fresh scan; repeating a saved analysis cannot resolve them", async () => {
  const f = fixture(); await f.advance(); await f.advance(true);
  f.failPoll(Object.assign(new Error("Different content"), { fileChanged: true }));
  await f.advance();
  assert.equal(f.item.virusTotalChecks.resultsBlockedReason, "content_changed");
  assert.equal(nextVirusTotalResultAttempt(f.item), 0);
  assert.equal(describeVirusTotalResult(f.item).action, "rescan");
  assert.equal(describeVirusTotalResult(f.item).label, "File changed");
  assert.doesNotMatch(describeVirusTotalResult(f.item).message, /Restore access/);
  const counts = f.counts();
  await f.advance(true);
  assert.deepEqual(f.counts(), counts, "retry must not repeat the mismatched analysis or upload");
});

test("already saved generic content-mismatch errors immediately get the correct scan/remove guidance", () => {
  const item = { virusTotalRefinement: { status: "blocked", message: "File changed during upload; the VirusTotal analysis belongs to different content. Restore access to the original file and retry, or remove this finding if the file is already gone." }, virusTotalChecks: { resultsBlockedReason: "file" } };
  const view = describeVirusTotalResult(item);
  assert.equal(view.action, "rescan"); assert.equal(view.label, "File changed");
  assert.match(view.message, /remove this old finding from Results/);
  assert.doesNotMatch(view.message, /Restore access/);
});
