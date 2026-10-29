import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { validateSource } = require('../scripts/release-source.cjs');
const { assetNames, digest, createManifest, verifyManifest } = require('../scripts/release-manifest.cjs');
const { verifyUploaded } = require('../scripts/publish-release.cjs');
const { finalizeRelease } = require('../scripts/finalize-release.cjs');
const { validateReusableRun, selectReusableArtifact } = require('../scripts/reuse-release-artifact.cjs');
const yaml = require('js-yaml');
const sha = 'a'.repeat(40), version = '9.8.7';
function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clamshield-release-'));
  const names = assetNames(version), exe = Buffer.from('signed installer fixture'), hash = digest(exe, 'sha512', 'base64');
  fs.writeFileSync(path.join(directory, names[0]), exe);
  fs.writeFileSync(path.join(directory, names[1]), 'final blockmap');
  fs.writeFileSync(path.join(directory, 'latest.yml'), `version: ${version}\nfiles:\n  - url: ${names[0]}\n    sha512: ${hash}\n    size: ${exe.length}\npath: ${names[0]}\nsha512: ${hash}\n`);
  fs.writeFileSync(path.join(directory, 'SHA256SUMS.txt'), names.slice(0, 3).map((name: string) => `${digest(fs.readFileSync(path.join(directory, name)))}  ${name}`).join('\n')+'\n');
  return { directory, names, clean: () => { assert.equal(path.dirname(directory), os.tmpdir()); fs.rmSync(directory, { recursive: true, force: true }); } };
}
test('release source rejects moving refs, mismatched checkouts and version/tag mismatches', () => {
  assert.equal(validateSource(sha, sha, version, version).sha, sha);
  assert.equal(validateSource(`v${version}`, sha, version, version).tag, `v${version}`);
  for (const args of [['main',sha,version,version],['--upload-pack=x',sha,version,version],['b'.repeat(40),sha,version,version],[sha,sha,version,'1.0.0'],['v1.0.0',sha,version,version]]) assert.throws(() => validateSource(...args));
});
test('sealed release rejects any artifact replacement, missing files and a different source commit', () => {
  for (const index of [0,1,2,3]) {
    const f = fixture();
    try {
      createManifest(f.directory, sha, version);
      assert.doesNotThrow(() => verifyManifest(f.directory, sha, version));
      assert.throws(() => verifyManifest(f.directory, 'b'.repeat(40), version), /mismatch/);
      fs.appendFileSync(path.join(f.directory,f.names[index]), 'changed');
      assert.throws(() => verifyManifest(f.directory,sha,version), /changed after sealing/);
      fs.unlinkSync(path.join(f.directory,f.names[index]));
      assert.throws(() => verifyManifest(f.directory,sha,version));
    } finally { f.clean(); }
  }
});
test('stale pre-signing updater metadata cannot be sealed even with fresh SHA-256 checksums', () => {
  const f=fixture();
  try {
    fs.appendFileSync(path.join(f.directory,f.names[0]),'signature');
    fs.writeFileSync(path.join(f.directory,'SHA256SUMS.txt'),f.names.slice(0,3).map((name:string)=>`${digest(fs.readFileSync(path.join(f.directory,name)))}  ${name}`).join('\n'));
    assert.throws(()=>createManifest(f.directory,sha,version),/Updater metadata differs/);
  } finally { f.clean(); }
});
test('publication rejects truncated, incomplete, or substituted server-side assets', () => {
  const f=fixture();
  try {
    const assets=f.names.map((name:string)=>{const bytes=fs.readFileSync(path.join(f.directory,name));return {name,size:bytes.length,digest:`sha256:${digest(bytes)}`,state:'uploaded'};});
    verifyUploaded(assets,f.directory,f.names);
    for(const change of [{size:1},{digest:`sha256:${'0'.repeat(64)}`},{state:'uploading'}])assert.throws(()=>verifyUploaded([{...assets[0],...change},...assets.slice(1)],f.directory,f.names));
    assert.throws(()=>verifyUploaded(assets.slice(1),f.directory,f.names));
  } finally { f.clean(); }
});
test('final signing targets only the installer, so unpacked executables cannot change after packaging', async () => {
  const f=fixture();
  try {
    fs.writeFileSync(path.join(f.directory,'package.json'),JSON.stringify({version}));
    const folder=path.join(f.directory,'release',version);fs.mkdirSync(folder,{recursive:true});
    const installer=path.join(folder,f.names[0]);fs.copyFileSync(path.join(f.directory,f.names[0]),installer);
    const calls:any[]=[];await finalizeRelease(f.directory,async (context:any)=>calls.push(context));
    assert.deepEqual(calls,[{artifactPaths:[installer]}]);
  } finally { f.clean(); }
});
test('release runs the shared full CI suite before audit, packaging, signatures, sealing and attestation', () => {
  const ci=yaml.load(fs.readFileSync('.github/workflows/ci.yml','utf8'));
  const release=yaml.load(fs.readFileSync('.github/workflows/release-build.yml','utf8'));
  const common=yaml.load(fs.readFileSync('.github/actions/validate/action.yml','utf8'));
  assert.ok(ci.jobs.validate.steps.some((s:any)=>s.uses==='./.github/actions/validate'));
  assert.ok(common.runs.steps.some((s:any)=>s.run==='npm test'));
  for(const command of ['npm run test:desktop-navigation','node scripts/test-desktop-alerts.cjs','npm run test:virustotal-ui','npm run test:localization-ui'])assert.ok(common.runs.steps.some((s:any)=>s.run===command));
  const steps=release.jobs.build.steps;
  const ordered=[steps.findIndex((s:any)=>s.uses==='./.github/actions/validate'),steps.findIndex((s:any)=>s.run==='npm run audit:security'),steps.findIndex((s:any)=>s.run?.includes('npm run build:exe')),steps.findIndex((s:any)=>s.run==='node scripts/finalize-release.cjs'),steps.findIndex((s:any)=>s.run?.includes('verify-release-signatures.ps1')),steps.findIndex((s:any)=>s.run?.includes('release-manifest.cjs create')),steps.findIndex((s:any)=>s.uses?.startsWith('actions/attest@'))];
  assert.ok(ordered.every((index:number,i:number)=>index>=0&&(!i||index>ordered[i-1])));
  assert.equal(release.jobs.build.permissions.contents,'read');
  assert.equal(release.jobs.publish.permissions.contents,'write');
  assert.deepEqual(release.jobs.publish.needs,['build','reuse']);
  assert.ok(release.jobs.publish.steps.some((s:any)=>s.run?.includes('--source-digest')));
  assert.ok(!release.jobs.publish.steps.some((s:any)=>/npm (ci|install|run build)|electron-builder|sign-windows/.test(s.run||'')));
  for(const job of Object.values(release.jobs) as any[])for(const step of job.steps)if(step.uses&&!step.uses.startsWith('./'))assert.match(step.uses,/@[a-f0-9]{40}$/);
});

test('artifact promotion rejects failed builds, pull-request runs, foreign sources and substituted artifacts', () => {
  const repository = 'owner/project';
  const run = { repository: { full_name: repository }, head_repository: { full_name: repository },
    path: '.github/workflows/release-build.yml', event: 'workflow_dispatch', status: 'completed', conclusion: 'success', head_sha: sha };
  assert.doesNotThrow(() => validateReusableRun(run, repository, sha));
  for (const change of [{ conclusion: 'failure' }, { status: 'in_progress' }, { event: 'pull_request' },
    { head_sha: 'b'.repeat(40) }, { path: '.github/workflows/ci.yml' }, { head_repository: { full_name: 'foreign/fork' } }])
    assert.throws(() => validateReusableRun({ ...run, ...change }, repository, sha));
  const artifact = { id: 123, name: `ClamShield-${sha}`, expired: false };
  assert.equal(selectReusableArtifact([artifact], sha), 123);
  for (const artifacts of [[], [{ ...artifact, expired: true }], [artifact, artifact], [{ ...artifact, id: -1 }], [{ ...artifact, name: 'other' }]])
    assert.throws(() => selectReusableArtifact(artifacts, sha));
});
