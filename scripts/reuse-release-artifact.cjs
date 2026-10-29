const fs = require('node:fs');
const { execFileSync } = require('node:child_process');
const { validateSource } = require('./release-source.cjs');

function validateReusableRun(run, repository, sha) {
  if (run?.repository?.full_name !== repository || run.head_repository?.full_name !== repository ||
      run.path !== '.github/workflows/release-build.yml' || run.event !== 'workflow_dispatch' ||
      run.status !== 'completed' || run.conclusion !== 'success' || run.head_sha !== sha)
    throw new Error('Only a successful release-build run from the selected repository source can be published.');
}
function selectReusableArtifact(artifacts, sha) {
  const matches = artifacts.filter(item => item.name === `ClamShield-${sha}`);
  if (matches.length !== 1 || matches[0].expired || !Number.isSafeInteger(matches[0].id) || matches[0].id <= 0)
    throw new Error('The original immutable release artifact is missing, expired or ambiguous.');
  return matches[0].id;
}
async function reuseRelease() {
  const repository = process.env.GITHUB_REPOSITORY;
  const runId = process.env.RELEASE_ARTIFACT_RUN_ID;
  const ref = process.env.RELEASE_SOURCE_REF;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository || '') || !/^[1-9]\d*$/.test(runId || '') ||
      !/^(?:[a-f0-9]{40}|v\d+\.\d+\.\d+)$/.test(ref || '')) throw new Error('Invalid release artifact/source input.');
  const git = args => execFileSync('git', args, { encoding: 'utf8', windowsHide: true }).trim();
  const sha = git(['rev-parse', '--verify', `${ref}^{commit}`]);
  git(['merge-base', '--is-ancestor', sha, 'refs/remotes/origin/main']);
  const pkg = JSON.parse(git(['show', `${sha}:package.json`]));
  const lock = JSON.parse(git(['show', `${sha}:package-lock.json`]));
  const source = validateSource(ref, sha, pkg.version, lock.version);
  if (lock.packages?.['']?.version !== source.version) throw new Error('Release lockfile version differs.');
  async function api(endpoint) {
    const response = await fetch(`https://api.github.com/repos/${repository}/${endpoint}`, {
      headers: { authorization: `Bearer ${process.env.GH_TOKEN}`, accept: 'application/vnd.github+json' },
      signal: AbortSignal.timeout(30000)
    });
    if (!response.ok) throw new Error(`Release artifact metadata request failed (${response.status}).`);
    return response.json();
  }
  validateReusableRun(await api(`actions/runs/${runId}`), repository, sha);
  const listing = await api(`actions/runs/${runId}/artifacts?per_page=100`);
  if (!Array.isArray(listing.artifacts) || listing.total_count > 100) throw new Error('Incomplete release artifact listing.');
  const artifactId = selectReusableArtifact(listing.artifacts, sha);
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `sha=${sha}\nversion=${source.version}\ntag=${source.tag}\nartifact_id=${artifactId}\nrun_id=${runId}\n`);
  console.log(`Selected immutable artifact ${artifactId} from release run ${runId}; ${source.tag} at ${sha}. No rebuild.`);
}
module.exports = { validateReusableRun, selectReusableArtifact };
if (require.main === module) reuseRelease().catch(error => { console.error(error.message); process.exitCode = 1; });
