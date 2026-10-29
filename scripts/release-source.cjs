const fs = require('node:fs');
const { execFileSync } = require('node:child_process');

function validateSource(ref, sha, version, lockVersion) {
  if (!/^(?:[a-f0-9]{40}|v\d+\.\d+\.\d+)$/.test(ref || '')) throw new Error('Select a published full commit SHA or version tag; moving branch names are not release inputs.');
  if (!/^[a-f0-9]{40}$/.test(sha || '')) throw new Error('Invalid source commit');
  if (!/^\d+\.\d+\.\d+$/.test(version || '') || version !== lockVersion) throw new Error('Package and lockfile release versions must agree.');
  if (ref.startsWith('v') && ref !== `v${version}`) throw new Error('Selected tag does not match the package version.');
  if (!ref.startsWith('v') && ref !== sha) throw new Error('Checkout differs from selected commit.');
  return { sha, version, tag: `v${version}` };
}
function readSource(ref, root = process.cwd()) {
  const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', windowsHide: true }).trim();
  const pkg = JSON.parse(fs.readFileSync(`${root}/package.json`, 'utf8'));
  const lock = JSON.parse(fs.readFileSync(`${root}/package-lock.json`, 'utf8'));
  const result = validateSource(ref, git(['rev-parse', 'HEAD']), pkg.version, lock.version);
  if (process.env.GITHUB_SHA && process.env.GITHUB_SHA !== result.sha) throw new Error('Dispatch the workflow from the same commit/tag as the selected release source so provenance identifies the tested source.');
  if (lock.packages?.['']?.version !== result.version) throw new Error('Root lockfile package version differs.');
  if (git(['rev-parse', '--verify', `${ref}^{commit}`]) !== result.sha) throw new Error('Selected ref does not identify the checkout.');
  git(['merge-base', '--is-ancestor', result.sha, 'refs/remotes/origin/main']);
  git(['diff', '--exit-code', 'HEAD']);
  return result;
}
module.exports = { validateSource, readSource };
if (require.main === module) {
  try {
    const result = readSource(process.env.RELEASE_SOURCE_REF);
    if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `sha=${result.sha}\nversion=${result.version}\ntag=${result.tag}\n`);
    console.log(`Release source fixed at ${result.sha}; ${result.tag}`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
