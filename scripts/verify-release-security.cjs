const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function validateAudit(report) {
  const counts = report?.metadata?.vulnerabilities;
  if (!counts || !Number.isInteger(counts.total) || counts.total < 0 || !report.vulnerabilities) {
    throw new Error('Dependency audit did not return a complete report. Release blocked.');
  }
  if (counts.total !== 0 || Object.keys(report.vulnerabilities).length !== 0) {
    throw new Error(`Dependency audit found ${counts.total} vulnerable dependency entries. Release blocked; development dependencies and Electron are included.`);
  }
}

function verifyInstalledDependencies(root) {
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  for (const [location, expected] of Object.entries(lock.packages)) {
    if (!location) continue;
    const manifest = path.join(root, location, 'package.json');
    if (!fs.existsSync(manifest)) {
      if (expected.optional || expected.devOptional) continue;
      throw new Error(`Missing installed dependency: ${location}. Run npm ci before packaging.`);
    }
    const installed = JSON.parse(fs.readFileSync(manifest, 'utf8'));
    if (installed.version !== expected.version) {
      throw new Error(`Installed dependency differs from lockfile: ${location} (${installed.version}, expected ${expected.version}). Run npm ci before packaging.`);
    }
  }
}

function verifyRelease(root = path.resolve(__dirname, '..')) {
  verifyInstalledDependencies(root);
  const npmCli = process.env.npm_execpath || path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  if (!fs.existsSync(npmCli)) throw new Error('Cannot locate npm for the full dependency audit. Run through npm or npx. Release blocked.');
  const result = spawnSync(process.execPath, [npmCli, 'audit', '--json', '--include=dev', '--include=optional'], {
    cwd: root, encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 10 * 1024 * 1024
  });
  if (result.error) throw new Error(`Dependency audit failed: ${result.error.message}. Release blocked.`);
  let report;
  try { report = JSON.parse(result.stdout); } catch { throw new Error('Dependency audit returned unreadable output. Release blocked.'); }
  validateAudit(report);
  if (result.status !== 0) throw new Error('Dependency audit did not complete successfully. Release blocked.');
  const native = spawnSync(process.execPath, [path.join(root, 'scripts/update-native-tools.cjs'), '--check'], {
    cwd: root, encoding: 'utf8', windowsHide: true, timeout: 180000, maxBuffer: 1024 * 1024
  });
  if (native.error || native.status !== 0) throw new Error(`Native helper freshness verification failed. Release blocked. ${native.error?.message || native.stderr}`);
  process.stdout.write(native.stdout);
  console.log('Release security gate passed: installed dependencies match the lockfile; full audit found zero known vulnerabilities.');
}

module.exports = context => verifyRelease(context?.packager?.projectDir);
module.exports.validateAudit = validateAudit;
module.exports.verifyInstalledDependencies = verifyInstalledDependencies;
if (require.main === module) {
  try { verifyRelease(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
