const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const digest = (data, algorithm = 'sha256', encoding = 'hex') => crypto.createHash(algorithm).update(data).digest(encoding);
function assetNames(version) {
  if (!/^\d+\.\d+\.\d+$/.test(version || '')) throw new Error('Invalid release version');
  return [`ClamShield-Setup-${version}.exe`, `ClamShield-Setup-${version}.exe.blockmap`, 'latest.yml', 'SHA256SUMS.txt'];
}
function readAsset(directory, name) {
  const file = path.join(directory, name), info = fs.lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink() || !info.size) throw new Error(`Invalid release artifact: ${name}`);
  return fs.readFileSync(file);
}
function verifyMetadata(directory, version) {
  const [installer] = assetNames(version), exe = readAsset(directory, installer);
  const latest = readAsset(directory, 'latest.yml').toString('utf8').replace(/\r\n/g, '\n');
  const hashes = [...latest.matchAll(/^\s*(?:-\s*)?sha512:\s*(\S+)\s*$/gm)];
  if (!latest.includes(`version: ${version}\n`) || !latest.includes(installer) || hashes.length !== 2 || hashes.some(match => match[1] !== digest(exe, 'sha512', 'base64')) || !new RegExp(`^\\s*size: ${exe.length}\\s*$`, 'm').test(latest)) throw new Error('Updater metadata differs from the final signed installer.');
  const sums = readAsset(directory, 'SHA256SUMS.txt').toString('utf8').trim().split(/\r?\n/);
  const expected = assetNames(version).filter(name => name !== 'SHA256SUMS.txt');
  if (sums.length !== expected.length) throw new Error('Checksum manifest has missing or unexpected artifacts.');
  for (const name of expected) if (!sums.includes(`${digest(readAsset(directory, name))}  ${name}`)) throw new Error(`Release checksum differs: ${name}`);
}
function createManifest(directory, sourceCommit, version) {
  if (!/^[a-f0-9]{40}$/.test(sourceCommit || '')) throw new Error('Invalid release source commit');
  verifyMetadata(directory, version);
  const files = assetNames(version).map(name => { const bytes = readAsset(directory, name); return { name, size: bytes.length, sha256: digest(bytes) }; });
  const manifest = { schemaVersion: 1, sourceCommit, version, tag: `v${version}`, files };
  fs.writeFileSync(path.join(directory, 'release-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}
function verifyManifest(directory, sourceCommit, version) {
  const manifest = JSON.parse(readAsset(directory, 'release-manifest.json').toString('utf8'));
  if (manifest.schemaVersion !== 1 || manifest.sourceCommit !== sourceCommit || manifest.version !== version || manifest.tag !== `v${version}`) throw new Error('Release manifest source/version mismatch.');
  const names = assetNames(version);
  if (!Array.isArray(manifest.files) || manifest.files.length !== names.length || new Set(manifest.files.map(file => file.name)).size !== names.length) throw new Error('Unexpected release file list.');
  for (const file of manifest.files) {
    if (!names.includes(file.name)) throw new Error('Unexpected release file name.');
    const bytes = readAsset(directory, file.name);
    if (file.size !== bytes.length || file.sha256 !== digest(bytes)) throw new Error(`Release artifact changed after sealing: ${file.name}`);
  }
  verifyMetadata(directory, version);
  return manifest;
}
module.exports = { assetNames, digest, verifyMetadata, createManifest, verifyManifest };
if (require.main === module) {
  try {
    const [mode, directory, sha, version] = process.argv.slice(2);
    if (!['create', 'verify'].includes(mode)) throw new Error('Use create or verify');
    (mode === 'create' ? createManifest : verifyManifest)(directory, sha, version);
    console.log(`Release ${mode}: ${version} from ${sha}`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
