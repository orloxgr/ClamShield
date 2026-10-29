const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { verifyManifest, digest, assetNames } = require('./release-manifest.cjs');

function verifyUploaded(assets, directory, names) {
  if (!Array.isArray(assets) || assets.length !== names.length) throw new Error('GitHub release assets are incomplete.');
  for (const name of names) {
    const item = assets.find(asset => asset.name === name), bytes = fs.readFileSync(path.join(directory, name));
    if (!item || item.state !== 'uploaded' || item.size !== bytes.length || item.digest !== `sha256:${digest(bytes)}`) throw new Error(`Uploaded release bytes differ: ${name}`);
  }
}
function publish(directory, sha, version, repository = process.env.GITHUB_REPOSITORY) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository || '')) throw new Error('Invalid release repository');
  verifyManifest(directory, sha, version);
  const gh = args => execFileSync('gh', args, { encoding: 'utf8', windowsHide: true });
  const api = endpoint => JSON.parse(gh(['api', `repos/${repository}/${endpoint}`]));
  const optional = endpoint => { try { return api(endpoint); } catch (error) { if (String(error.stderr).includes('(HTTP 404)')) return null; throw error; } };
  const tag = `v${version}`;
  if (optional(`releases/tags/${tag}`)) throw new Error('Release already exists; immutable releases are never overwritten.');
  const verifyTag = () => {
    let object = optional(`git/ref/tags/${tag}`)?.object;
    if (!object) return;
    for (let depth = 0; object.type === 'tag' && depth < 5; depth++) object = api(`git/tags/${object.sha}`).object;
    if (object.type !== 'commit' || object.sha !== sha) throw new Error('Release tag identifies a different source commit.');
  };
  verifyTag();
  const names = [...assetNames(version), 'release-manifest.json', 'provenance.json'];
  if (!fs.statSync(path.join(directory, 'provenance.json')).isFile()) throw new Error('Release provenance is missing.');
  const notes = `ClamShield ${version}\n\nSource commit: ${sha}\n\nThe installer was built, tested, signed and attested by the Release Build workflow. Verify the attached SHA256SUMS.txt, release-manifest.json and provenance.json before installation.\n\nSigning identity and Windows certificate trust are reported by the installer's Authenticode signature; GitHub provenance does not grant public certificate trust.`;
  gh(['release', 'create', tag, ...names.map(name => path.join(directory, name)), '--repo', repository, '--target', sha, '--title', `ClamShield ${version}`, '--draft', '--notes', notes]);
  const uploaded = api(`releases/tags/${tag}`);
  if (!uploaded.draft || uploaded.prerelease || uploaded.target_commitish !== sha) throw new Error('Unexpected draft release source/state.');
  verifyManifest(directory, sha, version);
  verifyUploaded(uploaded.assets, directory, names);
  gh(['release', 'edit', tag, '--repo', repository, '--draft=false', '--latest']);
  const released = api(`releases/tags/${tag}`);
  if (released.draft || released.prerelease) throw new Error('Release did not become public.');
  verifyTag();
  verifyUploaded(released.assets, directory, names);
  console.log(released.html_url);
}
module.exports = { publish, verifyUploaded };
if (require.main === module) {
  try { publish(...process.argv.slice(2, 5)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
