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
function publish(directory, sha, version, repository = process.env.GITHUB_REPOSITORY, executeGh = args => execFileSync('gh', args, { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository || '')) throw new Error('Invalid release repository');
  verifyManifest(directory, sha, version);
  const gh = executeGh;
  const api = endpoint => JSON.parse(gh(['api', `repos/${repository}/${endpoint}`]));
  const optional = endpoint => { try { return api(endpoint); } catch (error) { if (String(error.stderr).includes('(HTTP 404)')) return null; throw error; } };
  const tag = `v${version}`;
  // The tag endpoint returns published releases only. Drafts must be found in
  // the authenticated listing and subsequently addressed by their numeric ID.
  const findRelease = () => {
    const pages = JSON.parse(gh(['api', '--paginate', '--slurp', `repos/${repository}/releases?per_page=100`]));
    if (!Array.isArray(pages) || pages.some(page => !Array.isArray(page))) throw new Error('Incomplete release listing.');
    const matches = pages.flat().filter(item => item.tag_name === tag);
    if (matches.length > 1) throw new Error('Ambiguous release tag.');
    return matches[0];
  };
  let uploaded = findRelease();
  if (uploaded && !uploaded.draft) throw new Error('Release already exists; immutable releases are never overwritten.');
  const verifyTag = (required = false) => {
    let object = optional(`git/ref/tags/${tag}`)?.object;
    if (!object) {
      if (required) throw new Error('Published release tag is missing.');
      return;
    }
    for (let depth = 0; object.type === 'tag' && depth < 5; depth++) object = api(`git/tags/${object.sha}`).object;
    if (object.type !== 'commit' || object.sha !== sha) throw new Error('Release tag identifies a different source commit.');
  };
  verifyTag();
  const names = [...assetNames(version), 'release-manifest.json', 'provenance.json'];
  if (!fs.statSync(path.join(directory, 'provenance.json')).isFile()) throw new Error('Release provenance is missing.');
  const notes = `ClamShield ${version}\n\nSource commit: ${sha}\n\nThe installer was built, tested, signed and attested by the Release Build workflow. Verify the attached SHA256SUMS.txt, release-manifest.json and provenance.json before installation.\n\nSigning identity and Windows certificate trust are reported by the installer's Authenticode signature; GitHub provenance does not grant public certificate trust.`;
  if (!uploaded) {
    gh(['release', 'create', tag, ...names.map(name => path.join(directory, name)), '--repo', repository, '--target', sha, '--title', `ClamShield ${version}`, '--draft', '--notes', notes]);
    uploaded = findRelease();
  }
  if (!Number.isSafeInteger(uploaded?.id) || uploaded.id <= 0) throw new Error('Draft release ID is missing.');
  const releaseId = uploaded.id;
  uploaded = api(`releases/${releaseId}`);
  if (uploaded.id !== releaseId || uploaded.draft !== true || uploaded.prerelease !== false || uploaded.tag_name !== tag || uploaded.target_commitish !== sha) throw new Error('Unexpected draft release source/state.');
  verifyManifest(directory, sha, version);
  verifyUploaded(uploaded.assets, directory, names);
  gh(['api', '--method', 'PATCH', `repos/${repository}/releases/${releaseId}`, '-F', 'draft=false', '-f', 'make_latest=true']);
  const released = api(`releases/${releaseId}`);
  if (released.id !== releaseId || released.draft !== false || released.prerelease !== false || released.tag_name !== tag || released.target_commitish !== sha) throw new Error('Release did not become public with the expected source.');
  verifyTag(true);
  verifyUploaded(released.assets, directory, names);
  console.log(released.html_url);
  return released;
}
module.exports = { publish, verifyUploaded };
if (require.main === module) {
  try { publish(...process.argv.slice(2, 5)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
