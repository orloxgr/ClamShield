const fs = require('node:fs');
const path = require('node:path');

async function finalizeRelease(root, signer) {
  const { version } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Invalid release version');
  const installer = path.join(root, 'release', version, `ClamShield-Setup-${version}.exe`);
  if (!fs.statSync(installer).isFile()) throw new Error('Installer is missing');
  // electron-builder writes latest.yml after afterAllArtifactBuild. Refresh it
  // only after the final installer signature; never re-sign packaged app files.
  await signer({ artifactPaths: [installer] });
  return installer;
}
module.exports = { finalizeRelease };
if (require.main === module) {
  if (process.env.CLAMSHIELD_REQUIRE_SIGNING !== '1') { console.error('Release finalization requires mandatory signing.'); process.exitCode = 1; }
  else finalizeRelease(path.resolve(__dirname, '..'), require('./sign-windows-artifacts.cjs')).catch(error => { console.error(error.message); process.exitCode = 1; });
}
