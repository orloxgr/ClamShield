// Maintainer-only refresh of the trusted native-helper inventory. Downloads
// metadata from the official package publisher and pins every archive digest.
const fs = require('node:fs');
const crypto = require('node:crypto');
async function refresh() {
  const packages = new Map();
  async function add(name) {
    if (packages.has(name)) return;
    packages.set(name, null);
    const source = `https://packages.msys2.org/packages/${name}`;
    const response = await fetch(source);
    if (!response.ok) throw new Error(`Metadata unavailable: ${name}`);
    const html = await response.text();
    const url = html.match(/File:<\/dt>[\s\S]*?href="([^"]+)"/)?.[1];
    const sha256 = html.match(/SHA256:<\/dt>[\s\S]*?<code>([a-f0-9]{64})<\/code>/)?.[1];
    const version = html.match(/Version:<\/dt>\s*<dd[^>]*>([^<]+)/)?.[1]?.trim();
    if (!url?.startsWith('https://mirror.msys2.org/') || !sha256 || !version) throw new Error(`Invalid publisher metadata: ${name}`);
    const section = html.match(/>Dependencies:<\/dt>\s*<dd[^>]*>([\s\S]*?)<\/dd>/)?.[1] || '';
    const dependencies = [...section.matchAll(/href="https:\/\/packages\.msys2\.org\/packages\/([^/?\"]+)(?:\?[^\"]*)?"/g)].map(m => decodeURIComponent(m[1]));
    if (dependencies.some(value => !/^[a-zA-Z0-9_.+-]+$/.test(value))) throw new Error('Unexpected native package name');
    const directUrl = new URL(url); directUrl.hostname = 'repo.msys2.org';
    packages.set(name, { name, version, source, url: directUrl.href, sha256, family: name.startsWith('mingw-') ? 'archive' : 'msys', dependencies });
    for (const dependency of dependencies) await add(dependency);
  }
  for (const name of ['rsync', 'msys2-runtime', 'mingw-w64-ucrt-x86_64-7zip']) await add(name);
  const page = await (await fetch('https://gnupg.org/download/index.html')).text();
  const relative = page.match(/href="([^"]*gnupg-w32-([\d.]+)_\d+\.exe)"/)?.[1];
  if (!relative) throw new Error('No current official GnuPG Windows release');
  const url = new URL(relative, 'https://gnupg.org/download/index.html').href;
  if (!url.startsWith('https://gnupg.org/ftp/gcrypt/binary/')) throw new Error('Unexpected GnuPG publisher');
  const response = await fetch(url);
  if (!response.ok) throw new Error('GnuPG download failed');
  const bytes = Buffer.from(await response.arrayBuffer());
  const gnupg = { version: url.match(/gnupg-w32-([\d.]+)_/)[1], url, sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  const manifest = { schemaVersion: 1, reviewedAt: new Date().toISOString().slice(0, 10), packages: [...packages.values()].sort((a,b) => a.name.localeCompare(b.name)), gnupg };
  const target = require('node:path').resolve(__dirname, '../addons/sanesecurity/server/native-tools.json');
  if (process.argv.includes('--check')) {
    const current = JSON.parse(fs.readFileSync(target, 'utf8'));
    const content = value => JSON.stringify({ packages: value.packages, gnupg: value.gnupg });
    if (content(current) !== content(manifest)) throw new Error('Native helper inventory is outdated. Refresh, review and validate the new packages before release.');
    console.log('Native helper inventory matches the current official releases and publisher checksums.');
    return;
  }
  fs.writeFileSync(target, JSON.stringify(manifest, null, 2) + '\n');
  console.log(`Pinned ${packages.size} official native packages; rsync ${packages.get('rsync').version}; GnuPG ${gnupg.version}. Review the inventory before committing.`);
}
refresh().catch(error => { console.error(error.message); process.exitCode = 1; });
