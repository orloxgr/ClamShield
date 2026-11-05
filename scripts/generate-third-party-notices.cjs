// Read package metadata and license text as data; never load dependency code.
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
const records = [];
for (const [location, expected] of Object.entries(lock.packages)) {
  // Tailwind contributes generated CSS even though its compiler is a build tool.
  if (!location || (expected.dev && location !== 'node_modules/tailwindcss')) continue;
  if (!/^node_modules\/(?:[@\w.+-]+\/)*[\w.+-]+$/.test(location) || location.split('/').includes('..')) {
    throw new Error(`Unsafe dependency location: ${location}`);
  }
  const directory = path.join(root, location);
  if (!fs.existsSync(directory)) {
    if (expected.optional) continue;
    throw new Error(`Install locked dependencies first: ${location}`);
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
  if (manifest.version !== expected.version) throw new Error(`Dependency version mismatch: ${location}`);
  const license = manifest.license;
  if (typeof license !== 'string' || !license.trim()) throw new Error(`Missing license metadata: ${location}`);
  const names = fs.readdirSync(directory).filter(name => /^(?:LICEN[CS]E|COPYING|NOTICE)(?:$|[.-])/i.test(name)
    && fs.statSync(path.join(directory, name)).isFile()).sort();
  let text;
  if (names.length) {
    text = names.map(name => `${name}\n${fs.readFileSync(path.join(directory, name), 'utf8').trim()}`).join('\n\n');
  } else {
    // Some older MIT packages distribute their full notice inside README.md.
    const readme = fs.readFileSync(path.join(directory, 'README.md'), 'utf8');
    const match = /\n(?:#{1,3}\s+License\s*\n|License\s*\n[-=]+\s*\n)([\s\S]+)/i.exec(readme);
    if (!match || !/Copyright[\s\S]+Permission is hereby granted[\s\S]+THE SOFTWARE IS PROVIDED/i.test(match[1])) {
      throw new Error(`No complete license notice found: ${location}`);
    }
    text = `License section from README.md\n${match[1].trim()}`;
  }
  records.push({ name: manifest.name, version: manifest.version, location, license, text });
}
records.sort((a, b) => a.location.localeCompare(b.location, 'en'));
const output = [
  'CLAMSHIELD THIRD-PARTY NOTICES',
  '',
  'Generated from package-lock.json and the matching installed package contents.',
  'Includes production dependencies (including type-only peer packages that may be',
  'omitted by the packager) and Tailwind CSS. Build-only tools are not runtime dependencies.',
  'Each component retains its own license; this file does not relicense it.',
  '',
  'The Electron distribution includes LICENSE.electron.txt and LICENSES.chromium.html',
  'beside ClamShield.exe. Those cover Electron and its bundled Chromium/Node.js and',
  'other upstream components. Preserve those notices and the upstream signatures.',
  'The NSIS installer and its plugins have separate upstream licenses; see',
  'https://github.com/orloxgr/ClamShield/blob/main/docs/distribution-review.md.',
  'Separately downloaded engines, rule packs, signature',
  'databases and native helpers retain their publishers\' terms and notices.',
  '',
  ...records.map(record => `${'='.repeat(78)}\n${record.name} ${record.version}\n${record.location}\nDeclared license: ${record.license}\n\n${record.text}\n`)
].join('\n').replace(/\r\n/g, '\n').replace(/[ \t]+$/gm, '').trimEnd() + '\n';
const target = path.join(root, 'THIRD_PARTY_NOTICES.txt');
if (process.argv.includes('--check')) {
  if (!fs.existsSync(target) || fs.readFileSync(target, 'utf8').replace(/\r\n/g, '\n') !== output.replace(/\r\n/g, '\n')) {
    throw new Error('Third-party notices are stale. Run npm run licenses:generate and review the changes.');
  }
} else {
  fs.writeFileSync(target, output);
}
console.log(`Verified complete license notices for ${records.length} locked dependency entries.`);
