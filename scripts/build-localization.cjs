const path = require('node:path');
const { buildSync } = require('esbuild');
const root = path.resolve(__dirname, '..');
for (const [entry, output, platform] of [
  ['shared/localization/runtime.ts', 'public/localization-runtime.cjs', 'neutral'],
  ['shared/localization/desktop.ts', 'public/desktop-localization.cjs', 'node']
]) buildSync({ absWorkingDir: root, entryPoints: [entry], outfile: output, bundle: true, platform, format: 'cjs', target: 'es2022' });
buildSync({ absWorkingDir: root, entryPoints: ['shared/localization/runtime.ts'], outfile: 'public/localization-browser.js', bundle: true, platform: 'browser', format: 'iife', globalName: 'ClamShieldLocalization', target: 'es2022' });
console.log('Built trusted localization runtimes with the canonical English catalog.');
