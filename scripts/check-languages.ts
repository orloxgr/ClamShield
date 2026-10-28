import fs from 'node:fs';
import path from 'node:path';
import { englishPack, languageLengthWarnings, validateLanguagePack } from '../shared/localization/runtime';
import { readBoundedJson } from '../shared/localization/files';

const details = process.argv.includes('--details');
const files = process.argv.slice(2).filter(arg => arg !== '--details');
if (!files.length) files.push(...fs.readdirSync('languages').filter(name => name.endsWith('.json')).map(name => path.join('languages', name)));
let failed = false;
for (const file of files) {
  try {
    const pack = validateLanguagePack(readBoundedJson(path.resolve(file)));
    const translated = Object.values(pack.strings).filter(entry => entry.translation || entry.forms).length;
    const warnings = languageLengthWarnings(pack);
    console.log(`${file}: valid; ${translated}/${Object.keys(englishPack.strings).length} translated; ${warnings.length} length warnings (non-blocking).`);
    if (details || files.length === 1) for (const warning of warnings)
      console.warn(`${file}: ${warning.key} [${warning.field}]: ${warning.actual} characters; recommended maximum ${warning.maxChars}. Translation remains active: ${JSON.stringify(warning.translation)}`);
  } catch (error: any) { failed = true; console.error(`${file}: ${error.message}`); }
}
if (!details && files.length > 1) console.log('Use --details or pass one language file to list individual length warnings. Length warnings do not fail validation.');
process.exitCode = failed ? 1 : 0;
