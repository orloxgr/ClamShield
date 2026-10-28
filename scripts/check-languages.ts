import fs from 'node:fs';
import path from 'node:path';
import { englishPack, validateLanguagePack } from '../shared/localization/runtime';
import { readBoundedJson } from '../shared/localization/files';

const files = process.argv.slice(2);
if (!files.length) files.push(...fs.readdirSync('languages').filter(name => name.endsWith('.json')).map(name => path.join('languages', name)));
let failed = false;
for (const file of files) {
  try {
    const pack = validateLanguagePack(readBoundedJson(path.resolve(file)));
    const translated = Object.values(pack.strings).filter(entry => entry.translation || entry.forms).length;
    console.log(`${file}: valid; ${translated}/${Object.keys(englishPack.strings).length} translated. Missing text falls back to English.`);
  } catch (error: any) { failed = true; console.error(`${file}: ${error.message}`); }
}
process.exitCode = failed ? 1 : 0;
