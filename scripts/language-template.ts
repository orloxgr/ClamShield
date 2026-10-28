import fs from 'node:fs';
import { englishPack, validateLanguagePack } from '../shared/localization/runtime';
validateLanguagePack(englishPack);
const template = { ...englishPack, language: { code: 'es', name: 'Español', direction: 'ltr' },
  strings: Object.fromEntries(Object.entries(englishPack.strings).map(([key, entry]) => [key, { ...entry, translation: '' }])) };
fs.writeFileSync('languages/template.json', JSON.stringify(template, null, 2) + '\n');
console.log('Updated languages/template.json');
