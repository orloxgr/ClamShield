import path from 'node:path';
import { translate, type LanguagePack } from './runtime';
import { writeLanguageText } from './files';

// The shell extension reads these fixed, bounded text files. Translations never
// become registry commands, command-line arguments, action IDs or file paths.
const labels = {
  clamav: 'backend.platform.scan_with_clamav_only',
  'clamav-yara': 'backend.platform.scan_with_clamav_yara',
  'clamav-yara-vt': 'backend.platform.scan_with_clamav_yara_virustotal',
  'add-exception': 'backend.platform.add_to_clamshield_exceptions'
};
export function writeShellLanguage(pack: LanguagePack, directory: string) {
  for (const [id, key] of Object.entries(labels)) {
    const text = translate(pack, key);
    if (Buffer.byteLength(text, 'utf8') > 1024 || /[\r\n\u0000]/.test(text)) throw new Error('Invalid shell label');
    writeLanguageText(path.join(directory, id + '.txt'), text, 1024);
  }
}
