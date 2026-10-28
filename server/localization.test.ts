import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import vm from 'node:vm';
import ts from 'typescript';
import { createRequire } from 'node:module';
import { englishPack, englishText, languageLabel, localizeText, setLanguage, t, translate, validateLanguagePack, type LanguagePack } from '../shared/localization/runtime';
import { LanguageFiles, maxLanguageBytes, readBoundedJson, readLanguagePreference, writeLanguageText } from '../shared/localization/files';
import { writeShellLanguage } from '../shared/localization/shell';
import { registerLanguageRoutes } from './core/languages';
import { apiSessionToken, requireLocalApiSession } from './core/security';

const require = createRequire(import.meta.url);
const keyFor = (english: string) => Object.keys(englishPack.strings).find(key => englishPack.strings[key].english === english)!;
const pack = (strings: Record<string, any> = {}): LanguagePack => ({ schemaVersion: 1, language: { code: 'es', name: 'Español', direction: 'ltr' }, strings });
const entry = (key: string, translation: string) => ({ ...englishPack.strings[key], translation });
function temporary() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clamshield-language-'));
  return { directory, clean: () => { assert.equal(path.dirname(directory), os.tmpdir()); fs.rmSync(directory, { recursive: true, force: true }); } };
}

test('the complete volunteer template validates and empty translations fall back to English', () => {
  assert.ok(Object.keys(validateLanguagePack(englishPack).strings).length > 1000);
  const template = validateLanguagePack(JSON.parse(fs.readFileSync('languages/template.json', 'utf8')));
  assert.deepEqual(Object.keys(template.strings), Object.keys(englishPack.strings));
  for (const [key, value] of Object.entries(template.strings)) {
    assert.equal(value.translation, '');
    assert.equal(translate(template, key), englishText(key));
    assert.ok(Array.from(value.english).length <= value.maxChars, key);
  }
});

test('language labels include native names and distinguish automatic drafts from complete volunteer reviews', () => {
  assert.equal(languageLabel(validateLanguagePack(englishPack).language), 'English');
  const draft = pack(); draft.language = { ...draft.language, englishName: 'Spanish', status: 'auto', reviewers: ['Partial helper'] };
  assert.equal(languageLabel(validateLanguagePack(draft).language), 'Spanish — Español (auto)');
  const reviewed = structuredClone(englishPack); reviewed.language = { code: 'es', englishName: 'Spanish', name: 'Español', direction: 'ltr', status: 'reviewed', reviewers: ['Juan Pérez', 'Ana'] };
  assert.equal(languageLabel(validateLanguagePack(reviewed).language), 'Spanish — Español (Juan Pérez, Ana)');
  assert.throws(() => validateLanguagePack({ ...reviewed, language: { ...reviewed.language, reviewers: [] } }));
  assert.throws(() => validateLanguagePack({ ...reviewed, strings: {} }));
  assert.throws(() => validateLanguagePack({ ...draft, language: { ...draft.language, status: 'verified' } }));
  assert.throws(() => validateLanguagePack({ ...draft, language: { ...draft.language, status: 'source' } }));
  assert.throws(() => validateLanguagePack({ ...draft, language: { ...draft.language, reviewers: [{ toString: 'unsafe' }] } }));
  assert.throws(() => validateLanguagePack({ ...draft, language: { ...draft.language, englishName: 'x'.repeat(61) } }));
});

test('bundled languages use base codes, preserve technical literals and distinguish draft and review credits', () => {
  const codes = ['en', 'zh', 'hi', 'es', 'ar', 'fr', 'bn', 'pt', 'id', 'ur', 'ru', 'de', 'el', 'it', 'tr', 'ja'].sort();
  const actual = fs.readdirSync('languages').filter(name => name.endsWith('.json') && name !== 'template.json').map(name => name.slice(0, -5)).sort();
  for (const code of codes) assert.ok(actual.includes(code), `Missing bundled language: ${code}`);
  assert.ok(actual.every(code => /^[a-z]{2,3}$/.test(code)));
  const registry = new LanguageFiles([path.resolve('languages')]).refresh();
  assert.deepEqual(registry.errors, []);
  assert.equal(registry.languages.length, actual.length);
  for (const code of actual) {
    const language = validateLanguagePack(readBoundedJson(path.resolve('languages', code + '.json')));
    assert.ok(Object.keys(language.strings).length > 0, code);
    if (code === 'en') assert.equal(language.language.status, 'source');
    else assert.ok(['auto', 'reviewed'].includes(language.language.status!));
    for (const [key, entry] of Object.entries(language.strings)) {
      for (const literal of ['ClamShield', 'ClamAV', 'VirusTotal', 'SecuriteInfo', 'SaneSecurity', 'YARA', 'infectedsecuriteinfo', 'Byron Iniotakis']) {
        const expected = entry.english.split(literal).length - 1;
        if (expected && entry.translation) assert.equal(entry.translation.split(literal).length - 1, expected, `${code}: ${key}: ${literal}`);
      }
    }
    if (codes.includes(code)) assert.equal(language.language.direction, ['ar', 'ur'].includes(code) ? 'rtl' : 'ltr');
    assert.ok(language.language.englishName);
    if (language.language.status === 'auto') assert.ok(languageLabel(language.language).endsWith('(auto)'));
    if (language.language.status === 'reviewed') assert.ok(languageLabel(language.language).endsWith(`(${language.language.reviewers!.join(', ')})`));
  }
});

test('every authored JSX text and literal translation key belongs to the catalog', () => {
  const visitFiles = (directory: string): string[] => fs.readdirSync(directory, { withFileTypes: true }).flatMap(item => item.isDirectory() ? visitFiles(path.join(directory, item.name)) : [path.join(directory, item.name)]);
  const english = new Set(Object.values(englishPack.strings).map(entry => entry.english));
  const brands = new Set(['ClamShield', 'SecuriteInfo', 'SaneSecurity', 'Sanesecurity', 'VT']);
  for (const file of ['src', 'modules', 'addons', 'engines', 'server', 'shared'].flatMap(visitFiles).filter(file => /\.tsx?$/.test(file) && !file.endsWith('.test.ts'))) {
    const tree = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    const visit = (node: ts.Node) => {
      if (ts.isJsxText(node)) {
        const text = node.text.replace(/\s+/g, ' ').trim();
        if (/[A-Za-z]/.test(text) && !brands.has(text) && !/^\S+\.(?:ign2|hdb|ndb)$/.test(text)) assert.ok(english.has(text), `${file}: ${text}`);
      }
      if (ts.isCallExpression(node) && ['t', 'englishText'].includes(node.expression.getText(tree)) && node.arguments[0] && ts.isStringLiteral(node.arguments[0]))
        assert.ok(englishPack.strings[node.arguments[0].text], `${file}: unknown key ${node.arguments[0].text}`);
      ts.forEachChild(node, visit);
    };
    visit(tree);
  }
});

test('desktop language IPC accepts only known top-level app windows and pages', () => {
  const source = fs.readFileSync('electron-main.cjs', 'utf8');
  const tree = ts.createSourceFile('electron-main.cjs', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const policy = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'trustedLanguageSender')!;
  const frame = {}, sender = { mainFrame: frame, getURL: () => 'http://127.0.0.1:1234/alert.html' };
  const popup = { isDestroyed: () => false, webContents: sender };
  const main = { isDestroyed: () => false, webContents: {} }; let delegated = 0;
  const context = vm.createContext({ URL, require, getPublicAssetPath: (name: string) => path.resolve('public', name), mainWindow: main, resultsReminderWindow: null, scanSummaryWindow: null, updateAvailableWindow: null,
    activeAlerts: new Map([['threat', popup]]), currentApiPort: 1234, trustedMainSender: () => { delegated++; return main; } });
  vm.runInContext(policy.getText(tree), context);
  assert.equal(context.trustedLanguageSender({ sender, senderFrame: frame }), popup);
  assert.throws(() => context.trustedLanguageSender({ sender, senderFrame: {} }), /Untrusted/);
  assert.throws(() => context.trustedLanguageSender({ sender: { ...sender }, senderFrame: frame }), /Untrusted/);
  sender.getURL = () => 'http://127.0.0.1:1234/not-an-app-page.html';
  assert.throws(() => context.trustedLanguageSender({ sender, senderFrame: frame }), /Untrusted/);
  sender.getURL = () => 'https://example.com/alert.html';
  assert.throws(() => context.trustedLanguageSender({ sender, senderFrame: frame }), /Untrusted/);
  sender.getURL = () => require('node:url').pathToFileURL(path.resolve('public/alert.html')).href + '?id=example';
  assert.equal(context.trustedLanguageSender({ sender, senderFrame: frame }), popup);
  sender.getURL = () => require('node:url').pathToFileURL(path.resolve('other/alert.html')).href;
  assert.throws(() => context.trustedLanguageSender({ sender, senderFrame: frame }), /Untrusted/);
  const mainSender = main.webContents as any; mainSender.mainFrame = frame;
  assert.equal(context.trustedLanguageSender({ sender: mainSender, senderFrame: frame }), main); assert.equal(delegated, 1);
});

test('language files cannot redefine identifiers, English, limits, metadata or prototypes', () => {
  const key = keyFor('Dashboard'), valid = pack({ [key]: entry(key, 'Panel') });
  for (const change of [
    { ...valid, schemaVersion: 2 }, { ...valid, script: 'alert(1)' },
    pack({ '../file': entry(key, 'Panel') }),
    pack({ [key]: { ...entry(key, 'Panel'), english: 'Different meaning' } }),
    pack({ [key]: { ...entry(key, 'Panel'), maxChars: 99999 } }),
    pack({ [key]: { ...entry(key, 'Panel'), onclick: 'alert(1)' } }),
    { ...valid, language: { ...valid.language, code: '../../escape' } },
    { ...valid, language: { ...valid.language, code: 'en-INVALID-INVALID-INVALID-INVALID-INVALID' } },
    { ...valid, language: { ...valid.language, direction: 'anything' } },
    JSON.parse('{"schemaVersion":1,"language":{"code":"es","name":"Español","direction":"ltr"},"strings":{"__proto__":{}}}')
  ]) assert.throws(() => validateLanguagePack(change));
  assert.equal(({} as any).polluted, undefined);
  for (const value of ['x'.repeat(englishPack.strings[key].maxChars + 1), 'Text\u202eevil', 'Text\nline', 'Text\0'])
    assert.throws(() => validateLanguagePack(pack({ [key]: entry(key, value) })));
});

test('placeholders stay data and translations may reorder or repeat known placeholders', () => {
  const [key, definition] = Object.entries(englishPack.strings).find(([, e]) => e.english.includes('{{') && !e.optionalParameters && e.maxChars > 50)!;
  const names = [...definition.english.matchAll(/\{\{(\w+)\}\}/g)].map(m => m[1]);
  const translated = [...names].reverse().map(name => '{{' + name + '}}').join(' ');
  validateLanguagePack(pack({ [key]: entry(key, translated) }));
  assert.throws(() => validateLanguagePack(pack({ [key]: entry(key, 'No parameters') })));
  assert.throws(() => validateLanguagePack(pack({ [key]: entry(key, translated + '{{unknown}}') })));
  const text = '<img onerror=alert(1)>';
  const result = translate(pack({ [key]: entry(key, translated) }), key, Object.fromEntries(names.map(name => [name, text])));
  assert.ok(result.includes(text));
  assert.equal((globalThis as any).injected, undefined);
});

test('declarative plural forms use Intl rules with no executable expressions', () => {
  const [key, definition] = Object.entries(englishPack.strings).find(([, e]) => e.plural && e.optionalParameters?.length)!;
  const required = [...definition.english.matchAll(/\{\{(\w+)\}\}/g)].map(m => m[1]).filter(name => !definition.optionalParameters!.includes(name));
  const value = required.map(name => '{{' + name + '}}').join(' ');
  validateLanguagePack(pack({ [key]: entry(key, value) }));
  assert.throws(() => validateLanguagePack(pack({ [key]: entry(key, 'No actual values') })));
  assert.throws(() => validateLanguagePack(pack({ [key]: entry(key, value + '{{unknown}}') })));
  const plural = { ...entry(key, ''), forms: { one: value + ' uno', other: value + ' varios' } };
  const language = validateLanguagePack(pack({ [key]: plural }));
  const args = Object.fromEntries(required.map(name => [name, 1]));
  assert.match(translate(language, key, args), /uno$/);
  args[definition.plural!] = 2;
  assert.match(translate(language, key, args), /varios$/);
  assert.throws(() => validateLanguagePack(pack({ [key]: { ...plural, forms: { eval: 'code', other: value } } })));
});

test('file discovery rejects malformed, oversized, mismatched and linked files and recovers on refresh', () => {
  const temp = temporary();
  try {
    fs.writeFileSync(path.join(temp.directory, 'es.json'), JSON.stringify(pack()));
    fs.writeFileSync(path.join(temp.directory, 'fr.json'), '{bad');
    fs.writeFileSync(path.join(temp.directory, 'de.json'), Buffer.from([0xff, 0xfe]));
    fs.writeFileSync(path.join(temp.directory, 'it.json'), Buffer.alloc(maxLanguageBytes + 1));
    fs.writeFileSync(path.join(temp.directory, 'pt.json'), JSON.stringify(pack()));
    fs.writeFileSync(path.join(temp.directory, 'bad-name.json'), JSON.stringify(pack()));
    fs.writeFileSync(path.join(temp.directory, 'en.json'), 'untrusted override');
    const reader = new LanguageFiles([temp.directory]);
    const result = reader.refresh();
    assert.deepEqual(result.languages.map(l => l.code), ['en', 'es']);
    assert.equal(result.errors.length, 5);
    assert.equal(reader.get('../../anything'), null);
    assert.equal(reader.current('missing').language.code, 'en');
    assert.throws(() => readBoundedJson(path.join(temp.directory, 'it.json')));
    fs.writeFileSync(path.join(temp.directory, 'es.json'), '{bad');
    reader.refresh(); assert.equal(reader.current('es').language.code, 'en');
    const linked = path.join(temp.directory, 'linked');
    fs.symlinkSync(temp.directory, linked, 'junction');
    assert.equal(new LanguageFiles([linked]).refresh().languages.length, 1);
    assert.throws(() => writeLanguageText(path.join(linked, 'label.txt'), 'text', 100));
  } finally { temp.clean(); }
});

test('language preferences and shell labels are bounded text with fixed paths', () => {
  const temp = temporary();
  try {
    const pref = path.join(temp.directory, 'language.json');
    writeLanguageText(pref, JSON.stringify({ code: 'es' }), 256);
    assert.equal(readLanguagePreference(pref), 'es');
    fs.writeFileSync(pref, JSON.stringify({ code: '../../file' }));
    assert.equal(readLanguagePreference(pref), 'en');
    assert.throws(() => writeLanguageText(pref, 'x'.repeat(257), 256));
    const key = keyFor('Scan with ClamAV only');
    const translated = 'Texto & "comillas"';
    const language = validateLanguagePack(pack({ [key]: entry(key, translated) }));
    const labels = path.join(temp.directory, 'labels'); writeShellLanguage(language, labels);
    assert.equal(fs.readFileSync(path.join(labels, 'clamav.txt'), 'utf8'), translated);
    assert.deepEqual(fs.readdirSync(labels).sort(), ['add-exception.txt', 'clamav-yara-vt.txt', 'clamav-yara.txt', 'clamav.txt']);
    assert.equal(fs.readdirSync(temp.directory).some(name => name.startsWith('.language-')), false);
  } finally { temp.clean(); }
});

test('display translation preserves English business messages and formats diagnostic HTML safely', () => {
  const key = keyFor('ClamShield could not load');
  const text = '<img onerror=alert(1)>';
  const language = pack({ [key]: entry(key, text) });
  try {
    setLanguage(language);
    assert.equal(localizeText('ClamShield could not load'), text);
    assert.equal(englishText(key), 'ClamShield could not load');
    assert.equal(localizeText('C:\\files\\sample.exe'), 'C:\\files\\sample.exe');
    const desktop = require('../public/desktop-localization.cjs');
    // Load the same validated pack into the separate desktop runtime.
    const directory = temporary();
    try {
      fs.writeFileSync(path.join(directory.directory, 'es.json'), JSON.stringify(language));
      fs.writeFileSync(path.join(directory.directory, 'language.json'), '{"code":"es"}');
      desktop.desktopLanguage([directory.directory], path.join(directory.directory, 'language.json'), true);
      const html = require('../public/desktop-diagnostics.cjs').errorHtml({ message: 'ClamShield could not load', stage: 'test' });
      assert.ok(html.includes('&lt;img onerror=alert(1)&gt;'));
      assert.ok(!html.includes('<img onerror'));
    } finally { directory.clean(); }
  } finally { setLanguage(englishPack); }
});

test('the authenticated language API changes only the language, persists it, and offers a complete template', async () => {
  const temp = temporary(); const app = express();
  let server: ReturnType<typeof app.listen> | undefined;
  try {
    fs.writeFileSync(path.join(temp.directory, 'es.json'), JSON.stringify(pack()));
    const context = { settings: { languageCode: 'en', shieldEnabled: true, virusTotalResultsUploadUnknownEnabled: false } };
    const saved: any[] = [];
    app.use(express.json()); app.use(requireLocalApiSession);
    registerLanguageRoutes(app, context, { directories: [temp.directory], preference: path.join(temp.directory, 'preference.json'),
      persistSettings: async (settings, options) => { saved.push({ settings, keys: [...options.keys!] }); } });
    server = app.listen(0, '127.0.0.1'); await new Promise<void>(resolve => server!.once('listening', resolve));
    const origin = 'http://127.0.0.1:' + (server.address() as any).port;
    assert.equal((await fetch(origin + '/api/languages')).status, 403);
    const headers = { 'X-ClamShield-Session': apiSessionToken, 'Content-Type': 'application/json' };
    const request = (code: unknown) => fetch(origin + '/api/languages', { method: 'POST', headers, body: JSON.stringify({ code }) });
    assert.equal((await request('../../bad')).status, 400); assert.equal(saved.length, 0);
    assert.equal((await request('es')).status, 200);
    assert.equal(context.settings.languageCode, 'es'); assert.equal(context.settings.shieldEnabled, true);
    assert.equal(context.settings.virusTotalResultsUploadUnknownEnabled, false);
    assert.deepEqual(saved[0].keys, ['languageCode']);
    assert.equal(readLanguagePreference(path.join(temp.directory, 'preference.json')), 'es');
    const response = await fetch(origin + '/api/languages/template', { headers });
    assert.match(response.headers.get('content-disposition')!, /es.json/);
    assert.deepEqual(Object.keys(validateLanguagePack(await response.json()).strings), Object.keys(englishPack.strings));
  } finally { await new Promise<void>(resolve => server ? server.close(() => resolve()) : resolve()); temp.clean(); }
});
