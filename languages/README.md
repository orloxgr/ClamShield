# Translate ClamShield with a text editor

1. Copy `template.json` to a language-code filename, for example `es.json`.
2. Open it in Notepad, VS Code, or another text editor. Save as **UTF-8**.
3. Set `language.code` to the filename's code (`es`), `englishName` to `Spanish`, `name` to the native name (`Español`), and `direction` to `ltr` or `rtl`. Keep `status` as `auto` until the complete file has been reviewed.
4. Fill in each **`translation`**. Keep its string identifier, `StringInEng`, `maxChars`, and any placeholder metadata unchanged.
5. Put the file in `languages` beside the installed `ClamShield.exe`, or in `%ProgramData%\ClamShield\languages`. Open **Settings → Language → Refresh languages**, then select your language. No application rebuild is needed.

Use the existing file for your language, or copy the complete `template.json` for a new language. A volunteer only needs this one JSON file. A partial translation is usable: empty or missing translations use the built-in English text. Malformed JSON and unsafe/invalid fields are reported in Settings; exceeding a recommended length does not invalidate a file or hide a translation. English is compiled into the application; editing the external `en.json` cannot replace that trusted fallback.

An entry looks like this:

```json
"results.recheck_all_with_vt": {
  "StringInEng": "Recheck all with VT",
  "translation": "Επανέλεγχος με VT",
  "maxChars": 19
}
```

`StringInEng` and `translation` both have 11 characters in their field names, so the two texts begin in the same column in a monospaced text editor. Keep these adjacent lines and their indentation. The translated text can be shorter than the English text; do not pad it with spaces.

`maxChars` is the **recommended English-length budget**, exactly the number of Unicode code points in `StringInEng`, including spaces, punctuation and placeholder tokens. JSON escapes such as `\"` represent one character. In the example the English text has 19 characters and the Greek translation has 17. Aim to stay within the budget using clear, concise wording rather than a literal word-for-word translation. Preserve the action and its scope; do not remove a warning, a negation or an important distinction to save characters.

**Exceeding `maxChars` is a non-blocking warning, not a cutoff.** The full translation and plural forms remain active. Nothing is shortened, rejected, switched to English or marked unreviewed solely because it is longer. The app does not show translation-length warnings during normal use. The command-line checker reports the string identifier, field, actual character count and recommended maximum. Action labels wrap when necessary instead of hiding their meaning behind an ellipsis. Equal character counts do not guarantee equal pixel widths, particularly across writing systems; preview the actual screens as well.

Preserve every required `{{placeholder}}` exactly, including capitalization. You may move or repeat it. For example, `Found {{count}} files` can become `Se encontraron {{count}} archivos`. Tokens listed in `optionalParameters` represent English plural suffixes and can be omitted. All actual values remain required. Paths, hashes, detection names, versions, engine output and protocol identifiers are data, not text for volunteers to rewrite. Keep product names, literal filenames, URLs and report passwords such as `infectedsecuriteinfo` unchanged.

JSON requires double quotes and commas between entries. Escape a literal quote as `\"` and a backslash as `\\`. Do not add comments, scripts, HTML formatting, control characters, tabs, or line breaks inside translation values. Text resembling HTML is displayed literally; it is never rendered as markup or executed. A language file cannot add commands, change API routes, alter the maximum lengths, or load other files.

Optional advanced plural forms are available on entries already marked with `plural`. Keep that metadata unchanged and add or improve a `forms` object containing `other` and, as needed, `zero`, `one`, `two`, `few`, or `many`. The app chooses the form using the language's standard `Intl.PluralRules`. All forms retain the required placeholders and the same character limit. There are no executable plural expressions.

Contributors with the development environment can run:

```text
npm run languages:check -- languages/es.json
```

This reports coverage and each length warning for the selected file, and exits successfully when there are only length warnings. To list individual warnings across all languages, run `npm run languages:check -- --details`. Default checking of all files prints one summary per file. Invalid JSON, unknown fields, changed source text/metadata, unsafe controls and broken placeholders still fail validation; these are separate from layout guidance. The installed app applies the same data safety checks, so translators do not need Node.js. Files are limited to 2 MiB each, 16 MiB combined, and 64 language files. Filenames must match their language codes; duplicate languages and symbolic links are rejected. Older files using the `english` field and earlier length budgets are still readable; use the current file format when submitting changes.

For a new app string, developers add a `StringInEng` entry to `en.json` with `maxChars` equal to its Unicode code point count, use its key at the presentation point, and run `npm run languages:template` to refresh the volunteer template. Existing translations may omit newly added keys and continue to use English for those messages.

## Included languages and credits

The repository includes English and automatic starting translations for Arabic, Bengali, Chinese, French, German, Greek, Hindi, Indonesian, Italian, Japanese, Portuguese, Russian, Spanish, Turkish and Urdu. There is one file per language, with no regional variants in the shipped list.

| Language | Native name | File |
| --- | --- | --- |
| English | English | [en.json](en.json) (source) |
| Arabic | العربية | [ar.json](ar.json) |
| Bengali | বাংলা | [bn.json](bn.json) |
| Chinese | 中文 | [zh.json](zh.json) |
| French | Français | [fr.json](fr.json) |
| German | Deutsch | [de.json](de.json) |
| Greek | Ελληνικά | [el.json](el.json) |
| Hindi | हिन्दी | [hi.json](hi.json) |
| Indonesian | Bahasa Indonesia | [id.json](id.json) |
| Italian | Italiano | [it.json](it.json) |
| Japanese | 日本語 | [ja.json](ja.json) |
| Portuguese | Português | [pt.json](pt.json) |
| Russian | Русский | [ru.json](ru.json) |
| Spanish | Español | [es.json](es.json) |
| Turkish | Türkçe | [tr.json](tr.json) |
| Urdu | اردو | [ur.json](ur.json) |

The dropdown sorts alphabetically by English name and displays English first within each label, followed by the native name, for example `Greek — Ελληνικά (auto)` or `Spanish — Español (auto)`. English is the original source and displays simply `English`, in its alphabetical position.

All initial translations are machine-generated drafts, **not volunteer-reviewed translations**. They were seeded during development using Google Translate, with checks for placeholders, protected technical terms and character budgets, plus concise wording corrections. ClamShield does not contact a translation service at runtime. Please check wording and security terminology in context, particularly distinctions between not checked, pending, not detected, false positive, exceptions, removal and quarantine.

For partial corrections, leave `status` as `auto`; you may add your name to `reviewers` to record your contribution. When a native speaker has checked the entire file, including plural forms and the interface, set:

```json
"language": {
  "code": "es",
  "englishName": "Spanish",
  "name": "Español",
  "direction": "ltr",
  "status": "reviewed",
  "reviewers": ["Juan Pérez"]
}
```

The dropdown then displays `Spanish — Español (Juan Pérez)`. Several names are supported. Names are plain text and do not need to be real/legal names; a preferred name or GitHub username is fine. A `reviewed` file requires reviewer names and a complete translation. Maintainers confirm the review in the pull request. If later English additions have not yet been reviewed, keep the affected pack marked `auto` until its review is complete again.

## Contribute through GitHub and Git

**Current translation branch:** `codex/modular-localization`. Until this work is merged, use that branch as your starting point and pull-request base. After it is merged, use `main` instead.

1. Fork [orloxgr/ClamShield](https://github.com/orloxgr/ClamShield) on GitHub.
2. Clone your fork and create a translation branch from the current upstream translation branch:

```sh
git clone https://github.com/YOUR_NAME/ClamShield.git
cd ClamShield
git remote add upstream https://github.com/orloxgr/ClamShield.git
git fetch upstream
git switch -c translate-es upstream/codex/modular-localization
```

3. Edit only your file, for example `languages/es.json`, in a UTF-8 text editor. Correct `translation` and any `forms`; leave identifiers, English text, limits, `optionalParameters` and `plural` unchanged. Update review metadata only as described above.
4. Optionally validate locally. Node.js 22 or newer and the repository dependencies are needed for this command:

```sh
npm ci
npm run languages:check -- languages/es.json
```

5. Preview your file in Settings → Language. Check short buttons and labels, dialogs, count/plural messages and, for Arabic/Urdu, right-to-left layout. The app reports invalid entries. This preview does not require compiling code if you have a compatible installed build.
6. Commit only the translation file and push your branch:

```sh
git add languages/es.json
git commit -m "Improve Spanish translation"
git push -u origin translate-es
```

7. Open a pull request to the upstream translation branch. Say whether this is a partial correction or a full native-speaker review, list what screens were checked, and give your preferred credit name. CI validates the JSON, placeholders and limits. No one needs to send credentials, API keys, personal files, or engine samples for a translation contribution.

To get later changes before editing again, run `git fetch upstream` and merge the current upstream branch into your translation branch. Avoid regenerating other languages or replacing existing volunteer work with automatic output.

You can also contribute without command-line Git: select the translation branch on GitHub, open `languages/es.json`, choose **Edit**, make your corrections, and propose a pull request. For a large edit, download the raw file, edit it locally, and upload the corrected file to your fork on a new branch.
