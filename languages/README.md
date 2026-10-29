# Help translate ClamShield

**The easiest way to help is to edit your language file directly on GitHub.** You only need a free GitHub account and a browser. No Git installation, coding experience or local development setup is needed. Small corrections are welcome; you do not have to review the whole file.

## Recommended: edit on GitHub and submit a pull request

**Start here:** [ClamShield translation files](https://github.com/orloxgr/ClamShield/tree/main/languages). Open the file for your language and follow the steps below.

1. Sign in to GitHub and open your language file, for example [Spanish — es.json](es.json) or [Greek — el.json](el.json). The complete language list is below.
2. Click the **pencil icon** above the file. Its tooltip may say **“Fork this repository and edit the file”**. Confirm **Fork this repository** if prompted.
3. Correct the `translation` values; keep identifiers, English text, placeholders and JSON punctuation intact. For credits, see [Manual review and your name](#manual-review-and-your-name).
4. Click **Commit changes…**, enter a short message such as `Improve Spanish translation`, then confirm **Propose changes** or **Commit changes**, as shown.
5. Continue to the pull-request page; if needed, choose **Compare & pull request**. The destination should be **orloxgr/ClamShield → main**, which GitHub normally selects automatically.
6. Add a title, describe the changes and whether your review is partial or complete, then click **Create pull request**.

**A commit saves your edit; the pull request submits it to ClamShield. Make sure you complete the last step.** Maintainers review the contribution before merging it. For later corrections, edit and commit to the same branch; the existing pull request updates automatically.

See [GitHub's browser-editing guide](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository) for the button sequence. A fork is simply your own copy of the repository; a pull request asks the project to include your changes.

## Manual review and your name

To replace the `(auto)` label after a complete manual review, use **`"status": "reviewed"`**, not `"status": "manual"`. The app recognizes `reviewed` and displays the name(s) in `reviewers`.

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

This example is for Spanish. Keep your own file's language code, English/native names and writing direction; change `status` and `reviewers` as appropriate.

The dropdown then displays `Spanish — Español (Juan Pérez)`. Several names are supported. Names are plain text and do not need to be real/legal names; a preferred name or GitHub username is fine. A `reviewed` file requires reviewer names and a complete translation. Maintainers confirm the review in the pull request. If later English additions have not yet been reviewed, keep the affected pack marked `auto` until its review is complete again.

## Alternative: edit a downloaded file and send it by email

If you prefer a text editor or do not want a GitHub account:

1. Open your language file, then click **Download raw file**. Alternatively, open **Raw** and save it with its language-code filename, such as `es.json`.
2. Edit it in Notepad, VS Code or another text editor. Follow the format and review instructions here, save as **UTF-8**, and keep the `.json` extension.
3. Attach the edited JSON file to an email to **[orloxgr@gmail.com](mailto:orloxgr@gmail.com)**. Suggested subject: `ClamShield Spanish translation`.
4. Include the language, whether this is a partial correction or a full review, your preferred credit name, and the app version or branch you started from. If you have not tested it in the app, say so; partial contributions are still welcome.

Maintainers can review and add the file to Git for you. You can also edit locally and submit through GitHub: upload the corrected file to a new branch in your fork, then open a pull request as above.

## Optional: install your file manually to test it

Use ClamShield **1.4.1 or newer** for this file format. No application rebuild is needed.

1. Download your edited file from your GitHub branch, or use the file you edited locally. Keep its language-code filename, for example `es.json`.
2. For an included language, replace the existing file in the installation's `languages` folder, normally `C:\Program Files\ClamShield\languages`. Keep a backup outside that folder first. Windows may request administrator permission to replace the file.
3. For a new language that is absent from the installation, you may instead put the file in `%ProgramData%\ClamShield\languages`; create that folder if needed. **Do not put the same language in both locations.** Duplicate language codes are rejected; the second copy does not override the first.
4. Open **Settings → Language → Refresh languages**, then choose your language.
5. Check short buttons, labels, dialogs, alerts and count/plural messages. Check right-to-left layout for Arabic and Urdu. Pay attention to not checked, pending, not detected, false positive, exceptions, removal and quarantine: these have different meanings.

Long translations remain active. Empty or missing translations use built-in English. Malformed JSON and unsafe/invalid fields are reported in Settings; restore your backup or remove a broken file and refresh to recover. English is compiled into the app, so editing external `en.json` cannot replace that fallback.

## What to edit in the JSON file

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

## Included languages

The repository includes English and automatic starting translations for Arabic, Bengali, Chinese, French, German, Greek, Hindi, Indonesian, Italian, Japanese, Portuguese, Russian, Spanish, Turkish and Urdu. There is one file per language, with no regional variants in the shipped list.

| Language | Native name | File |
| --- | --- | --- |
| Arabic | العربية | [ar.json](ar.json) |
| Bengali | বাংলা | [bn.json](bn.json) |
| Chinese | 中文 | [zh.json](zh.json) |
| English | English | [en.json](en.json) (source; not a translation target) |
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

## Add a new language

Copy [template.json](template.json) to a base language-code filename, such as `nl.json`. Set `language.code` to match the filename, `englishName` to the English language name, `name` to its native name, and `direction` to `ltr` or `rtl`. Start with `"status": "auto"` and `"reviewers": []`; use `reviewed` only after the complete review described above. Fill in translations and submit the new file through a pull request or email. For a GitHub upload, add the file to the `languages` folder in your own fork, then submit it to **orloxgr/ClamShield → main** as described above.
