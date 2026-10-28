# Translate ClamShield with a text editor

1. Copy `template.json` to a language-code filename, for example `es.json`.
2. Open it in Notepad, VS Code, or another text editor. Save as **UTF-8**.
3. Set `language.code` to the filename's code (`es`), `name` to the native name (`Español`), and `direction` to `ltr` or `rtl`.
4. Fill in each **`translation`**. Keep its string identifier, `english`, `maxChars`, and any placeholder metadata unchanged.
5. Put the file in `languages` beside the installed `ClamShield.exe`, or in `%ProgramData%\ClamShield\languages`. Open **Settings → Language → Refresh languages**, then select your language. No application rebuild is needed.

The same complete template can be downloaded from Settings. A volunteer only needs this one JSON file. A partial translation is usable: empty or missing translations use the built-in English text. Removing or breaking a language file also falls back to English and shows the validation error in Settings. English is compiled into the application; editing the external `en.json` cannot replace that trusted fallback.

An entry looks like this:

```json
"settings.language": {
  "english": "Language",
  "translation": "Idioma",
  "maxChars": 24
}
```

`maxChars` counts Unicode characters in the translation, including spaces, punctuation and placeholder tokens. JSON escapes such as `\"` represent one character. Keep the translation within the limit; it is rejected rather than silently cut off. Use concise wording. Long words wrap and small notification windows can scroll to keep actions reachable. Character limits help fit the design, but please also preview your language in the app.

Preserve every `{{placeholder}}` exactly, including capitalization. You may move or repeat it. For example, `Found {{count}} files` can become `Se encontraron {{count}} archivos`. The values are supplied as text at runtime. Paths, hashes, detection names, versions, engine output and protocol identifiers are data, not text for volunteers to rewrite.

JSON requires double quotes and commas between entries. Escape a literal quote as `\"` and a backslash as `\\`. Do not add comments, scripts, HTML formatting, control characters, tabs, or line breaks inside translation values. Text resembling HTML is displayed literally; it is never rendered as markup or executed. A language file cannot add commands, change API routes, alter the maximum lengths, or load other files.

Optional advanced plural forms are available on entries already marked with `plural`. Keep that metadata unchanged and add a `forms` object containing `other` and, as needed, `zero`, `one`, `two`, `few`, or `many`. The app chooses the form using the language's standard `Intl.PluralRules`. All forms retain the required placeholders and the same character limit. Placeholders listed in `optionalParameters` may be omitted from a plural form; these represent English suffixes. There are no executable plural expressions.

Contributors with the development environment can run:

```text
npm run languages:check -- languages/es.json
```

This reports the precise invalid entry or translation coverage. The installed app performs the same validation, so translators do not need Node.js. Files are limited to 2 MiB each, 16 MiB combined, and 64 language files. Filenames must match their language codes; duplicate languages and symbolic links are rejected.

For a new app string, developers add an English entry and a suitable character limit to `en.json`, use its key at the presentation point, and run `npm run languages:template` to refresh the volunteer template. Existing translations may omit newly added keys and continue to use English for those messages.
