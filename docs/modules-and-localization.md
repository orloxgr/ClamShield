# Modules and localization

The application is organized in sidebar order. Each feature has its UI in `modules/<feature>/ui` and its HTTP routes, storage and services in `modules/<feature>/server`:

| Tab | Feature folder |
| --- | --- |
| Dashboard | `dashboard` |
| Shield | `shield` |
| On-Demand Scan | `on-demand` |
| Scheduled Scanner | `scheduler` |
| Results | `results` |
| Exceptions | `exceptions` |
| Quarantine | `quarantine` |
| DNS Protection | `dns-protection` |
| Updates | `updates` |
| History | `history` |
| Settings | `settings` |

`engines/clamav` and `engines/yara` own engine operations. `addons/virustotal`, `addons/securiteinfo`, and `addons/sanesecurity` own the bundled optional integrations. These are source modules shipped with ClamShield, not executable third-party plugins. YARA rules remain engine data with their existing validation and handling.

`server.ts` starts logging and calls `server/bootstrap.ts`. Bootstrap composes Express, session authentication, the database-backed settings, scan sessions, queues, workers, timers, and route registrations. Feature route entry points live under each feature's `server/routes`; long-running workers and database operations have separate owners. Shared infrastructure lives in `server/core`, Windows integration in `server/platform`, and common scan policies in `server/scanning`. Live application dependencies are explicit in `ApplicationContext`; route and worker factories declare the fields they require with `Pick`. Mutable runtime coordination has one owner in `runtimeState`.

The refactor preserves existing API paths, scheduler behavior, queue persistence, settings, SQLite schema/migrations, session authentication, scan policies and upload consent. The existing behavioral tests inspect the actual moved production declarations and continue testing these decisions. They do not use a copy of the old monolith.

## Translation contract

`languages/en.json` is the trusted source catalog. Builds embed it in the React UI, backend and desktop localization runtimes. `languages/template.json` is the single complete file handed to volunteers. See [the translator guide](../languages/README.md).

Only presentation is translated. `t(key, parameters)` renders a UI string; `englishText` preserves stable English business messages in saved records and protocols. Display adapters recognize authored messages and format them from the catalog without modifying the underlying status, route, identifier, action or command. Structured message descriptors are also included alongside authored API message fields. Unknown engine/vendor output remains original diagnostic data. Locale-aware dates and relative times use `Intl`.

The same validated packs feed the sidebar, every tab, common dialogs, tray menu, startup, diagnostics, threat alerts, results reminders, scan summaries and update notifications. Native pages use text nodes and an explicit allowlist of text attributes. Diagnostic HTML escapes translated text and stores feedback as escaped data attributes. The shell extension reads only four fixed UTF-8 text label files with a 1024-byte limit; translations never enter command arguments or action IDs.

## Language-file boundary

External language packs are bounded UTF-8 JSON parsed as data. There is no language-file `require`, dynamic import, script evaluation, HTML rendering, template execution, ICU expression evaluation, translator-provided regex, or file/URL reference resolver. Validation rejects unknown identifiers, changed English/metadata, invalid locales, unsupported fields, prototype keys, control characters, excessive nesting and invalid placeholders. `StringInEng` and `translation` have equal-length field names for visual alignment; `maxChars` is the English code point count and is advisory. Longer translations and plural forms remain active, with non-blocking reports available in the command-line checker. The Settings page links to the repository translation guide instead of showing translator instructions or length warnings. Previous files with `english` fields are normalized to the new representation and trusted budgets. File discovery rejects links, duplicate codes and mismatched filenames, with per-file, total-size, directory-entry and file-count limits. Invalid files are reported and English remains available.

Language routes use the existing local-session authentication. They accept only a code already present in the validated file registry, save the language preference, and leave scanning and upload consent unchanged. Desktop IPC validates the requesting window, top-level frame and app origin/page before returning language data. Generated preferences and shell labels use exclusive temporary files and rename, avoiding writes through existing file links.

## Verification

Run `npm test`, `npm run languages:check`, `npm run lint`, `npm run build`, `npm run test:localization-ui`, plus the existing desktop/navigation/alert/VT interface checks. The localization interface fixture opens all eleven tabs, changes language through Settings, checks maximum-length sidebar text, malicious-looking literal text, RTL, and all native HTML pages. It starts no real backend engines and touches no installed user settings.
