# ClamShield - Windows GUI for ClamAV

ClamShield is a lightweight Windows desktop GUI for the ClamAV antivirus engine. It is designed for advanced users who want configurable, low-impact protection powered by ClamAV, with direct control over scans, signature updates, real-time monitoring, exclusions, and quarantine.

> Public beta: ClamShield is intended for users who understand basic security hygiene and want a transparent ClamAV-based tool. It should not be presented as a commercial antivirus replacement.

For development transparency, runtime AI/cloud-service behavior, CI status, binary provenance, and current security limitations, see [Security, Trust, and Build Transparency](SECURITY.md).

## Highlights

- Automatic ClamAV engine download and setup on Windows.
- One-click FreshClam signature updates.
- Optional SecuriteInfo third-party signatures using an account-specific FreshClam URL stored with Windows encryption.
- Optional SaneSecurity signatures downloaded from public rsync mirrors and verified with the provider's official GPG key.
- Optional VirusTotal Cloud second-opinion layer for Results refinement, real-time Shield cloud checks, and user-controlled unknown-file uploads with configurable size limits.
- Optional Microsoft Defender compatibility exclusions for ClamShield YARA folders and quarantine storage.
- Optional Windows DNS protection using public, account-free filtering resolvers from Cloudflare, AdGuard, CleanBrowsing, or Control D, with saved settings for restoration.
- Optional YARA scanning powered by ready-to-use YARA Forge rule packages.
- YARA Forge Core rules are enabled by default, with Extended and Full profiles available for advanced coverage.
- Separate update controls for ClamAV, SecuriteInfo, SaneSecurity, YARA Forge, and ClamShield releases.
- Persistent weekly or monthly scheduled scans with saved disk, directory, and running-process targets.
- Optional idle-only scheduling based on Windows keyboard and mouse inactivity; an active scheduled scan stops when activity resumes.
- Manual full system, folder, file, and memory scans.
- Windows process scan checks executable images used by running processes.
- Low-impact real-time shield for watched folders.
- Automatic detection of custom Desktop, Documents, Downloads, and browser download folders.
- Shield cache to avoid repeatedly scanning unchanged files.
- SQLite-backed shield cache to avoid large JSON cache files and startup stalls.
- User-controlled shield depth and concurrent scan count.
- Quarantine management and threat action prompts.
- Exceptions list for trusted files and folders.
- Results page actions for per-file quarantine, exception, VirusTotal cloud checks, MD5 hash reports, and user-controlled VirusTotal upload checks.
- One-click false-positive reporting helpers for exceptions with provider-specific routing for ClamAV, SecuriteInfo, SaneSecurity, and YARA Forge detections.
- Tray app with background monitoring and threat popup alerts.
- One threat decision per file across ClamAV, YARA and VirusTotal, with visible action errors. Closing a decision popup keeps its detections in Results. Notifications stack inside the work area of the monitor under the pointer.
- Dashboard → VirusTotal Cloud → **View queue** lists unfinished Results, Shield and on-demand tasks with source filters, file search, stages and scheduled retries. Viewing it does not submit files. The count includes unfinished tasks across all three queues; one file can have tasks in multiple scans. Results distinguish a completed hash lookup with no report from an accepted upload awaiting a report, an unchecked finding and a failed check. Opening an upload website is not treated as proof of submission.
- Clean NSIS installer and uninstaller.

## Performance Model

ClamShield is built for low disk and CPU impact:

- The desktop window paints a bundled dark startup shell before loading the backend. Loading continues inside the window until the local service and protection status are ready; it does not navigate repeatedly to an unavailable server. Failed initial status requests retry automatically. Existing minimized-launch preferences are preserved.
- ClamAV and YARA version checks run in parallel with provider status checks. The Dashboard's VirusTotal card shows current configuration, queue and usage information without the aggregate detection-vote count or last-result label.

- The real-time shield does not scan existing files on startup.
- Existing files are indexed only after the user manually runs a full, folder, or file scan.
- File changes can use the Shield cache when size and modification time are unchanged. Newly added or recreated files are scanned even when their size and modification time match a cached entry.
- Shield depth is configurable. The default is shallow to avoid scanning entire profile trees.
- Concurrent shield scans default to `1` to avoid disk saturation.
- Terminal output is capped so long scans do not overload the UI.
- Full disk scans skip Windows kernel-locked paging/system files such as `pagefile.sys`, `swapfile.sys`, and `DumpStack.log.tmp`, because they cannot be opened while Windows is running.
- YARA scanning uses timeout and max-size limits so rule evaluation cannot run without bounds.
- ClamShield excludes its own YARA rules/cache folders from ClamAV scans because rule packages intentionally contain malware strings.

Recommended defaults for most users:

- Shield depth: `1`
- Concurrent shield scans: `1`
- Max file size: `50 MB`
- Scan archives: enabled only if you accept the extra scan cost

## Installation

Download the latest installer from the GitHub Releases page:

```text
ClamShield Setup x.y.z.exe
```

Run the installer as administrator. On first launch, ClamShield can download and configure the Windows ClamAV engine and then download the latest virus definitions.

During install or upgrade, the installer closes a running `ClamShield.exe` process before replacing files. Upgrades are handled as an in-place file replacement and do not run ClamShield's full uninstall cleanup. Existing ClamAV engine files, signature databases, settings, and first-run agreement state in `C:\ProgramData\ClamShield` are preserved during upgrades.

### Microsoft Defender SmartScreen

Because ClamShield is a new public beta application, Windows may show a Microsoft Defender SmartScreen warning the first time the installer or app is opened. This can happen when an app is not yet commonly downloaded, even if the file is clean.

If you downloaded ClamShield from the official GitHub Releases page and you trust the release, use:

1. `More info`
2. `Run anyway`

On localized Windows installations, the button names may be translated.

Do not bypass SmartScreen for installers downloaded from unofficial links.

## YARA Detection Layer

ClamShield can use YARA as a second detection layer in addition to ClamAV.

Default YARA behavior:

- `Enable YARA scanning`: enabled by default
- `YARA Forge ruleset`: Core
- `YARA auto-update`: weekly
- `YARA timeout`: 15 seconds
- `YARA max file size`: 50 MB

YARA profiles:

- Core: high accuracy, low false positives, optimized for performance.
- Extended: broader coverage with a small increase in scan impact and false positives.
- Full: maximum coverage, best for manual scans and advanced investigation.

YARA files are stored under:

```text
C:\ProgramData\ClamShield\yara
```

YARA engine files are stored under:

```text
C:\ProgramData\ClamShield\engine\yara
```

Use the Updates page to download or refresh YARA rules with `Update YARA Rules`. ClamShield uses the ready-to-use YARA Forge packages:

- `https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip`
- `https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip`
- `https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip`

YARA matches appear in the Results page with `Engine: YARA`, rule name, source, and selected ruleset. Users can quarantine the file or add it to exceptions from the Results flow.

On Windows, ClamShield writes YARA scan lists as UTF-16LE without BOM so the upstream YARA CLI can scan paths with Greek, Cyrillic, Arabic, and other Unicode characters.

YARA engine updates are resolved from official VirusTotal/YARA GitHub releases. If the latest YARA source release does not include a Windows x64 ZIP asset, ClamShield uses the newest recent release that does include a Windows x64 binary package.

Because YARA Forge rules contain detection patterns, Microsoft Defender or another antivirus may flag the rules file itself. If the affected file is under `C:\ProgramData\ClamShield\yara\rules\`, this is usually a false positive against the rule database rather than active malware.

ClamShield stores its temporary scripts, scan lists, and FreshClam configuration files in `C:\ProgramData\ClamShield\temp`. ClamAV also uses this folder for temporary extraction files. This app-owned folder is excluded from ClamShield's scans alongside its rule and signature directories; the normal Windows Temp folders remain covered. Development and compatibility tests that download rule packages should use this app-owned folder too. Existing test leftovers in Windows Temp are not automatically moved or excluded.

## Updates

The Updates page groups its cards under **Signatures & Rules** and **Apps & Engines**, separated by a divider on the same page. Each card has its own settings and update action:

- `Update ClamAV`: runs FreshClam for virus signatures.
- `Update SecuriteInfo`: updates optional account-linked SecuriteInfo databases through FreshClam.
- `Update SaneSecurity`: downloads and verifies the selected public SaneSecurity database profile.
- `Update YARA Rules`: checks the local YARA engine and downloads the selected YARA Forge ruleset.
- `Check YARA`: checks for a newer installable Windows YARA engine package.
- `Check ClamShield`: checks GitHub Releases for a newer ClamShield installer.

Dashboard → Engine Info → Manage also shows live update output inside the SecuriteInfo and SaneSecurity dialogs. Logs remain available when a dialog is reopened, and a read-only polling fallback keeps progress visible if the event stream disconnects. SecuriteInfo setup stays open while its first update runs. FreshClam runs use the existing 30-minute timeout so an unresponsive process cannot hold the signature-update lock indefinitely.

ClamShield update checks can be enabled weekly from Settings. Silent app install is available as an explicit setting; when enabled, ClamShield downloads the latest installer, launches it, and closes itself so the installer can replace application files.

### Optional SecuriteInfo signatures

SecuriteInfo integration is disabled by default and requires an account-specific `DatabaseCustomURL` from the user's SecuriteInfo account.

- Basic mode configures `securiteinfo.ign2` and `securiteinfoold.hdb`.
- Paid mode configures supported paid databases, including the 0-hour databases.
- The mailserver spam-domain database (`spam_marketing.ndb`) is not installed by ClamShield because it is mainly useful for mailserver filtering, not normal Windows folder or disk scans.
- The PUA and vulnerability database (`securiteinfo-pua-app-and-vulnerabilities.ndb`) is optional and disabled by default because it can generate many false positives.
- The private account token is encrypted with Electron `safeStorage` on Windows.
- The token is not stored in `settings.json`, returned by the API, written to source control, or placed on the FreshClam command line.
- ClamShield generates a temporary FreshClam configuration for the update and deletes it afterward.

SecuriteInfo is an independent third-party provider. Detection-rate statements shown in ClamShield are attributed provider claims and are not guarantees by ClamShield.

### Optional SaneSecurity signatures

SaneSecurity integration is disabled by default and does not require an account.

- Malware Protection installs 9 malware, phishing, macro, hash, whitelist, and exploit-focused databases.
- Complete installs 20 databases, adding spam, scam, URL, attachment, image, and spear-phishing signatures.
- Databases and detached signatures are downloaded from SaneSecurity's public rsync mirrors.
- ClamShield verifies every database with SaneSecurity's official GPG signing key and asks ClamAV to load-test it before installation.
- First-time setup extracts isolated, SHA-256-pinned official MSYS2 packages (rsync 3.5.1 and 7-Zip 26.05) and the official Windows GnuPG 2.5.24 distribution inside `C:\ProgramData\ClamShield\tools\sanesecurity-native`. No package installer or package hooks are executed. The helpers use approximately 50 MB, plus download cache, and require outbound TCP port 873 for database updates.
- Subsequent automatic updates follow ClamShield's configured ClamAV signature update interval.

SaneSecurity is an independent third-party provider. Its signatures can improve detection coverage but may also increase false positives. ClamShield does not guarantee provider availability or detection results.

### VirusTotal Cloud integration

VirusTotal integration is disabled by default. Users can add their own VirusTotal API key from the Dashboard or Settings. The key is stored locally with Electron `safeStorage`; it is not written into `settings.json`.

When enabled, ClamShield can:

- check Results items against VirusTotal by SHA-256
- label findings as likely false positive, needs review, suspicious, malicious, unknown, upload skipped, or analysis queued
- recheck all Results items through a rate-limited background queue
- optionally upload Results files that are unknown to VirusTotal, only after the hash has no report
- optionally use VirusTotal as a background Real-Time Shield engine
- optionally upload unknown Shield-scanned files, subject to the Shield upload size limit

The On-Demand Scan page offers **Check every file with VirusTotal** for Full, Folder, File, and Process scans. This independently queues every eligible file, including files that ClamAV and YARA did not flag. Built-in exclusions and user exceptions still apply. Each file is checked by SHA-256 first; if its hash needs analysis, ClamShield automatically uploads the file and retrieves the completed analysis. The existing switch enables the complete flow. There is no file-count or executable-only filter. Files larger than 32 MB use VirusTotal's large-file upload endpoint, up to its 650 MB upload limit. Unreadable, excluded, changing, oversized, or provider-rejected files are skipped with a reason.

Cloud queues and upload analysis IDs are stored in SQLite and continue separately after local scanning finishes. They survive app restarts, follow shared API pacing, and can be paused, resumed, or cancelled on the scan page. Pausing/resuming a local scan preserves its cloud-check choice. Identical file content within a scan shares an upload, analysis, and report (reports are cached for 24 hours). Pending analysis is polled at most once per minute per submitted hash and stays queued until completed; an upload acknowledgement is not a verdict. **Needs upload** and **analysing** counters show progress. Previously finished missing-hash entries are returned to the upload queue when upgrading. VirusTotal-only detections appear in Results with the VirusTotal engine label.

When more than four files are queued for an on-demand VirusTotal scan, a confirmation shows the estimated duration using the actual file count, request pacing, and cached daily/monthly quotas. VirusTotal makes no scan requests until accepted. Choosing **Local scan only** cancels the cloud queue while local scanning continues. Accepted scans do not prompt again on resume, and unanswered confirmations survive restarts. **Show VirusTotal limit warnings** is available in Settings under Cloud Checks. For this preference only, missing or empty means on, checked means on, and explicitly unchecked (`false`) means off. Saving this preference alone updates only its settings row and does not change installer defaults or restart scan engines.

Successful new-file uploads and their analysis retrievals do not spend the local daily/monthly lookup estimate, and can continue when ordinary hash lookups are waiting for their quota reset. They still follow shared request pacing and provider rate limits. Obtaining a large-file upload URL is conservatively treated as a quota-consuming request. All of these requests count toward the automatic usage-refresh interval; VirusTotal's fetched usage remains authoritative.

ClamShield follows the public VirusTotal API pacing in the background queue. The Dashboard's **Fetch usage** button retrieves VirusTotal's quota summary, including actual daily/monthly usage and allowances. Shared group limits are respected alongside individual limits. Snapshots and local request counters are stored separately for each API key; the key itself is not stored in the usage tables. Counts between successful syncs are labelled as estimates.

**Auto-fetch every** defaults to **500 requests** and can be changed on the Dashboard. Quotas are also checked when first configured, when a UTC usage period changes before the next lookup, and before an estimated quota would stop work. Repeated fetches share one request and have a 60-second cooldown; failed automatic fetches back off for 15 minutes. Ordinary dashboard polling reads the cached snapshot without contacting VirusTotal. If quota access fails, the last snapshot/local estimate remains visible with an error, rather than showing zero usage. A successful manual fetch with remaining allowance wakes waiting cloud queues.

The separate Results and Shield unknown-file upload size limits are configurable and default to `20 MB`; those settings are capped at `32 MB`, matching the normal VirusTotal file upload endpoint. Files above those configured limits are not uploaded and the Results page shows `Upload required` with the file size, configured limit and directions to adjust Settings or quarantine the file. On-demand scans use the complete upload-and-analysis flow described above.

VirusTotal cloud checks are a second-opinion layer. They do not replace local ClamAV/YARA scanning, and uploads should be enabled only when the user is comfortable submitting unknown files to VirusTotal.

Results separate the local detection from the VirusTotal workflow and verdict. Workflow states are **Not checked with VT**, **Hash check queued**, **Upload required**, **Upload queued**, **Awaiting analysis**, **Waiting to retry**, and **Action required**. A missing hash report is an upload decision, never an "unknown" verdict or evidence that a file is safe. Completed reports produce **Likely false positive**, **Needs review**, **Suspicious**, or **Malicious**; a report with no completed engine verdicts requires review.

Accepted Results submissions retain their analysis IDs and are polled through the analysis endpoint until completed, with shared API pacing and no five-check cutoff. Legacy submissions resume after upgrade. Accepted submissions and explicitly requested uploads continue even if automatic initial hash checks are off; disabling Cloud Check pauses them. Temporary errors show the retry time; invalid keys, unavailable files and upload size limits explain the required action. Rechecking preserves submissions rather than uploading the same file again.

### Results, second opinions, and false positives

The Results page is the decision queue for detections that were not automatically quarantined. Each result shows the detection name, original file path, engine, source, and date, with actions directly under the file path:

- `Check with VT` / `Recheck VT`: checks the item's SHA-256 with VirusTotal Cloud and applies a verdict label. If Results unknown-file upload is enabled and the file is under the configured size limit, ClamShield uploads the file for analysis and follows up through the background queue.
- `Open hash report`: opens a VirusTotal report by hash.
- `Upload for analysis`: submits a file after confirmation and monitors its analysis ID. Opening a web upload page is never treated as proof of submission.
- Legacy web upload action: opens VirusTotal's upload page and copies the local file path so the user can choose whether to upload the file manually.
- `Exception`: trusts the item and records detection metadata for later false-positive reporting.
- `Quarantine`: moves the file into ClamShield quarantine.
- `Remove from Results`: removes only the finding after confirmation, records the decision in History, keeps the file on disk and leaves future scanning enabled. It never adds an exception or marks the file as safe.

If the submitted analysis belongs to different content, Results shows **File changed** with **Scan current file** and **Remove from Results**. Repeating the mismatched analysis is stopped. The file scan page is prefilled for a fresh local scan; it does not upload the new content merely by opening the page. A new local detection at the same path clears stale hashes and VirusTotal evidence unless its SHA-256 is explicitly confirmed unchanged. Delayed cloud responses cannot restore dismissed findings or overwrite a newer detection.

The page also includes `Recheck all with VT`, which clears existing VirusTotal labels and queues all eligible Results items for background recheck using the configured VirusTotal options and API limits.

When an exception was created from a detection, the Exceptions page can prepare a false-positive report for the likely source:

- ClamAV detections open the ClamAV false-positive report form.
- SecuriteInfo detections open a pre-filled email/contact flow.
- SaneSecurity detections open a pre-filled false-positive email.
- YARA detections open a pre-filled YARA Forge GitHub issue.

The report dialog shows the original detection details and editable report text, with explicit copy controls and provider-specific submission links. Opening the dialog does not change report status. Opening a submission channel or copying the report marks it as **Submission unconfirmed**; only **Mark as sent** changes it to **Reported by you**. This is the user's confirmation, not confirmation from the provider. Status can be reset without removing the exception. Existing records that only tracked opening a channel are shown as unconfirmed. ClamShield does not automatically send reports or attach samples.

Exceptions can be searched across all records and filtered by provider, origin, report status, file/folder type, and date added. Selection applies to the current page and clears when filters or pages change. **Remove from exceptions** makes the paths eligible for future scans; it does not delete files or immediately start a scan. Older entries with missing origin or type information are shown as Unknown.

### Startup and interface diagnostics

If the local service, page, required interface resources, or renderer fails, ClamShield shows a diagnostic screen independently of the normal web interface. It includes the failure stage, code, time, app version and diagnostic ID, with **Retry**, **Copy diagnostics**, **Open logs folder**, and expandable technical details. The screen does not assume protection is still running.

Backend readiness has a 45-second deadline and initial protection-status loading has a 45-second deadline. After a full document load, interface mounting is checked after 30 seconds. Switching between React pages does not restart this check. Before showing a mounting failure, ClamShield checks whether the interface actually rendered; a missing readiness acknowledgement or inconclusive check alone does not replace a working page. Errors are logged even with Debug Log disabled; debug logging adds extra detail. Desktop diagnostics redact credentials and URL queries. Default logs are under `C:\ProgramData\ClamShield\logs`.

### Scheduled scanner

The Scheduled Scanner page supports weekly schedules using selected weekdays or monthly schedules using selected calendar days. The start time and scan targets are stored in `settings.json`, including Full disk, reusable directory selections, and running-process scanning.

When **Scan only if the computer is not being used** is enabled, ClamShield begins reading Windows keyboard and mouse inactivity 15 minutes before the scheduled time. It continues only while waiting for the idle threshold or while the scheduled scan is running. If user activity resumes during the scan, the active job is stopped and its temporary resume state is discarded. ClamShield must remain running in the tray for its internal scheduler to operate.

### Optional DNS protection

The DNS Protection page can apply a selected public resolver profile to active Windows adapters that have an internet gateway. Both IPv4 and IPv6 addresses are configured to prevent an IPv6 DNS bypass.

- Cloudflare: malware-only or malware plus adult-content filtering.
- AdGuard: ads, tracking, and security filtering, with an optional family profile.
- CleanBrowsing: security or family filtering.
- Control D: malware, ads-and-tracking, or family-friendly filtering.
- No account or registration is required for the listed public profiles.
- ClamShield saves the resolver list that was active before protection was enabled and provides a restore action.
- Manual uninstall also attempts to restore the saved resolver list before removing ClamShield.

DNS filtering does not inspect files and cannot replace ClamAV, YARA, browser security, or safe browsing habits. VPNs, captive portals, organization policy, and browsers with independent Secure DNS settings may bypass or conflict with Windows DNS settings.

## Uninstall Behavior

The Windows uninstaller is configured to clean up ClamShield state:

- closes `ClamShield.exe`
- removes the scheduled startup task
- removes legacy startup registry entry if present
- restores the Microsoft Defender settings managed by ClamShield
- restores the DNS resolver list saved before ClamShield DNS protection was enabled
- removes the Windows Security notification override used by ClamShield
- removes the encrypted SecuriteInfo account token
- can optionally remove `C:\ProgramData\ClamShield` during manual uninstall

`C:\ProgramData\ClamShield` contains the downloaded engine, optional SaneSecurity helper tools, signature databases, settings, logs, quarantine metadata, and shield cache.

The shield cache is stored in:

```text
C:\ProgramData\ClamShield\shield_scan_cache.sqlite
```

## Development

Requirements:

- Node.js 26.13.0 or newer for development (Electron supplies its own Node runtime in the installed application)
- npm
- Windows for the packaged `.exe` build

Install dependencies:

```powershell
npm install
```

Run the TypeScript check:

```powershell
npm run lint
```

Build the frontend and bundled backend:

```powershell
npm run build
```

Create the Windows installer:

```powershell
npm run build:exe
```

Release artifacts are written to a versioned directory:

```text
release/<version>/ClamShield-Setup-<version>.exe
```

Generate SHA-256 checksums for the release directory:

```powershell
npm run release:checksums
```

The `release/` and `dist/` folders are build outputs and should not be committed to Git.

## Release Checklist

Follow [the signed release process](docs/release-process.md). The release workflow
uses a published full commit SHA or version tag, runs the same complete tests as
CI, audits every dependency, builds and signs, then generates final checksums and
GitHub attestations. Its publishing job verifies and uploads that exact artifact
without rebuilding. Signing secrets are required; existing releases cannot be
overwritten. Older releases are not retroactively attested by this workflow.

Release preparation and acceptance checks:

1. Bump and commit the version in `package.json` and `package-lock.json`, then push to `main`.
2. Configure the signing secrets described in the release guide.
3. Dispatch Release Build from the same commit/tag, passing its fixed `source_ref`.
4. Require every test and the full zero-vulnerability dependency audit to pass.
5. Require verified signatures, final metadata/checksums and source-bound provenance.
6. Use only the sealed workflow artifact; run with `publish` enabled when publication is intended.
7. Install the generated `.exe` on a clean Windows test machine or VM.
8. Install the ClamAV engine from the app.
9. Update signatures.
10. Test the EICAR sample detection flow.
11. Update YARA rules from the Updates page.
12. Test a YARA detection flow with Core rules enabled.
13. Test real-time shield with depth `1` and concurrent scans `1`.
14. Uninstall and verify cleanup:

```powershell
Test-Path "$env:ProgramData\ClamShield"
schtasks /query /tn ClamShield
```

## Security Notes

ClamShield wraps ClamAV and depends on ClamAV signatures for detection. It is not a machine-learning endpoint protection platform and does not claim to replace a full commercial EDR or managed antivirus suite.

YARA is a rule-matching engine, not a standalone antivirus. YARA Forge rules can improve detection coverage, but broader rulesets may create false positives or increase scan cost. Core is the recommended default for public beta use.

Some Windows Defender integration settings require administrator permissions. On Windows 10 and Windows 11, ClamShield can request that Defender real-time monitoring stays paused to avoid running two real-time scanners at the same time. Windows Tamper Protection, Group Policy, or Security Center registration rules can block that request, so ClamShield verifies and reports the actual Defender state after each attempt.

## License

This project is released under the GNU General Public License v2.0.

ClamAV is a trademark of Cisco Systems, Inc. ClamShield is an independent GUI application and is not affiliated with Cisco.

## Translations

ClamShield includes English and 15 automatic translation drafts. The language selector shows both English and native language names; drafts stay marked `(auto)` until a volunteer reviews the complete language file. Reviewed translations display the contributor's preferred name.

The easiest way to help is to open your language's JSON file on GitHub, click the pencil icon, edit it and submit a pull request. No Git installation or coding experience is needed. See the [translation guide](languages/README.md) for the browser steps, manual-review credits and local testing. You can also edit a downloaded file and email it to [orloxgr@gmail.com](mailto:orloxgr@gmail.com).

## Support

If you like ClamShield, you can support development from the in-app Settings page.
