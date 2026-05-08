# ClamShield - Windows GUI for ClamAV

ClamShield is a lightweight Windows desktop GUI for the ClamAV antivirus engine. It is designed for advanced users who want configurable, low-impact protection powered by ClamAV, with direct control over scans, signature updates, real-time monitoring, exclusions, and quarantine.

> Public beta: ClamShield is intended for users who understand basic security hygiene and want a transparent ClamAV-based tool. It should not be presented as a commercial antivirus replacement.

## Highlights

- Automatic ClamAV engine download and setup on Windows.
- One-click FreshClam signature updates.
- Optional YARA scanning powered by ready-to-use YARA Forge rule packages.
- YARA Forge Core rules are enabled by default, with Extended and Full profiles available for advanced coverage.
- Separate update controls for ClamAV signatures, YARA Forge rules, and ClamShield releases.
- Manual full system, folder, file, and memory scans.
- Windows process scan checks executable images used by running processes.
- Low-impact real-time shield for watched folders.
- Automatic detection of custom Desktop, Documents, Downloads, and browser download folders.
- Shield cache to avoid repeatedly scanning unchanged files.
- SQLite-backed shield cache to avoid large JSON cache files and startup stalls.
- User-controlled shield depth and concurrent scan count.
- Quarantine management and threat action prompts.
- Exceptions list for trusted files and folders.
- Tray app with background monitoring and threat popup alerts.
- Clean NSIS installer and uninstaller.

## Performance Model

ClamShield is built for low disk and CPU impact:

- The real-time shield does not scan existing files on startup.
- Existing files are indexed only after the user manually runs a full, folder, or file scan.
- Files are skipped by the shield if size and modification time have not changed since the last clean scan.
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

## Updates

The Updates page has separate actions:

- `Update ClamAV`: runs FreshClam for virus signatures.
- `Update YARA Rules`: checks the local YARA engine and downloads the selected YARA Forge ruleset.
- `Check ClamShield`: checks GitHub Releases for a newer ClamShield installer.

ClamShield update checks can be enabled weekly from Settings. Silent app install is available as an explicit setting; when enabled, ClamShield downloads the latest installer, launches it, and closes itself so the installer can replace application files.

## Uninstall Behavior

The Windows uninstaller is configured to clean up ClamShield state:

- closes `ClamShield.exe`
- removes the scheduled startup task
- removes legacy startup registry entry if present
- restores Windows Defender real-time monitoring
- removes the Windows Security notification override used by ClamShield
- can optionally remove `C:\ProgramData\ClamShield` during manual uninstall

`C:\ProgramData\ClamShield` contains the downloaded engine, signature databases, settings, logs, quarantine metadata, and shield cache.

The shield cache is stored in:

```text
C:\ProgramData\ClamShield\shield_scan_cache.sqlite
```

## Development

Requirements:

- Node.js
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
release/<version>/ClamShield Setup <version>.exe
```

The `release/` and `dist/` folders are build outputs and should not be committed to Git.

## Release Checklist

Before publishing a release:

1. Bump the version in `package.json` and `package-lock.json`.
2. Run `npm install`.
3. Run `npm run lint`.
4. Run `npm run build:exe`.
5. Install the generated `.exe` on a clean Windows test machine or VM.
6. Install the ClamAV engine from the app.
7. Update signatures.
8. Test the EICAR sample detection flow.
9. Update YARA rules from the Updates page.
10. Test a YARA detection flow with Core rules enabled.
11. Test real-time shield with depth `1` and concurrent scans `1`.
12. Uninstall and verify cleanup:

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

## Support

If you like ClamShield, you can support development from the in-app Settings page.
