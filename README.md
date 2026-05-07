# ClamShield - Windows GUI for ClamAV

ClamShield is a lightweight Windows desktop GUI for the ClamAV antivirus engine. It is designed for advanced users who want configurable, low-impact protection powered by ClamAV, with direct control over scans, signature updates, real-time monitoring, exclusions, and quarantine.

> Public beta: ClamShield is intended for users who understand basic security hygiene and want a transparent ClamAV-based tool. It should not be presented as a commercial antivirus replacement.

## Highlights

- Automatic ClamAV engine download and setup on Windows.
- One-click FreshClam signature updates.
- Manual full system, folder, file, and memory scans.
- Low-impact real-time shield for watched folders.
- Automatic detection of custom Desktop, Documents, Downloads, and browser download folders.
- Shield cache to avoid repeatedly scanning unchanged files.
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

## Uninstall Behavior

The Windows uninstaller is configured to clean up ClamShield state:

- closes `ClamShield.exe`
- removes the scheduled startup task
- removes legacy startup registry entry if present
- restores Windows Defender real-time monitoring
- removes the Windows Security notification override used by ClamShield
- removes `C:\ProgramData\ClamShield`

`C:\ProgramData\ClamShield` contains the downloaded engine, signature databases, settings, logs, quarantine metadata, and shield cache.

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
9. Test real-time shield with depth `1` and concurrent scans `1`.
10. Uninstall and verify cleanup:

```powershell
Test-Path "$env:ProgramData\ClamShield"
schtasks /query /tn ClamShield
```

## Security Notes

ClamShield wraps ClamAV and depends on ClamAV signatures for detection. It is not a machine-learning endpoint protection platform and does not claim to replace a full commercial EDR or managed antivirus suite.

Some Windows Defender integration settings require administrator permissions. If enabled, ClamShield can keep Defender real-time monitoring paused to avoid running two real-time scanners at the same time.

## License

This project is released under the GNU General Public License v2.0.

ClamAV is a trademark of Cisco Systems, Inc. ClamShield is an independent GUI application and is not affiliated with Cisco.

## Support

If you like ClamShield, you can support development from the in-app Settings page.
