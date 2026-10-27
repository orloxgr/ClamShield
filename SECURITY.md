# Security, Trust, and Build Transparency

ClamShield is a public beta Windows desktop application that orchestrates third-party security tools. It runs with administrator privileges for installation and for some Windows integration features, so the project should be easy to audit and conservative about claims.

## AI-Assisted Development

ClamShield has been developed with significant AI/LLM assistance, including code generation, refactoring suggestions, UI iteration, documentation, and release-checklist work. Human review and local testing are still required before release.

AI assistance is not used at runtime. ClamShield does not send scanned files, file contents, file paths, signatures, quarantine contents, or user settings to an AI service.

## Runtime AI and Cloud Services

ClamShield does not use Gemini, OpenAI, or another hosted AI API during normal desktop use.

Older development scaffolding included unused AI Studio/Gemini configuration. That dependency and environment-variable scaffolding were removed in `v1.1.27`.

ClamShield can open external provider websites when the user asks for a second opinion or false-positive report flow, for example VirusTotal hash lookups or provider false-positive forms. VirusTotal file submission is opt-in. If the user enables unknown-file uploads, ClamShield may submit files that VirusTotal does not already know, subject to the configured size limit and API pacing.

## Backend Structure

Most backend logic currently lives in `server.ts`. This is intentional for the public beta while behavior is still moving quickly, but it is not the desired long-term shape.

The planned split is:

- update/install services for ClamAV, YARA, SaneSecurity, and app updates
- scan orchestration and job logging
- settings validation and persistence
- quarantine/results/history storage
- Windows integration helpers
- API route registration

Until that split happens, security-sensitive changes should be reviewed carefully because a large single file makes audit boundaries harder to see.

## CI and Tests

The repository includes GitHub Actions CI for:

- `npm ci`
- TypeScript validation with `npm run lint`
- focused tests for exception reporting, desktop startup and diagnostics, threat alerts, update timeouts, and VirusTotal queues and usage
- real Electron checks for interface navigation, preload IPC and threat popup actions
- production build with `npm run build`
- full dependency audit and installed-version verification with `npm run audit:security`

The release security gate audits production, development and optional dependencies, including Electron, and requires zero known vulnerabilities at every severity. It also verifies installed package versions against the lockfile so stale local modules cannot enter an installer. CI and the release workflow run this gate; Electron Builder also runs it before packaging. An unavailable or incomplete audit blocks packaging. Electron is declared as a development dependency but is included in the installer, so a production-only audit is insufficient for release validation.

The project does not yet have a comprehensive automated test suite. Manual release testing is still required, especially for:

- clean Windows installation
- first-run ClamAV engine installation
- FreshClam signature update
- YARA engine and YARA Forge rule installation
- EICAR detection
- quarantine and exception flows
- Windows Defender integration behavior
- uninstall cleanup

Adding focused automated tests for settings validation, updater selection logic, scan-output parsing, and quarantine/result storage is on the roadmap.

## Binary Provenance

Release installers are built from the source in this repository with Electron Builder. Release assets should include:

- `ClamShield-Setup-<version>.exe`
- `ClamShield-Setup-<version>.exe.blockmap`
- `latest.yml`
- `SHA256SUMS.txt`

GitHub release assets expose SHA-256 digests, and `SHA256SUMS.txt` is generated from the local release directory. The repository also includes a manual GitHub Actions release-build workflow that can build the Windows installer and generate GitHub artifact attestations.

Current limitations:

- builds are not reproducible byte-for-byte
- public releases may be maintainer-built unless the release notes explicitly say the GitHub Actions artifact was used
- maintainer-built installers may use a local self-signed Authenticode certificate; this is not a publicly trusted publisher certificate and does not remove Windows trust warnings
- automated builds without access to a signing certificate may be unsigned

Publicly trusted code signing and stricter release provenance are planned improvements.

## Third-Party Engines and Rules

ClamShield downloads ClamAV and YARA engine binaries from their official GitHub release sources when available. YARA Forge rules are downloaded from official YARA Forge release assets.

Some YARA rule files intentionally contain malware strings or byte patterns. Other antivirus products, including Microsoft Defender, may flag those rule files as threats. If the affected path is under:

```text
C:\ProgramData\ClamShield\yara\rules\
```

the detection is usually a false positive against the detection rules themselves, not active malware. Detections outside ClamShield's managed rules directory should be treated as normal security findings.

## Microsoft Defender

ClamShield can request Defender real-time monitoring changes only when the user enables the relevant setting or action. Windows Tamper Protection, Group Policy, or Security Center rules may prevent those changes. ClamShield reports the observed Defender state after attempts, but users remain responsible for deciding whether side-by-side scanning or Defender pause behavior is appropriate for their environment.
