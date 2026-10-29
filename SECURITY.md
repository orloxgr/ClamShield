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

The backend is organized into feature modules matching the sidebar, shared engine and bundled addon services, infrastructure, scan policies and Windows integration. The small `server.ts` entry point calls `server/bootstrap.ts` to compose authenticated routes and workers. See [the architecture and localization boundary](docs/modules-and-localization.md).

External language files are bounded UTF-8 JSON data. They cannot redefine trusted English strings or limits, add executable modules, run expressions, supply commands or load referenced files. Translations render as escaped text, with English fallback for missing or invalid data. The same validation protects the UI and native windows.

## CI and Tests

The repository includes GitHub Actions CI for:

- `npm ci`
- TypeScript validation with `npm run lint`
- every automated test, including failure paths for quarantine/restore, exception/report transactions, settings persistence, engine activation, API/IPC authorization, Defender refusal, desktop startup and VirusTotal queues
- real Electron checks for interface navigation, preload IPC and threat popup actions
- production build with `npm run build`
- full dependency audit and installed-version verification with `npm run audit:security`

The release security gate audits production, development and optional dependencies, including Electron, and requires zero known vulnerabilities at every severity. It also verifies installed package versions against the lockfile so stale local modules cannot enter an installer. CI and the release workflow run this gate; Electron Builder also runs it before packaging. An unavailable or incomplete audit blocks packaging. Electron is declared as a development dependency but is included in the installer, so a production-only audit is insufficient for release validation.

Automated tests cover critical application flows and failure paths. Clean-Windows acceptance testing is still required, especially for:

- clean Windows installation
- first-run ClamAV engine installation
- FreshClam signature update
- YARA engine and YARA Forge rule installation
- EICAR detection
- quarantine and exception flows
- Windows Defender integration behavior
- uninstall cleanup

CI and release call the same shared validation action. Tests use disposable
databases/files and injected Windows failures; they do not change the test host's
Defender configuration. See [privilege separation](docs/privilege-separation.md)
for the current elevated architecture, completed boundary hardening and the
proposed service design. The service migration has not been implemented.

## Binary Provenance

Release installers are built from the source in this repository with Electron Builder. Release assets should include:

- `ClamShield-Setup-<version>.exe`
- `ClamShield-Setup-<version>.exe.blockmap`
- `latest.yml`
- `SHA256SUMS.txt`
- `release-manifest.json` (new workflow releases)
- `provenance.json` (new workflow releases)

The [release workflow](docs/release-process.md) requires a fixed published source,
all tests and the full audit before packaging. It requires signing, verifies the
signer's certificate, finalizes updater metadata after the last signature and
attests the final bytes. A separate publishing job verifies source-bound
provenance, uploads the same immutable workflow artifact and compares GitHub's
asset digests before publication. It cannot overwrite an existing release.
Signing secrets must be configured before using this workflow; missing secrets
block the release. Previous maintainer-built releases retain their original
provenance and are not retroactively attested.

Current limitations:

- builds are not reproducible byte-for-byte
- public releases may be maintainer-built unless the release notes explicitly say the GitHub Actions artifact was used
- maintainer-built installers may use a local self-signed Authenticode certificate; this is not a publicly trusted publisher certificate and does not remove Windows trust warnings
- release-workflow builds without access to a signing certificate fail; local development builds are not a substitute for the signed release process

Publicly trusted code signing remains a separate requirement from GitHub build provenance.

## Third-Party Engines and Rules

ClamShield downloads ClamAV and YARA engine binaries from their official GitHub release sources when available. YARA Forge rules are downloaded from official YARA Forge release assets.

Some YARA rule files intentionally contain malware strings or byte patterns. Other antivirus products, including Microsoft Defender, may flag those rule files as threats. If the affected path is under:

```text
C:\ProgramData\ClamShield\yara\rules\
```

the detection is usually a false positive against the detection rules themselves, not active malware. Detections outside ClamShield's managed rules directory should be treated as normal security findings.

## Microsoft Defender

ClamShield can request Defender real-time monitoring changes only when the user enables the relevant setting or action. Windows Tamper Protection, Group Policy, or Security Center rules may prevent those changes. ClamShield reports the observed Defender state after attempts, but users remain responsible for deciding whether side-by-side scanning or Defender pause behavior is appropriate for their environment.
