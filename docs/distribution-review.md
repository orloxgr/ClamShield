# Distribution and license review

Reviewed: 2026-11-05. This is a technical inventory for the SignPath application,
not an assertion of Foundation approval or a blanket licensing certification.

## Published artifact examined

The review examined the published [ClamShield 1.4.6 installer](https://github.com/orloxgr/ClamShield/releases/tag/v1.4.6),
its embedded `app-64.7z` payload and `resources/app.asar`, without executing it.
Installer SHA-256:

```text
70ef47050e500b790b90397f911f0778ea2bf77d67988e27efc2ebb9ffd68fb3
```

This is the published artifact, not a substitute local build. Packaging is
configured in [package.json](../package.json).

| Layer | Included components | License and signing boundary |
| --- | --- | --- |
| ClamShield | Built JavaScript, HTML/CSS, translations, icons and scripts | Project [GPL v2 license](../LICENSE); upstream libraries retain their notices |
| Explorer integration | `ClamShieldShellExt.dll`, context-menu scripts and sparse-package manifest | Project source in `native/ClamShieldShellExt`, `shell` and `sparse-package`; user-mode integration, not a kernel driver |
| npm runtime | 110 package instances in the published ASAR | 97 MIT, 7 ISC, 2 BSD-3-Clause and 4 BlueOak-1.0.0 declarations; no missing license identifiers |
| Electron 45.1.0 | Chromium/Node.js resources, runtime and graphics libraries | Preserve `LICENSE.electron.txt`, `LICENSES.chromium.html`, upstream metadata and signatures; not all runtime files are MIT-licensed ClamShield source |
| Installer | NSIS installer/uninstaller, `System`, `StdUtils`, `nsDialogs`, `UAC`, `nsExec`, `nsis7z`, `WinShell` plugins and packaged elevation helper | Separate upstream components; disclose their terms and agree the installer signing boundary with SignPath |

The four BlueOak packages are `chownr`, `minipass`, `tar` and `yallist`.
[BlueOak-1.0.0 is OSI-approved](https://opensource.org/license/BlueOak-1.0.0).
Package-by-package notices are in [THIRD_PARTY_NOTICES.txt](../THIRD_PARTY_NOTICES.txt).

The NSIS publisher documents its [licenses and exceptions](https://nsis.sourceforge.io/License).
Separately maintained plugins retain their applicable upstream terms. The pinned
`nsis` toolset is selected in `package.json`. Its prebuilt components must be
disclosed rather than assumed to be independently signable ClamShield binaries.
Similarly, SignPath must confirm the treatment of the Electron-based executable,
upstream graphics/platform DLLs and generated uninstaller in its approved artifact
configuration. License identifiers alone do not establish that approval.

## Separately downloaded components

| Component | Publisher and license boundary |
| --- | --- |
| ClamAV | Official Cisco-Talos/clamav Windows distribution; GPL v2 engine and separately licensed upstream libraries; installed by `engines/clamav/server/install.ts` |
| UnRAR support | `libclamunrar.dll` can be present in the independent ClamAV download. ClamAV documents the [UnRAR restriction](https://docs.clamav.net/manual/Installing/Packages.html); this DLL is absent from the reviewed ClamShield installer |
| YARA | Official VirusTotal/yara assets; retain the upstream BSD license and dependency notices |
| YARA Forge rules | YARAHQ/yara-forge downloads; individual rules may have different upstream licenses |
| ClamAV signatures | FreshClam publishers/mirrors; database terms are distinct from the engine license |
| SecuriteInfo | Optional authenticated signature downloads; account, subscription and signature-use terms apply |
| SaneSecurity | Optional public rsync databases and GPG verification; respective database publishers' terms apply |
| SaneSecurity helpers | Optional rsync/MSYS2 libraries, 7-Zip and GnuPG, pinned in `addons/sanesecurity/server/native-tools.json`; supplied upstream license/doc files are retained by the extraction code |

No `clamscan.exe`, `clamd.exe`, `freshclam.exe`, `yara64.exe`, `libclamunrar.dll`,
`rsync.exe` or `gpg.exe` is bundled in the reviewed application payload. The build
also uses downloaded 7-Zip to create archives; this does not bundle that executable
into the application. NSIS extraction plugins are disclosed separately above.

Disclose these downloads, their licenses and the UnRAR restriction in the
Foundation application. Ask the Foundation to confirm its treatment of the
complete product; do not describe this boundary as an exemption already granted.
No engine or archive feature was removed by this review.

## Notice improvements for subsequent builds

The published ASAR has 107 standalone license/notice files. Three older MIT
packages (`agent-base` 6.0.2, `https-proxy-agent` 5.0.1 and `isarray` 1.0.0) instead
put their full notices in README license sections. The new generator preserves
those full texts too, rather than relying only on a license identifier.

```sh
npm ci
npm run licenses:generate
npm run licenses:check
```

`scripts/generate-third-party-notices.cjs` reads locked, installed manifests and
license text as data. It does not execute dependency code or invent copyright
notices. Missing notices and mismatched versions fail validation. Review generated
changes when updating dependencies.

The notice bundle covers 114 entries: the 110 packaged npm instances, three
type-only peer dependencies omitted by the packager, and Tailwind CSS, which
contributes generated styles. The additional notices do not imply all entries
are shipped as runtime code.

CI and release validation check the bundle. Subsequent installers include the
project license, privacy policy, code signing policy and third-party notices
beside the application. Existing published installer bytes remain unchanged.

## Before Foundation production signing

- Confirm acceptance of the disclosed runtime, installer and download boundaries,
  and approve the exact artifact configuration.
- Disclose the optional Defender controls and uninstaller restoration behavior
  described in the privacy policy and installer notice during product review.
- Verify maintainer MFA and configure manual signing approvals.
- Integrate approved signing into the workflow; verify signatures, notices and
  provenance on a test build.
- Show the updated privacy disclosure during installation and review consent
  controls against the Foundation requirements before claiming compliance. A
  repository policy does not retrofit earlier installer screens.

See the [Code signing policy](../CODE_SIGNING_POLICY.md), [Privacy policy](../PRIVACY.md)
and [release process](release-process.md).
