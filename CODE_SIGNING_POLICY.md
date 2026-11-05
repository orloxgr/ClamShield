# Code signing policy

Last updated: 2026-11-05

## Current status

ClamShield is preparing an application to the
[SignPath Foundation open-source program](https://signpath.org/). Acceptance and
production signing through SignPath are not yet in place. Current official
installers use the project's self-signed Authenticode certificate, as described in
[SECURITY.md](SECURITY.md). No existing release is represented as SignPath-signed.

If the project is accepted and production signing is activated, the applicable
acknowledgement will be:

> Free code signing provided by [SignPath.io](https://signpath.io/), certificate by
> [SignPath Foundation](https://signpath.org/).

The following requirements describe the intended SignPath release process. They
do not imply that a SignPath account, certificate or approval policy is already
configured.

## Team and responsibilities

| Role | Responsible maintainer |
| --- | --- |
| Committer | Byron Iniotakis ([orloxgr](https://github.com/orloxgr)) |
| Reviewer of contributions from outside the trusted committer group | Byron Iniotakis ([orloxgr](https://github.com/orloxgr)) |
| Release signing approver | Byron Iniotakis ([orloxgr](https://github.com/orloxgr)) |

External contributions must be reviewed before merging. Changes to workflows,
build scripts, dependency locks and signing configuration require the same
attention as application code. Everyone with repository write or signing access
must use multi-factor authentication for GitHub and SignPath before participating
in Foundation signing. The maintainer must verify this requirement during setup;
this document is not an attestation of current account settings.

Each Foundation signing request must receive manual approval from the designated
approver. Possession of the CI submission token alone must not authorize a
production signature. A signing failure or missing approval must stop publication
of a release described as SignPath-signed.

## Artifacts and third-party software

The proposed signing scope is the ClamShield Windows application
(`ClamShield.exe`), its native Explorer integration (`ClamShieldShellExt.dll`) and
the installer (`ClamShield-Setup-<version>.exe`). Any installer-generated
uninstaller and the Electron-based application executable must be explicitly
accounted for in the approved artifact configuration. Executable identity,
product name and version restrictions must be enforced there. Expansion of this
scope requires review and agreement with the signing provider.

The JavaScript application, translations, scripts and local HTML resources are
packaged with the application; they do not receive independent Authenticode
signatures. The installer signature covers the packaged installer contents.

Third-party components retain their licenses, notices and existing publisher
signatures. They must not be indiscriminately re-signed under ClamShield's
Foundation project. Electron/Chromium runtime components and installer helpers
are disclosed in the [distribution review](docs/distribution-review.md).

ClamAV, YARA, signature databases, YARA Forge rules and SaneSecurity helper tools
are downloaded separately. They are not ClamShield-built binaries and are outside
the proposed ClamShield Foundation signing scope. In particular, UnRAR support
can be present in an independently downloaded ClamAV distribution; that does not
make it a bundled ClamShield installer component. These download relationships
and provider licenses must be disclosed during application review.

No kernel driver is currently included. Application code signing does not provide
Microsoft kernel-driver approval.

## Build, approval and publication

1. Identify a public source commit on the official repository and a matching
   version/tag, following the [release process](docs/release-process.md).
2. Build from that source using the approved GitHub Actions workflow. All jobs
   leading to a Foundation signing request must use GitHub-hosted runners. Run
   the complete automated validation and dependency security gate.
3. Upload unsigned artifacts as GitHub workflow artifacts. SignPath must obtain
   them through its trusted GitHub integration and verify their build origin.
   Locally substituted binaries must not enter this process.
4. Submit only the approved application artifacts, await manual approval and
   verify the returned signatures, publisher, product metadata and versions.
5. Build the installer containing those artifacts, submit it for approval/signing
   and verify its final signature. Resolve installer/uninstaller signing details
   with SignPath before activating this workflow.
6. Generate final updater metadata, blockmaps, checksums, release manifest and
   GitHub provenance for the final signed bytes. Publish those same artifacts
   without rebuilding or modifying them after verification.

No SignPath-signed release will be published until the project is accepted, the
artifact scope and licenses are approved, MFA and approval requirements are
verified, and this process passes a test release. When activated, update this
policy and the release/download pages to identify the first affected version.

## Privacy and reporting

The [privacy policy](PRIVACY.md) describes local records, automatic update
requests, optional VirusTotal hash lookups and file submissions, DNS providers,
and user-initiated support reports. ClamShield must not claim that it never
transfers information: the documented network features have different triggers
and consent controls.

Report suspected signature misuse, substituted releases or security problems to
**orloxgr@gmail.com** using the guidance in [SECURITY.md](SECURITY.md). Suspected
misuse of a future Foundation signature can also be reported to
**support@signpath.io**, as explained in the
[Foundation terms](https://signpath.org/terms).
