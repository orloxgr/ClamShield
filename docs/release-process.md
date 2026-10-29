# Signed releases from a fixed source

The release workflow is `.github/workflows/release-build.yml`. CI and release
both call `.github/actions/validate`, including **every** `server/*.test.ts`
test and the real Electron navigation, notifications, VirusTotal and language
interface checks. A release cannot skip those checks.

## One-time signing configuration

Configure these repository Actions secrets through GitHub's settings:

- `RELEASE_PFX_BASE64`: base64-encoded PFX containing exactly one code-signing
  private key and its certificate chain.
- `RELEASE_PFX_PASSWORD`: its non-empty password.

Keep private keys out of the repository, logs, release assets and support
messages. The workflow imports the PFX on the ephemeral Windows runner,
requires signatures, deletes the temporary PFX and removes the imported key
afterwards. The signing key is not available to pull-request CI. Restrict who
can change or dispatch the release workflow and protect `main` using repository
settings appropriate to the maintainer account.

These secrets must be configured by the owner before the first signed Actions
release; adding the workflow does not configure them. Missing secrets stop the
release. A self-signed certificate can be used for testing, but trusting it on
the runner **does not** give consumer PCs a publicly trusted publisher or remove
SmartScreen warnings. Use a publicly trusted signing certificate for that goal.

## Prepare and dispatch

1. Commit matching versions in `package.json` and both root version fields in
   `package-lock.json`. Push the commit to `main`. Each version is used once;
   previously published releases and installers are never replaced.
2. Select **Actions → Release Build → Run workflow** from the same published
   commit/tag. Enter its full 40-character commit SHA, or its `vX.Y.Z` tag, in
   `source_ref`. The checked-out source must be an ancestor of published `main`,
   match the dispatch commit and match the package version. Moving branch
   names are not accepted as `source_ref`.
3. Leave `publish` unchecked to produce a verified artifact for Windows VM
   acceptance testing. Check it to publish after the automated gates succeed.
   A second dispatch is a **new build**; its artifact must be assessed as such.
   There is no claim that it reuses a previous dispatch's bytes.

The workflow performs this sequence:

1. Checkout the fixed source; install exactly the lockfile with `npm ci`.
2. Run the complete shared validation suite.
3. Audit all dependencies, including development tools and Electron. Unknown,
   incomplete or unavailable audits fail, as does any known vulnerability.
4. Import the release key; build and sign the Windows app, shell extension and
   NSIS installer. Packaging runs the audit gate again.
5. Finalize the installer signature and regenerate the blockmap and updater
   metadata **after** the last installer change. Packaged app files are not
   re-signed after packaging.
6. Verify signatures against the explicitly imported certificate. Generate
   final SHA-256 checksums and a manifest binding all four assets to the source.
7. Create GitHub build-provenance attestations for the installer, blockmap,
   updater metadata, checksum file and manifest. Store `provenance.json` with
   them in one immutable workflow artifact.
8. In a separate publishing job, download that exact artifact ID. Verify the
   manifest, each attestation and the source commit. No dependencies, build or
   signing step run in this job.
9. Create a draft release, upload those same six files and compare every
   GitHub asset's SHA-256 digest, size and upload state. Publish only after they
   match. Recheck the published tag, state and digests. Existing releases and
   mismatched tags stop publication.

If upload or verification fails, publication stops; a draft may remain for
inspection. Do not work around a failure by replacing a published installer or
by disabling the security gates. Workflow artifacts and draft releases still
require maintainer review; they are not independent security certification.

## Verify a downloaded release

Download all six assets into the same directory. Obtain the expected source
commit from the release tag, not from an untrusted local manifest alone:

```powershell
node scripts/release-manifest.cjs verify <directory> <full-source-sha> <version>
gh attestation verify <directory>/ClamShield-Setup-<version>.exe --bundle <directory>/provenance.json --repo orloxgr/ClamShield --signer-workflow orloxgr/ClamShield/.github/workflows/release-build.yml --source-digest <full-source-sha>
Get-AuthenticodeSignature <directory>/ClamShield-Setup-<version>.exe
```

Repeat provenance verification for the blockmap, `latest.yml`, `SHA256SUMS.txt`
and `release-manifest.json`. Verify the expected signing identity as well as
the signature's validity. A digest detects replacement only when compared to
a trusted value; provenance identifies the workflow and source, not the absence
of software defects.

Clean Windows installation, real engine/signature updates, EICAR detection,
Defender policy behavior and uninstall remain VM acceptance checks. The
automated tests inject OS and disk failures but do not disable the host's
Defender or execute malware. This process applies to future workflow releases;
it does not retroactively attest older maintainer-built releases.
