# Dependency maintenance

Use Node.js 26.13.0 or newer and `npm ci`. The lockfile fixes the complete
dependency tree; direct dependencies track stable current releases. Electron
45.1.0 includes its own Node runtime (24.22.1), separate from the developer's
Node installation. ClamAV 1.5.4 and YARA 4.6.0 were already current during the
2026-10-29 update.

The application uses Express 5, Vite 8, React 19 and React Router 8. Router
imports use `react-router` directly. The old `react-router-dom` compatibility
package is no longer needed. TypeScript 7 checks the project; the previous
non-strict policy is explicit in tsconfig. Test source fixtures use Babel's
parser and esbuild because TypeScript 7 no longer provides the legacy compiler
JavaScript API. Production checks are not replaced with fixture-only builds.

The ASAR, Electron downloader, universal packager and Squirrel installer helper
overrides select reviewed current versions where electron-builder still pins
older releases. Validate packaging after changing these overrides. Other
transitive versions follow their owning packages' API compatibility ranges;
the latest version of a parent package does not imply every nested package has
the same major version as its latest standalone release.

The Windows build selects NSIS 3.12 and Windows Kits 10.0.26100.0 explicitly
through electron-builder's current toolset bundles. The installer wrapper also
uses the verified 7-Zip 26.05 executable. Custom NSIS page functions are emitted
after plugin directory registration so the unified bundle can resolve
nsDialogs consistently. The packaging wrapper bundles are labelled beta by
electron-builder; the compiler and signing tools themselves are stable versions.

## Native SaneSecurity tools

`addons/sanesecurity/server/native-tools.json` pins official source URLs,
versions and SHA-256 hashes for every required MSYS2 package and the official
Windows GnuPG distribution. Helpers are extracted into an isolated directory;
no Cygwin setup, MSYS2 package hooks or GnuPG installer is executed. All package
hashes and executable versions must pass before the staged directory replaces
the active tools. A failed update retains the existing directory, and raises
an error; it does not select an older download. Database signatures must match
the pinned SaneSecurity signing fingerprint before ClamAV load-testing.

Run `npm run native-tools:refresh` to refresh publisher metadata. Review the
diff, validate a clean native install and real database transfer/signatures,
then commit it. `npm run native-tools:check` only checks freshness; it never
edits the inventory. The release security gate performs this check as well as
the full npm audit. Unavailable publisher metadata blocks the gate.

Existing legacy Cygwin helper directories are not used by this version. They
are not recursively deleted automatically, to avoid removing files belonging
to a running older installation. Updating the source does not update an already
installed ClamShield executable.

An npm audit reports published npm advisories; native version/hash checks are
additional controls, not proof that all native libraries are vulnerability-free.
