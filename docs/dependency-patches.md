# Dependency patches

## Chokidar 6.0.0: Windows startup enumeration

`scripts/patch-chokidar.cjs` fixes a race in the Windows root-parent subscription
in Chokidar 6.0.0. A metadata notification for the watched root can start a live
directory reconciliation while its initial enumeration is still running. Entries
not yet discovered by the initial enumeration are then emitted as `add` events,
despite `ignoreInitial: true`.

The patch keeps the root-parent subscription active during initialization, but
coalesces its invalidations until the initial enumeration and buffered file events
have been processed. It then reconciles the current directory state. It does not
discard new downloads or introduce a startup delay during which changes are
ignored. Shield still scans genuine `add` events, including a file downloaded
again at the same path.

The patch runs automatically through the root `postinstall` script. It accepts
only version 6.0.0 and the exact reviewed upstream or patched file hashes. Normal
builds and the installer security gate verify the patched file, so an installation
with lifecycle scripts disabled cannot silently produce an unfixed installer.

After changing the Chokidar version, review whether the upstream release fixes
this race, update/remove the patch, and run `server/shieldWatcher.test.ts` on
Windows. This test uses real filesystem notifications while slowing the initial
enumeration. It also checks downloads during/after startup, modifications, and
deletion followed by downloading the same file again.

Run:

```sh
npm install
node scripts/patch-chokidar.cjs --check
node --import tsx --test server/shieldWatcher.test.ts server/shieldLifecycle.test.ts server/dependencyPatches.test.ts
```
