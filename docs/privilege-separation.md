# Windows privilege separation assessment

Status: design and boundary hardening; a separate privileged service has **not**
been implemented. The current `requireAdministrator` manifest remains in place
until an end-to-end replacement can preserve protection. Running the existing
application without elevation is not equivalent to this design.

## Current boundaries

`package.json` requests elevation for the application. `electron-main.cjs`
starts the backend with the inherited token. Its React UI, Electron main
process, backend orchestration and launched engines therefore belong to the
same elevated application. Electron renderer isolation does not turn the main
process or backend into a least-privilege service.

| Area | Actual source | Intended owner |
| --- | --- | --- |
| Dashboard, results, language selection and notification display | `modules/*/ui`, `electron-main.cjs` | Per-user UI at normal integrity |
| Reading protected files, quarantine and restore | `server/scanning`, `modules/quarantine/server` | Privileged broker with constrained file operations; scanning workers with limited tokens |
| Shared settings, history, exceptions and secrets | `modules/settings/server`, `server/core/database`, `server/core/secrets.ts` | Explicitly separated machine policy, user preferences and service-owned data |
| Managed engine/rule installation and activation | `engines/*/server/install.ts`, `server/core/files.ts` | Privileged updater validating provider artifacts and protected destinations |
| Defender preferences and compatibility exclusions | `server/platform/defender.ts` | Narrow administrator-authorized operations, reporting actual Windows state |
| Startup task and context menu registration | `server/platform/startup.ts`, `server/platform/contextMenu.ts` | Installer/service operations; per-user registration where possible |
| DNS/network changes | `modules/dns-protection/server` | Fixed network operations through the broker |
| Ordinary VirusTotal requests | `addons/virustotal/server` | Network worker without administrator privileges |

This is an ownership proposal, not a claim that each file operation always
needs administrator rights. An engine scanning user-readable files can run
without elevation. Protection that reads other users' files or changes machine
configuration needs a separately controlled privileged component.

## Target design

1. A signed Windows service owns machine policy, the protection lifecycle,
   protected engine directories and quarantine. The installer registers it;
   closing the UI or signing out must not stop protection.
2. A normal per-user UI asks for typed operations. The service authenticates the
   connecting Windows identity and authorizes each operation. A named pipe with
   an explicit DACL and verified peer identity is preferable to relying solely
   on a bearer token given to the UI. Deny remote pipe clients, unknown message
   types, oversized messages, replayed actions and unauthorized users.
3. Never expose generic PowerShell, command execution, arbitrary registry writes
   or arbitrary elevated file-copy/delete endpoints. Quarantine actions refer
   to service-issued finding IDs. Verify canonical paths, handles, reparse
   points, file identity and expected content before privileged changes.
4. Separate read-only status access from policy changes. Standard users must
   not create machine-wide exclusions, disable protection or change engine
   executables merely because they can open the UI. Administrator approval is
   needed for those policy operations. Define behavior for multiple signed-in
   users and concurrent decisions.
5. Define and verify ProgramData and executable directory ACLs on installation
   and upgrade. Quarantine, keys, engine files and service policy must not be
   writable by ordinary users. Keep user UI preferences outside service-owned
   policy. Account for SQLite journal/WAL files and recovery copies.
6. Run parsers/scanners and network clients in workers with reduced access,
   bounded resource use and timeouts. An authenticated UI must still not be
   able to make a privileged scanner execute a user-selected executable or DLL.
   Validate updates before switching the active engine and keep a recoverable
   previous installation.
7. Migrate secrets to the service identity explicitly. Existing Windows DPAPI
   blobs may be tied to the current user and cannot simply be assumed readable
   under LocalSystem. Preserve settings and quarantine through service upgrade,
   rollback and uninstall.

Service account choice must follow the required operations: use a restricted
service identity and privileges where possible; do not assume LocalSystem is
necessary for every worker. See Microsoft's
[special-privileges guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/running-with-special-privileges).

## Hardening implemented before the service migration

- API sessions also check local Host/port and a matching browser Origin;
  malformed cookies fail authentication without producing a server exception.
- Threat-alert IPC is bound to its live window, top-level frame, local page and
  finding ID. Reminder actions and alert logging also authenticate their owning
  windows. Unknown actions cannot reach the backend.
- A failed settings database commit does not replace the live settings or
  runtime logging/cloud flags. Exception/report removal is one transaction.
- Restore refuses to overwrite an existing original, verifies copied content
  before source removal and commits exception/report/history/quarantine metadata
  together. Database failure attempts to return the file to quarantine and
  reports both paths if that recovery also fails.
- Managed engine activation keeps the previous engine until the staged
  replacement is active. Failure restores the backup; a locked backup is
  retained for recovery instead of silently discarded.

Tests exercise actual modules against disposable SQLite databases and files,
with injected disk/Windows failures. They do not prove immunity to malicious
filesystem races. Native handle-based operations, crash recovery across a
filesystem move plus database transaction, custom engine directories, update
authenticity and multi-user policy need further assessment during migration.
No claim is made that a JavaScript copy/hash/delete sequence provides a kernel
security boundary or an atomic crash-safe transaction across the filesystem
and SQLite.

## Future kernel protection

Windows ETW, directory notifications and USN can supply useful events without
shipping a custom driver. They do not generally hold an arbitrary file open or
process execution pending a scan verdict. Administrator rights do not remove
that distinction.

A filesystem minifilter can gate selected I/O while a user-mode scanning service
uses ClamAV. Microsoft provides a
[scanner minifilter sample](https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/scanner-file-system-minifilter-driver/)
and documents [authenticated communication ports](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode).
The scanner stays outside the kernel; the driver must handle cancellation,
timeouts, re-entrancy, cache invalidation, service failure and uninstall without
deadlocking file access.

For public deployment, plan for Microsoft-assigned
[minifilter altitude](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers),
Hardware Dev Center enrollment, the applicable HLK/WHCP signing route and
Secure Boot/HVCI compatibility. See the current
[Windows driver policy](https://support.microsoft.com/en-us/windows/hardware/drivers/the-windows-driver-policy)
and [signing offerings](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings).
An installer Authenticode certificate alone does not make a kernel driver
loadable. Test-signed development drivers belong in isolated VMs; a normal
release must not ask users to disable Secure Boot or driver signature checks.

Defender's private driver is not a documented plug-in interface for ClamAV.
[AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
is a scanning integration API and does not grant general filesystem interception.
