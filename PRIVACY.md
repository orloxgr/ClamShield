# Privacy policy

Last updated: 2026-11-05

ClamShield is a free, open-source Windows application maintained by Byron Iniotakis
([orloxgr](https://github.com/orloxgr)). This policy describes the desktop
application. External websites and services have their own policies.

## Local scanning and storage

ClamAV and YARA scans run on the computer. Local scanning does not require sending
the scanned files to the ClamShield maintainer. ClamShield does not include
application usage analytics, advertising trackers, or automatic reporting of scan
logs to the maintainer. It does not send scan data to a hosted AI service.

Settings, scan history, detections, file paths, hashes, exceptions, quarantine
metadata, scan caches, cloud-task queues and diagnostic logs are stored locally.
Quarantined files are also stored locally. The default shared data directory is
`C:\ProgramData\ClamShield`; some directories can be changed in Settings. Electron
also maintains local application/session data in the Windows user's profile.
File paths and logs can reveal usernames and other personal or confidential data.

VirusTotal API keys and SecuriteInfo account tokens are stored separately using
Electron's Windows-backed encrypted credential storage. They are sent to the
relevant provider when its authenticated features are used. Encryption does not
protect against all software running with access to the same Windows account or
administrator privileges.

## Downloads and update checks

ClamShield connects to third parties to obtain application and engine release
information, engines, signature databases, rule packages and optional helpers.
ClamAV, YARA and SaneSecurity helpers are downloaded separately; they are not
bundled into the ClamShield installer. Typical destinations include:

| Purpose | Service or publisher |
| --- | --- |
| ClamShield releases, engine release information and download assets | GitHub and its download infrastructure; the ClamShield, Cisco-Talos/clamav and VirusTotal/yara repositories |
| ClamAV signatures | ClamAV/FreshClam infrastructure and configured mirrors |
| Optional YARA Forge rule packages | YARAHQ/yara-forge on GitHub |
| Optional SecuriteInfo signatures | SecuriteInfo, using the configured account token |
| Optional SaneSecurity signatures and verification key | SaneSecurity and its public rsync mirrors |
| Optional SaneSecurity helper packages | MSYS2 package infrastructure and GnuPG |

These services receive the network requests, including the connecting IP address,
requested resource and ordinary protocol/client metadata. Engine updaters may make
their own network or DNS requests. Downloading signatures does not upload the
user's scan history or scanned files. User-configured sources receive requests
when the corresponding feature is used.

Application and engine update checks, ClamAV signature updates and YARA rule
updates can run automatically under their configured settings. SecuriteInfo and
SaneSecurity require their respective integrations to be enabled. Update controls
are available in Updates and Settings; an enabled local scanner is distinct from
an enabled cloud analysis feature.

## Optional VirusTotal integration

VirusTotal Cloud is disabled by default. It uses the API key supplied by the user.

- **Hash lookup:** sends a file hash to VirusTotal to retrieve an existing report.
  A hash can identify a known file even though its contents are not uploaded.
- **File upload:** sends the file's contents and its base filename to VirusTotal.
  Results and Shield have separate unknown-file upload controls and size limits.
  These upload controls are disabled by default. A user can also explicitly
  request an upload from Results.
- **On-demand cloud scanning:** enabling **Check every file with VirusTotal**
  enables hash lookup and automatic upload of eligible unknown files for that
  scan. It is not a hash-only option. The interface provides the associated upload
  and quota warning/consent controls.
- **Account and analysis requests:** usage checks send authenticated requests;
  background queues store and query analysis identifiers and reports.

Uploads use VirusTotal's standard service, not a private-file analysis service.
Submitted samples may be retained and shared with VirusTotal's security partners
under its terms. Do not submit confidential files without authorization. ClamShield
cannot withdraw data already sent or control a third party's retention.

Accepted uploads may continue to be checked in the background. Turning off an
automatic initial-lookup option does not itself cancel an already accepted
analysis. Use the queue's pause/cancel controls or disable VirusTotal Cloud to
stop the applicable queued processing. Already transmitted requests cannot be
undone. A popup detection threshold changes notification behavior, not upload
consent or quarantine policy.

See [VirusTotal privacy policy](https://www.virustotal.com/gui/privacy-policy) and
[terms of service](https://www.virustotal.com/gui/terms-of-service).

## Optional DNS protection

DNS protection is disabled by default. When enabled, it changes the DNS resolver
addresses on active Windows network adapters to the chosen provider. DNS queries
using those adapters can then be sent to that provider, revealing requested domain
names and network metadata. This affects other applications using the adapters,
not just ClamShield. Browser Secure DNS, VPNs and device policy may use other
resolvers. Previous adapter DNS settings are backed up locally for restoration.
The selected profile's behavior also applies; for example, an EDNS Client Subnet
(ECS) profile can disclose client-network information beyond the recursive resolver.

Provider policies: [Cloudflare](https://www.cloudflare.com/privacypolicy/),
[Quad9](https://quad9.net/privacy/policy/),
[AdGuard DNS](https://adguard-dns.io/en/privacy.html),
[CleanBrowsing](https://cleanbrowsing.org/privacy/) and
[Control D](https://controld.com/privacy).

## Windows integration

The application currently requests administrator privileges. Its Windows
integration can create a startup task and Explorer menu entries. Optional settings
can request Defender compatibility exclusions or changes to Defender protection;
Windows policy and Tamper Protection may refuse those requests. The uninstaller
also attempts to restore Defender protection and associated default preferences,
including cloud reporting/sample-submission preferences. Windows and Defender
then operate under their own settings and
[Microsoft's privacy policy](https://privacy.microsoft.com/privacystatement).
These Windows services are distinct from ClamShield's optional VirusTotal uploads.

## Reports, external links and support

Opening a hash report, provider website, email composer or false-positive form
connects the user's browser or mail application to that service. Prepared reports
may contain file names, paths, hashes and detection details. Review and remove
sensitive information before sending. Preparing a report or marking it as sent
in ClamShield is not proof that a provider received it.

Diagnostic copy/export actions operate locally. If users choose to post diagnostics
in a public GitHub issue, that information becomes public. Information voluntarily
emailed to the maintainer is received through the maintainer's email service and
used to handle the request. Avoid sending files, secrets or logs unrelated to the
problem. The application does not automatically send support email.

## Retention and removal

Local records remain until removed through the relevant application controls,
maintenance or data removal. Log-file cleanup defaults to seven days, is
configurable, and applies to eligible `.log` files; it is not a blanket retention
limit for history, quarantine, cloud tasks, backups or exported reports. Persistent
queues can survive restarts. Upgrades preserve application data.

The interactive uninstaller offers removal of shared ClamShield data. Keeping
that data retains records and may retain credentials; silent uninstall retains
shared data. Separately configured storage, exports, backups and Electron profile
data may require separate removal. Review quarantined files and restore anything
needed before deleting their storage. Removing local data does not delete data
already submitted to external services.

## Other service policies and contact

- [GitHub privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)
- [Cisco privacy statement](https://www.cisco.com/c/en/us/about/legal/privacy-full.html) (ClamAV publisher)
- [SecuriteInfo legal and privacy information](https://www.securiteinfo.com/legal/mentions-legales.shtml)
- [SaneSecurity](https://sanesecurity.com/) (public signature mirrors)
- [MSYS2](https://www.msys2.org/) and [GnuPG](https://gnupg.org/) (optional helper publishers)

Privacy questions: **orloxgr@gmail.com**. Future policy changes are published in
this repository with an updated date. Consult the policy corresponding to the
source revision of a particular release when checking historical behavior.
