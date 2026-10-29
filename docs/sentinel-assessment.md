# Sentinel integration assessment

Read-only source review on 2026-10-29, against upstream commit
[`4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b`](https://github.com/mukti-sys/sentinel-antivirus/tree/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b).
No Sentinel code, model, driver or dependency has been installed or integrated.
This is a selective review, not a security audit or detection benchmark.

## What driverless operation means

The [service](https://github.com/mukti-sys/sentinel-antivirus/blob/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b/sentinel/service.py)
attempts to connect to an optional minifilter. If it is absent, kernel enforcement
is disabled and the rest operates in user mode. Its
[directory sensor](https://github.com/mukti-sys/sentinel-antivirus/blob/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b/sentinel/sensors/fs_sensor.py)
handles created/modified/moved/deleted events; its
[ETW sensor](https://github.com/mukti-sys/sentinel-antivirus/blob/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b/sentinel/sensors/etw_sensor.py)
subscribes to process/image/registry events and requires elevation.

These provide monitoring and response, not a general guarantee that every file
is scanned before any process can execute it. The optional
[minifilter callback](https://github.com/mukti-sys/sentinel-antivirus/blob/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b/driver/SentinelFilter/SentinelFilter.c)
blocks opens of paths already present in its blocklist; it is not a complete
scan-before-access ClamAV integration.

Upstream's own [driver development guide](https://github.com/mukti-sys/sentinel-antivirus/blob/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b/driver/README.md)
requires an isolated VM, test signing and disabling Secure Boot for that driver.
It therefore does not solve production Windows driver distribution. Safe Mode,
Secure Boot and test-signing mode are different things. Public deployment must
follow Microsoft's current driver signing and compatibility requirements.

## Useful candidates

| Candidate | Possible ClamShield use | Acceptance requirement |
| --- | --- | --- |
| ETW process/image/registry events | Correlate suspicious activity and prioritize ClamAV scans | Provider compatibility, event-loss monitoring, bounded queues, performance and permission tests |
| Canary files and write-rate/entropy signals | Additional ransomware warning | Explicit setup/cleanup, attribution evidence and benign backup/sync/editor false-positive tests; no promise of preventing all damage |
| Static PE/ML classification | An optional local evidence provider for executable files | Validate the actual model and feature extraction on representative independent benign/malicious corpora; versioned trusted model updates |
| Memory inspection/YARA | Optional investigation of selected processes | Permission failures, resource limits, privacy and process identity handled explicitly |

Use one ClamShield findings pipeline: events schedule existing ClamAV/YARA scans;
optional behavioral/ML providers add separately identified evidence. Keep one
settings store, exceptions policy, quarantine, history and user decision flow.
Avoid two services independently moving/quarantining the same file or duplicating
VirusTotal uploads. Behavioral suspicion alone should not be presented as a
confirmed virus or silently trigger destructive decisions without validated
policy.

## Concrete reasons not to embed the whole project now

- In [sandbox/isolation.py](https://github.com/mukti-sys/sentinel-antivirus/blob/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b/sentinel/sandbox/isolation.py),
  Windows execution uses ordinary `subprocess.Popen` and then assigns a Job
  Object. Assignment failure is logged and execution continues. No VM or
  AppContainer/restricted token/filesystem/network boundary is established there.
  Copying an executable into a scratch directory and limiting its CPU/RAM is
  insufficient containment for malware. Do not adopt this as a safe detonation
  feature on users' machines. Microsoft's [Job Object documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
  describes process grouping and resource management.
- In [kernel/bridge.py](https://github.com/mukti-sys/sentinel-antivirus/blob/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b/sentinel/kernel/bridge.py),
  `poll_events(timeout_ms=0)` describes non-blocking behavior, but calls
  `FilterGetMessage` with a null OVERLAPPED pointer and does not use the timeout.
  The implementation itself notes that this call blocks without a message.
  This needs review before relying on service responsiveness.
- The [static classifier](https://github.com/mukti-sys/sentinel-antivirus/blob/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b/sentinel/engine/static_classifier.py)
  includes multiple model fallbacks, including `joblib.load`. Loading a model
  must be treated as loading trusted code-capable input, with protected paths
  and authenticated distribution. Upstream's claims and small system-binary
  benchmarks do not establish a production false-positive rate for ClamShield.
- The engines, Python runtime, native libraries and models add packaging,
  update, licensing and audit obligations. The repository's
  [MIT license](https://github.com/mukti-sys/sentinel-antivirus/blob/4edfa264f4f5403bbc57ced9a7d5d8cacb8c205b/LICENSE)
  allows reuse with its notice; it does not replace checking dependency, model,
  dataset and rule licenses.

Recommendation: first prototype a bounded behavioral event provider feeding
ClamShield's existing scan queue, without adopting the sandbox or development
driver. Evaluate ML and ransomware response separately before enabling them by
default. No integration is authorized merely by this assessment.
