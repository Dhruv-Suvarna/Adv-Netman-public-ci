# Phase 18 — Raw Configlets and the isolated verifier / sandbox

Structured Device Builder intentionally does **not** accept arbitrary CLI. Phase 18 adds an *explicitly separate* facility for
**Raw Configlets**: operator-authored network **configuration statements** for one device that the structured schema cannot express,
verified in an **isolated sandbox** before they can enter the normal Change pipeline.

Raw is an escape hatch from the structured *schema* — **not** from validation, verification, dependency ordering, planning, execution
eligibility, locking, audit, security, postcheck or human control. Nothing in Phase 18 executes a Raw Configlet on a real device except the
existing Phase-17 engine, in Partial (UAT) mode, from the pinned, verified revision.

Contents: 1 Purpose and boundary · 2 Architecture · 3 Models · 4 Verification pipeline · 5 Vocabulary · 6 Static gate · 7 Secret policy ·
8 Sandbox isolation · 9 Platform support · 10 Discovery evidence · 11 Dependencies and order · 12 Validation integration · 13 Plan integration ·
14 Execution: Partial (UAT) · 15 Complete-mode restriction · 16 Postcheck · 17 UI · 18 Security · 19 CI · 20 Operating it · 21 Finding codes ·
22 Tests · 23 Known limitations.

## 1. Purpose and the structured-vs-raw boundary

* Structured intent (`DeviceIntent` / `DeviceIntentRevision.sections`) stays strongly typed. **No CLI text field was added to any structured
  section** (interfaces, routing, fhrp, nat, services, security, policy) and there is no generic "Custom CLI" field.
* Raw Configlets have their **own** models, service (`raw_configlet_service.py`, package `core/services/raw_configlets/`), routes and
  templates. They are *input* objects; the planner materialises a **verified** revision into a normal, immutable plan Configlet
  (`Configlet.origin == RAW`).
* "Raw" means raw **network configuration CLI** in configuration mode. It does **not** mean a Linux shell, Python, Bash, a device shell
  escape, container-host commands, exec-mode operational commands or file-system access; the static gate refuses them and no code path
  ever hands operator text to a shell.
* The payload is **configuration-mode statements only**: no prompts (`R1(config)#`), and the verifier / executor own entry to and exit from
  configuration mode, so `enable`, `configure`, `exit`, `end` are refused. Nesting is expressed by indentation (three spaces), exactly like
  the project's rendered Configlets, and is flattened by the *same* function (`modules.eos_render.eos_commands`) for both the verifier and the executor.

## 2. Architecture

```
operator authors raw configuration (browser-local until Save Revision)
   -> Save Revision      static gate + metadata validation; a failing text is NEVER persisted      (no sandbox, no device)
   -> immutable RawConfigletRevision (text, content hash, target, platform, priority, dependencies, assertions)
   -> Verify (explicit CSRF POST)   static gate again -> capability -> isolated sandbox adapter      (never a managed device)
   -> append-only RawConfigletVerificationRun (result, structured findings, bounded sanitized evidence, provenance)
   -> CURRENT + acceptable verification is part of the EFFECTIVE Change input (snapshot / input hash)
   -> Phase-13 whole-Change validation  (opaque nodes, explicit dependency edges, verification status)
   -> Phase-14 ChangePlan  (opaque Configlet pinned to the exact revision + verification run)
   -> Phase-15 precheck
   -> Phase-17 execute_change, Partial (UAT) only, payload re-read from the pinned revision on the server
   -> Phase-15 postcheck  (only operator-declared, closed-catalogue assertions; otherwise UNVERIFIED)
```

Package layout (`web/core/services/raw_configlets/`): `codes.py` (limits, versions, vocabulary, finding catalogue) · `text.py`
(normalization, hash, shared command stream) · `static_gate.py` · `capability.py` · `assertions.py` · `sandbox.py` (the only process
boundary) · `adapters.py` (FRR, cEOS) · `verifier.py` (`verify_raw_configlet`, pure, no DB) · `store.py` · `verification.py`. The facade
`core/services/raw_configlet_service.py` is what views call. Django views are thin adapters; nothing is implemented in JavaScript.

## 3. Models (migration `0007_phase18_raw_configlets`)

| Model | Role |
|---|---|
| `RawConfiglet` | Stable identity: per-Change `RAW-001`… (`raw_id`, immutable, DB-unique with the Change) and the only mutable state, `enabled`. Never deleted by the application. |
| `RawConfigletRevision` | **Immutable** (a database-level edit raises). Text, `content_hash` (SHA-256 of the normalized text), `schema_version`, name, description, target device, **platform**, declared **priority**, explicit **dependencies**, declared **assertions**, `policy_version` at save, creator, time. Editing = a new revision; an identical save is a no-op. |
| `RawConfigletVerificationRun` | **Append-only** evidence: created `RUNNING` (which is also the DB-enforced duplicate-run guard), finalised exactly once, immutable afterwards. Pins revision, content hash, platform, verifier framework version, policy version, adapter id / version, backend (server-owned image tag), started / finished, static result, structured findings, bounded sanitized evidence, provenance. |
| `Configlet` (extended) | `origin` (`STRUCTURED` default / `RAW`), `raw_revision`, `raw_verification`. The pinned facts are in `PLAN_FROZEN_FIELDS`. Historical Phase-14/17 rows keep `STRUCTURED` and keep working. |
| `AuditEvent` types | `RAW_CONFIGLET_CREATED`, `RAW_REVISION_SAVED`, `RAW_ENABLED_CHANGED`, `RAW_VERIFICATION_REQUESTED`, `RAW_VERIFICATION_COMPLETED` (plus the existing `DEPLOYMENT_RECORDED` for execution, now carrying raw pins). No text and no secret is ever in audit metadata; one event per action, never per sandbox output line. |

`enabled = False` is the **soft removal** from the effective Change: the Change's validation and plan become STALE, every revision,
verification and historical plan/execution reference is preserved. Removing a Raw Configlet does **not** remove anything from a device (that is Phase 21).

## 4. Verification pipeline

`verify_raw_configlet(revision, context)` returns a structured outcome (no DB access): the **static policy result**, **sandbox availability**,
the **platform parser verdict**, warnings, blocking findings and provenance. Order: static gate → integrity (stored text still hashes to its
recorded hash) → platform capability → sandbox adapter. A static / capability failure returns `BLOCKED` **without starting a sandbox**.
Only *syntax* is verified: an accepted syntax always carries the info finding `SEMANTICS_NOT_VERIFIED`. "The process exited zero" is never
reported as "safe". Network semantics belong to Phase-13 validation and the operational postcheck.

Verification is **always explicit**. Viewing a page, typing, saving a revision, validating and planning never start a sandbox. **Reuse rule:**
an explicit Verify of a revision whose latest run is CURRENT *and* acceptable (PASS / PASS_WITH_WARNINGS) returns that run instead of
spending a sandbox; BLOCKED, INCOMPLETE and STALE results are never reused. **Concurrency:** a partial UNIQUE index allows at most one `RUNNING`
run per revision; a second attempt is refused (`VERIFICATION_IN_PROGRESS`). Every run holds a lease (`RAW_VERIFIER_LEASE_SECONDS`); an expired
lease is reaped as `INCOMPLETE` so a crash never blocks a revision. This lock is separate from the Phase-17 device locks.

## 5. Result and currency vocabulary

* **Result:** `PASS`, `PASS_WITH_WARNINGS`, `BLOCKED` (known unacceptable content / parser rejection), `INCOMPLETE` (verification could not be completed honestly: timeout, sandbox unavailable or disabled, missing image, unparseable output, failed cleanup). Never a numeric score. `STALE` is never a result.
* **Currency (computed, never stored):** `NEVER_RUN`, `CURRENT`, `STALE`. A revision's latest finished run is CURRENT only while all of these still match: content hash, the run's and the target device's platform, static policy version, verifier framework version, adapter id + version, sandbox backend identity (image tag). Any difference → STALE with machine-readable reasons (`CONTENT_CHANGED`, `PLATFORM_CHANGED`, `POLICY_VERSION_CHANGED`, `VERIFIER_VERSION_CHANGED`, `ADAPTER_CHANGED`, `BACKEND_CHANGED`). A new revision — even one byte — is `NEVER_RUN`; an old revision keeps its own result.
* UI states: *Never verified* · *Current / PASS* · *Current / PASS WITH WARNINGS* · *Current / BLOCKED* · *Current / INCOMPLETE* · *Stale*.

## 6. Static safety gate (`static_gate.py`, policy `18.0.0-static1`)

Deterministic defence in depth **before** any sandbox. A denylist is not a security parser and is not presented as one; the real boundaries are the
sandbox (verification) and the Phase-17 engine (execution). Bounds (server-side; the browser's `maxlength` is never trusted): **32768 bytes**,
**500 lines**, **512 characters per line**; nothing is silently truncated — an oversized input is blocked with a clear finding.
Input must be printable ASCII plus newlines: a NUL byte, invalid encoding, control characters (tabs included) and non-ASCII characters are refused. Line endings are
normalised (CRLF/CR → LF, trailing whitespace and trailing blank lines dropped, one final newline), deterministically and idempotently.
It also refuses: device-prompt transcripts, mode-control commands (`enable`/`configure`/`exit`/`end`/…), host-shell and remote-access commands (`bash`, `python`, `docker`,
`ssh`, `curl`, …), exec-mode commands (`show`, `write`, `copy`, `reload`, `erase`, …), configuration constructs that can run host commands (`event-handler`,
`daemon`, `schedule`, `alias`, `action bash`), shell metacharacter sequences, multi-line contexts (`banner`) and secret-shaped content. Full-line comments and free-text
`description` / `remark` lines are never scanned, so documentation and BGP `send-community` / `set community` are not false positives. Findings carry stable codes,
line numbers, pattern **names** and command words — never the matched text.

## 7. Secret policy

Raw Configlets are **not** a loophole in the project's no-plaintext-secret rule. Text is checked **before persistence** (a secret-shaped revision is refused and never stored)
and again before verification. Detection reuses the repository's credential-format patterns (`ci.redact`: private-key blocks, webhooks, tokens, cloud keys) plus keyword rules
from the shared `secret_policy` vocabulary — `password`, `passwd`, `secret`, `token`, `webhook`, `credential`, `apikey`/`api_key`, `private_key`/`priv_key`, `auth_key`, `community`
(SNMP only) — flagged only when a *value* follows, plus SNMPv3 auth/priv key material. The project has **no secret-reference resolution inside raw CLI**, so raw snippets that
need credentials are **not deployable in Phase 18**. Name, description and assertion values are checked too. Sandbox output, findings and audit metadata are redacted (`nsot_live.redact_config` + `ci.redact`).

## 8. Sandbox isolation (`sandbox.py`, `adapters.py`)

Verification **never** targets a managed device: it can only start disposable containers from server-owned images. Guarantees (each covered by a contract or behaviour test):

* the **only** process spawn in the package is `sandbox.run_process`: a `docker` argv **list**, `shell=False`, allowlisted environment (`PATH`, `HOME`, `DOCKER_*`, `XDG_RUNTIME_DIR` — no application secret, token or credential is forwarded), hard timeout, bounded capture; no `eval`/`exec`/`os.system`/`sh -c`;
* browser text travels **only over stdin** of a fixed command; images come from settings, validated against a strict pattern; container names are generated (`clab-rawverify-<adapter>-<12 hex>`) and validated before use;
* ephemeral unique container, `--network none`, no mounts, no Docker socket, no host PID/network namespace, bounded memory / CPU / PIDs, no credential, SSH key or token;
* **cleanup in `finally`** on success, failure, timeout and exception, *confirmed* by a follow-up query; a container that cannot be proven removed yields `SANDBOX_CLEANUP_FAILED` → `INCOMPLETE` (never PASS);
* timeout, runtime unavailable, missing image, start failure, unparseable output → `INCOMPLETE`; parser rejection → `BLOCKED`;
* output is bounded (64 KiB captured, ≤40 stored lines of ≤240 characters), stripped of control characters, redacted and path-scrubbed; only structured findings and that bounded excerpt are stored — never an environment dump or raw log.

| Backend | Adapter | Isolation actually applied | Honest limits |
|---|---|---|---|
| Ubuntu/FRR | `frr_vtysh_dryrun` — `vtysh -C -f /dev/stdin` | `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, non-root `65534`, 256 MiB, 1 CPU, 64 PIDs, `noexec` tmpfs, **not privileged** | Syntax only (vtysh's compiled command tree); no daemon runs. Needs the local image `clab-raw-verifier-frr:8.4.4-1.1ubuntu6.7`. |
| Arista cEOS | `ceos_config_session` — statements parsed inside a `configure session` that is always **aborted** (never committed) | `--network none`, no mounts, 3 GiB, 2 CPUs, 4096 PIDs — but **`--privileged` is unavoidable** (systemd is PID 1; unprivileged start was tested and exits 255) | Reduced isolation, so it is **disabled unless `RAW_VERIFIER_ALLOW_PRIVILEGED=1`**; when disabled nothing is started and the result is `INCOMPLETE` (`SANDBOX_DISABLED`). The static gate blocks the constructs that would let config run host commands, and the session is aborted, but this is still a privileged container. ~40 s boot per verification. Syntax only. |

## 9. Platform support (evidence-based, four-state; verification and execution are separate)

| Platform | Raw verification | Raw execution (apply) | Complete (compensation) | Evidence |
|---|---|---|---|---|
| Arista cEOS | **SUPPORTED** (privileged, opt-in) | **SUPPORTED** (Partial (UAT) only) | NOT_IMPLEMENTED | Local `ceos:4.36.2F` (the live image); config-session parse observed: valid → silent, invalid → `% Invalid input at line N`; executor reuses the Phase-17 Netmiko config-mode path. |
| Ubuntu/FRR | **SUPPORTED** (unprivileged) | **NOT_IMPLEMENTED** | NOT_IMPLEMENTED | `vtysh -C` of the same frr 8.4.4-1.1ubuntu6.7 R3/R4 run; but `master.py` applies FRR only as a whole `frr.conf` + `vtysh -b`, so no incremental raw apply is proven, and a Raw Configlet is never run as a Linux command. |
| Nokia SR Linux | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED | Not part of the approved Labs 2/3 baseline (an unused image exists locally; no verifier was built). |
| Cisco IOS 8000v | NOT_IMPLEMENTED | NOT_IMPLEMENTED | NOT_IMPLEMENTED | No image / parser locally, no repository evidence. |
| SONiC | NOT_IMPLEMENTED | NOT_IMPLEMENTED | NOT_IMPLEMENTED | No image / parser locally, no repository evidence. |
| any other | UNKNOWN | UNKNOWN | UNKNOWN | Never assumed. |

A Raw Configlet can be **authored only** for a platform whose verification is SUPPORTED; the server rejects the rest (`RAW_PLATFORM_UNSUPPORTED`). Raw support has its own scope: it does **not** make
"all cEOS features" or "all FRR features" supported.

## 10. Discovery evidence (Phase-18 §57)

Observed on this host, read-only or in disposable containers, without touching the live topology: Docker 27.5.1 usable by the application user; images `ceos:4.36.2F`, `ubuntu:24.04`, `ghcr.io/nokia/srlinux:24.10` present; the live cEOS nodes run
`privileged=true`; `ubuntu:24.04` has no FRR (R3/R4 have frr 8.4.4-1.1ubuntu6.7); unprivileged cEOS exits immediately (255); a privileged network-less cEOS boots in ~36 s and its EOS parser reports rejected lines; FRR `vtysh -C` accepts valid and rejects
invalid config (exit 0 / 2) inside `--network none --read-only --cap-drop ALL --user 65534`. No arbitrary vendor image was pulled: the FRR image is built from the already-local `ubuntu:24.04` plus the same distro package version, from a Dockerfile in Git.

## 11. Dependencies and order

Raw text is opaque; dependencies are **explicit**, never inferred. A revision declares stable node references (`R1/interface/<id>`, `R1/raw_configlet/RAW-001`, …; the editor lists the
structured objects from the latest validation). They become edges of the Phase-13 dependency graph: an unresolvable reference is `DEPENDENCY_MISSING`, a cycle `DEPENDENCY_CYCLE`, a self-reference `RAW_DEPENDENCY_SELF`;
cross-device references are allowed. **Priority** (1–9, the canonical classes) is the operator's declared value and is never inferred from text; **dependencies override priority** (`PRIORITY_DEPENDENCY_INVERSION` is reported); the planner's deterministic sort key
`(priority, device, operation, identity)` — with raw Configlets ordered as `ACTIVATE_ATTACH` — remains authoritative.

## 12. Whole-Change validation integration

The Change snapshot gains a `raw_configlets` section **only when at least one enabled Raw Configlet exists**, so the canonical input hash of every Change without one is unchanged (historical runs and plans keep their hash; no engine/planner version bump was needed).
The section carries, per Raw Configlet, the revision number, content hash, platform, priority, dependencies, assertions and the **verification status** (currency, result, run id, versions, backend) — never the text. Therefore adding, editing, retargeting, reordering, removing, re-verifying, or a
verifier/policy/backend version change all make a prior validation and plan STALE. The `raw_configlets` validator (pure) treats each as an opaque verified artifact: `RAW_NOT_VERIFIED`, `RAW_VERIFICATION_STALE`, `RAW_VERIFICATION_BLOCKED` → **BLOCKED**;
`RAW_VERIFICATION_INCOMPLETE` → **INCOMPLETE**; `RAW_VERIFICATION_WARNINGS` / `RAW_EXECUTION_NOT_SUPPORTED` → warnings; plus target, platform, capability and priority checks. It never parses vendor CLI. No plan can be built from a BLOCKED / INCOMPLETE validation.

## 13. Plan integration

There is no second planner. Verified Raw Configlets become opaque Configlet nodes of the **same** deterministic `ChangePlan`: stable `CFG-NNN` ids, the same dependency graph, ordering, plan hash and immutability. Each pins the exact revision **and** verification run (`Configlet.origin=RAW`, `raw_revision`, `raw_verification`,
`metadata.raw`), the plan hash covers those pins, the builder re-checks the revision hash and the verification's currency, and a later edit or re-verification makes the plan STALE without rewriting it. Historical plans stay exactly as they were.

## 14. Execution: Partial (UAT)

Raw Configlets enter `execute_change` like any Configlet — the same eligibility, locks, persistence, precheck requirement, execution results, postcheck and audit. Extra gates: the pinned revision must still hash to what the plan pinned (`RAW_REVISION_INTEGRITY`) and its pinned verification must still be CURRENT and acceptable
(`RAW_VERIFICATION_NOT_CURRENT`); an unsupported platform is `PLATFORM_EXECUTION_UNSUPPORTED`. The payload is **always re-read server-side from the pinned immutable revision** — not from the browser, and not from the copied plan text; the browser supplies only the mode confirmation, the five
acknowledgements and the `through` Configlet id. All five UAT acknowledgements are still required; the run is an ordered prefix, stops at the first failure, preserves the successful prefix, never rolls back, and postchecks only the executed scope. History (`ConfigletExecutionResult.previous_state.raw`, the run report and the audit event) references the exact revision and content hash.

**Notifications and audit.** No new notification system was added: execution outcomes reuse the Phase-17 notification path (persist first, Slack second; failure never affects the run) and
verification does not notify (warnings and results are shown in the UI). Audit events: Raw Configlet created, revision saved, added to / removed from the effective Change, verification requested, verification completed, and the existing execution events (now carrying raw pins).

## 15. Complete-mode restriction

**Raw Configlets can never enter Complete mode.** An inverse cannot be derived from opaque text, and no platform-backed whole-raw rollback was proven, so the eligibility gate refuses with `RAW_COMPLETE_FORBIDDEN` ("a raw Configlet lacks proven transactional compensation") **before any lock or device method** (`connect` is not even called). No rollback text is ever fabricated and the
Phase-17 Complete guarantees for structured Configlets are unchanged.

## 16. Postcheck semantics

Sandbox verification asks "can the platform parser accept this?"; the postcheck asks "did the intended state occur on the real target?". They are different, and a PASS verification is never deployment success. An opaque Raw Configlet has no derivable expected state, so none is invented:
with **no** declared assertion its single requirement is `RAW_CONFIG_APPLIED`, which the Phase-15 engine reports as not verified → a Partial (UAT) run ends **`UAT_SCOPE_APPLIED_UNVERIFIED`**. An operator may instead declare structured assertions from a **closed, server-owned catalogue** that map onto *existing* Phase-15 evaluators:
`INTERFACE_STATE`, `ADDRESS_PRESENT`, `ROUTE_PRESENT`, `OSPF_ADJACENCY`, `BGP_ADJACENCY` (`KIND key=value …`, strictly validated). An assertion PASS confirms only the declared facts — not that the whole configuration applied. **No arbitrary show / read command is ever accepted or executed.**

## 17. UI workflow

Inside the existing Change / Device Builder experience (a **RAW** badge is on every page): Change → *Raw Configlets* (`…/changes/<id>/raw/`) → New / editor (`raw/new/`, `raw/<RAW-id>/`) → **Save Revision** → **Verify revision N** → verification page → Change Validation → Plan → Precheck → Execution. The editor shows target, platform, name, description,
priority, dependencies, configuration, content hash, revision, verification status / currency and the latest structured findings; history pages list every revision (read-only, `raw/<id>/revisions/<n>/`) and every verification (`raw/<id>/verifications/<run>/`). Typing stays in the browser (a plain form, no JavaScript, no keystroke round-trips); *Save Revision* and *Verify* are separate explicit CSRF POSTs; Verify names only the revision number
the operator was looking at (a superseded number is refused). There is **no** raw execute endpoint.

## 18. Security summary

Secrets: refused before persistence, redacted in output, absent from audit. Shell boundary: none — argv list, `shell=False`, stdin-only payload. Container boundary: see §8. Credentials: none are passed to the sandbox and no device credential is used for verification. CSRF: every mutation is POST + the project-wide CSRF middleware. Browser trust: bounded fields only;
execution input is limited to the Phase-17 controls. Verification and execution are never conflated.

## 19. CI (GitHub Actions / Tier-3)

Phase-16 Actions remain validation-only. Ordinary CI runs the unit tests with a **fake** process runner and scripted verifier adapters — no Docker and no vendor image is needed or used, no device credential exists in the workflow, and Actions never executes a Raw Configlet. The real sandbox is exercised only by the explicit local tool
`python manage.py raw_verifier_selftest --platform ubuntu_frr|arista_ceos`. Tier-3 has a `raw_configlets` subsystem (paths `web/core/services/raw_configlets/**`, `raw_configlet_service.py`, the self-test command) selecting `raw_configlets`, `raw_sandbox`, `raw_integration`, `raw_views`, `contracts`; the
validation, planning and execution subsystems additionally select `raw_integration`, and models select the whole suite.

## 20. Operating it

```
# once (explicit operator step; the application never builds or pulls images)
docker build -t clab-raw-verifier-frr:8.4.4-1.1ubuntu6.7 -f web/core/services/raw_configlets/images/frr.Dockerfile web/core/services/raw_configlets/images
# prove the real sandbox (harmless synthetic valid + invalid snippet; proves cleanup)
python web/manage.py raw_verifier_selftest --platform ubuntu_frr
RAW_VERIFIER_ALLOW_PRIVILEGED=1 python web/manage.py raw_verifier_selftest --platform arista_ceos
```
Settings (environment, all server-owned): `RAW_VERIFIER_FRR_IMAGE`, `RAW_VERIFIER_CEOS_IMAGE`, `RAW_VERIFIER_ALLOW_PRIVILEGED` (default off), `RAW_VERIFIER_TIMEOUT_SECONDS`, `RAW_VERIFIER_CEOS_BOOT_TIMEOUT_SECONDS`, `RAW_VERIFIER_CLEANUP_TIMEOUT_SECONDS`, `RAW_VERIFIER_LEASE_SECONDS`.
Changing an image tag makes existing verifications STALE by design.

## 21. Finding codes (Raw Configlet static / sandbox / platform findings)

Stable codes carried by static-gate and verification findings (the Phase-13 validation codes for Raw Configlets are in `CHANGE_VALIDATION_AND_DEPENDENCIES.md`).

| Code | Stage | Severity | Blocking | Incomplete | Meaning |
|---|---|---|---|---|---|
| `RAW_EMPTY` | STATIC | ERROR | yes | no | The configuration body is empty. |
| `RAW_TOO_LARGE` | STATIC | ERROR | yes | no | The configuration exceeds the maximum size. |
| `RAW_TOO_MANY_LINES` | STATIC | ERROR | yes | no | The configuration exceeds the maximum number of lines. |
| `RAW_LINE_TOO_LONG` | STATIC | ERROR | yes | no | A line exceeds the maximum length. |
| `RAW_NUL_BYTE` | STATIC | ERROR | yes | no | The input contains a NUL byte. |
| `RAW_INVALID_ENCODING` | STATIC | ERROR | yes | no | The input is not valid text (invalid encoding). |
| `RAW_CONTROL_CHARACTER` | STATIC | ERROR | yes | no | The input contains a control character (tabs are not allowed; indent with spaces). |
| `RAW_NON_ASCII_CHARACTER` | STATIC | ERROR | yes | no | The input contains a non-ASCII character. |
| `RAW_SECRET_SHAPED_CONTENT` | STATIC | ERROR | yes | no | A line looks like it carries a credential or secret. Raw Configlets cannot hold secret values and the project has no secret-reference resolution for raw CLI. |
| `RAW_PROMPT_TRANSCRIPT` | STATIC | ERROR | yes | no | A line looks like a device prompt / login transcript. Submit the configuration body only. |
| `RAW_MODE_CONTROL_COMMAND` | STATIC | ERROR | yes | no | A mode-control command (enable, configure, exit, end, ...) is not allowed: the executor owns configuration-mode entry and exit; express nesting with indentation. |
| `RAW_HOST_SHELL_COMMAND` | STATIC | ERROR | yes | no | A host-shell / remote-access / file command is not network configuration. |
| `RAW_SHELL_METACHARACTER` | STATIC | ERROR | yes | no | A shell metacharacter sequence is not allowed in configuration statements. |
| `RAW_EXEC_MODE_COMMAND` | STATIC | ERROR | yes | no | An exec-mode / operational command (show, clear, write, copy, reload, ...) is outside the Raw Configlet contract. |
| `RAW_HOST_EXECUTION_CONSTRUCT` | STATIC | ERROR | yes | no | A configuration construct that can run host commands (event-handler, daemon, schedule, alias, action bash) is not allowed. |
| `RAW_UNSUPPORTED_CONTEXT` | STATIC | ERROR | yes | no | A multi-line input context (for example a banner) is not supported. |
| `RAW_PLATFORM_UNSUPPORTED` | STATIC | ERROR | yes | no | The target platform has no supported raw verification path. |
| `RAW_NAME_INVALID` | STATIC | ERROR | yes | no | The name is required and must be short printable text. |
| `RAW_TARGET_INVALID` | STATIC | ERROR | yes | no | The target device must be a device that already has a Device Intent in this Change. |
| `RAW_PRIORITY_INVALID` | STATIC | ERROR | yes | no | The priority must be one of the nine canonical deployment priorities (1-9). |
| `RAW_DEPENDENCY_INVALID` | STATIC | ERROR | yes | no | A dependency reference is malformed. |
| `RAW_DEPENDENCY_SELF` | STATIC | ERROR | yes | no | A Raw Configlet cannot depend on itself. |
| `RAW_ASSERTION_INVALID` | STATIC | ERROR | yes | no | A postcheck assertion is not valid for the closed assertion catalogue. |
| `SANDBOX_DISABLED` | SANDBOX | ERROR | no | yes | This sandbox backend requires reduced isolation (a privileged container) and is disabled by server policy. |
| `SANDBOX_UNAVAILABLE` | SANDBOX | ERROR | no | yes | The container runtime is not available to the server. |
| `SANDBOX_IMAGE_MISSING` | SANDBOX | ERROR | no | yes | The server-owned sandbox image is not present locally. |
| `SANDBOX_START_FAILED` | SANDBOX | ERROR | no | yes | The sandbox could not be started. |
| `SANDBOX_TIMEOUT` | SANDBOX | ERROR | no | yes | The sandbox did not finish within the time limit. |
| `SANDBOX_CLEANUP_FAILED` | SANDBOX | ERROR | no | yes | The disposable sandbox could not be removed; verification is not reported as PASS. |
| `SANDBOX_OUTPUT_TRUNCATED` | SANDBOX | WARNING | no | no | Sandbox output exceeded the bound and was truncated. |
| `VERIFIER_OUTPUT_UNPARSEABLE` | INTERNAL | ERROR | no | yes | The verifier output could not be interpreted. |
| `VERIFIER_INTERNAL_ERROR` | INTERNAL | ERROR | no | yes | The verifier failed unexpectedly. |
| `RAW_REVISION_INTEGRITY` | INTERNAL | ERROR | yes | no | The stored revision text no longer matches its recorded content hash. |
| `VERIFICATION_INTERRUPTED` | INTERNAL | ERROR | no | yes | The verification did not finish (lease expired). |
| `SYNTAX_REJECTED` | PLATFORM | ERROR | yes | no | The platform parser rejected the configuration. |
| `PLATFORM_WARNING` | PLATFORM | WARNING | no | no | The platform parser emitted a warning. |
| `SYNTAX_ACCEPTED` | PLATFORM | INFO | no | no | The platform parser accepted the configuration syntax. |
| `SEMANTICS_NOT_VERIFIED` | PLATFORM | INFO | no | no | Only syntax was verified. The semantic / operational effect of this configuration is unknown; Change validation and the postcheck own that. |

## 22. Tests

`test_raw_configlets` (static-gate matrix, normalization / hash, capability matrix, assertions, identity / revisions / immutability, result and currency semantics, duplicate-run guard, reuse), `test_raw_sandbox` (argv / env / stdin boundary, adapter output interpretation, cleanup on every path, AST contracts: one process boundary, no shell, no managed-device access),
`test_raw_integration` (input hash and staleness, validation matrix, dependencies, plan pinning, Phase-17 execution incl. Complete refusal and pinned payload), `test_raw_views` (HTTP boundaries). Shared fakes live in `tests/helpers/raw.py`; the sandbox is faked at the single `run_process` boundary, so ordinary runs never need Docker.

## 23. Known limitations (deliberate unless marked as a defect)

* **Syntax only.** No verifier proves semantic or network correctness; validation and the postcheck own that.
* **cEOS verification needs a privileged container** (vendor constraint), so it is **off by default** and reduced-isolation when enabled; ~40 s per verification; one sandbox per request (no global concurrency cap).
* **FRR raw execution is NOT_IMPLEMENTED**: FRR raw Configlets can be authored, verified and planned, but a plan containing one cannot be executed. Other platforms have no verifier.
* **Complete mode is never available for Raw Configlets.** Running configuration only; no `write memory` (persistence belongs to Golden / Probation phases).
* **Static gate is a denylist**, not a complete parser; ASCII only; explicit `exit` / `end` are refused (use indentation); multi-line contexts (banners) unsupported; comments are dropped before sending.
* **A block opener outside `eos_commands`' `MODE_STARTS` list is sent flat**; the verifier and executor treat it identically, so a mis-nested block is caught by the verifier rather than hidden.
* **Assertions are a small closed catalogue**; without one, execution ends UNVERIFIED by design.
* **Live mutation not performed.** No Raw Configlet was applied to a real managed device (no approved harmless UAT Change exists); the raw execution path is proven against fake transports only.
* Not implemented (later phases): golden / probation bundles (19), soak / promotion (20), operator rollback / removal from devices (21), from-scratch lifecycle (22).
