# One-time Legacy Baseline Bootstrap (between Phase 20 and Phase 21)

> **This is a one-time transition, not a phase and not a redesign of Phase 20.** It exists so the automation framework can start from a known-good
> baseline of a network that was configured *traditionally, before the framework existed*. It is used **once**, then locked out forever. The normal
> probation policy is unchanged: **seven days (168 h)**.

```
CURRENT LIVE NETWORK ── read-only discovery ──> sanitized, canonical LEGACY_BASELINE candidate (immutable)
        ── 30 REAL minutes of read-only observation (a sample every 5 min: health + drift + interference) ──> technical PASS
        ── operator's explicit approval (POST + CSRF; devices re-read first) ──> the INITIAL GOLDEN (provenance LEGACY_BOOTSTRAP)
        ── lockout: this path refuses forever ──> every later Golden follows UAT -> Probation -> 7-day soak -> decision
```

Contents: 1 Why it exists · 2 Why it is not UAT · 3 What it is made of · 4 Provenance and the narrow exception · 5 The two policies · 6 Capture semantics ·
7 Secret handling · 8 What is checked every sample · 9 Drift and interference · 10 Result vocabulary and success criteria · 11 Approval · 12 The initial Golden ·
13 The one-time lockout · 14 Phase 21 and Checkpoint 4 · 15 Operator runbook · 16 Interruption · 17 Limitations · 18 Tests and Tier-3.

## 1. Why it exists

The lab topology was built and configured by hand. The Phase-16 to Phase-20 lifecycle (Change -> validation -> plan -> Partial UAT -> UAT bundle ->
Probation bundle -> soak -> Golden) can only describe changes that went *through* it. There is no Change, plan or execution for the configuration that
is already running, and inventing them would falsify history. The operator therefore approved **one** exception: treat what is *actually running now* as
the initial legacy baseline candidate, observe it for 30 real minutes, and -- only on explicit approval -- record it as the initial Golden.

## 2. Why it is not UAT

Nothing about this is presented as ordinary UAT. **No** `Change`, `ChangePlan`, `ChangeValidationRun`, `ChangeExecutionRun`, `OperationalCheckRun`, UAT bundle,
Probation bundle or `ProbationSoakRun` is created (a test counts the rows before and after a full bootstrap). The initial Golden says so itself, in
structured provenance, in its manifest, on its page and in its export: `provenance = LEGACY_BOOTSTRAP`, `predates_automation_framework = true`, and no soak
promotion block. It is never described as having passed a seven-day soak.

## 3. What it is made of

| Piece | Where |
|---|---|
| candidate + initial Golden bundle, one-time gate, integrity | `web/core/services/bundles/legacy.py`, `legacy_sanitize.py`, `entry.py` (+ `persistence` / `integrity` / `export` / `canonical` extensions) |
| read-only capture, sanitization into the payload, drift comparison | `web/core/services/bootstrap/capture.py` |
| per-sample evidence read and assessment | `bootstrap/evidence.py` (reuses `health.device.deep_checks`, `health.evaluators`, `soak.assessment`) |
| evaluation, coverage, evidence digest | `bootstrap/evaluator.py` (reuses the pure `soak.evaluator`, adds only the drift rule) |
| lifecycle: start, cancel, collector tick, wait loop | `bootstrap/lifecycle.py` |
| capture service + read-only readiness probe | `bootstrap/baseline.py` |
| operator approval | `bootstrap/decision.py` (the only caller of `legacy.create_initial_golden`) |
| policy `LEGACY_BOOTSTRAP_POLICY_V1` | `bootstrap/policy.py`, `settings.LEGACY_BOOTSTRAP_*` |
| facade | `web/core/services/bootstrap_service.py` |
| UI | Automation -> **Initial Golden Bootstrap** (`/device-builder/bootstrap/`), `templates/core/bootstrap/` |
| operator command | `python web/manage.py legacy_bootstrap probe / capture / start / observe / status / approve / verify` |
| models (migration `0010`) | `LegacyBootstrapRun`, `LegacyBootstrapSample`, `LegacyBootstrapDecision`; `ConfigurationBundle.provenance`, `BundleKind.LEGACY_BASELINE` |

There is **no second monitoring stack** and no second health engine. A separate run / sample / decision model exists (instead of reusing
`ProbationSoakRun`) *because* a `ProbationSoakRun` would falsely imply Probation lineage -- honesty over forced reuse. The pure evaluator, coverage maths,
classification and interference detection **are** reused.

## 4. Provenance and the narrow exception

`ConfigurationBundle` gained an explicit typed `provenance` column (`EXECUTION_LINEAGE`, the default and the only value every existing bundle has, or
`LEGACY_BOOTSTRAP`) and a new kind `LEGACY_BASELINE` (`BND-LEGACY-000001`). The exception is enforced three times:

* **Model validation** (`_validate_bundle_lineage`): a bundle with `EXECUTION_LINEAGE` provenance still needs its Change / plan / validation / execution and
  the exact UAT -> Probation -> Golden lineage; `LEGACY_BOOTSTRAP` is valid only for a `LEGACY_BASELINE` candidate and the single Golden derived from it, and
  then it must have **none** of those sources. A normal bundle can never derive from a legacy bundle.
* **Database CHECK constraints** (`bundle_kind_parent_shape`, `bundle_provenance_sources`): `parent = NULL` / missing sources are valid *only* for legacy
  provenance -- **not** universally. Proved with `bulk_create`, which bypasses the model.
* **Digest coverage**: `lineage.legacy_bootstrap` is covered by the bundle digest *only when present* (every UAT / Probation / normal-Golden digest is
  byte-identical to before), and `verify_bundle_integrity` cross-checks it against the stored decision, the observation run and the candidate.

## 5. The two policies

| | Normal probation soak (unchanged) | Legacy bootstrap (this document) |
|---|---|---|
| duration | **7 days = 604 800 s = 168 h** | **30 minutes = 1 800 s** |
| policy | `20.0.0` (`soak/policy.py`) | `LEGACY_BOOTSTRAP_POLICY_V1` (`bootstrap/policy.py`) |
| sample interval | 900 s | **300 s** (T+0, T+5 ... T+25, closing sample at / after T+30) |
| minimum coverage | 90 % | **80 %** of six intervals (five) |
| maximum unobserved gap | 7 200 s | **600 s** |
| critical CPU / memory | 3 consecutive samples (`cpu_threshold_policy.yml`) | the same project value |
| decision window | 72 h | 1 h |
| settings | `PROBATION_SOAK_*` (lower bound: exactly 7 days) | `LEGACY_BOOTSTRAP_*` (lower bound: exactly 30 minutes) |

Time semantics are exactly Phase 20's: `timedelta` arithmetic on timezone-aware UTC, computed once by the server at start
(`required_end_at = started_at + 30 min`), pinned in the run, never backdated, sleep-skipped, patched or browser-supplied; `now >= required_end_at` is
enough (30 minutes exactly is eligible, 1 799 s is not). Tests run the **real** 30-minute policy on a controlled clock. The bootstrap policy never reads or
writes `PROBATION_SOAK_*`; a test proves normal probation still starts with `604800` after the bootstrap.

## 6. Capture semantics

The authority is **what the devices report**, not `DeviceIntent`, YAML, Jinja or Git (the network predates them). Reads use the existing trusted,
allowlisted, server-owned sessions of `health.live` -- nothing from a browser ever reaches a command:

| platform | devices | read |
|---|---|---|
| cEOS | R1, R2, S1-S4, mgmt_swt | Netmiko privileged EXEC `show running-config` |
| cEOS (Containerlab-assigned management address) | R5 | `docker exec <container> Cli -p 15 -c "show running-config"` (the repository's credential-free cEOS read, as in `verify_dhcp_servers.py`) |
| Ubuntu / FRR | R3, R4 | `docker exec <container> vtysh -c "show running-config"` and `nft list ruleset` |

The managed set is `inventory.yml` `network_devices` (ten devices; repository policy currently excludes none). **All-or-nothing:** an unreachable,
unsupported or failing device (or an empty configuration, or an unreadable interface / route / adjacency group, or an unavailable topology service) yields
`BOOTSTRAP_BASELINE_INCOMPLETE` and nothing is created. A network that is **demonstrably unhealthy** at capture (`BASELINE_UNHEALTHY`) or whose required
evidence is stale / missing (`BASELINE_EVIDENCE_UNAVAILABLE`) is not adopted either. Nothing is repaired to make a capture succeed.

Discovered while validating against the real lab (read-only): R5's management address is `auto`, so the health engine's SSH lookup returned
`NOT_CONFIGURED`. `health.live.DockerEosSession` (used only for a cEOS device with no inventory address) fixes that; R5 is now readable by Deep Health too.

**Canonical baseline.** The payload lists devices sorted by name; each record has the device, platform, capture timestamp and method, management
provenance, read status, sanitized sections with their SHA-256, a per-device config digest, and the baseline-relative expected state (interfaces,
addresses, routes, OSPF / BGP adjacencies) plus the captured topology. The overall **baseline digest** is the existing domain-tagged canonical payload
digest (never `repr()`).

## 7. Secret handling

Nothing secret-bearing is persisted -- not in the database, manifest, export, audit, notifications or logs. Before anything is stored the captured text is
sanitized by `bundles/legacy_sanitize.py`, which **reuses the project's shared detector** (`raw_configlets.static_gate.secret_patterns`) and adds two
stricter baseline rules because a stored baseline must fail closed: the bare `key` / `psk` / `passphrase` keywords (for example `tacacs-server key 7 ...`) and
free-text lines such as `description` are scanned too. A flagged statement is cut at the first *value* token and `<REDACTED>` replaces the rest
(`username admin ... secret <REDACTED>`), PEM blocks become one `<REDACTED-PEM-BLOCK>` line, and anything still not clean becomes `<REDACTED-LINE>`.
Comment-only lines and blank lines are dropped and line endings normalised, so cosmetic noise is never drift.

The artifact says so about itself: `sanitization.stored_text = SANITIZED_NOT_BYTE_IDENTICAL`, with the redacted-line count and pattern *names* (never text).
The Golden represents **managed configuration semantics, not literal secret bytes**; a change to *only* a redacted value (for example rotating a password) is
therefore not visible to the digest (a documented limitation, asserted by a test). Integrity re-scans the stored text on every verification and export.
Validated on the real lab: two reads 20 s apart gave identical digests on all ten devices, the redactions were the local-user secrets, the SNMPv3 auth key and
the certificate `key` reference, and the only secret-looking residue was the public `snmp-server engineID`.

## 8. What is checked every sample

Each sample re-reads every device read-only and runs, in this order (`bootstrap/evidence.py`):

| Check | How |
|---|---|
| A device reachability | live read-only session succeeds (`health.device.reachability_check`) |
| B IP connectivity | management-plane reachability + interface / adjacency / route / link evidence (see limitations: no synthetic data-plane traffic) |
| C routing neighborships | every OSPF / BGP neighbor healthy (`deep_checks`) **and** every adjacency that was FULL / Established at capture is still present (Phase-15 evaluators over baseline-relative requirements). RIP has no dedicated evaluator: it is covered through the routes it installs |
| D route state | every prefix present at capture is still in the table (`evaluate_requirements`) |
| E interface / link state | addressed interfaces up; every baseline interface still present and up; topology links that were UP still exist and are UP |
| F, G CPU, memory | the authoritative gNMI-fed topology telemetry, existing thresholds (`quick_checks`) |
| H telemetry freshness | freshness of every device; a stale device makes the sample `INCOMPLETE`, never `PASS` |
| I topology | the captured nodes and links vs the live topology snapshot |
| J baseline integrity | the candidate is re-verified against its digests (every tick) |
| K configuration drift | every device's running configuration re-read, sanitized and compared with the captured baseline (every sample) |

"Required" means **regression from the baseline** -- what was healthy at capture must stay healthy. Grafana is a visualization and is never read;
`master.py --snmp-only` is never called (it can converge devices); a stale SNMP-poll panel therefore cannot fail the run while the streamed telemetry is
current, but stale *underlying* telemetry is `INCOMPLETE`.

## 9. Drift and interference

* **Configuration drift** in any sample -> the run is `INVALIDATED / CONFIG_DRIFT_DETECTED`. The new configuration is **never adopted**; the operator
  captures a new baseline from what is running and observes that.
* **Execution interference** (reused Phase-20 detection over persisted `ChangeExecutionRun` history): a later execution that touched an included device
  (started or finished at / after the capture, or still running), unless it demonstrably changed nothing -> `INVALIDATED / OVERLAPPING_EXECUTION`; also
  checked before start and at approval. Out-of-band edits leave no execution record; the drift check is what sees them.

## 10. Result vocabulary and success criteria

No weighted score. Sample: `PASS`, `PASS_WITH_WARNINGS`, `FAIL`, `INCOMPLETE`, `INVALIDATED`. Run state: `RUNNING` / `COMPLETED` / `INVALIDATED` /
`CANCELLED`; result (only when completed): `PASS` / `FAIL` / `INCOMPLETE`. `FAIL`: a required adjacency, route, interface or link demonstrably failed (a
baseline interface no longer operationally up and a DOWN link are failures here, stricter than the soak's warning classification), or sustained critical
CPU / memory. `INCOMPLETE`: required evidence unavailable / stale, or coverage below the policy.

Technical PASS needs **all** of: elapsed >= 30 min; candidate integrity valid; no drift; no interference; evaluable devices; no required-health failure;
>= 80 % of intervals covered by a usable sample; no unobserved gap over 10 min (leading and trailing edges included); no clock anomaly. A successful T+0
and T+30 alone are not enough (the tests show two isolated missed samples -> `INCOMPLETE`). With only six intervals, one critical-resource sample is
tolerated, two consume the coverage (`INCOMPLETE`), three consecutive end the run (`FAIL`).

## 11. Approval

A technical PASS never creates Golden. `bootstrap.decision.approve` is reached only from the explicit `POST .../bootstrap/runs/<id>/approve/` (CSRF,
acknowledgement) or the operator-run `legacy_bootstrap approve --confirm`. The page shows the baseline digest, included devices, start / end, actual elapsed,
sample count, coverage, drift result, routing / connectivity / CPU / memory / telemetry results and warnings. The echoed run / candidate / digests are
staleness guards, never authority. **Immediately before sealing**, the server re-reads every device's configuration: any difference blocks approval
(`CONFIG_DRIFT_DETECTED`), an unreadable device blocks it (`DRIFT_CHECK_INCOMPLETE`); the re-check must be fresh (180 s) and is pinned into the Golden.
Everything else is re-checked inside the creating transaction on locked rows (integrity, run identity and digest, technical PASS, elapsed duration,
reproducible evidence, decision window, interference, no earlier decision, the one-time gate). Approval configures nothing and saves no startup-config.

## 12. The initial Golden

One immutable `GOLDEN` bundle whose parent is the candidate. Its payload is a **deep copy of the candidate's pinned payload** (equal payload digest): nothing
read after approval is ever substituted. `lineage.legacy_bootstrap` pins the provenance type and role, the candidate id and digest, the baseline digest, the
observation run id, policy version, duration, `started_at`, `required_end_at`, `completed_at`, the evidence digest, the decision, operator identity and
time, the decision-time re-check, and `predates_automation_framework`. The bundle page and the manifest export expose the Golden ID, `created_at`,
approval time, baseline capture time, the observation window and the digests. A `LegacyBootstrapDecision` row and a `LEGACY_GOLDEN_APPROVED` audit event
are written in the same transaction.

## 13. The one-time lockout

The shortcut refuses with `LEGACY_BOOTSTRAP_ALREADY_COMPLETED` once the initial Golden exists, and with `GOLDEN_EXISTS` while *any* Golden exists. It is
**persisted application state, not a flag**: the gate is computed from bundle rows alone, a unique partial index (`unique_legacy_bootstrap_golden`) allows at
most one legacy Golden even around the service, and a server restart changes nothing (tests remove the rows out of band inside a savepoint to prove the gate
reads only rows). Capture, start, candidate sealing, the readiness probe and the UI all honour it. Only one observation may run at a time (partial unique
index).

## 14. Phase 21 and Checkpoint 4

A valid Phase-21 entry is **either** (A) a Golden produced by the full lifecycle **or** (B) the one-time `LEGACY_BOOTSTRAP` Golden.
`bundle_service.known_good_baseline()` returns the newest Golden that still verifies and **always reports its source** -- B is never presented as A, and
its note says it did *not* pass a seven-day soak.

Checkpoint 4 is created only **after** the initial Golden exists and verifies, as a separate explicit action, and must state:
`INITIAL GOLDEN SOURCE: LEGACY_BOOTSTRAP` · `NORMAL PROBATION POLICY: 7 DAYS` · `BOOTSTRAP EXCEPTION: 30 MINUTES, ONE TIME ONLY`. It must never claim the
initial Golden passed a seven-day soak.

## 15. Operator runbook

1. Merge this change (PR, hosted Tier-3, `tools/phase_integrate.py merge`). **Never start the real observation from an unmerged branch.**
2. `cd web && DJANGO_DEBUG=true python manage.py migrate` on the LOCAL dev database (never delete / recreate it; do not commit `db.sqlite3`); check
   `showmigrations core`. NetBox owns port 8000; if the control plane is needed use e.g. `runserver 127.0.0.1:8001`.
3. `python manage.py legacy_bootstrap probe` -- read-only; fix real blockers at their source (nothing is repaired for you).
4. `python manage.py legacy_bootstrap capture` (or the page's **Capture Current Baseline**).
5. `python manage.py legacy_bootstrap start` (or **Start 30-Minute Observation**) -- the server pins the clock.
6. `python manage.py legacy_bootstrap observe` -- samples every 5 minutes and waits (bounded sleeps, never a busy loop) until the run ends. **Do not
   configure any device meanwhile.** If the normal scheduler is not installed this one-time command is the collector.
7. Review the run page; `legacy_bootstrap approve --confirm` or the page's **Approve Initial Golden** (POST + CSRF).
8. `legacy_bootstrap verify`; then, separately, Checkpoint 4.

## 16. Interruption

Ctrl-C leaves the run `RUNNING`; nothing is fabricated, no timestamp is edited, and running `observe` again resumes it. The interruption is a real gap: if
the remaining coverage still satisfies the policy the run can still pass, otherwise it ends `INCOMPLETE` and a **new** baseline must be captured and
observed. A completed non-pass run is immutable.

## 17. Limitations (deliberate, stated plainly)

* **IP connectivity is management-plane + control-plane evidence.** The repository has no read-only, allowlisted data-plane probe, and the known
  H1 -> WebServer issue is out of scope, so no synthetic traffic is generated.
* **Secret values are not part of the baseline** (section 7). Sanitized text is not byte-identical to the device configuration.
* **Running configuration only.** Startup-config persistence is not decided or performed (as in Phases 17-20).
* **Regression, not specification.** "Required" is defined by the baseline itself; a fault that already existed at capture and is not a demonstrated
  failure is adopted as-is (a demonstrated failure at capture blocks the capture).
* **Device-granular interference; out-of-band edits are seen only by the drift check.**
* **A digest is not a signature** (as in Phase 19).
* There is no REJECT decision: not approving simply leaves the run without a decision, and a new baseline is a new run.

## 18. Tests and Tier-3

`test_bootstrap` (policy, sanitizer, capture, immutability, tamper detection, the 30-minute observation on a controlled clock -- boundaries, coverage / gap
matrices, drift, interference, resources, interruption, the wait loop -- approval, lockout, constraints, Phase-21 entry, the probe) and `test_bootstrap_views`
(read-only GET pages, POST + CSRF, browser cannot choose the duration, the single approval route, the operator command). The contract tests enumerate the one
new Golden-creation site. Tier-3 has a `legacy_bootstrap` subsystem (paths `services/bootstrap/**`, `bootstrap_service.py`, `legacy_bootstrap.py`) with
impact edges to models, bundles, soak, health, execution and notifications.
