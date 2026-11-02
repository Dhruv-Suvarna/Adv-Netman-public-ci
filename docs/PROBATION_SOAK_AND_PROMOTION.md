# Phase 20 — Probation soak and the operator's Golden decision

Phase 19 produced immutable **Probation** bundles. Phase 20 answers one question:

> *Has this exact immutable Probation configuration stayed healthy and valid through the required observation period — and does the operator now approve this exact artifact as Golden?*

```
eligible immutable Probation bundle
        │  explicit POST "Start 7-Day Probation Soak"            (server fixes start, end and duration)
        v
   ACTIVE SOAK  ── scheduled, read-only evidence samples ── integrity + interference re-checked every tick
        │
        ├── INVALIDATED  a later execution touched the devices / the bundle stopped verifying
        ├── COMPLETED / FAIL        a demonstrated intended-state failure, or sustained critical CPU / memory
        ├── COMPLETED / INCOMPLETE  the window ended without enough usable evidence coverage
        ├── CANCELLED    the operator cancelled
        └── COMPLETED / PASS   ("technical soak passed — operator Golden decision required")
                 │  explicit operator POST
                 ├── REJECT   immutable decision, no Golden
                 └── APPROVE  new immutable GOLDEN bundle (identical payload)
```

**There is no automatic promotion.** The scheduler can collect evidence, evaluate it and mark a run ready. It can never create Golden.

Phase 20 has two separate milestones. **20A (implementation)** is this code, its tests and this document. **20B (real operational acceptance)** is a real, wall-clock soak run *after* 20A is merged into `main` — see [§17](#17-phase-20b-operational-runbook). A passing test suite is not seven days of evidence, and nothing here shortens, back-dates or simulates the real soak. **Checkpoint 4 is not created by Phase 20A.**

Contents: 1 Architecture · 2 Data model · 3 Time semantics · 4 State and result · 5 Start eligibility · 6 Interference · 7 Evidence sources · 8 Sample classification and the transient-failure policy · 9 Cadence and coverage · 10 Evaluation · 11 The collector · 12 Scheduling · 13 The operator decision · 14 Golden bundle lineage · 15 Audit, notifications, security · 16 Documented limitations · 17 Phase-20B runbook · 18 Tests and Tier-3.

---

## 1. Architecture

Phase 20 adds **no** second monitoring system, postcheck engine, bundle engine or deployment engine. It composes what exists:

| Concern | Reused component |
|---|---|
| immutable artifact, integrity, payload equivalence | Phase-19 `bundles` package (`verify_bundle_integrity`, `seal_bundle`) |
| "did the network change since?" | persisted Phase-17 `ChangeExecutionRun` history (read only) |
| expected-state evidence | Phase-15 postcheck engine (`run_plan_postcheck(persist=False)`) over the bundle's pinned descriptors of the **executed prefix**, fed by `collect_scope_evidence` (its fixed read-only `show` / `ip -j` allowlists) |
| telemetry evidence | the existing topology service (gNMI stream in InfluxDB) via `health.telemetry` + `health.fleet.quick_checks` — freshness, CPU, memory, critical events |
| thresholds | `monitoring/config/cpu_threshold_policy.yml`, the memory 75/90 % dashboard values and the topology freshness values — exactly one threshold system |
| notifications | `notification_service.publish_event` (persist, then a bounded Slack attempt) |
| audit | `AuditEvent` |

New code lives in `web/core/services/soak/` (facade `soak_service.py`) and, for the promotion itself, `web/core/services/bundles/golden.py` — the Phase-19 seam.

```
soak/codes.py         vocabularies + fixed messages        soak/evaluator.py   PURE deterministic evaluation, evidence digest
soak/policy.py        server-owned policy + pinned copy    soak/lifecycle.py   start / cancel / the idempotent collector tick
soak/interference.py  later executions on the devices      soak/decision.py    the operator's APPROVE / REJECT (only Golden caller)
soak/eligibility.py   may a soak start?                    soak/assessment.py  PURE classification of results into a sample verdict
soak/sampling.py      ONE read-only evidence read          bundles/golden.py   evidence-checked Probation -> Golden
```

The collector side (`assessment`, `sampling`, `evaluator`, `lifecycle`, `policy`, `interference`, `eligibility`, `codes`) imports no Netmiko / subprocess / socket / NetBox / Git / execution-engine / Golden module. Contract tests enforce it, and a runtime test runs a whole soak with the engine entry point, Netmiko, `subprocess`, sockets, `seal_bundle` and `create_golden_bundle` all rigged to fail.

## 2. Data model (migration `0009_phase20_probation_soak`)

All three models are append-oriented, use the same guarded manager as the bundles (no queryset `update` / `delete`) and cannot be deleted.

| Model | Role |
|---|---|
| `ProbationSoakRun` | One observation window over one Probation bundle. `soak_id` (`SOAK-000001`) is derived from the primary key. Pins the Probation **bundle digest**, the **policy** it started under (`policy_version` + a JSON copy of every duration / cadence / gap / coverage value), `started_at`, `required_end_at` and the operator. Created `RUNNING`, finalised **exactly once**, immutable afterwards. Holds the final structured `evaluation` and its `evidence_digest`. |
| `ProbationSoakSample` | One bounded, sanitized evidence record per sample interval (`bucket`). Never updated or deleted. Stores verdicts and bounded findings, **not** raw telemetry (InfluxDB stays the telemetry store). |
| `GoldenDecision` | The operator's explicit `APPROVE` / `REJECT` of one technically passed soak. One per run (`OneToOne`). Immutable. `APPROVE` ⇔ a Golden bundle exists (DB check constraint). |

Database guarantees (not merely buttons): `unique_active_soak_per_bundle` (partial unique index on `state = RUNNING`), `unique_soak_sample_per_bucket`, `soak_result_only_when_completed`, `golden_decision_bundle_only_when_approved`, and the existing `unique_golden_bundle_per_probation`.

New audit types: `PROBATION_SOAK_STARTED / _CANCELLED / _FAILED / _INCOMPLETE / _INVALIDATED / _READY`, `GOLDEN_APPROVED`, `GOLDEN_REJECTED`. New notification types: `SOAK_STARTED`, `GOLDEN_APPROVED`, `GOLDEN_REJECTED` (the reserved `SOAK_COMPLETE` means "ready for the decision", `SOAK_REGRESSION` covers fail / incomplete / invalidated).

## 3. Time semantics

* The production duration is **`timedelta(days=7)` = 604 800 s = 168 elapsed hours**. It is elapsed time on timezone-aware UTC datetimes: not "seven calendar dates", and unaffected by daylight-saving transitions or local midnight.
* `started_at` is the server's `timezone.now()` at the start request. `required_end_at = started_at + duration`, computed **once** and stored. Changing a setting later never shortens or extends a started run: the evaluator reads only the run's pinned `policy`.
* **A browser can supply none of it.** The start form posts only a confirmation checkbox. Extra POST fields or query parameters (`duration`, `started_at`, `PROBATION_SOAK_DURATION_SECONDS`, …) are ignored — tested.
* **Production cannot be shortened by configuration.** `PROBATION_SOAK_DURATION_SECONDS` (settings.py) has a hard lower bound of seven days at settings load: the environment can raise it (to at most 30 days), not lower it. Automated tests use `override_settings` (which bypasses that loader) to run a short soak; the production code path is identical. There is no `if TESTING` anywhere in the business logic.
* A soak whose pinned duration is below seven days is labelled **NOT A PRODUCTION DURATION** on every page.
* Boundaries: `now >= required_end_at` is enough (`exactly` the required duration is eligible; one second before is `RUNNING`). Sample times come only from the server clock. If the clock moves backwards (earlier than recorded evidence, or before the start) the tick reports `CLOCK_ANOMALY` and collects nothing; a timeline with backwards timestamps can never PASS (`CLOCK_ANOMALY` → INCOMPLETE).

## 4. State and result

| Field | Values | Meaning |
|---|---|---|
| `state` (lifecycle) | `RUNNING`, `COMPLETED`, `INVALIDATED`, `CANCELLED` | where the run is |
| `result` (technical evaluation) | `PASS`, `FAIL`, `INCOMPLETE` — only for `COMPLETED`; empty otherwise | what the evidence concluded |
| `terminal_reason` | `TECHNICAL_PASS`, `EXPECTED_STATE_FAILED`, `RESOURCE_CRITICAL_SUSTAINED`, `COVERAGE_INSUFFICIENT`, `BUNDLE_INTEGRITY_FAILED`, `OVERLAPPING_EXECUTION`, `CANCELLED_BY_OPERATOR` | why it ended |

`GOLDEN` is a bundle kind and a decision outcome, **never** a soak state or result. "Ready for the Golden decision" is derived: `COMPLETED` + `PASS` + no `GoldenDecision` yet (`golden_decision_pending`).

`FAIL` (the intended state demonstrably failed), `INCOMPLETE` (evidence missing, stale or too sparse) and `INVALIDATED` (the artifact is no longer what is running / no longer verifies) are deliberately different. None of them can create Golden.

## 5. Start eligibility

`soak_service.check_soak_start(bundle)` (read-only; `start_soak` re-checks it inside its transaction, whatever the page showed). Every blocker has a stable code, a fixed message and a remediation:

| Code | Blocks when |
|---|---|
| `NOT_PROBATION` | the bundle is not a Probation bundle |
| `BUNDLE_INTEGRITY_FAILED` | `verify_bundle_integrity` fails **now** (digests, lineage, payload equivalence with the UAT parent, items, raw-revision pins, sources). Also writes the existing bounded `BUNDLE_INTEGRITY_FAILED` audit event |
| `GOLDEN_EXISTS` / `SOAK_ACTIVE` | a Golden child exists / a soak is already running |
| `SOURCE_UNVERIFIED` / `POSTCHECK_NOT_ACCEPTABLE` / `SOURCE_EMPTY` | the candidate lacks acceptable verification quality (defence in depth: Phase 19 already blocks an UNVERIFIED UAT from entering Probation) |
| `SUPERSEDED` | a later execution touched the candidate's devices (§6) |
| `EVIDENCE_SCOPE_UNSUPPORTED` | a scoped device is not a managed inventory device, its platform has no read-only verification capability, or a pinned descriptor has no evaluator — nothing is invented |

Starting a soak **never** reruns UAT, replans, prechecks, reverifies Raw Configlets or modifies either bundle. It writes the run, one audit event and one notification, and nothing else. A double click returns the active run (idempotent).

> **Changed in Version 2 Phase 5C.** Starting a soak now also makes **one read-only configuration read per observed device** (outside any
> transaction, through the same allowlisted session a sample uses) and pins the digests, with the rest of the start-time baseline, on the
> run. A soak does not start when a device cannot be read (`BASELINE_UNREADABLE`). Each sample re-reads those digests: a difference
> invalidates the soak (`CONFIGURATION_DRIFT`). A Probation bundle may derive from a UAT bundle or, for a provisioned device, from a
> `DEPLOYED` bundle. The collector's systemd units now live in `deploy/systemd/`. See `docs/V2_PHASE5_PROVISIONING_TRAFFIC_SOAK.md` §3 and §7.

## 6. Interference (superseded candidates)

The Probation bundle represents one exact executed configuration. Nothing locks the network for the window — **no `ExecutionDeviceLock`, database row lock, SSH / Netmiko session or transaction is held for seven days**. Interference is *detected* instead, from persisted history: every other `ChangeExecutionRun` that started at or after the candidate's source UAT execution and lists any of the candidate's devices is interference, unless it demonstrably changed nothing (`BLOCKED`, `FAILED_NO_MUTATION`). A run still `RUNNING` (or whose lease expired mid-flight) counts.

The same function is used **before start** (blocks with `SUPERSEDED`), **on every collector tick** (a soak is `INVALIDATED` as soon as a tick notices, even between sample instants) and **at Golden-decision time** (`INTERFERENCE_DETECTED`). It never silently creates a new Probation artifact; the remedy is a new UAT / Probation lifecycle.

*Granularity:* device level. The recorded results cannot prove that two Configlets on one device are independent, so a later change to any object of the same device supersedes the candidate (conservative by design). *Scope:* project-driven change only — see §16 for out-of-band edits.

## 7. Evidence sources

Each sample runs, in this order, against the **live** state:

1. **Guard** (database only): bundle integrity + interference. A failure short-circuits to an `INVALIDATED` sample; nothing else is read.
2. **Expected state** (Phase-15 engine): the descriptors of the executed prefix (interface, address, route, OSPF, BGP, FHRP, DHCP relay, ACL, NAT — whatever the pinned plan carries) evaluated against fresh read-only device evidence and telemetry, with the POSTCHECK rules ("every requirement is required; a missing observation is never a PASS"). Evidence collection is limited to the fixed per-platform read-only allowlists (`live.CEOS_COMMANDS`, `live.LINUX_COMMANDS`); no browser input ever reaches a command, and the sample is evaluated with `persist=False` (no per-tick `OperationalCheckRun` pollution).
3. **Telemetry** (existing monitoring): for each scoped device — freshness of the gNMI stream, CPU, memory, recent critical syslog / SNMP-trap counts, adjacent link state, and the monitoring pipeline state.

Only the candidate's own devices (and validation-derived peers needed to evaluate its requirements) are read; the unexecuted remainder of the plan is not.

### Where telemetry data really comes from (freshness, and the stale-Grafana condition)

The soak reads the **gNMI stream** (`nmas-gnmi-collector.service`, a 20 s sample interval, continuously running) through the topology service — **not** Grafana and **not** the SNMP poll.

* Grafana is a visualization. Its HTML, screenshots and panels are never read. A presentation-layer problem cannot fail a soak, and a healthy panel is not evidence.
* The known `verify_grafana.py` failure — *"Latest polled CPU returned no recent real data"* — concerns **SNMP poll** data, which is produced **only on demand** (`master.py --snmp-only` / `monitoring/tests/verify_snmp.py`) and ages out of the verifier's fixed 24 h window. It is a data-producer gap in the SNMP poller, unrelated to the streamed telemetry the soak depends on.
* **The soak never refreshes anything.** It does not call `master.py --snmp-only` (which can also converge device SNMP configuration) or any other refresh path. If the streamed telemetry is stale, the sample is `INCOMPLETE` — never PASS — and the operator must restore the collector.

Measured on 2026-09-21 (read-only probe of the real lab before writing this document): the collector and topology service were active and all ten managed devices reported FRESH streamed telemetry (0.6 – 15.5 s old, CPU ≈ 46 %, memory ≈ 31 %). The source data a soak needs is therefore currently suitable; the stale condition was confined to the SNMP-poll panel.

## 8. Sample classification and the transient-failure policy

Explicit rules, no weighted score. Every health / postcheck result is classified, and a sample takes the worst class present in a **fixed** order — so a failed required state is never "averaged away" by healthy CPU.

| Class | When | Effect on the sample | Effect on the soak |
|---|---|---|---|
| **INTENDED_STATE_FAILED** | a Phase-15 requirement FAILED (the engine's verdict is authoritative), or a *blocking-coded* FAIL on a scoped target (the existing `CODES` / `effective_blocking` policy) | `FAIL` | **terminal `COMPLETED / FAIL` at once** — no tolerance, no recovery |
| **RESOURCE_CRITICAL** | `CPU_HIGH` / `MEMORY_HIGH` at the project's CRITICAL level (90 %) | `FAIL` | terminal `FAIL` only after the project's **`consecutive_samples`** (3, from `cpu_threshold_policy.yml`) consecutive samples for the same device and metric; a healthy sample resets it; an INCOMPLETE sample neither extends nor resets it. **May recover.** |
| **UNAVAILABLE** | evidence missing, stale, expired, not implemented: telemetry freshness / reachability / pipeline results that are not PASS, any UNKNOWN, a postcheck verdict of INCOMPLETE, or any scoped device whose telemetry is not FRESH | `INCOMPLETE` — **never PASS** | a coverage gap (§9); the soak can still recover |
| **WARNING** | a WARN; a FAIL that is not blocking or not on a target (e.g. `LINK_HEALTH_DEGRADED`, a peer's failure); recent critical events | `PASS_WITH_WARNINGS` | never fails a soak; counted and shown to the operator |
| OK | PASS / N/A | `PASS` | — |

An unreachable device or a dead telemetry pipeline is missing evidence, not a proven device failure (a real outage is indistinguishable from a monitoring outage), so it makes samples INCOMPLETE and — if it lasts — the soak INCOMPLETE. `GRAFANA_UNAVAILABLE` and `NETBOX_SOURCE_UNAVAILABLE` are not soak evidence sources and are not collected. A contract test forces every health check code to have a classification (`PolicyTests`), so a new code cannot silently bypass the policy.

## 9. Cadence and coverage

Defaults (server-owned settings, bounded, pinned per run, never browser-overridable):

| Parameter | Default | Rationale from repository evidence |
|---|---|---|
| sample interval | **900 s** | equals `recent_event_window_seconds` in `monitoring/config/topology.yml`: the topology service counts critical syslog / SNMP-trap events inside that window, so consecutive samples **tile** the timeline and no critical event can fall between two of them. (A contract test keeps the two values equal.) 672 intervals over seven days. |
| maximum unobserved gap | **7 200 s** (8 intervals) | tolerates a short host reboot / maintenance window; far below the day-scale outage that would leave real problems unobserved. Leading and trailing edges of the window are included. |
| minimum coverage | **90 %** of the window's intervals | lets a few transient read failures pass without letting sparse evidence through. |
| resource streak | **3** samples | the project's own collector-alert policy. |
| decision window | **72 h** after completion | see §13. |

A seven-day clock alone never produces PASS. **PASS requires all of:** elapsed ≥ the pinned duration · ≥ 90 % of intervals covered by a usable sample · no gap (including the first and last edge) over the maximum · no interference · a verifying bundle · no intended-state failure · no sustained critical resource · no clock anomaly. A "usable" sample is `PASS` or `PASS_WITH_WARNINGS`. The *closing* sample (taken at / after the end) never extends coverage, but its failure still counts. A scheduler outage that opens an excessive gap makes the final result `INCOMPLETE` — correct, and never backfilled.

## 10. Evaluation

`evaluator.evaluate(policy, started_at, required_end_at, samples, now, guard)` is a **pure** function; the rule order is the policy: integrity → interference → intended-state failure → resource streak → *not yet ended* → coverage / clock → PASS. The same inputs always give the same verdict, which is how `verify_run` later re-derives a run's verdict from its own persisted samples.

**Final evidence summary and digest.** When a run ends, a canonical summary is stored in `evaluation`: soak id, Probation bundle digest, policy (version + values), state / result / reason / problems, start / required end / completion, sample count, coverage, max gap, first / last sample, blocking and warning counts, expected-state and telemetry tallies, interference and integrity status, and a `samples_digest` (SHA-256 over the ordered core facts of every sample — it binds the summary to the persisted rows without copying seven days of data). `evidence_digest = SHA-256` over the domain-tagged canonical JSON of that summary. Raw metrics are **not** duplicated into Django.

## 11. The collector

```
python web/manage.py probation_soak_tick [--dry-run] [--soak SOAK-000001] [--json]
```

For every `RUNNING` soak: take the due sample (bucket = `floor(elapsed / interval)`, clipped to the closing bucket), re-check integrity and interference, evaluate, and finalise **exactly once** if the verdict is terminal.

* **Read-only against the network.** It writes only soak evidence, the run's own final state, audit and notification rows.
* **Idempotent and race-safe.** Network reads happen *outside* any transaction; the sample and any finalisation are persisted in one short transaction under `select_for_update` (a no-op on SQLite — the constraints still hold). Two overlapping ticks, a repeated tick or two workers persist exactly one sample per bucket (`UNIQUE (run, bucket)`; the loser reports `DUPLICATE`) and one finalisation.
* **Crash recovery.** A crashed tick rolls back as a whole; the run is never falsely finished. The next tick re-derives everything from the persisted samples; downtime is **never** backfilled.
* One failing run is reported (`ERROR`, exit status 1) without stopping the others; the next tick retries.
* `--dry-run` reads nothing external and writes nothing.

`python web/manage.py probation_soak_probe BND-PROB-…` is a **read-only evidence probe** (spec §77): it runs the same guard and evidence collection a real sample would and prints what is available, the freshness, and any start blockers. It starts nothing and persists nothing. `--no-live` skips the device reads.

## 12. Scheduling

The repository has **no scheduler abstraction** and no tracked service or timer files: its monitoring services are provisioned by scripts against the host. Phase 20 therefore adds no Celery / Redis / framework and installs nothing. The management command *is* the authoritative automation unit; wire it to whatever your host already uses. **Run it at most every `interval / 2` (5 minutes recommended)** so scheduler jitter cannot skip an interval. GitHub Actions is **not** a scheduler for this (GitHub is Tier-3 source validation; lab connectivity and credentials must never live there).

cron (illustrative — not installed by the repository):

```
*/5 * * * * cd /home/student/Scripts/clab_dualstack_lab/web && DJANGO_DEBUG=true /home/student/Scripts/.venv/bin/python manage.py probation_soak_tick >> "$HOME/.local/state/probation_soak_tick.log" 2>&1
```

systemd (illustrative; `/etc/systemd/system/probation-soak-tick.service` + `.timer`, or the `--user` equivalents):

```
# probation-soak-tick.service
[Unit]
Description=Probation soak evidence tick (read-only)
[Service]
Type=oneshot
User=student
WorkingDirectory=/home/student/Scripts/clab_dualstack_lab/web
Environment=DJANGO_DEBUG=true
ExecStart=/home/student/Scripts/.venv/bin/python manage.py probation_soak_tick

# probation-soak-tick.timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
[Install]
WantedBy=timers.target
```

Do not put secrets in the unit. Slack notifications are optional and use the existing environment-only webhook.

## 13. The operator decision

`soak_service.decide(run, decision=APPROVE|REJECT, actor=…, reason=…, confirm={soak_id, bundle_id, bundle_digest})`, reached only from the explicit `POST /device-builder/soaks/<id>/decision/` (CSRF, acknowledgement checkbox). Only a technically passed soak shows the controls. The page shows the exact bundle, digest, duration, coverage, warnings, integrity and interference state.

* The echoed soak / bundle / digest are **staleness guards** compared with the server's records — never authority. The browser cannot supply a manifest, digest replacement, timestamp or evidence.
* **APPROVE** delegates to `bundles.golden.create_golden_bundle`, which — inside the creating transaction, on a locked soak row — **re-checks everything** because real time passed since the last sample: Probation integrity now · the soak observed this bundle id **and digest** · `COMPLETED / PASS` · the pinned duration elapsed · the stored verdict, summary and `samples_digest` **reproduce from the soak's own rows** (`verify_run`) · the pass is inside the decision window (72 h) · no later execution touched the devices · no decision already exists · no Golden child exists (else that one is returned). Any failure → **refused, nothing written**, with a stable code (`GOLDEN_BLOCKERS`).
* **Idempotent.** A double click / racing approval returns the existing Golden bundle; the database allows one Golden per Probation and one decision per soak.
* **REJECT** records an immutable decision and creates nothing. It deletes nothing, rolls nothing back (that is Phase 21) and is never edited into an approval.
* **Retry semantics (chosen and documented):** a decision is final *for that soak*. To reconsider — after a REJECT, or after an expired pass — start a **new** soak on the same Probation bundle (allowed while no Golden child exists and no soak is active). If the configuration itself changed, a new UAT / Probation lifecycle is required; a Probation bundle is never retargeted.
* The optional comment is bounded (500 characters), stored on the decision and screened with the project's shared secret detector (which recognises credential-shaped *configuration* lines; free text is a documented limitation) — refused, never silently redacted.
* Approval **does not deploy anything**: it never calls the execution engine, contacts a device, reapplies configuration or writes startup-config.

## 14. Golden bundle lineage

A Golden bundle is a **new** immutable `GOLDEN` `ConfigurationBundle` whose parent is the exact Probation bundle. Its `manifest.payload` is a deep copy of the Probation payload (nothing is re-rendered, no `DeviceIntent` is reloaded, no "latest" Raw Configlet revision is read), so its **payload digest is identical** and only kind / lineage / promotion differ (so its bundle digest differs). Its `lineage.promotion` block pins:

```
soak_id · soak_policy_version · soak_duration_seconds
observation_started_at · observation_required_end_at · observation_completed_at
evidence_digest · probation_bundle_digest
decision (APPROVE) · decided_by · decided_at
```

The bundle digest **covers** the promotion block (only when present, so every UAT / Probation digest is byte-identical to Phase 19). `verify_bundle_integrity` cross-checks it against the stored decision and soak: any edited promotion field, decision row, soak summary, evidence digest or sample is reported (`PROMOTION_MISMATCH`, `PROMOTION_MISSING`, `BUNDLE_DIGEST_MISMATCH`). The DB-free export verifier (`verify_export`) covers the promotion digest too. Bundle pages show `UAT → Probation → successful soak → operator decision → Golden`.

**What Golden means:** *the approved known-good artifact under the implemented evidence contract* — the pinned expected-state descriptors, telemetry health and absence of interfering executions held for the required window and the operator approved it. It does **not** claim the device running configuration is byte-identical to the bundle (§16).

## 15. Audit, notifications, security

**Audit** (bounded metadata, no telemetry dump, no secrets): `PROBATION_SOAK_STARTED / _CANCELLED / _FAILED / _INCOMPLETE / _INVALIDATED / _READY`, `GOLDEN_APPROVED`, `GOLDEN_REJECTED`, plus the Phase-19 `BUNDLE_INTEGRITY_FAILED` when an explicit action is refused for integrity.

**Notifications** (persist first, then a bounded Slack attempt — a delivery failure never touches soak state): soak started · failed / incomplete / invalidated (`SOAK_REGRESSION`) · ready for the decision (`SOAK_COMPLETE`) · Golden approved · Golden rejected. Never one per sample. A cancellation is audited, not announced.

**Security:** four mutating endpoints — start, cancel, approve / reject — are POST + CSRF, change application state only, and accept no browser-supplied time, duration, policy, evidence, manifest, digest or command. No secrets are stored; no `shell=True`; no arbitrary execution. GET pages mutate nothing and contact nothing. Refusal codes echoed in a query string are displayed only if they match a known catalogue entry.

## 16. Documented limitations

*Design limitations (deliberate):*

* **Startup-config persistence is NOT implemented and NOT decided.** Phases 17 / 18 / 19 say persistence "belongs to the Golden / Probation phases", but no repository requirement explicitly assigns it to Phase 20, and there is no evidence-backed safe executor for `write memory` / `copy running-config startup-config`. Inventing one would create a second device-mutation path from an approval action, which Phase 20 must not do. Golden approval is artifact + database + audit work only. A device reload before persistence is a future design decision.
* **Golden is not byte-identical running-config proof.** No config-diff engine exists; the expected-state descriptors prove intended objects, not the entire configuration.
* **Out-of-band edits.** A manual edit on a device leaves no execution record, so it is visible **only** through the expected-state / telemetry evidence. Perfect manual-config detection is not claimed.
* **Interference is device-granular** (§6), so a later unrelated change to the same device supersedes the candidate.
* **A digest is not a signature** (as in Phase 19): someone with database write access who rewrites the bundle, decision, soak rows and every digest consistently is not detectable from the database alone.
* **One soak run's evidence stops when it ends.** A passed soak is not sampled while awaiting the decision; the 72 h decision window (and the decision-time interference / integrity rechecks) bound that.
* The operator comment screen only recognises credential-shaped configuration lines; free-text secrets can slip through. The form says never to enter one.
* Concurrency guarantees are database constraints; `select_for_update` is a no-op on SQLite (the local dev DB), where the constraints still prevent duplicates.

*Environmental notes (not defects of this phase):*

* The SNMP poller is on-demand only; its data ages out of the Grafana verifier's 24 h window (the known `Latest polled CPU` failure). The soak does not use SNMP polls and does not refresh them.
* The application database `web/db.sqlite3` is migrated only when the operator runs `migrate`; the repository does not install the scheduler.

## 17. Phase-20B operational runbook

**Do not start any of this from a feature branch, and never alter timestamps, the clock, the database or a duration setting to make time pass.** The real soak needs 168 real hours.

1. **Merge Phase 20 first.** After hosted `Tier-3 validation` is green, the operator runs `python3 tools/phase_integrate.py merge`. Confirm `git branch --show-current` is `main` and `git log -3` shows the merge.
2. **Migrate the application database.** Confirm `web/db.sqlite3` is the local development database (not an external / shared one), then: `cd web && DJANGO_DEBUG=true /home/student/Scripts/.venv/bin/python manage.py migrate` (applies any of 0006 – 0009 not yet applied; schema maintenance only, no device is touched). Do not delete or recreate it.
3. **Verify the collector and the telemetry it needs.** `DJANGO_DEBUG=true …/python manage.py probation_soak_tick --dry-run` (must print `0 running soak(s)` and exit 0). Check the streamed telemetry is fresh (Fleet Quick health page, or the probe in step 5). Restore `nmas-gnmi-collector.service` / the topology service first if anything is stale.
4. **Activate the scheduler** (§12): a cron line or systemd timer running `probation_soak_tick` every 5 minutes. Confirm it runs (`--json` output, or the timer's journal).
5. **Inspect the candidate.** Open `/device-builder/bundles/` → the Probation bundle. Check integrity is INTACT, the source UAT / execution / targets, and the soak panel. Optionally `…/python manage.py probation_soak_probe BND-PROB-… ` for the live evidence view and any blockers. A `SUPERSEDED` blocker means a later execution touched the devices: start a new UAT / Probation lifecycle instead.
6. **Start the real soak** with **Start 7-Day Probation Soak** (POST + confirmation). Nothing else is required.
7. **Confirm `started_at` and `required_end_at`** on the soak page: required end must be **exactly 168 h** (`7d 0h 0m (168 h)`) after the start, the badge must **not** say NOT A PRODUCTION DURATION.
8. **Verify samples arrive**: the timeline grows one row per 15 minutes; `probation_soak_tick --json` reports `SAMPLED` / `NOT_DUE`. A tick that reports `ERROR` or a stream of `INCOMPLETE` samples means telemetry or device reads are failing — fix the source (collector, management path).
9. **Watch evidence gaps and failures** on the soak page (coverage %, longest gap, findings). Warnings never end a soak; INCOMPLETE samples widen gaps.
10. **If it ends early:** `INVALIDATED` (a later execution touched the devices, or the bundle stopped verifying), `COMPLETED / FAIL` (a demonstrated failure), `COMPLETED / INCOMPLETE` (coverage). Each keeps its evidence and can never become Golden. Nothing is repaired or rolled back automatically (Phase 21). Once the cause is resolved, start a new soak — or a new UAT / Probation lifecycle if the configuration changed.
11. **Wait the actual seven days.** The collector must keep running; a scheduler outage longer than 2 h opens a gap.
12. **Confirm READY.** After the required end the next tick finalises the run. The soak page says *Technical soak passed — Operator Golden decision required* and the Probation page links to it. A notification is sent.
13. **Review the evidence** — coverage, warnings, findings, integrity, interference, the digests — and decide within 72 h.
14. **APPROVE or REJECT** (with the acknowledgement). APPROVE creates the Golden bundle; REJECT creates nothing.
15. **Verify the Golden bundle:** its page shows integrity INTACT, the lineage `UAT → Probation → soak → decision → Golden`, the identical payload digest and the pinned evidence digest. Optionally download `manifest.json` and verify it with `bundle_service.verify_export`.
16. **Only after 1 – 15 are genuinely complete, Checkpoint 4 becomes eligible** — as a **separate, explicit action**. It is not created by Phase 20A, by the merge, or by unit tests.

## 18. Tests and Tier-3

Tests (`test_soak`, `test_soak_decision`, `test_soak_views`, plus the updated Phase-19 bundle / contract tests): pure evaluator and classification matrices (duration boundary, coverage, gaps, streaks, clock anomalies), model / constraint guarantees, start eligibility over real engine runs, the collector under a controlled clock (idempotency, races, outages, crash recovery, interference, integrity, non-spam notifications, read-only guarantee), the decision service (technical PASS ≠ promotion, every decision-time recheck, tamper detection, idempotency, REJECT immutability, retry), views (GET read-only, POST + CSRF, no browser time / duration authority) and a simulated end-to-end lifecycle. Every bundle is built from a **real run of the production engine** on the simulated network; only the SSH / docker read is replaced. None of this is the real soak.

Tier-3 has a `probation_soak` subsystem (paths `services/soak/**`, `soak_service.py`, `management/commands/probation_soak_*.py`), impact edges between models / bundles / health / execution / notifications and the soak, and selects `soak`, `soak_decision`, `soak_views`, `bundles`, `bundle_views`, `health_engine` and `contracts`; templates select Django tests only (no lab verifier).
