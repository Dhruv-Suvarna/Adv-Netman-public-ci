# NMAS V2 unattended Troubleshooter: operations

This document covers the fault-to-recovery chain that runs unattended:

> monitoring → correlated incident → case → deterministic run → Codex → policy → Change Engine → verification → closure

It was proven live in campaign `NMAS-R2-E1-20261117-011` (2026-11-17), with no operator action at any step.

## Services

| Unit | Runs as | Role | Restart |
|---|---|---|---|
| `nmas-ts-intake` | student | Read-only interface/intent detection; opens cases; starts the dispatcher | always |
| `nmas-troubleshooter-dispatch@AIH-*` | nmas-ts-runtime | One Codex handoff under the global AI lease. Started by the intake through polkit, which allows exactly this unit pattern and only the `start` verb | per handoff |
| `nmas-ts-auto-recover` | student | The single executor of policy-authorized plans, run through the Change Engine | on-failure |
| `nmas-troubleshooter-device-worker` | nmas-ts-diagnostic | Live diagnostic tests; sees only the R2 credential copy | on-failure |
| `nmas-ts-model-broker@codex` | broker user | Completion-only model broker. ClaudeA and ClaudeB are masked and outside the provider pool | on-failure |
| `nmas-ts-worker-credential-sync.{path,timer}` | root | Keeps the worker's restricted credential copy current | event + hourly |

Use `manage.py nmas_ts_ops_status` for a read-only view of all of the following:
- services
- the provider pool and disabled providers
- 24 h handoff outcomes
- the global AI lease
- policies (validity, executions used and remaining, cooldown, warnings)
- intake configuration and open or idle monitoring cases
- locks and leases
- in-flight plans
- audit-chain integrity

## Standing recovery policies

The policies live in `/etc/nmas/ts-recovery-policies.json` (root:student 0640). Each policy has these fields:
- exact scope: device, interface, `kind`, `intended_state`
- `risk` (unchanged)
- `owner_authorization`
- `expires_at`
- `max_executions`
- `cooldown_seconds`
- `max_evidence_age_seconds`
- `protected_flows`
- `enabled`
- `revoked_at`
- `supersedes`

Use `manage.py nmas_ts_auto_recover --status` to see a policy's state.

- **Renewal** needs a new owner authorization and a new policy id (a successor). Nothing extends a policy automatically. A successor is used only while it is active (enabled, not revoked, not expired). It inherits the cooldown of its predecessors' executions for the same scope, but not their execution count.
- **Revocation:** `sudoedit` the file and set `"revoked_at": "<UTC ISO>"` (or `"enabled": false`). The watcher reads the file again on every pass, so revocation takes effect at once.
- **Warnings** are logged hourly and emailed once each: `EXPIRES_WITHIN_24H`, `ONE_EXECUTION_LEFT`, `EXECUTIONS_EXHAUSTED`, `EXPIRED`, `REVOKED`, `DISABLED`. Policies already superseded by an active successor are not emailed.
- **Gates still checked before every execution:**
  - fresh evidence through the management path
  - authoritative intent
  - maintenance
  - conflicting change or lock
  - protected flows
  - rollback readiness
  - exact one-operation scope
  - external Configuration Validation
  - precheck
  - Change Engine postcheck

## Automatic intake

`core/services/troubleshooting/intake.py`

- **Detection.** The intake reads `show interfaces status | json` on R1, R2, R5 and S1–S4 every 10 s, read-only. A violation is a physical interface whose intent is `up` but whose state is not connected/up. It must persist for 30 s, so a flap that clears inside that window is not an incident.
- **Unreadable devices.** An unreadable device is never treated as healthy: its pending violations are kept and no new decision is made for it.
- **Correlation.** Both ends of one Containerlab link are a single incident, fingerprinted as `LINK:A:if|B:if`. The case is scoped to the side that is administratively disabled.
- **Admission rules.** These are durable because they are decided from the case table:
  - one open case per fingerprint
  - a 900 s cooldown per fingerprint
  - a budget of 4 monitoring cases per hour

  A refused admission is emailed once.
- **Idle cases.** If an open case shows no progress for 600 s, the engineer is emailed once; no duplicate case is opened.
- **Tunables** (environment): `NMAS_TS_INTAKE_DEVICES`, `NMAS_TS_INTAKE_CONFIRM_SECONDS`, `NMAS_TS_INTAKE_COOLDOWN_SECONDS`, `NMAS_TS_INTAKE_MAX_CASES_PER_HOUR`.
- **Replay** (non-disruptive validation): see `replay009.py` in the activity report. Feed recorded observations through `Intake(reader=...)` with `cfg.fingerprint_prefix = "REPLAY:"`.
- **Telemetry option.** gNMI telemetry (`gnmi_telemetry` in InfluxDB, 20 s samples) also records these transitions. An Influx reader can replace the management-path reader once a *read-only*, bucket-scoped Influx token is provisioned by the owner. The collector's write token must not be reused.

## Restart and partial-failure behaviour

- **Recovery watcher start-up sweep.** Plans left mid-pipeline are handled as follows, and nothing is ever re-executed:
  - pre-execution states (DRY_RUN_PASS, PREAUTHORIZED, PRECHECK_PASS) → `BLOCKED`
  - an `EXECUTING` action → `INTERRUPTED` → `BLOCKED`, with the Change Engine run outcome recorded
  - `VERIFYING` → left for a human

  Each case gets an `AUTOMATED_RECOVERY_INTERRUPTED` audit event and an email.
- **Unexpected error inside `recover()`.** The plan fails closed (`AUTOMATED_RECOVERY_ERROR`, `BLOCKED` if not yet executing) and is never retried.
- **Change Engine.** Each run holds a lease. A device lock with an expired lease no longer blocks the engine, but the recovery policy still treats any lock as `CONFLICTING_CHANGE`, which fails safe. Compensation restores the captured pre-change lines when a postcheck fails.
- **AI lease.** A single global lease with fencing tokens; a stale lease expires. When no eligible provider exists (broker down, unauthenticated, quota exhausted or cooldown), the handoff is `PAUSED`, and the idle-case email brings in a human.
- **Audit and evidence.** Case audit events are append-only and hash-chained (`repository.verify_audit_chain`). Evidence blobs live in the same database.

## Credential rotation (R2 diagnostic worker)

The worker never sees the full credential store. Its unit bind-mounts `/etc/nmas/troubleshooter-worker-store.r2.json`, which holds only `r2-nmas-automation`.

1. Rotation runs as before: `nmas-credential-rotation.timer` runs `rotate_due_credentials`.
2. `nmas-ts-worker-credential-sync.path` fires when the full store changes. `/usr/local/lib/nmas/sync_worker_credential.py` (root) then:
   - copies only the allowlisted secret ids (current and pending)
   - writes the copy atomically (0600, owner nmas-ts-diagnostic)
   - runs `systemctl try-restart` on the worker, because the bind mount pins the old inode
   - does nothing when nothing changed, and fails closed if the allowlisted id is missing
   - logs ids only, never values

   An hourly timer is the fallback trigger.
3. After an UNCERTAIN rotation: run `manage.py reconcile_device_credential --credential-id N`; the path unit then syncs the copy.
4. Check that it worked: `journalctl -u nmas-ts-worker-credential-sync` shows `SYNCED`/`UNCHANGED`, and a live `request_diagnostic_test` HC29 on R2 returns PASS.
