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
| `nmas-troubleshooter-device-worker` | nmas-ts-diagnostic | Live diagnostic tests; sees only the R2 automation and S2 read-only diagnostic credentials | on-failure |
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

- **Detection.** Every 10 s the intake reads `show interfaces | json` on R1, R2, R5 and S1–S4, read-only. Interfaces are read on all nine managed devices plus R5 (cEOS `show interfaces`; R3/R4 `ip -j -s link`, cabled ports only). Every third pass it also reads, on R1, R2, R3, R4, R5, S1 and S2, the OSPFv2, OSPFv3, BGP-IPv4 and BGP-IPv6 neighbors and the IPv4/IPv6 route counts (FRR through `vtysh ... json`). Each new case records topology-wide forwarding paths (`TsTopologyPath`, TOPOLOGY_PATHS audit) for H1->H2 and H1->WebServer, v4 and v6, every ECMP branch. `faults.py` classifies each interface against intent and its bounded history (see `MULTI_FAULT_CLASSIFICATION.md`):
  - `ADMIN_STATE_MISMATCH` and `OPERATIONAL_LINK_DOWN` must persist for 30 s.
  - `LINK_FLAPPING` needs ≥ 4 transitions in 300 s, counted from poll edges and the device's own `linkStatusChanges` counter.
  - `INTERFACE_DEGRADATION` uses deltas over 2 consecutive intervals; counter resets are excluded.
  - An interface reported `disabled` is called admin DOWN only when the running config shows `shutdown`.
- **Deterministic decision.** Each case opens with three records before any model call: the stored observations, the classification and a `REMEDIATION_DECISION` audit (`AUTO_REMEDIATE` / `PROPOSE_FOR_APPROVAL` / `DIAGNOSE_AND_ESCALATE` / `INSUFFICIENT_EVIDENCE` / `NO_ACTION_REQUIRED`). Every outcome other than AUTO is emailed with its coded denial reasons.
- **Routing.** An adjacency loss on a device with a link incident in the last 300 s is appended to that incident's case as `SECONDARY_SYMPTOM`; it never opens a new case. Otherwise it opens `ADJ:<dev>:<proto>:<neighbor>`. Expected adjacencies are a baseline learned by the intake process, labelled as such. A learned route source (RIP, OSPF, OSPF externals, OSPFv3, IS-IS, BGP) that drops by half or more for 30 s opens `RSRC:<dev>:<af>:<source>` (`ROUTE_OR_REACHABILITY_FAILURE`, `DIAGNOSE_AND_ESCALATE`), or is appended as `SECONDARY_SYMPTOM` to a link or adjacency incident on the same device within 300 s. The learned counts only rise while healthy and are relearned after an intake restart. ADJ and RSRC cases are never auto-closed: verified clearance applies to link and interface fingerprints only.
- **Maintenance.** An active maintenance on an incident device suppresses the case. The reason is `MAINTENANCE_ACTIVE (...)`; it is logged and emailed once.
- **AI-path outage.** If the dispatcher cannot start, the case keeps its deterministic evidence and decision, and the intake retries every 120 s, at most 15 times (`INTAKE_DISPATCH_RETRY`). Starting a unit that is already running is a no-op.
- **Verified clearance.** An escalated (non-AUTO) case whose fault cleared without NMAS acting is closed only after all of the following hold:
  - the link has been up/up and stable for 60 s, plus a 30 s confirmation
  - no handoff is open and no plan is in flight
  - both ends have been re-read and the protected flows measured

  It closes `UNRESOLVED`, with `cleared_externally=true` and `nmas_performed_repair=false`.
- **Unreadable devices.** An unreadable device is never treated as healthy: its pending violations are kept and no new decision is made for it.
- **Correlation.** Both ends of one Containerlab link are a single incident, fingerprinted as `LINK:A:if|B:if`. The case is scoped to the side that is administratively disabled for an admin mismatch, otherwise to both readable ends.
- **Admission rules.** These are durable because they are decided from the case table:
  - one open case per fingerprint
  - a 900 s cooldown per fingerprint
  - a budget of 4 monitoring cases per hour

  A refused admission is emailed once.
- **Idle cases.** If an open case shows no progress for 600 s, the engineer is emailed once; no duplicate case is opened.
- **Tunables** (environment): `NMAS_TS_INTAKE_ROUTING_DEVICES` (empty disables routing reads), `NMAS_TS_PROTECTED_FLOWS` (JSON; the default is the standing policies' flows), `NMAS_TS_INTAKE_DEVICES`, `NMAS_TS_INTAKE_CONFIRM_SECONDS`, `NMAS_TS_INTAKE_COOLDOWN_SECONDS`, `NMAS_TS_INTAKE_MAX_CASES_PER_HOUR`.
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

## Credential rotation (restricted R2/S2 diagnostic worker)

The worker never sees the full credential store. Its unit bind-mounts
`/etc/nmas/troubleshooter-worker-store.r2-s2.json`, which holds only
`r2-nmas-automation` and `s2-nmas-diag`. R2 remains on its previously verified
automation credential. S2 uses the dedicated EOS privilege-1
`network-operator` account; malformed S2 diagnostic metadata fails closed and
never falls back to `s2-nmas-automation`.

1. Rotation runs as before: `nmas-credential-rotation.timer` runs `rotate_due_credentials`.
2. `nmas-ts-worker-credential-sync.path` fires when the full store changes. `/usr/local/lib/nmas/sync_worker_credential.py` (root) then:
   - copies only the two allowlisted secret ids (current and pending)
   - writes the copy atomically (0600, owner nmas-ts-diagnostic)
   - runs `systemctl try-restart` on the worker, because the bind mount pins the old inode
   - does nothing when nothing changed, and fails closed if the allowlisted id is missing
   - logs ids only, never values

   An hourly timer is the fallback trigger.
3. After an UNCERTAIN rotation: run `manage.py reconcile_device_credential --credential-id N`; the path unit then syncs the copy.
4. Check that it worked (re-verified 2026-11-17 21:27Z: `UNCHANGED: r2-nmas-automation, s2-nmas-diag`; the installed unit
   description was aligned with the repository): `journalctl -u nmas-ts-worker-credential-sync` shows
   `SYNCED`/`UNCHANGED`; HC29 on R2 remains healthy; and an S2 live diagnostic
   reports the dedicated `nmas-diag` identity with device-enforced
   configuration denial.

## Fault-harness emergency rollback (lab owner channel)

`break.py rollback --policy … --flow-map … --fault-id …` restores and re-verifies the recorded baseline independently of
NMAS. Campaign 017 exercised it live after the automatic restore failed, because the peer lost a dynamic DHCPv6 address.
The address was first re-added by hand with the remaining server-side lease lifetimes, then `break.py rollback` verified the
full baseline → `RESTORED`. Evidence: `~/nmas-evidence/fault-campaigns/NMAS-S2-E4-20261117-017.ANNOTATION.md`. A harness
restore is never Change Engine remediation, and the case records `nmas_performed_repair=false`.

## Worker restart (re-verified 2026-11-17 21:28Z)

Restarting `nmas-troubleshooter-device-worker` with no case open recreates `/run/nmas-ts-diagnostic/worker.sock` (0660,
group `nmas-ts-diagnostic-ipc`) within a few seconds. The namespace routes to 192.168.200.2 and 192.168.200.12 persist
(they are owned by the overlay unit), and the S2 host key seen from the namespace still matches the pin.

## Diagnostic worker scope after bulk admission (CHG-NMAS-20261117-BULK-ADMISSION-019)

- Overlay `/etc/nmas/diagnostic-target-overlay.json`: eight exact tcp/22 targets on top of the R2 base (nine in total).
- Worker drop-in `zz-managed-scope.conf`: `IPAddressAllow` of exactly nine /32 addresses, and a bind-mount of
  `/etc/nmas/troubleshooter-worker-store.managed.json`.
- Credential sync copies exactly the nine `nmas-diag` secrets; any missing id fails closed.
- `nmas-diag` rotation: `modules/diagnostic_accounts.ensure_password(rotate=True)` stages, the IaC applies, verification is
  followed by a promote, and the sync path unit propagates to the worker. No timer schedules it yet.
- SQLite lock contention: governed calls in the bulk tooling retry safely, and the dispatcher's pre-model calls retry under
  distinct nonces. Recommended long-term fix: `transaction_mode=IMMEDIATE` or PostgreSQL. Not WAL: the sandboxed units
  bind-mount the database file alone.
