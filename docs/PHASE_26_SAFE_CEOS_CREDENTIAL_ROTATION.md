# Phase 26A — Safe cEOS Credential-Rotation Transaction

Status: implemented and regression-tested; production rotation remains
disabled pending the separately approved S4 `nmas-automation` pilot.

## Scope and invariants

Phase 26A replaces the direct cEOS password mutation with a recoverable EOS
transaction. It does not change MFA/RADIUS/privacyIDEA, topology, routing,
monitoring, or any production credential policy. The scheduler command remains
`manage.py rotate_due_credentials --json`.

The protected provider is the only location that holds credential values. The
database and evidence contain opaque version IDs, booleans, result codes,
timestamps, digests, and bounded non-secret metadata only. The secret-bearing
EOS command is supplied to `docker exec -i` on stdin; it is absent from argv,
the environment, logs, exceptions, and evidence.

## Successful transaction

The implementation is split between:

* `web/core/services/credentials/engine.py` — claim, ordering, durable phases,
  provider promotion, finalization and reconciliation;
* `web/core/services/credentials/platforms.py` — protected authentication
  probes and adapter error boundaries;
* `web/core/services/credentials/ceos_transaction.py` — checkpoint, named EOS
  session, commit timer, operational gates, confirmation and persistence;
* `modules/device_credentials.py` — atomically locked current/pending provider
  slots.

The enforced order is:

1. Atomically claim exactly one enabled, due, runnable credential row.
2. Resolve the managed cEOS target and refuse any pre-existing open EOS
   configuration session.
3. Read the current protected version and stage a distinct pending version.
4. Capture the exact normalized running digest and a safe operational baseline.
5. Create and hash a pre-change flash checkpoint.
6. Stage the username command in a run-unique named EOS session and commit it
   with a ten-minute automatic-revert timer.
7. Prove the new credential accepts a fresh device login and identifies the
   expected hostname.
8. Prove the previous credential receives an explicit authentication reject;
   timeout or connection failure is not accepted as rejection evidence.
9. Before confirmation, require Health with no blocking result (only the
   existing conditional `CRITICAL_EVENTS_RECENT` warning may be tolerated),
   NSOT, config retrieval, privileged recovery, target and fleet identity
   routing, MFA/AAA policy, Vlan200, management reachability, expected timer
   state, and masked full-config drift checks to pass.
10. Confirm the named EOS session, prove no session remains, run `write memory`,
    and require normalized startup configuration to equal running configuration.
11. Promote pending to current in the protected provider.
12. Atomically finalize credential timestamps/status and the audit run, including
    the recurring `next_due_at` calculation.

Any required gate before confirmation leaves the EOS timer unconfirmed. The
device therefore reverts independently of Python. Both provider candidates
remain available until reconciliation can prove the result.

## Crash and reconciliation matrix

| Boundary | Durable observation | Deterministic action |
|---|---|---|
| 1. After DB claim | `IN_PROGRESS`, `CLAIMED`, no pending | Current authenticates; finalize `RECONCILED_CLAIM_ONLY`, defer retry 24 hours. |
| 2. After provider stage | Pending exists, no recorded EOS transaction | If current accepts and pending rejects, discard pending and defer retry. Any other result remains `UNCERTAIN`. |
| 3. After EOS timer armed | Recorded session/digests or an unrecorded pending candidate | While timer exists, return `TIMER_REVERT_PENDING`. After revert, prove pre-digest/current authentication, discard pending and defer retry. |
| 4. After password changed | Timer pending, current rejects, pending accepts | Do not confirm during reconciliation; wait for automatic revert unless prior operational validation was durably recorded and the timer is already confirmed. |
| 5. After new-login proof | Timer remains armed | Same automatic-revert path; no promotion. |
| 6. After operational validation | Durable `OPERATIONAL_VALIDATED` | An armed timer is still allowed to revert. If confirmation completed just before the crash, prove post-digest/no session, rerun validation/persistence, then promote. |
| 7. After device confirm | Post-digest, no open session, pending authenticates | Rerun operational checks with no expected timer, persist if needed, then promote pending. |
| 8. After startup persistence | Startup equals running, pending authenticates | Revalidate and promote pending. |
| 9. After provider promotion | No pending; current opaque version equals recorded new version | Require all pre-promotion phases plus current authentication, post-digest, startup equality and no sessions; finalize as `RECONCILED_POST_PROMOTION`. |
| 10. Before DB finalization | Same as boundary 9 | Database credential/run finalization is atomic and reconciliation records success, never a misleading failed rotation. |

`IN_PROGRESS` and `UNCERTAIN` are non-runnable scheduler states. A safely
reconciled prior state receives a 24-hour retry delay, preventing an immediate
second automatic rotation.

## Evidence and failure proof

`CredentialRotationRun.phase` and its explicit result fields make the order
auditable. Recovery metadata includes the EOS session, checkpoint identity and
hashes, exact pre/post normalized digests, validation booleans and opaque
provider versions. It excludes credential material and password-derived
authentication hashes.

The automated suite includes a live-like in-memory EOS transport based on the
already proven MFA `FakeEos`. It creates the checkpoint, arms the timer, changes
the account line, intentionally expires the timer, proves exact restoration,
then exercises confirmation and startup persistence. It also asserts that the
secret-bearing command is present only on stdin. This test changes no container,
provider, or production database. A disposable real cEOS was not added because
the approved topology must not be deployed/destroyed and the repository has no
isolated cEOS lifecycle fixture; live operational proof is therefore the
reviewed successful S4 pilot, not a deliberately failed production rotation.

## Future S4 pilot guardrails

The future pilot must first prove S4 `nmas-automation` is the only enabled/due
row and that no provider pending version or EOS configuration session exists.
It may then invoke the same scheduler entry point once manually. Success is
accepted only when the run selects exactly one credential and records new
acceptance, old rejection, all operational gates, transaction confirmation,
startup equality, provider promotion and final database evidence. The timer's
enabled/active state and independent journal history prove scheduling without
waiting an hour. No failure is injected into production S4.
