# NMAS V2 Phases 5 + 6: trusted isolation, commissioning and admission (live evidence)

Recorded on 2026-10-26 (UTC) in the disposable, isolated fixture `labs/isolation-commissioning-isolated/`. Nothing here ran
against the production lab, its VLAN 200, NetBox, DHCP, routing, monitoring or the deployed database. The fixture's "CORE",
"production host" and "production network" are fixture containers that stand in for those roles. They are not the deployed
lab. Design and platform findings: `docs/V2_TRUSTED_ISOLATION_COMMISSIONING.md`.

## Fixture: what is real and what stands in

| Element | Real | Stand-in / limitation |
|---|---|---|
| UP1 (trusted upstream), CORE, NEW1, NEW2 | cEOS `4.36.2F` with real EOS CLI, SSH, ACLs, OSPF, DHCP relay | Software forwarding (ETBA). Each container uses Docker network `none`; links are veth pairs created by `fixture.sh`. There is no Containerlab management bridge and no route to the lab or the host |
| NEW1 onboarding | Native EOS ZeroTouch from factory default. Real ISC dhcpd (option 67) relayed by UP1, plus the NMAS bootstrap delivery server over HTTP | Console reads use `docker exec … Cli -A`. This stands in for a physical console; `-A` bypasses the ZTP-delivered `aaa authorization exec default local` |
| Hostile device before attachment | `probe-a` / `probe-b` alpine namespaces on the very bootstrap links, later moved into the new device (`fixture.sh attach`) | A probe is a Linux host, not a malicious NOS |
| NMAS | NMAS code (`core/tests/live_isolation_commissioning_fixture.py`) runs inside the SVC namespace through `run-harness.sh`, using the production service modules, executor, transaction, provisioning run and generic execution engine | Fixture SQLite database. Fixture inventory listing only UP1 (managed on its loopback 10.254.255.1). Fixture secret store (`runtime/`, git-ignored, destroyed by `down`) |
| NetBox | none contacted | `FakeGateway` records the activation call the admitted provisioning run makes |
| Configuration Validation (GitHub Actions) | not contacted | `NMAS_CONFIGURATION_VALIDATION_ENABLED = False` in `settings_fixture.py` |
| Capability authority | A read-only copy of the deployed database's capability evidence rows, with their recorded_at preserved | See `43-…` for one correction |
| Precheck snapshot / DHCP state | DHCP state is read from the fixture dhcpd | The health snapshot for the provisioning precheck is synthetic. Notifications go to an in-memory recorder |
| NEW2 | Factory-default cEOS behind NEW1:Ethernet2; isolation, attachment and ZTP authorization are real | NEW2's own native ZTP was not run. Device Builder cannot render `ip dhcp relay information option` on NEW1, and the fixture's ISC class needs it. That is a Device Builder gap, not a protocol limit |

Run: `fixture.sh up`, then `run-harness.sh <stage>` for each stage in order: prepare, isolate, ztp, onboard, commission,
downstream-early, admit-fail, admit, downstream, report. Finish with `fixture.sh down`.

## Files (`live/`)

- `00-prepare.json`: fixture device records. UP1 is a legacy in-service upstream; NEW1 is REGISTERED and NOT_ADMITTED.
  Also UP1's starting configuration and the approved attachment NEW1 → UP1:Ethernet1.
- `10-isolation-before-device.json` (ISOLATION):
  - The policy was planned from UP1's running config, prechecked and approved by a second operator. Self-approval was
    refused (`ISOLATION_SELF_APPROVAL`), and a wrong plan hash was refused (`ISOLATION_CONFIRMATION_MISMATCH`).
  - It was applied through the governed transaction and verified **before any device existed**. Before isolation, every
    hostile flow from probe-a was PERMITTED: production v4/v6, CORE loopback, UP1's own SSH, and production → bootstrap
    side.
  - After isolation, every hostile flow was DENIED. The only flows still permitted were DHCP/relay, the bootstrap HTTP
    delivery and NMAS → device SSH. Deny-ACL counters corroborate the result, and OSPF on the port is passive.
- `20-dhcpd.conf`, `20-ztp.json`: native ZTP of NEW1 behind the enforced isolation. The first management verification
  failed with `MANAGEMENT_AUTH_FAILED` (finding 15) and the retry succeeded. Session result: BOOTSTRAPPED.
- `30-onboard.json`: management verification, the lifecycle move to ISOLATED, identity VERIFIED, and a live
  bootstrap-credential transition (BCRED COMPLETE: service key installed, bootstrap credential proven rejected).
- `38-commissioning-provisioning-runs.json`: every commissioning ProvisioningRun in order, with its plan, executions,
  compensation and postcheck failures.
- `39-…`: COM-000001 was aborted before execution. The first plan was refused with `CAPABILITY_UNCLASSIFIED` (finding 20).
- `41-…`, `42-…`: COM-000002. The run failed its postcheck (findings 19, 21) and compensation could not prove the
  restoration (finding 17), so the record went UNCERTAIN.
  - The first reconcile was refused.
  - The proof-based reconcile later read the device digest equal to the run's pre-execution digest, and the record went
    to ABORTED.
  - `42` records an operator diagnostic replay and the manual restore that happened between those two steps. The run's
    own after-failure digest already matched before that diagnosis.
- `43-…`: removal of the 33 capability rows that the failed fixture run had recorded under since-fixed defects. It also
  records a correction of the operator's first, over-broad clean-up: all 1028 deployed rows were re-copied read-only.
- `44-…`: COM-000003 ended FAILED_ROLLED_BACK. CFG-009 was refused before sending (finding 18). Every applied Configlet
  was compensated and digest-verified, and NEW1 was back at its pre-execution digest.
- `40-commission.json` (COMMISSION): COM-000004 went through readiness → evidence hash → approval by a second operator.
  Self-approval and a wrong digest were both refused.
  - The ProvisioningRun was executed by the generic engine over the commissioning transport: 11 Configlets, postcheck
    PASS, record CONFIGURED.
  - Isolation still VERIFIED after configuration. NEW1's OSPF stays non-FULL toward the isolated port, and UP1 has no
    route to NEW1's loopback (no leak).
- `45-downstream-before-upstream-admission.json`: NEW2's attachment on NEW1 was refused (`UPSTREAM_NOT_TRUSTED`).
  The declared dependency NEW2 → NEW1 is unmet, and a cycle NEW1 → NEW2 was refused
  (`COMMISSIONING_DEPENDENCY_CYCLE`).
- `50-admission-injected-failure.json`: an admission expected a route that NEW1 never advertises. The release ran on UP1,
  the postcheck failed, and the release was compensated: ADM-000001 RESTORED, UP1 byte-identical to the enforced
  digest, policy re-verified, and NEW1 stays COMMISSIONING and NOT_ADMITTED.
- `60-admission.json` (ADMISSION):
  - ADM-000002 was approved by a second operator; self-approval was refused.
  - The release was applied, and OSPF went FULL UP1 ↔ NEW1. CORE learned 10.254.255.11 and the fixture production host
    reached NEW1's loopback and uplink.
  - NEW1 is IN_SERVICE and ADMITTED.
  - Three PENDING outbox events were written: NSOT, TOPOLOGY and MONITORING `…_DEVICE_ADMITTED` / `…_TARGET_ADMITTED`.
  - The FakeGateway records the activation.
- `70-downstream-rehearsal.json`:
  - Once NEW1 was admitted, NEW2's attachment retry succeeded and the dependency became satisfied.
  - Isolation was planned, approved, applied and verified on NEW1:Ethernet2, with NEW1 as the trusted upstream and
    probe-b as the hostile side. Before, hostile flows were permitted; after, they were denied.
  - NEW2's ZTP authorization was granted, and the ZTP gate had no blockers.
- `90-lifecycle-events.json`, `99-index.json`: the full lifecycle event stream and the final device states.

## Migration

`migration-0034-validation.json` covers two disposable SQLite databases:
- A fresh database.
- A read-only backup of the deployed database, which starts at 0030.

For each, 0031–0034 were applied forward, 0034 was reversed, then 0034 was reapplied. Existing rows were unchanged at every
step. Each scratch file was deleted afterwards, and the production database was never migrated.

## What was and was not exercised live

Exercised on real cEOS:
- trusted-upstream isolation (two upstreams: a legacy device and a freshly admitted one), with traffic proof
- native ZTP behind isolation
- management verification and BCRED
- commissioning through ProvisioningRun and the generic engine (real writes, real compensation)
- admission release with OSPF and route verification
- an injected admission failure restored byte-identically
- dependency ordering

Not exercised live:
- NEW2's own ZTP and commissioning (see above)
- IPv6 routing admission (the fixture runs OSPFv2 only)
- RIP / IS-IS / BGP isolation (refused or blocked by design; see the platform findings)
- the Phase 8 consumers of the outbox (contracts only)

The secret scan of every file found no private keys, secrets or password hashes. Host keys appear as SHA256
fingerprints only.
