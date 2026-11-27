# Lifecycle, ZTP, commissioning and isolation — acceptance record

- **Change:** CHG-NMAS-20261127-LIFECYCLE-022.
- **Implementation commit:** `3c47d93ad119e51952989744af4217a19f64d71d` on `lifecycle/commissioning-isolation` (parent
  `99282bc`, the deployed Troubleshooter release).
- **Change record (outside Git):** `~/nmas-backups/CHG-NMAS-20261127-LIFECYCLE-022/`.
- **Release:** `~/Scripts/nmas-v2-lifecycle-release-20261127-3c47d93/`.

Every statement below carries one of four labels. **LIVE-PROD** means observed on the production NMAS or devices.
**LIVE-FIXTURE** means real cEOS 4.36.2F in a disposable, network-isolated fixture. **UNIT** means the Django test suite.
**PRIOR-FIXTURE** means earlier fixture evidence for code this branch does not change.

## 1. Classification

### Implemented and deployed (LIVE-PROD)

- Read-only lifecycle stage projection, as website pages, audited JSON and `manage.py nmas_lifecycle_report`.
- 10 files; no migration; only the `nmas-web` HUP reload.

### Implemented, verified in isolated fixtures and unit tests; not deployed to production

- **Lab 9 isolation and admission integration**, verified with LIVE-FIXTURE and UNIT evidence. Production already runs its own
  live-verified Lab 9 implementation, which admitted R8 and S5 on 2026-11-03. The two lineages diverge in 24 lifecycle modules,
  so replacing production's versions is a separate reconciliation release.
- **ZTP DHCP lease lifetime and the controlled re-discovery window** (`ztp/lease.py`), verified with UNIT evidence. Production's
  `ztp/discovery.py` and `ztp/workflow.py` belong to the diverged lineage, which predates option 82, and production has no open
  ZTP session.
- **R6-first / R7-second sequencing, isolation against unauthorized routing, failed-admission rollback**, verified with
  LIVE-FIXTURE evidence (R4→R6→R7 analogue: UP1→NEW1→NEW2).
- **Management-path failover** (OOB → VLAN 200 adjacent switch → management VRF), verified with UNIT and PRIOR-FIXTURE evidence.
- **Governed maintenance and decommissioning** (idle versus active traffic, lossless-only, precise refusal), verified with UNIT
  and PRIOR-FIXTURE evidence.

### Blocked by absent platform capability

- **DHCPv6 SOLICIT re-discovery:** no adapter discovers over DHCPv6. It is refused with `DHCPV6_DISCOVERY_NOT_IMPLEMENTED`.
- **Renewal windows for adapters without a documented native retry interval** (e.g. IOS XE): refused with
  `NATIVE_RETRY_UNDOCUMENTED`.
- **ZTP on any OS other than cEOS 4.36.2F:** no live evidence; adapters keep their declared evidence class.
- **Upstream control-plane ACL (Lab 9) on the fixture:** not exercised there. The fixture upstream exposes no eAPI, gNMI or
  NETCONF service, so the plan closed the upstream to the bootstrap side with the per-service SSH ACL only
  (`acl-mgmt-v4/v6`, `attach-mgmt-v4/v6` under `management ssh`), which was applied and verified. The control-plane copy is
  covered by UNIT tests (`test_isolation_eos`) plus the Lab 9 production run that predates this branch (R2/R8 upstreams).

### Requiring a separate disruptive-change authorization

- **Live R6/R7 re-onboarding.** R6 and R7 are already IN_SERVICE/ADMITTED (Lab 8). Re-running their ZTP needs `write erase` /
  reload and new links, both excluded by this assignment.
- **Live DHCP lease expiry or renewal on a production port.**
- **Live management-path failover on production VLAN 200.**
- **A live maintenance or decommission entry on a production device.**

**No live R6/R7 acceptance is claimed.** R6/R7 evidence here is fixture (analogue) evidence, plus their existing production
lifecycle records read by the projection.

## 2. Evidence

### 2.1 Identity, admission, bootstrap isolation, commissioning, R6→R7 (LIVE-FIXTURE, this branch, 2026-11-27 ~03:36–03:50Z)

**Environment.** `labs/isolation-commissioning-isolated` (Docker `none` network, veth pairs) ran
`core.tests.live_isolation_commissioning_fixture` with every stage, `prepare` through `report`. The evidence is in
`evidence/fixture-isolation-commissioning/` of the change record (SHA256SUMS included). The fixture was torn down afterwards.

**Isolation, before any device exists** (`10-…`):
- Isolation was verified against a hostile probe.
- Of 8 flows, the 6 expected DENY flows were denied, with 0 mismatches.
- Self-approval was refused (`ISOLATION_SELF_APPROVAL`). A wrong confirmation hash was refused
  (`ISOLATION_CONFIRMATION_MISMATCH`).

**ZTP and onboarding** (`20-`, `30-`):
- Native ZTP ran behind the isolation, with out-of-band host-key enrollment.
- With the device present, 6 flows were checked: 4 DENY, 0 mismatches.

**Commissioning** (`40-`):
- NEW1 was configured with OSPF while still isolated. The isolation stayed `VERIFIED` with no drift.
- UP1 kept only its CORE adjacency, NEW1 had 0 neighbours, and UP1 had no route to NEW1's loopback.
- So the unauthorized adjacency and route advertisement were not accepted.

**R7 before R6** (`45-`):
- NEW2's attachment on NEW1 was refused (`UPSTREAM_NOT_TRUSTED`) while NEW1 was COMMISSIONING.
- The declared dependency was unmet (`COMMISSIONING_DEPENDENCY_UNMET`).

**Failed admission** (`50-`):
- An injected verification failure gave `ADMISSION_VERIFICATION_FAILED`.
- The upstream was restored byte-identical, the isolation was re-verified (6 flows, 0 mismatches), and the device stayed
  NOT_ADMITTED.

**Admission** (`60-`):
- `ADM-000002` gave NEW1 OSPF FULL with UP1, and production reached NEW1's loopback.
- NEW1 is ADMITTED / IN_SERVICE.

**R7 after R6** (`70-`):
- The NEW2 attachment retry was accepted, with the upstream satisfied "admitted by ADM-000002".
- The isolation of NEW1:Ethernet2 was verified (7 flows, 5 DENY, 0 mismatches).
- NEW2's ZTP gate was clear.

**Immutable evidence** (`90-`): every lifecycle event chain was exported.

**First attempt.** The first run's `isolate` stage failed with `ISOLATION_UPSTREAM_UNREADABLE` because it ran seconds after
`fixture up`, while UP1's SSHD was still disabled during boot. That log is kept. The harness resumed from `isolate` once
UP1's SSH was enabled.

### 2.2 DHCP lease lifetime and renewal (UNIT: `test_ztp_lease`, 15)

The tests cover:
- lapse on expiry and on release before delivery;
- no regression after delivery;
- a lease-file re-read is not a renewal;
- a genuine renewal re-advances only after the authorization is re-decided, and is refused once the authorization expired;
- delivery refuses an ended binding;
- the renewal window is refused while the upstream is unadmitted;
- PENDING, OBSERVED and OVERDUE states, with native-only recovery;
- DHCPv6 and an undocumented retry interval are refused.

### 2.3 Lifecycle projection and website (UNIT: `test_lifecycle_stage_report`, 14; LIVE-PROD)

**Unit coverage:**
- legacy devices show no fabricated history;
- the projection writes nothing;
- tampering is detected by raw SQL (the ORM refuses the update);
- `--verify` exits 2 on a broken chain or when an adopted device reports ADMITTED;
- the routes are read-only, and the JSON is audited;
- a refused-transition row renders. A live-data regression found this before deploy: the template raised
  `VariableDoesNotExist`.

**Production tree.** In a production-tree stage (production code plus the release overlay), 39 of 39 tests passed, and all 13
production devices rendered (HTTP 200) from a DB snapshot.

**After deploy** (LIVE-PROD):
- `--verify` passed: 13 devices, 13 chains intact, 4 ADMITTED (R6, R7, R8, S5), 9 LEGACY_PREEXISTING.
- Login returns 200. Every new route redirects to login unauthenticated, like the existing JSON routes. An unauthenticated
  POST returns 403.
- An authenticated page view needs an operator's MFA and was not performed by automation.

### 2.4 Regression

**Dev tree.** The lifecycle, ZTP, isolation, commissioning, management, maintenance, decommission and CI modules (2308 tests)
pass except 2. Both fail identically on base `99282bc`, so neither comes from this branch:
- `test_identity_access…website_mfa_is_separate_from_device_mfa`: the Troubleshooter's `single_admin_exception` imports
  `..health`.
- `test_tier3_selection…every_repository_file_has_a_classification_rule`: 79 Troubleshooter paths are unclassified.

This branch adds no unclassified path.

**Deployed production code.** A copy of the deployed production tree, taken after the install, ran 68 Troubleshooter /
observation / management-path / SSH / route-intent / single-admin modules plus `test_lifecycle_stage_report`. Result: 1303
tests OK (change record `post-deploy-regression.log`).

After deploy, all Troubleshooter services were active (`nmas-ts-intake`, `nmas-ts-auto-recover`, device worker, model broker,
gateway). Execution was quiescent and the route-intent intake HEALTHY. Recovery policy ARP-R2-E1-002 was unchanged: enabled,
not revoked, expiry 2026-12-01.

### 2.5 Production connectivity and diagnostic readiness (LIVE-PROD, VM1 collector)

| | Before | After deploy |
|---|---|---|
| DB / migrations | healthy | healthy |
| Containers | 15 | 15 |
| Management paths ready | 9/9 | 9/9 |
| Diagnostics fresh | all nine | all nine |
| Lifecycle | all LEGACY_PREEXISTING | all LEGACY_PREEXISTING |
| `nmas_revision` | `a62722ff…` | `ae26d5fc…` (accepted) |

`devices_admitted=0` / `credential_ready=false` is the unchanged, truthful legacy classification.
