# JOB-9AA10B4E7CA7 — Gateway attestation and operational readiness, phase 1

Date: 2026-11-10. Author: standalone Claude Code session on VM 1, working outside the orchestrator. It continues from checkpoint #23
([`JOB-9AA10B4E7CA7-continuation.md`](JOB-9AA10B4E7CA7-continuation.md)), and none of the 30 completed subtasks were redone.

**Status: INCOMPLETE_WORK. No gateway attestation was obtained.** The gateway rejects this session: the client answers
`no orchestrator proxy in this environment (the gateway is reachable only from an orchestrator agent sandbox)`. I did not try to
reach it any other way. Every result below is a **local** result. None of them is gateway-attested, and none is live network evidence.

## 1. Audit

| Item | Finding |
|---|---|
| Worktree | `/home/student/Scripts/nmas-public-dev-troubleshooting`, branch `troubleshooting/job-9aa10b4e7ca7-port`, HEAD `4f950b36`, origin `Adv-Netman-public-ci`. Nothing is staged or committed. All earlier uncommitted work is preserved. |
| Migration `0037_troubleshooting` | Depends on `0036_v2_phase9_relay_option82_readback`. It adds 18 `CreateModel`. `makemigrations core --check` reports no changes, and `manage.py check` reports 0 issues. |
| Production lineage (deployment prerequisite) | `nmas-web.service` runs from `clab_dualstack_lab-deploy`, which is the **legacy** origin `Adv-Netman` at `129d3f0`, at migration `0035`. The public `0036` must be deployed before `0037`. Deploying troubleshooting therefore depends on moving production onto the public lineage, which is an operator decision. |
| Source pin (local, installed helper) | `sandbox_pin.py hash` succeeds with **no PermissionError**. The pin changes with every edit. The values at the end of this session are in §6. |
| Earlier PermissionError | Resolved for the authorized public repository at the local-helper level. The gateway itself was not exercised (see Status above). Nothing was bypassed. |

## 2. Corrections made in this phase

| Change | Why | Test |
|---|---|---|
| `tests/fixtures/troubleshooting_collectors/capture_live.py`: `sys.path` now uses the script's own worktree (`parents[4]`). Before, it used the hard-coded legacy archive `/home/student/Scripts/clab_dualstack_lab/web`. | A gateway capture would have recorded evidence produced by **unpinned legacy code** under a pin of this worktree, which is a source-provenance mismatch. | RDY13 |
| New `services/troubleshooting/readiness.py` and `manage.py troubleshooting_readiness` (read-only) | Shows, per device, why admission refuses it, with every gate's blocker, the owner and the exact corrective action. Also shows per-runbook readiness. It uses the runtime's own admission path, and it never adopts, verifies or contacts anything. | RDY01–RDY12 |
| `services/ci/rules.py`: `troubleshooting_readiness` added to the troubleshooting Tier-3 selection | Keeps the selection complete | `test_tier3_selection`, `test_test_governance` |
| Docs: `deployment-bindings.md` (readiness section), `port-to-public.md` (tests added) | — | — |

No admission rule, gateway, settings, production device, service, credential or orchestrator state was changed. No second configuration
writer exists: `ChangeEngineExecutor` stays a hand-off to the Change page (`EXECUTION_VIA_CHANGE_WORKFLOW`), and
`test_contracts…the_mutating_engine_has_exactly_one_caller` passes.

## 3. Test results (local; `web/`, `/opt/ai-orchestrator/nmas-env`, `DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test`)

| Scope | Command | Result |
|---|---|---|
| New readiness + provenance tests | `manage.py test core.tests.test_troubleshooting_readiness` | **13 tests, OK** |
| CI / governance / contract boundary | `manage.py test core.tests.test_tier3_selection core.tests.test_tier3_changes core.tests.test_test_governance core.tests.test_contracts` | **117 tests, OK** |
| Full troubleshooting suite, one run (33 modules, serial) | `manage.py test $(core/tests/test_troubleshooting_*.py → labels) --parallel 1` | **719 tests, OK** (312 s). The run started before RDY13 existed. |
| Same 33 modules, one run each (batch timing) | `scratchpad time_modules.sh` | **720 tests, all 33 modules OK** |
| Tier-3 plan (`--working-tree`, base `origin/main`) | `ci.service.plan_change_effect` | targeted, 152 files, **0 unclassified**; required gates: 6 static + `django.tests` (labels `core`) |
| Tier-3 required static gates | `static.hygiene`, `static.syntax`, `django.check`, `django.migrations`, `governance.catalog`, `quality.pylint` via `ci.execute.execute_plan` | **6 PASS** (39,844 added lines scanned; 98 files parsed) |
| Full `core` regression (Tier-3's `django.tests` gate) | `manage.py test core --noinput --parallel 1` | **8,746 tests, OK** (2,080 s; 44 skipped; 0 failures, 0 errors) |
| Migration consistency | `makemigrations core --check --dry-run`; `manage.py check` | no changes; 0 issues |

Gateway-attested results: **0**. Live network evidence: **0**.

Evidence class: every runbook and HC result uses **SIMULATED** replay inputs. The readiness tests use the real lifecycle registry in a
test database. Nothing here is live network evidence.

## 4. Why devices are refused admission (exact)

Admission is `DeploymentAdmission.resolve`, and a device is admitted only when **all** of these gates pass:
inventory ∧ platform ∧ lifecycle ∧ version.

1. **No binding is configured.** `config/settings.py` defines no `NMAS_TS_DEPLOYMENT`, so `lifecycle_provider` is `None` and
   every device answers `LIFECYCLE_UNKNOWN` ("no authoritative lifecycle answer"). This is a deployment/settings step.
2. **With the documented NMAS binding** (`nmas_providers.inventory` and `lifecycle`):
   * A device with no `ManagedDevice` row answers `UNREGISTERED`. *Adopt Existing Device* is a human action and is never automatic.
   * **R5 cannot be adopted.** `resolver.adoption_scope` answers `OUT_OF_WRITABLE_SCOPE`, because the inventory gives `address: auto` (no
     declared management address) and the resolver refuses it. R5 stays outside troubleshooting scope, which is correct. Changing that
     would mean changing the frozen Lab 1 inventory/management addressing, which is not authorized.
   * Adopted devices are `LEGACY_ADOPTION`, `IN_SERVICE`, `LEGACY_PREEXISTING`, identity `UNVERIFIED`, and they answer
     `IDENTITY_UNVERIFIED`.
   * **There is no producer for the evidence that identity verification needs.** `lifecycle.verify_identity` needs an
     `AUTHENTICATED_SESSION` `IDENTITY` observation that carries the SSH host key. The only code that records one is ZTP management
     verification (`ztp/workflow.py:362`), which applies to new ZTP devices. Nothing records it for an adopted device. Verify Identity is
     therefore impossible today for all nine adoptable Lab 1 devices. This is an engineering gap that needs a reviewed, read-only,
     host-key-pinned identity-observation producer for adopted devices. The readiness report names it `IDENTITY_NO_PRODUCER`.
3. **No version provider exists.** `ManagedDevice` has no OS-version field, `DeviceObservation.claims` accepts only
   `serial/base_mac/host_key/hostname/client_id`, and no other model persists an observed version. Every device would stay
   `VERSION_UNKNOWN` even with every other gate passed. No version is invented: the inventory `os_version` is ignored by design.

I could not read the production registry (`clab_dualstack_lab-deploy/web/db.sqlite3`) because the session's permission policy refused it,
and I did not work around that. The operator can produce the authoritative per-device answer, read-only, with:

```
cd /home/student/Scripts/clab_dualstack_lab-deploy/web   # after deploying this code; or point a public checkout at a read-only copy
manage.py troubleshooting_readiness --with-nmas-providers --json
```

## 5. Device-by-device operational readiness

Sources: the tracked `inventory.yml` (via `resolver.engine_devices()`), `resolver.adoption_scope`, the provider code, and
`manage.py troubleshooting_readiness` (shown for the default and NMAS-provider bindings against this worktree). The "registry" column
cannot be confirmed (see §4). It shows what the code gives for each possible registry state.

| Device | Platform (inventory) | Observed OS version | Identity | Lifecycle admission (default settings → NMAS binding) | Adoptable | Reachable telemetry sources for troubleshooting | Missing providers | Exact corrective action (in order) |
|---|---|---|---|---|---|---|---|---|
| R1, R2, S1, S2, S3, S4, mgmt_swt | cEOS (`ceos` → `arista_ceos`); declared mgmt `192.168.200.x` / `2001:db8:200::x` on Vlan200 | **none recorded** (NMAS persists none; the AGENTS.md baseline says 4.36.2F, but that is documentation, not an observation, and it is not used) | UNVERIFIED if adopted; no producer for the evidence | `LIFECYCLE_UNKNOWN` → `UNREGISTERED`, or `IDENTITY_UNVERIFIED` once adopted | yes | **none bound.** NMAS itself collects SNMP, syslog and gNMI for all 10 devices, but no troubleshooting transport or reader is bound (`cli_transport_factory`, `snmp_session_factory`, `syslog_source`, `gnmi_getter_factory` and all readers are unbound) | lifecycle binding; identity-observation producer; version provider; all source bindings | 1 bind `lifecycle_provider` and `inventory` (settings, reviewed deploy) · 2 operator *Adopt Existing Device* · 3 engineering: reviewed read-only host-key-pinned `AUTHENTICATED_SESSION` identity producer for adopted devices · 4 operator *Verify Identity* · 5 engineering: observed-version record and provider · 6 bind source readers |
| R3, R4 | Ubuntu/FRR (`linux` → `ubuntu_frr`); declared mgmt `192.168.200.3/.4` | none recorded (FRR 8.4.4 is documented, not observed) | as above | as above | yes | as above (FRR has no systemd PID 1; providers must use the existing `snmpd` / link-watcher / gNMI paths) | as above | same steps 1–6 |
| R5 | cEOS; `address: auto`, Management0, `edge: true` | none recorded | — | `LIFECYCLE_UNKNOWN` → `UNREGISTERED` | **no**: `OUT_OF_WRITABLE_SCOPE` | none; `NO_MANAGEMENT_ADDRESS` | — | none within scope. R5 stays out of troubleshooting. Making it eligible would need a declared management address, which is a frozen-baseline change and needs explicit instruction. |

Readiness command output against this worktree (default settings, empty dev DB):
`LIFECYCLE_UNKNOWN` for all 10 devices, with blockers `LIFECYCLE_PROVIDER_UNBOUND`, `VERSION_PROVIDER_UNBOUND`, and for R5 also `NO_MANAGEMENT_ADDRESS`.
`admitted = 0/10`. Under the NMAS binding, RDY02–RDY07 show the exact verdict for each registry state on the real registry code.

## 6. Gateway attestation plan (to be run by the orchestrator dispatcher)

Each batch fits inside the 480 s per-run limit with at least 4× margin, based on local serial timings that include about 13 s of test-database setup. B1–B6 together cover all 33 `test_troubleshooting_*` modules (720 tests).

| Batch | Tests | Local est. (s) | Modules |
|---|---|---|---|
| B1 | 89 | 32 | access, nmas_providers, deployment, runtime_ports, readiness |
| B2 | 66 | 116 | qos_source, forwarding_source, engine |
| B3 | 47 | 97 | acl_source, fib_source, l2_source |
| B4 | 156 | 103 | dns_source, runtime, runbooks, config_snapshot, baseline_scope, stp_source, dns_rules, pmtu_source |
| B5 | 168 | 53 | ai_runtime, probe_source, flow_runtime, governance, views, evidence, ai, baseline_history |
| B6 | 194 | 23 | acl_history, l2_history, protocol_source, physical_source, collectors, flow_wire |
| B7 | 117 | ~30 | regression boundary: contracts, Tier-3 selection/changes, test governance |

Commands (run from an orchestrator agent sandbox only):

```
# B1
python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting core.tests.test_troubleshooting_access core.tests.test_troubleshooting_nmas_providers core.tests.test_troubleshooting_deployment core.tests.test_troubleshooting_runtime_ports core.tests.test_troubleshooting_readiness
# B2
python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting core.tests.test_troubleshooting_qos_source core.tests.test_troubleshooting_forwarding_source core.tests.test_troubleshooting_engine
# B3
python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting core.tests.test_troubleshooting_acl_source core.tests.test_troubleshooting_fib_source core.tests.test_troubleshooting_l2_source
# B4
python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting core.tests.test_troubleshooting_dns_source core.tests.test_troubleshooting_runtime core.tests.test_troubleshooting_runbooks core.tests.test_troubleshooting_config_snapshot core.tests.test_troubleshooting_baseline_scope core.tests.test_troubleshooting_stp_source core.tests.test_troubleshooting_dns_rules core.tests.test_troubleshooting_pmtu_source
# B5
python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting core.tests.test_troubleshooting_ai_runtime core.tests.test_troubleshooting_probe_source core.tests.test_troubleshooting_flow_runtime core.tests.test_troubleshooting_governance core.tests.test_troubleshooting_views core.tests.test_troubleshooting_evidence core.tests.test_troubleshooting_ai core.tests.test_troubleshooting_baseline_history
# B6
python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting core.tests.test_troubleshooting_acl_history core.tests.test_troubleshooting_l2_history core.tests.test_troubleshooting_protocol_source core.tests.test_troubleshooting_physical_source core.tests.test_troubleshooting_collectors core.tests.test_troubleshooting_flow_wire
# B7
python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting core.tests.test_contracts core.tests.test_tier3_selection core.tests.test_tier3_changes core.tests.test_test_governance
```

For each run, record: run id, `pin_id`, `source_pin.head` / `tree_sha256` / `dirty_count`, `worktree_changed_during_run=false`, and the test counts. Accept a batch only when the gateway's pin `head` is `4f950b36…`, its branch and origin match, and its `tree_sha256` matches a fresh local `sandbox_pin.py hash` taken while the tree is unchanged.

The full `core` regression (Tier-3's required `django.tests` gate for this change set, which labels `core`) takes about 2,100 s and **cannot** run inside one 480 s gateway run. It belongs to Tier-3 CI on the PR, or to an orchestrator-split run. It is not part of this attestation plan.

Local pin at the end of this session (installed helper, no PermissionError): head `4f950b36`, branch `troubleshooting/job-9aa10b4e7ca7-port`, origin `Adv-Netman-public-ci`, 1971 files, 153 dirty paths, tree_sha256 `15523186dded11c5cd46c1f939aefc175939e49fa2aaa275c816b7246b33fec1`. It was taken just before this line was written, so writing it changes the tree. The gateway records its own pin for each run, and that pin is the one that counts.

## 7. Isolated live-validation campaign RB01–RB07 (prepared, not executed)

**Nothing here was executed. Fault injection on gateway fixtures needs orchestrator dispatch and explicit authorization.** No
production device, the frozen Lab 1 topology or any production flow is touched. Every fault is injected only into a
gateway-owned, TTL-bounded, isolated fixture (`ceos_pair`, `ceos_peer`, `iosxe_peer`), and through the gateway's allowlisted
`config` / `peer` operations. Each step is recorded as gateway evidence under one `pin_id`.

**Step 0, engineering prerequisite (not built in this phase, needs review).** Fixture devices are not in `inventory.yml`, so production
admission refuses them correctly. The campaign needs a **fixture-scoped** binding that is never placed in production settings:
* `inventory`: the nodes from `fixture_status`
* `lifecycle`: `IN_SERVICE` only while the gateway reports the fixture `ready` and unexpired
* `version`: parsed from that run's own gateway-evidenced `show version` / `vtysh -c 'show version'`, never typed in by hand
* transports: `GatewayTransport` with `gateway_platforms`

`capture_live.py` currently accepts the OS version as a CLI argument. The campaign must instead derive it from the captured
`version` command.

Stages for every runbook (each stage is one row in the structured report, with evidence seq, timestamp, pin and verdict):

| # | Stage | Content | Abort / stop condition |
|---|---|---|---|
| S0 | Pin | `aiorch_gw.py pin nmas-public-dev-troubleshooting` → `pin_id`; record head, tree, dirty | pin refused or tree changes later |
| S1 | Fixture | `fixture-start <template> 1800` → `fixture-wait`; record nodes, links, images, isolation | not `ready`, or isolation missing |
| S2 | Baseline (healthy) | troubleshooting case on the healthy fixture; expect a no-fault outcome (negative control) | any write requested |
| S3 | Inject | one allowlisted fault (below), under its own evidence label | gateway refuses: stop and report |
| S4 | Diagnose | same case flow; capture Stage-1 tables, test matrix, hypotheses, disposition | budget exhausted → `INCONCLUSIVE_ESCALATED` |
| S5 | Remediate | plan only. Execution is a hand-off to the NMAS Change page (`EXECUTION_VIA_CHANGE_WORKFLOW`); no second writer | — |
| S6 | Restore | apply the inverse of S3 through the gateway; re-run S2 and expect healthy | not restored → `REMEDIATION_FAILED_UNRESTORED` recorded |
| S7 | Cleanup | `fixture-stop`; require `cleanup_verified=true`; `manifest --fixture FX --pin P` | cleanup not verified |

| Runbook | Fixture | Fault (S3) and inverse (S6) | Expected isolation | Feasibility now |
|---|---|---|---|---|
| RB01 link flapping | `ceos_pair` | `interface EthernetN` `shutdown` / `no shutdown` cycles, bounded count, then a planned admin-down negative case | distinguish admin-down from instability | needs Step 0 and physical/event readers (syslog via fixture `show logging`) |
| RB02 reachability | `ceos_peer` | ACL denying ICMP only (TCP production intact), then a real TCP deny | IT-02 expected ICMP vs. real TCP loss; ≥20 applicable HC | needs Step 0, probe runner on the peer (`peer` argv), FIB/ACL readers |
| RB03 neighborship | `ceos_peer` (cEOS + FRR) | OSPF hello/dead timer or area mismatch on one side | protocol-specific mismatch plus RIB/FIB check | needs Step 0 and protocol reader |
| RB04 STP | `ceos_pair` | root-priority change (no loop injection unless the template has a redundant L2 link, to be confirmed with `fixture-status`) | root/TCN evidence | template L2 redundancy unknown; confirm first |
| RB05 DNS | none suitable | — | — | **EXTERNALLY_BLOCKED**: no template provides a resolver or authoritative zone |
| RB06 MTU/PMTUD | `ceos_peer` | lower MTU on one link and block ICMP PTB with an ACL | size-dependent loss with PTB suppression | needs Step 0 and PMTU probe runner on the peer |
| RB07 Layer 1 | — | — | — | **EXTERNALLY_BLOCKED**: virtual optics answer `UNSUPPORTED_OPERATION`. Needs real hardware or an accepted documented limitation. |

Production-flow safety: S2/S6 health checks run only inside the fixture. The frozen Lab 1 topology, the H1→WebServer issue, R1–R5/S1–S4
and all monitoring services are outside the campaign scope.

## 8. Outstanding operational prerequisites

| # | Prerequisite | Owner | Approval type |
|---|---|---|---|
| 1 | Gateway-attested runs B1–B7 (§6) | orchestrator dispatcher | existing read-only `test` op |
| 2 | Reviewed commit, PR and Tier-3 CI of this worktree (full `core` gate) | user | GitHub remote write |
| 3 | Production lineage: `clab_dualstack_lab-deploy` is on the legacy origin at `0035`. Moving it to the public lineage (`0036`, `0037`) is required before troubleshooting can be deployed. | operator | production deploy |
| 4 | `NMAS_TS_DEPLOYMENT` `inventory` and `lifecycle_provider` binding, plus the factory settings | operator | settings change (reviewed deploy) |
| 5 | Adopt Existing Device for R1–R4, S1–S4, mgmt_swt | operator | human lifecycle action |
| 6 | Read-only, host-key-pinned identity-observation producer for adopted devices | engineering | code review (touches device sessions) |
| 7 | Verify Identity per device | operator | human lifecycle action |
| 8 | Authoritative observed OS-version record (model + producer + provider) | engineering | schema/code review |
| 9 | Source bindings: CLI/SNMP/syslog/gNMI transports with credentials from the existing secret provider; FIB/QoS/phy/proto readers; DNS/probe runners; STP/L2/ACL/forwarding contexts; flow input; baseline sources | engineering + operator | review + settings |
| 10 | Fixture-scoped admission binding (§7 Step 0) and campaign authorization | engineering + user | review + fault-injection approval |
| 11 | DNS fixture template; real optics hardware or an accepted RB07 limitation | gateway owner / user | privileged infrastructure (staged, not done) |
| 12 | Rollback service port (compensation is `COMPENSATION_UNAVAILABLE` today) | engineering | review |
| 13 | AI provider and approval for the operational AI campaign | user | external service |
| 14 | `LAB_REQUIREMENTS.md`, `IMPLEMENTATION_PLAN.md`, `GAP_ANALYSIS.md` still point new work at the legacy archive | user | doc edit approval |
| 15 | Optional gateway hardening: gitignore-aware `sandbox_pin.walk()` (`source-pin-rca.md`) | gateway owner | privileged, re-pin |

### Readiness per runbook

| Runbook | Code + simulated validation | Live readiness now | Blocking items |
|---|---|---|---|
| RB01 | IMPLEMENTED_NOT_LIVE_VERIFIED | NOT_READY | 1, 10, readers in 9 |
| RB02 | IMPLEMENTED_NOT_LIVE_VERIFIED | NOT_READY | 1, 10, probe/FIB/ACL/flow/baseline in 9 |
| RB03 | IMPLEMENTED_NOT_LIVE_VERIFIED | NOT_READY | 1, 10, proto reader |
| RB04 | IMPLEMENTED_NOT_LIVE_VERIFIED | NOT_READY | 1, 10, STP/L2 contexts, template confirmation |
| RB05 | IMPLEMENTED_NOT_LIVE_VERIFIED | EXTERNALLY_BLOCKED | 11 (DNS fixture), DNS runner/context |
| RB06 | IMPLEMENTED_NOT_LIVE_VERIFIED | NOT_READY | 1, 10, PMTU probe runner |
| RB07 | IMPLEMENTED_NOT_LIVE_VERIFIED | EXTERNALLY_BLOCKED (hardware) | 11 |

For production devices, every runbook additionally needs prerequisites 3–9.

## 9. Next safe execution step

1. The user reviews this worktree diff. Nothing is staged.
2. The orchestrator dispatcher runs gateway batch **B1** (§6) from an agent sandbox against `nmas-public-dev-troubleshooting`,
   with the tree unchanged since the pin recorded in §6. It records the run id, the `source_pin` and `worktree_changed_during_run`.
   If B1 is attested and source-matched, it runs B2–B7.
3. Only after that, it requests approval for items 4–8 of §8 in that order. The fault campaign (§7) waits for Step 0 and explicit
   authorization.
