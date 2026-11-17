# JOB-9AA10B4E7CA7 — attempt 10 final master validation

Status: **INCOMPLETE_WORK**. Work-cycle limit reached. No production-readiness, live restoration, losslessness or global acceptance claim.

Codex inspected the authoritative specification, repository policy, project requirements/history/status, attempt9 checkpoint, shared deployment factory, physical request adapter, runtime wiring and new binding tests. Existing worktrees, paused compatibility matrix and unrelated changes were preserved. No credentials, network changes, fixtures, permission changes, commits or remote writes.

## Stage review and ownership

| Stage | Delivered and owner | Evidence / readiness |
|---|---|---|
| Collect | claude_b f8-phyproto_dep: optional physical/protocol reader factories and physical context provider | Both shared factory paths bind existing RuntimeDeps fields lazily; site readers/settings remain absent |
| Normalize | Retained claude_b physical and claude_a protocol source contracts | Identity, scope, completeness and quality gates retained; operational qualification remains absent |
| Baseline | Retained config snapshot, persistent ACL/L2 history, golden/soak integration | Accepted site history/baseline and revision provenance still required |
| Correlate | Lazy typed PhysicalContext supplies peer scope | New DEP029 exercises peer request selection through collector; topology/provider acceptance still required |
| Test | Retained seven runbooks and HC01–HC28 | Unchanged worker checks retained; no complete new suite or live campaign claimed |
| AI | Retained NMAS-controlled continuation | Operational evidence-grounded AI/tool campaign unverified |
| Governance / verification | Retained approval, traffic guard, compensation and soak implementation | Operational safety integrations, restoration, sustained soak and Tier-3/regression acceptance unverified |
| Reports / persistence | Retained structured stage tables, immutable evidence and journals | Final operational lifecycle report and complete acceptance mapping absent |

## Focused validation

Worker claude_b reports deployment DEP025–028 plus unchanged tests: 28 passed. Retained without redundant rerun. Earlier checks in attempt9 and attempt8 remain applicable; overlapping counts are not added together.

Codex added DEP029 to test_troubleshooting_deployment.py. It composes the new factories with existing simulated physical/protocol readers, resolves a lazy peer context, verifies Ethernet7 is requested for the peer, and passes both wrapped readers through their actual collectors. It asserts normalized physical/neighbor observations and preserves simulated provenance.

Command (web directory): `DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_deployment.PhysProtoBindingTests.test_DEP029_bound_readers_reach_collectors_with_lazy_peer_scope --noinput`.

Observed: **1 test passed, 0.005s**, Django system check clean. SIMULATED inputs only.

Gateway command: `python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test clab_dualstack_lab core.tests.test_troubleshooting_deployment.PhysProtoBindingTests`.

Observed run **ptd226f8fb5671**, state **error**, source pin PermissionError on `monitoring/runtime/influxdb2-engine`. No attested tests executed. No permission workaround attempted. This infrastructure error does not erase local passing evidence or satisfy live acceptance.

`git diff --check -- web/core/tests/test_troubleshooting_deployment.py docs/troubleshooting` exited 0; untracked files are not covered by this check, so actual source review and focused execution are the primary evidence.

## Exact remaining requirements

1. Gateway owner must repair source-pin access within authorized boundaries; then obtain a successful attested pin/test record. Current source-pin failure prevents attested campaign evidence.
2. Implement and accept authoritative site inventory/version/lifecycle/topology, baseline/history/config/soak, production-flow and service-health providers; qualify bounded FIB/QoS/physical/protocol readers, DNS and probe runners; configure both consumers with reviewed settings. Existing injected contracts alone do not deliver operational collection. Physical optics require real hardware evidence or an explicit unsupported limitation.
3. With accepted providers and approved isolated fault fixtures, produce seven source-pinned fault/recovery bundles, rich-host >=20 applicable diagnostics with genuine isolation, protocol/AF qualification, topology-aware storm correlation, AI continued tool investigation, TCP-vs-diagnostic distinction and scoped anomaly evidence.
4. Demonstrate governed dry-run/approval, active-flow safeguards, safe alternate-path refusal, abort/compensation and rollback failure/recovery, restart/audit integrity, service-specific before/after restoration, collateral regressions, sustained soak and residual assessment. Never inject production faults for coverage.
5. Consolidate UT001–090 / IT01–20 traceability, complete stage tables and evidence links, exact suite outcomes, existing regression and applicable Tier-3 results, platform limitations, operational overhead and observable MTTD/MTTI/MTTR. Final acceptance depends on the operational campaign; no complete aggregate pass count is established here.

Shared physical/protocol deployment composition from checkpoint22 is now covered by f8-phyproto_dep plus DEP029. Operational provider acceptance, gateway-attested campaign and final consolidated acceptance remain unfinished. No further work cycle requested.
