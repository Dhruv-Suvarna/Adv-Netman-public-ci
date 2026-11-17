# JOB-9AA10B4E7CA7 — attempt 9 master validation

Status: **INCOMPLETE_WORK**. Production readiness and end-to-end acceptance are unverified.

Codex read the complete authoritative specification, repository policy, required project documents and attempt8 checkpoint; inspected working-tree status/history, deployment bindings, physical/protocol adapters, runtime composition, normalization gates and FIB restart assertions. Existing changes, services and paused compatibility matrix were preserved. No production/fixture commands, remote writes, credentials, commits or sandbox changes.

## Stage and ownership review

| Stage | Latest contribution | Evidence / remaining prerequisite |
|---|---|---|
| Collect | claude_a f7-dep_readers: lazy read-only FIB/QoS factory bindings; claude_b f7-phy_source: bounded physical collector; claude_a f7-proto_source: bounded protocol collector | deployment.py and adapters/physical.py, protocol.py; physical/protocol shared deployment binding absent; operational readers absent |
| Normalize | Physical identity/scope/DOM/epoch gates; protocol capability/scope/completeness and secret scrubbing | normalization.py; simulated tests only, platform qualification absent |
| Baseline | Retained history/config/soak adapters | Prior checkpoint retained; site history reader/tag and accepted baseline providers still absent |
| Correlate | Physical peer-link and protocol two-end scope | Explicit context and target required; authoritative site composition unaccepted |
| Test | Retained seven executable runbooks and HC01–HC28 | Worker final combined 681 tests: one FIB restart assertion failure; corrected below; no new consolidated 681-pass claim |
| AI | Retained NMAS-governed continuation | Operational evidence-grounded model/tool campaign absent |
| Governance / verification | Retained authorization, traffic guards, rollback and soak infrastructure | Operational provider acceptance, restoration, sustained soak and regression/Tier-3 gates remain unverified |
| Reports / persistence | Retained structured tables, immutable evidence and restart history | Complete source-pinned operational lifecycle report and final acceptance inventory absent |

## Focused correction and observed checks

FIBSRC-014 assumed r1/r2 both completed within the rich six-device shared collection budget. New collection units exhausted it before r2 manifest persistence; restart correctly retried that unfinished device. Scoped this specific restart fixture to r1/r2 via an optional test-helper devices parameter. Kept the assertions that completed devices are not contacted, source calls are not duplicated and r1 has one FIB observation. Runtime budgets and production code unchanged.

| Command / record | Exact result |
|---|---|
| Local manage.py test core.tests.test_troubleshooting_fib_source.RuntimeToHc16Tests.test_FIBSRC_014_source_failure_and_restarted_run_are_bounded_and_idempotent --noinput (DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test; /opt/ai-orchestrator/nmas-env/bin/python) | Before: 1 run, 1 failure, 4.109s; after: 1 run, 1 passed, 2.907s; system check clean; SIMULATED only |
| Gateway same focused test | run ptdbf812013e3e: state error; source pin PermissionError on monitoring/runtime/influxdb2-engine; zero attested test/live results |
| git diff --check -- web/core/tests/test_troubleshooting_fib_source.py | exit 0; file untracked, so actual focused test and source review provide validation |

Retain worker self-verification without redundant reruns: deployment 24 passing; physical 20 passing plus reported related regressions; protocol 24 passing and final combined 681 run with the above one failure. These are overlapping simulated/local results, not gateway evidence or a unique aggregate pass count. Earlier verified unchanged checks remain in attempt8 and earlier checkpoints.

## Exact remaining work

Eligible new engineering: add lazy read-only physical/protocol reader and typed PhysicalContext bindings to both deployment factories, preserving unknown/fail-closed behavior and admission/scope gates. Add focused tests and deployment documentation. This completes shared composition, not operational qualification.

External prerequisites: source-pin access repaired by the gateway owner without widening agent permissions; authoritative inventory/version/lifecycle/topology/baseline/history/service-health providers; qualified platform FIB/QoS/physical/protocol readers and bounded authorized probe runner; approved isolated fault fixtures and safety/maintenance/flow/readback integrations. No actual optics measurements exist on virtual ports.

Final master acceptance remains: UT-001–090 / IT-01–20 traceability, seven source-pinned fault/recovery bundles, >=20 applicable rich-host tests with actual fault isolation, AI continuation, production TCP versus diagnostic protocol distinction, safe remediation and compensation/rollback failure evidence, service-specific before/after verification, sustained soak, complete stage reports, existing regressions and applicable Tier-3 CI, residual-issue assessment and measured overhead/MTTD/MTTI/MTTR where observable. No restoration, zero-loss, soak-complete or production-readiness claim is supported.
