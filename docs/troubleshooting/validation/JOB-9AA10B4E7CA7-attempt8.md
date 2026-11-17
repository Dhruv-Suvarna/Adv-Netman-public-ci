# JOB-9AA10B4E7CA7 — attempt 8 master validation

Status: **INCOMPLETE_WORK**. No production-readiness or end-to-end completion claim.

Codex read the authoritative specification and repository policy, inspected the current working tree, prior attempt7 checkpoint, new source contracts, runtime mapping, normalization and deployment composition. No production commands, fixture creation, credentials, permission changes, commits, remote writes or compatibility-matrix modifications occurred. Existing unrelated changes were preserved.

## Contributions and architectural stages

| Stage | Delivered / owner | Verification and remaining work |
|---|---|---|
| Collect | claude_b: independent injected FIB and authorized PMTU sources; claude_a: QoS source/fixture integration, earlier config snapshot and ACL collection | FIB/QoS readers have no deployment bindings or qualified operational implementations; PMTU has no operational runner |
| Normalize | claude_b: FIB identity/scope/completeness/restart contract and typed PMTU; claude_a: directional QoS classification/counter contract | Reviewed explicit refusals and missing-data semantics; operational platform samples remain absent |
| Baseline | Earlier configuration/history adapters | Site Influx reader/tag qualification and accepted baseline providers still required |
| Correlate | Independent FIB versus RIB, directional QoS versus time-aligned production loss, PMTU versus PTB visibility | Simulated source tests only; no measured operational restoration |
| Test | Seven executable runbooks, HC01–HC28 catalog; latest QoS fixtures conform to source schema | Seven DAGs validate and match documentation; operational >=20-test rich host and seven fault/recovery bundles absent |
| AI | Existing NMAS-controlled read-only continuation | Operational model/tool investigation with source-pinned evidence not established |
| Governance | Existing risk/approval/dry-run/traffic guard/compensation/soak infrastructure | Operational maintenance, redundancy, MFA, flow and readback providers unaccepted; writes remain disabled |
| Persistence | claude_a: ACL deployment provider and restart-safe scoped history | Prior gap now implemented; real sample cadence/site composition still required |
| Reports/UI | Existing structured stage tables and journal | Complete operational lifecycle report, evidence inventory and final acceptance still required |

## Small defect fixed by Codex

`normalization._qos_counters` accepted samples with absent boot IDs because `{None}` appeared to be a single epoch. It could also raise TypeError for a list/object boot ID. It now requires nonempty string epochs before comparing them; otherwise counter history is MISSING with no delta. Added QOSSRC-018 for seven invalid epoch forms. No source label or simulated evidence was promoted to live.

## Exact checks

| Check | Result |
|---|---|
| `cd web; DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_qos_source --noinput` | 18 tests, 34.437 seconds, all passed; Django system check clean; simulated/injected inputs |
| `PYTHONPATH=web python3 -c 'from core.services.troubleshooting.runbooks import REGISTRY, check_sync; assert all(not r.validate() and not check_sync(r) for r in REGISTRY.values()); print("7 DAGs valid and synchronized")'` | Exit 0, seven DAGs valid and synchronized |
| `git diff --check -- web/core/services/troubleshooting web/core/tests/test_troubleshooting_qos_source.py docs/troubleshooting` | Exit 0; most troubleshooting files are untracked so this is not a substitute for source inspection/tests |
| Gateway `help` | Available CLI inspected; no device/test execution or new live evidence |

Retained worker results, not rerun or summed into a unique total: FIB 14 focused tests plus 177/222 overlapping regressions; QoS 45 engine/source tests and corrected QOSSRC-012; PMTU 24 cases plus reported related regression; ACL history 59 overlapping tests. These are local worker reports, not attestation. Earlier RT003 was fixed before this attempt (attempt7 evidence). Unchanged passing tests were retained. No complete regression/Tier-3 campaign was run this attempt because required engineering remains.

## Evidence limits and continuation

Prior gateway source-pin denial remains `ptd50fa77bffba`: PermissionError on `monitoring/runtime/influxdb2-engine`; FIB worker also reported the same boundary. No retry or permission workaround. No new live fixture evidence, production loss measurement, restoration, MTTD/MTTI/MTTR, overhead or completed soak exists here.

Eligible new engineering: bind FIB/QoS providers through the deployment factory; supply bounded physical/DOM/FEC evidence consumed by RB01/RB07; supply capability-qualified protocol configuration/state evidence consumed by RB03. These extend current implementation rather than redo listed subtasks. Shared runtime/collector/normalization write scopes must be sequential. Unsupported virtual optics must remain explicitly unavailable.

External/operational prerequisites: authorized source-pin recovery; qualified platform readers and probe runner; accepted inventory/version/lifecycle/history/baseline/service-health/safety bindings; scoped isolated fault fixtures and any required change authorization. Final master consolidation must map UT-001–090 and IT-01–20, run required existing regression and applicable Tier-3, produce seven pinned fault/recovery bundles and operational rich-host coverage, demonstrate AI continuation, service-specific before/after verification, guarded compensation/rollback failures, sustained soak, residual assessment and complete linked stage reports. Passing mocks do not close these gates.
