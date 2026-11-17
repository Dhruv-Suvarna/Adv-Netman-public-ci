# JOB-9AA10B4E7CA7 — attempt 7 master validation

Status: **INCOMPLETE_WORK**. Production readiness is not established.

Codex read the complete authoritative specification, repository policy, prior checkpoint and the changed runtime, deployment, normalization, ACL, configuration snapshot and L2-history integration points. Existing unrelated changes and compatibility-matrix artifacts were preserved. No fixtures, production commands, credential reads, permission changes or remote writes were performed.

## Delivered contributions and stage readiness

| Stage | Contribution / owner | Remaining requirement |
|---|---|---|
| Collect / normalize | claude_a: config snapshot ingestion, directional cEOS ACL parsing/join, earlier L2/RIB/ARP/ND/flow sources. claude_b: authorized probes, DNS/STP and deployment providers | Independent FIB, QoS, PMTUD, remaining PHY/protocol operational sources; gateway qualification |
| Baseline | claude_a: running snapshots collected before baseline; claude_b: scoped goldens and history adapters | Operational history reader/tag acceptance and snapshots across other runbooks |
| Correlate / test | Seven executable runbooks; HC18 now checks filtering direction, rule order and counter history | Operational multi-hop >=20 applicable tests, seven fault/recovery bundles |
| Deployment / restart | claude_b: lazy L2 provider and immutable tenant/case/device/VLAN/parser-scoped MAC history | Site cadence and per-case composition; ACL context binding/persistence still absent |
| AI | Existing NMAS-governed read-only continuation | Source-pinned model/tool operational investigation |
| Governance / verification | Existing guarded remediation, compensation and persisted soak | Accepted safety providers, before/after measured service restoration, rollback and sustained soak |
| Reports / UI | Existing structured stage reports, evidence and audit | Complete operational lifecycle report and final acceptance inventory |

Codex found and fixed a small HC18 defect: a traversed ACL with no explicit rule matching the production tuple previously returned PASS, overlooking implicit/default deny. It now remains INCONCLUSIVE; no default counter or causal evidence is invented. Added ACLSRC-017 through the runtime/ORM/engine path, and clarified RB02's actual source limitations.

## Checks and exact results

All commands below ran from the repository (Django commands from `web/`). Local tests use simulated/injected inputs; they are **not live evidence**.

| Check | Result |
|---|---|
| `DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_acl_source core.tests.test_troubleshooting_runbooks core.tests.test_troubleshooting_engine --noinput` | 71 tests in 68.482s: 70 passed, 1 failed. New ACLSRC-017 correctly produced INCONCLUSIVE, but its explanatory-text assertion used `observed_summary` instead of structured `observed`. |
| Same runner, `test core.tests.test_troubleshooting_acl_source.RuntimeToHc18Tests.test_ACLSRC_017_no_explicit_match_cannot_exclude_implicit_deny --noinput` | After correcting only the assertion field: 1 passed in 1.395s. The other 70 passing tests' source files were unchanged; not rerun. |
| `PYTHONPATH=web python3 -c 'from core.services.troubleshooting.runbooks import REGISTRY, check_sync; assert all(not r.validate() and not check_sync(r) for r in REGISTRY.values()); print("7 DAGs valid and documentation synchronized")'` | Exit 0; all seven valid and synchronized. |
| `git diff --check -- web/core/services/troubleshooting web/core/tests/test_troubleshooting_acl_source.py docs/troubleshooting` | Exit 0. |
| `python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test clab_dualstack_lab core.tests.test_troubleshooting_acl_source core.tests.test_troubleshooting_config_snapshot core.tests.test_troubleshooting_l2_history` | Gateway run `ptd50fa77bffba`: state error before tests, source pin PermissionError on `monitoring/runtime/influxdb2-engine`. No attested pass or new live evidence. No workaround attempted. |

An initial package `python -m ...runbooks` invocation failed because no `__main__.py` exists; the explicit import-based validation above succeeded.

Retained worker evidence: config-snapshot.md (10 new tests; 208 and 171 overlapping regression checks reported), l2-history.md (10 new tests; 61 overlapping checks), acl-source.md (16 new tests; 131 overlapping checks). These are worker-reported local results, inspected without repeating unchanged passing suites; do not sum them into a unique acceptance count. The stale RT003 failure was already corrected and verified in attempt6.md.

## Safety, measurements and continuation

Reviewed refusal paths include admission/version/capability checks, bounded running-config collection, explicit missing data, redacted immutable evidence, unknown MAC history on foreign/corrupt evidence, and directional ordered ACL counter requirements. These code/test properties do not establish operational losslessness. No measured production loss, restoration, MTTD/MTTI/MTTR, telemetry overhead or completed soak exists in this attempt.

Eligible new engineering remains: independent forwarding evidence; directional QoS/classification/counter sources; authorized bounded PMTUD evidence; deployment and restart-safe ACL history integration. These are new source/composition scopes, not rework of completed worker tasks. Remaining external prerequisites: successful authorized gateway source pin, accepted site inventory/lifecycle/version/transport/history/service-health/safety providers, owned fault fixtures and required change authorization. Master-owned final consolidation still requires regression, applicable Tier-3, UT/IT inventory, seven source-pinned fault/recovery examples, operational rich-host coverage, real AI continuation and complete report, production-flow before/after comparisons, residual assessment and soak. No completion claim is justified.
