# Deterministic engine (Stage 1): Collect → Normalize → Baseline → Correlate → Test

Source: `web/core/services/troubleshooting/{engine,baselines,correlation}.py` and `runbooks/` (RB01–RB07). Persistence goes only through `repository.py` (s1 `Ts*` models, migration 0012); collection goes through the s2 `collectors`/`adapters` via an injected `EvidenceProvider`.

## Stages
| Stage | Code | Output (persisted) |
|---|---|---|
| Collect | `Engine.collect` → `repo.begin_collection_run` (read-only privilege only; out-of-scope devices refused; idempotent by key; run budget) | collection runs, raw evidence |
| Normalize | `Engine.normalize` (s2 `normalization`) | observations with provenance, freshness, quality |
| Baseline | `baselines.py`: INTENT/GOLDEN_CONFIG (NetBox + active golden bundle revision, digest, direct operator URL), LEARNED_HISTORICAL (hour-of-day buckets, robust stats, confidence, staleness), SLO/production contract; approved-change and soak classification; preserve-vs-remediate decision | baseline + drift records |
| Correlate | `correlation.py`: topology/time-aware alarm-storm grouping, NetBox-vs-observed topology diff, intended-vs-observed path (RIB/FIB/return), protocol distinction, scoped expiring exceptions, counter↔flow correlation, change correlation (proximity ≠ blame) | correlation, path, flow-monitor records |
| Test | `Engine.test`: runbook DAG, strategy selection, applicability, adaptive stopping | one test row for every catalogue test, hypotheses |
| Diagnose / dossier | `diagnose`, `exhaustion_dossier` (`ai_handoff/1`), `handoff_gate`, `disposition_for`, `proposed_remediations` | report contracts for s4 |

## Rules enforced (and tested)
* Unsupported, stale, failed or untrusted evidence → INCONCLUSIVE/UNAVAILABLE, never PASS (UT-053).
* Adaptive stop only after a *proven* causal finding (confidence ≥ 0.85, not contradicted by impact tests); skipped tests keep an applicability row with the exact reason (UT-041/043). `EngineConfig.exhaustive` runs everything.
* Production loss despite golden conformity takes priority (UT-030); TCP healthy + ICMP denied is an expected distinction only when intended; unexplained ICMP failure gets no remediation (UT-031); scoped exceptions never hide actual TCP loss and expire/invalidate (UT-032–034).
* Approved soak changes are correlated without blame or rollback (UT-028/029); unapproved change is a lead, not a verdict.
* 100+ alarms collapse to one candidate with all alert ids preserved; redundant link failure does not swallow remote alarms (UT-035/036).
* Restart-safe: recorded tests are reloaded, not repeated. Handoff gate refuses while safe applicable tests are unexamined.
* Engine never requests a non-read-only collection. Remediations are only *proposed* (tiered, with pre/post tests and rollback) and executed by governance (s4), never by the engine.

## Runbooks
Seven versioned runbooks, each a typed hypothesis/test DAG in `runbooks/` with a human document in `docs/troubleshooting/runbooks/`. The DAG table inside each document is generated (`python -m core.services.troubleshooting.runbooks` prints status; `write_dag_blocks()` regenerates) and `check_sync` (UT-054) fails on any drift in ids, versions, titles or required sections.

| Runbook | Domain | Tests |
|---|---|---|
| RB01 | link flapping | 9 |
| RB02 | reachability / host connectivity HC01–HC28 (incl. RIB/FIB/return-path) | 28 |
| RB03 | routing neighborship (OSPF/BGP/IS-IS) | 10 |
| RB04 | STP loops / topology change | 10 |
| RB05 | DNS resolution / zone propagation | 10 |
| RB06 | MTU / PMTUD black hole | 8 |
| RB07 | Layer 1 degradation | 9 |

## Test results (this run)
Command: `cd web && DJANGO_DEBUG=1 /home/student/Scripts/.venv/bin/python manage.py test core.tests.test_troubleshooting_engine core.tests.test_troubleshooting_runbooks` → **Ran 54 tests, OK** (UT-025…046, 048–054 by stable id in test names; the RB02 scenario UT-040/047 is covered by the engine host-connectivity tests: ≥20 distinct applicable tests isolating an injected ACL fault, and recovery clears it).

## Limits (live vs simulated)
* Scenario fixtures (`web/core/tests/fixtures/troubleshooting_runbooks/scenarios.py`) are **SIMULATED** replay bundles (`PROVENANCE="SIMULATED"`); they are not live evidence.
* The gateway-attested run (`aiorch_gw.py test`) fails at the source pin (PermissionError on `monitoring/runtime/influxdb2-engine`), so these results are local, **not gateway-attested**. No fixtures were started and no live fault injection was done.
* NetFlow/IPFIX collection is replay-only (s2). IOS XE gNMI/SNMP/syslog is unsupported (INCOMPLETE_WORK, reported by s2).
* No serial whole-suite run was completed by this subtask.
