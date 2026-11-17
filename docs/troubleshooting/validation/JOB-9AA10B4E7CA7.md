# JOB-9AA10B4E7CA7 — master validation, attempt 2

**Status: INCOMPLETE_WORK. Not operationally ready for production deployment.**

The complete authoritative specification at `/home/student/Scripts/NMAS_V2_TROUBLESHOOTING_IMPLEMENTATION_SPEC.md` was located and read. Existing working-tree changes, migration 0011, and repository policy were inspected and preserved. No staging, commits, remote writes, production changes, credential reads, permission changes, or fixtures were performed by this validator. No live continuity claim is made.

## Delivered substrate and ownership

| Owner | Deliverable | Evidence / limitation |
|---|---|---|
| claude_a, s1 | Ts* persistent case/evidence/journal models, migration 0012, contracts, repository and structured Markdown/HTML reports | Worker reported 29 focused tests; 80 including overlapping architecture/contracts/admin checks. Local only. |
| claude_b, s2 | Bounded collectors, vendor normalizers, cEOS/IOS XE/FRR adapters and collection documentation | Worker reported 99 focused tests. Existing live replay recordings have null source pins. NetFlow/IPFIX is replay input only. |
| claude_b, s3 | Baselines, topology correlation, deterministic engine, seven runbooks and HC01–HC28 | Worker reported 54 tests, including simulated fault/recovery scenarios. UT-047 lacks its own stable named test. |
| claude_b, s4 | AI tool governance, remediation/verification modules, operator API/templates and guides | Worker reported 77 tests. Default ports refuse remediation; real integration dependencies remain unwired. |
| Codex, master validator | Fixed default AI catalog discovery; blocked verification without service checks, supporting evidence, or post-change samples for previously monitored flows; removed synthetic PEM scanner false positive | 91 focused tests observed passing after edits, plus Tier-3 static gates. |

Worker results are retained, not independently re-run when unchanged. Counts overlap with master reruns and must not be added to imply a consolidated acceptance run.

## Stage-by-stage inspection

| Stage | Implemented files | Assessment |
|---|---|---|
| Collect | `collectors.py`, `adapters/{transports,monitoring,capabilities,contracts_bridge}.py` | CLI, gNMI, SNMP, syslog, capture metadata, NETCONF and provider interfaces exist. Actual source-to-engine runtime planner is missing. |
| Normalize | `normalization.py`, `adapters/contracts_bridge.py` | Typed quality/time/unit normalization exists. Bridge renders target as `device=...,interface=...`; repository scope expects device names and engine uses subject-qualified keys. Production integration cannot be inferred from schema-only bridge tests. Bridge raw envelope also differs from ingest's text/pointer/parser envelope. |
| Baseline | `baselines.py` | Django golden/soak/NetBox seams exist. History and config comparisons explicitly return unavailable without overrides. Golden/soak selection needs device/change scope review before real operation. |
| Correlate | `correlation.py`, `engine.py` | Intended/observed paths, protocol-aware flow policy, alarm storms and scoped exceptions covered by simulated tests. No attested production-flow end-to-end evidence. |
| Test | `runbooks/`, `engine.py` | All seven runbooks registered; 28 host tests. Engine currently consumes provided observations; application intake does not initiate it. |
| AI | `ai.py` | Default catalog import pointed at nonexistent module; corrected to actual runbook registry with regression for every runbook and unknown IDs. Callable agent/diagnostic runner still need managed model-provider/runtime bindings. |
| Remediation | `governance.py` | Default UnconfiguredExecutor fails closed; ChangeEngineExecutor adapter exists. Production device/flow/redundancy/MFA/readback/rollback bindings still need implementation. No device writes tested here. |
| Verify | `verification.py` | Empty or evidence-free successful checks and missing postchange baseline-flow samples now fail. Sustained soak/recovery evidence and complete runtime flow sampling still need integration; elapsed time alone is insufficient proof of a clean soak. |
| Document/UI | `reporting.py`, troubleshooting views/URLs/templates, docs | Structured stages and exports exist. Actual runtime-generated full lifecycle example and final IT-01–IT-20 acceptance inventory remain outstanding. |

## Observed commands and results

| Check | Result |
|---|---|
| `DJANGO_DEBUG=1 /home/student/Scripts/.venv/bin/python web/manage.py test core.tests.test_troubleshooting_ai --noinput` | **26 passed**, 4.283 s. Includes new real-registry lookup regression. |
| `DJANGO_DEBUG=1 /home/student/Scripts/.venv/bin/python web/manage.py test core.tests.test_troubleshooting_governance core.tests.test_troubleshooting_evidence --noinput` | **65 passed**, 9.617 s. Includes two added verification negatives. Log: `/home/student/Scripts/nmas-job-9aa-fixes-tests.log`. |
| Serial `manage.py test core --parallel 1 --noinput` | **Incomplete**: 1494 discovered, interrupted with SIGINT after implementation changed; 79 ran/passed in 130.845 s. Its final `OK` describes only those 79, not the full suite. Log: `/home/student/Scripts/nmas-job-9aa-validator-regression.log`. |
| Tier-3 working-tree selection `tier3.py --base HEAD --working-tree --plan-only --format json` | Plan generated at `/home/student/Scripts/nmas-job-9aa-tier3-plan.json`. Full applicable Tier-3 execution outstanding. |
| Tier-3 `execute_plan` restricted to `static.hygiene`, `static.syntax` | **Both PASS** after fixes: 27056 added lines / 130 files scanned; 475 files parsed (396 Python, 45 Jinja, 15 JSON, 12 YAML, 7 shell). `/home/student/Scripts/nmas-job-9aa-tier3-static.json`. Initial hygiene FAIL was synthetic redaction-test PEM; test preserves its runtime value through concatenation. |
| `git diff --check` for five edited Python files | PASS. |
| Gateway `pin clab_dualstack_lab` | **FAIL**: `PermissionError: [Errno 13] Permission denied: '/home/student/Scripts/clab_dualstack_lab/monitoring/runtime/influxdb2-engine'`. No attempt to change permissions or traverse secrets. Absolute worktree argument was rejected; documented basename invocation reproduced actual blocker. |

## Remaining acceptance requirements

1. Runtime orchestration from authenticated intake/job to collector planning, canonical device/subject mapping, persisted engine/report, restart and admission checks.
2. Wire-format NetFlow/IPFIX ingestion with template lifecycle, exporter identity, budgets/backpressure, sampling uncertainty and production-flow integration; no exporter deployment to production is authorized.
3. Managed AI model-provider and read-only diagnostic runner binding with source-scoped tool results, budgets, continuation and actual additional diagnostics.
4. Existing-service bindings for device lifecycle, historical monitoring, config drift, named production flows, verified alternate paths, approvals/step-up, guarded change execution/readback/compensation and sustained soak/recovery. Keep default writes disabled.
5. Full regression and applicable Tier-3, explicit UT/IT acceptance manifest, real generated all-stage case report, seven scenario evidence packs, measured overhead/MTTD/MTTI/MTTR where applicable.
6. Source-pinned gateway evidence: gateway-side pinning must safely handle excluded secret/runtime directories without widening agent access. Then authorized isolated live checks and cleanup, including production protocol distinctions and relevant recovery/fault scenarios. Existing unpinned replay cannot satisfy this gate.
7. IOS XE telemetry/NETCONF availability and virtual transceiver limitations must remain explicit until capability-proven. No matrix cell, live service or existing worktree was intentionally changed.

Engineering continuation can progress on items 1–4 without resolving gateway pinning. Final consolidation and live acceptance remain master-owned.
