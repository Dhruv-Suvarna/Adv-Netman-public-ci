# JOB-9AA10B4E7CA7 — master validation, attempt 4

Status: **INCOMPLETE_WORK**. No end-to-end or production-readiness claim.

The authoritative implementation specification and repository policy were read. Existing worktrees, unrelated edits, historical artifacts and the paused 396-cell matrix were preserved. No credentials were read, permissions changed, device connections attempted, fixtures started, production changes made, or remote writes performed. The local gateway CLI `help` was inspected; no gateway network operation was attempted under this run's model-provider-only network restriction. Earlier source-pin PermissionErrors remain prior evidence, not a newly reproduced result.

## Delivery and ownership

| Stage | Worker | Inspected delivery | Acceptance still missing |
|---|---|---|---|
| Evidence and reports | claude_a / s1 | Ts models, migration 0012, contracts, repository, report renderer | Attested complete lifecycle/report |
| Collect and normalize | claude_b / s2, f1-flow_wire | Bounded telemetry collectors, versioned parsers, wire decoder | Operational feeds; remaining host sources; live schemas |
| Baseline, correlate, test | claude_b / s3 | Three reference contracts, topology correlation, seven runbook DAGs, HC01–HC28 | Device-scoped golden/soak; historical/config sources; complete runtime diagnostic coverage |
| AI, governance and UI | claude_b / s4, f1-ai_binding, f1-safety_ports | Typed AI continuation, tool authorization, guarded remediation, persistent soak, UI/API | Actual model/tool acceptance; configured safety providers and measured service restoration |
| Runtime | claude_a / f1-runtime, f2-flow_runtime | Inventory admission, provenance, bounded restart-safe orchestration and flow consumption | Deployment providers and operational flow receiver |
| STP | claude_b / f2-stp_source | Version-gated EOS parser, collector/runtime mapping and windowed context | Live schema pin; MAC churn, MST and storm-control sources |
| DNS | claude_b / f2-dns_source | Typed bounded collector, parser, runtime binding, TTL evidence | Real runner; runbook serial arithmetic, negative answers and missing delegation handling |
| Deployment | claude_b / f2-runtime_cfg | Shared fail-closed dependency factory, strict lifecycle/version admission, read-only wrappers | New DNS/STP/flow dependencies not exposed by factory; site providers/configuration |
| Consolidation | Codex master | Corrected two obsolete STP test expectations | Final integrated acceptance remains outstanding |

## Measured local verification

Environment: cwd `web/`; `DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python`.

| Command | Observed result |
|---|---|
| `manage.py test core.tests.test_troubleshooting_runtime core.tests.test_troubleshooting_collectors core.tests.test_troubleshooting_governance --verbosity 1` | 150 tests in 15.210s: 148 passed, 2 failed. Both failures were obsolete STP expectations. All 36 governance tests passed, including the prior checkpoint's persisted-soak corrections. |
| `manage.py test core.tests.test_troubleshooting_runtime.MappingTests.test_RT003_partial_parser_results_are_gaps_beside_parsed_values core.tests.test_troubleshooting_collectors.UT053_UnsupportedNeverInvented.test_UT053_empty_stp_evidence_is_retained_but_yields_no_observation --noinput` | 2 passed in 0.353s; Django check clean. Malformed `{}` is PARSE_FAILED; a valid empty instance map is EMPTY. Both retain evidence and produce no invented observations. |
| `git diff --check -- web/core/tests/test_troubleshooting_runtime.py web/core/tests/test_troubleshooting_collectors.py` | PASS |

The other 148 tests were unchanged after their passing run and were not repeated. Worker checks on unchanged files are retained as local worker evidence: STP/runbooks 44, DNS 24, deployment 13, flow-runtime/wire 39. Counts overlap prior suites and must not be added into a unique consolidated total. Source-pin blocks, previous parallel regression crash and unfinished serial regression remain open. No live acceptance, overhead, MTTD, MTTI, packet-loss or operational MTTR result was measured here.

## Review findings and continuation

1. `DjangoBaselineSources.golden()` selects the latest two GOLDEN bundles globally and the latest RUNNING soak globally. It must select relevant device/bundle/change scope before it can support safe incident conclusions. History/config providers also remain unavailable by default.
2. Runtime route, ARP/ND and MAC catalog commands still have no validated parsers. In particular, FIB must be independently observed, never copied from a RIB. Subsequent work must add evidence sources rather than merely increasing simulated test counts.
3. RB05 DN03 can report success for NXDOMAIN, DN05 uses numeric `max()` instead of RFC 1982 serial ordering, and optional delegation can be absent while the explanation says it is fine. These require executable fixes and negative tests.
4. `deployment._KEYS` and `build_runtime_deps()` do not expose `RuntimeDeps.dns_runner`, `dns_context`, `stp_context`, `flow_input`, or baseline sources. The operational factory needs explicit safe bindings without enabling network writes or reading credentials.
5. After those bounded engineering tasks: finish ACL/QoS, approved service probes, remaining physical/protocol sources and historical/config baseline integration; configure site-owned safety/flow/model providers; obtain source-pinned authorized fixture fault/recovery and cleanup evidence; then master runs final serial regression, applicable Tier-3 and IT-01–IT-20 acceptance/report campaign.

Production safety remains fail closed in default deployment. Local tests cover refusal, approval, production-loss distinction, compensation/recovery and mandatory soak, but do not establish live losslessness or successful production remediation. No fixture cleanup is needed for this run.
