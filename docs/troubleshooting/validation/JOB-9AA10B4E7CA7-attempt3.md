# JOB-9AA10B4E7CA7 — master validation, attempt 3

Status: **INCOMPLETE_WORK**. Production readiness and end-to-end acceptance are unverified.

The master validator read all 614 lines of the authoritative specification and repository policy. Existing unrelated edits, worktrees and paused compatibility work were preserved. No credentials were read, permissions changed, devices contacted directly, fixtures started, remote writes made, or production operations performed.

## Ownership and implemented stages

| Stage | Owner | Delivery inspected | Remaining requirement |
|---|---|---|---|
| Persistent evidence and reports | claude_a, s1 | Ts* ORM models, migration 0012, contracts/repository/reporting | Attested integrated lifecycle/report evidence |
| Collection and normalization | claude_b, s2 | Bounded collectors, version/quality-gated cEOS/IOS XE/FRR parsers and adapters | Many CLI catalog entries have no parser; IOS XE telemetry not verified |
| Baseline, correlation, test | claude_b, s3 | Baselines, topology correlation, seven executable runbooks, HC01–HC28 | Historical/config sources unwired; golden and running-soak selection currently global, not scoped by requested devices |
| AI/governance/UI | claude_b, s4 | AI tool contracts, governed execution, verification, authenticated UI/API | Real provider and operational source dependencies unconfigured |
| Runtime integration | claude_a, f1-runtime | Authoritative inventory admission, canonical provenance mapping, budgets, restart/idempotent endpoint | No default transport; inventory lacks parser version; RB04/RB05 lack validated runtime sources |
| Flow wire input | claude_b, f1-flow_wire | NetFlow v9/IPFIX templates, sequence/sampling/expiry/bounds/privacy, FlowCollector adapter | No operational receiver/runtime consumer or live exporter evidence; capability remains unsupported |
| Managed AI binding | claude_b, f1-ai_binding | Typed provider loop, runtime diagnostic runner, checkpoint and CLI | Provider doubles only; no configured real-model acceptance |
| Safety bindings and soak | claude_b, f1-safety_ports | Guarded service ports, persisted monitoring ledger, monitor command | Real flow/redundancy/maintenance/MFA/readback providers absent; writes disabled |
| Consolidation correction | Codex master | Updated two outdated governance tests to persist samples and explicitly reset degraded soak | Focused corrected tests pass; no weakening of production code |

All above files live under `web/core/services/troubleshooting/`, associated `web/core/tests/test_troubleshooting_*`, and `docs/troubleshooting/`. Previous checkpoint remains at `JOB-9AA10B4E7CA7.md`; its pending requirements are superseded only where this table supplies implementation, not live acceptance.

## Exact observed validation

| Command / evidence | Result |
|---|---|
| Gateway `test clab_dualstack_lab core.tests.test_troubleshooting_governance` | Gateway run `pt949668133773`, state `error`: source pin failed with PermissionError on `/home/student/Scripts/clab_dualstack_lab/monitoring/runtime/influxdb2-engine`. Tests did not run. No permissions workaround attempted. |
| Local NMAS venv, `manage.py test core.tests.test_troubleshooting_governance --noinput` | 36 run in 2.989 s: 34 passed, UT-077 and UT-088 failed. Log `/home/student/Scripts/nmas-job-9aa-attempt3-governance.log`. These failures reproduce the worker report. |
| After correction: same venv, `manage.py test core.tests.test_troubleshooting_governance.VerificationTests.test_ut077_soak_prevents_premature_success_then_completes core.tests.test_troubleshooting_governance.VerificationTests.test_ut088_metrics_exclude_unresolved_from_mttr --noinput` | 2 passed in 0.690 s; Django system check clean. Log `/home/student/Scripts/nmas-job-9aa-attempt3-soak-fix.log`. |
| `git diff --check -- web/core/tests/test_troubleshooting_governance.py` | PASS |

Environment for local Django commands: `DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python`, cwd `web/`. Worker passing checks on unchanged code were retained without repetition: evidence 29 (80 with overlapping architecture checks), collectors 99, engine/runbooks 54, s4 77, runtime/views 33, flow-wire+collectors 128, AI-runtime+AI 33, runtime-ports 27. These overlapping counts are not a consolidated suite total. No new live evidence, overhead benchmark, MTTD, MTTI, or production MTTR measurement is claimed. The 40-minute MTTR in UT-088 is a simulated timestamp assertion.

The UT-077 correction records degradation, an operator-authorized reset with retained history, then 31 minute-spaced clean samples over a 30-minute window. UT-088 records the mandatory clean ledger before resolution and continues excluding unresolved cases from MTTR. Default refusal of writes, missing monitoring, unsafe drains and incomplete soak is retained. Production safety is supported by local negative tests, not live losslessness evidence.

## Unfinished acceptance inventory

1. Validated STP and DNS collectors/parsers and canonical runtime bindings; remaining host evidence paths (RIB versus independently observed FIB, ARP/ND/MAC/ACL/QoS/production probes) cannot be inferred from the catalog alone.
2. Deployment-ready read-only runtime factory using existing authorized transports, authoritative version/lifecycle data and consistent settings for API and AI continuation. Defaults currently return unavailable evidence.
3. Connect wire-flow input to the runtime and persistent evidence; an actual receiver/exporter remains deployment-owned and requires capability evidence. Do not mistake sampled byte counts for measured packet loss.
4. Device/change-scoped golden and soak lookup, historical baseline/config-drift source integration with freshness, exact provenance and honest missing-data behavior.
5. Configure real model, flow-health, maintenance, alternate-path/capacity, MFA, config-readback and approved change/rollback dependencies before governed operational remediation. No production deployment or enabling writes is authorized here.
6. Gateway owner must repair source pinning to exclude protected runtime/secret directories safely. Agent access must not be widened. Then obtain source-pinned isolated live evidence, actual additional AI diagnostics, authorized fault/recovery evidence and cleanup.
7. Master final consolidation: complete serial regression and applicable Tier-3; IT-01–IT-20 manifest with explicit pass/fail/unavailable, seven scenario bundles, real generated full lifecycle structured report, before/after flow and sustained-soak evidence, audit completeness and measured operational results. Prior parallel crash and interrupted serial suite do not satisfy regression acceptance. Defer final broad campaign until remaining engineering lands; do not repeat unchanged worker suites routinely.

No whole-task completion is asserted. Continued eligible engineering is requested through the orchestrator checkpoint; external evidence requirements remain explicit.
