# JOB-9AA10B4E7CA7 — master validation, attempt 5

Status: **INCOMPLETE_WORK**. Production readiness is not established.

Read the authoritative specification at `/home/student/Scripts/NMAS_V2_TROUBLESHOOTING_IMPLEMENTATION_SPEC.md`, repository policy and prior checkpoints. Inspected current runtime mappings, forwarding evidence, device-scoped baselines, DNS rule semantics, deployment composition, governance tests and documentation. Retained prior passing checks without repeating unchanged worker suites. No credentials, network hosts, production services, fixtures, remote repositories or compatibility-matrix state were accessed or changed. Earlier gateway source-pin PermissionErrors are historical evidence, not a newly reproduced result. No fixture cleanup is required.

## Delivery and ownership

| Stage | Delivery and owner | Remaining acceptance |
|---|---|---|
| Collect / normalize | claude_b: telemetry/flow wire, STP, DNS, route/ARP/ND parsing; claude_a: runtime and flow binding | MAC, independent FIB, ACL/QoS, approved service/path/MTU probes, remaining physical/protocol sources; operational feeds and live parser validation |
| Baseline | claude_b f3-f3_baseline: device-scoped golden/soak with explicit partial/mixed coverage | Historical normal and running/config comparison remain unavailable by default in `DjangoBaselineSources.history/configs` |
| Correlate / test | Existing topology engine and seven DAGs; claude_b f3-f3_dns_rules fixes negative answers, RFC1982 and delegation uncertainty | Qualifying operational host coverage, all scenario fault/recovery and before/after evidence |
| Deployment | claude_b f3-f3_dep_ext: lazy DNS/STP/flow/baseline providers | Site-owned version/lifecycle, transports, flow, baseline, model and safety providers |
| AI | claude_b f1-ai_binding: governed typed iterative continuation | Actual model + authorized tools acceptance; doubles are not live evidence |
| Remediate / verify | claude_b f1-safety_ports: guarded execution, compensation, persisted soak | Configured providers; measured restoration, continuous production monitoring and sustained soak |
| Reports / UI / audit | Existing models, stage tables, API/UI and journal | Source-pinned real full lifecycle report and final acceptance manifest |
| Master correction | Codex: deployment could not supply the new runtime forwarding context; added lazy typed `forwarding_context_provider` and DEP-019/020 | Site must supply authoritative ownership/gateway intent; no invented paths |

## Verification observed in this attempt

Environment: repository root; `DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /home/student/Scripts/.venv-ci/bin/python web/manage.py`.

| Check | Exact observed result |
|---|---|
| `test core.tests.test_troubleshooting_governance --noinput` | **36 passed**, 3.166s; no system-check issues. Both reported UT-077/UT-088 failures are absent in current tree. Existing persisted minute samples and explicit soak reset correctly satisfy verification. No safety rule relaxed. |
| `test core.tests.test_troubleshooting_deployment --noinput` after master fix | **20 passed**, 1.282s; no system-check issues. Includes lazy scoped forwarding context through both consumer factories and failure sanitization. |
| `check` | No issues (0 silenced). |
| `python3 -m py_compile web/core/services/troubleshooting/deployment.py web/core/tests/test_troubleshooting_deployment.py` | Exit 0. |
| `git diff --check` scoped to troubleshooting source, latest worker tests and documentation; repeated for master changed files | Exit 0. |

Worker results retained as local evidence, with overlapping counts not summed: baseline scope+engine+flow runtime 56 pass; forwarding source 20 pass and integration collection/runtime/ports/STP/DNS/flow/runbooks/engine 247 pass; DNS rules/runbooks/source 71 pass; deployment prior 18 pass superseded by the 20 above. These are simulated/injected tests, not gateway-attested operational evidence. Earlier attempts preserve additional local substrate tests and static Tier-3 results. No final serial regression, full applicable Tier-3, IT-01–IT-20 operational acceptance, live model acceptance, measured telemetry overhead, MTTD, MTTI, MTTR, production losslessness or verified remediation result was obtained.

## Exact remaining work

1. Add validated runtime sources for MAC/VLAN, independent FIB, ACL/QoS, approved service/path/MTU probes and remaining physical/routing branches. HC16 is explicitly UNAVAILABLE; do not turn the RIB into FIB evidence.
2. Integrate scoped historical telemetry and configuration snapshots/golden comparisons; prove stale, partial, absent and approved-change handling without claiming conformity from missing data.
3. Supply site-owned operational providers. A lazy dependency contract is not a configured functioning external source. No live model/tool or safety provider acceptance exists.
4. Obtain authorized gateway source pins and fixture evidence without changing security boundaries. Historical gateway test/pin attempts failed on `monitoring/runtime/influxdb2-engine` permission; this run did not attempt a workaround or network contact under the model-provider-only constraint.
5. Master final campaign after engineering: serial regressions, applicable Tier-3, all UT/IT gate inventory, seven pinned scenario bundles, >=20 applicable host tests with genuine isolation, complete generated stage/report journal, before/after service and sustained soak, residual issue assessment and cleanup. Existing mocks or passing modules alone cannot satisfy completion.

Production safety remains fail closed by default; local refusal/approval/loss/rollback/soak tests support code behavior, not a production losslessness guarantee. Existing worktrees, unrelated changes and paused matrix preserved. New engineering follow-ups are proposed separately; final validation/consolidation stays with the master.

## Master source pins

- `web/core/services/troubleshooting/deployment.py`: `3e302ff2beb4392f95198529ce4d6fb620627189c9f1c1d72f8c6cf0e2d9dd48`
- `web/core/tests/test_troubleshooting_deployment.py`: `b778fb3c55e715b97836cf5cb19267b6c9a722ee9dc79d9d59175066c404ffda`
- `docs/troubleshooting/deployment-bindings.md`: `00f607cc24df33156d91865a2d4706ece5b02328e692dec367032c469edc4110`
