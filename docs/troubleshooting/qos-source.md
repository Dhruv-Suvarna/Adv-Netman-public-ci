# Directional QoS evidence source (HC19)

Spec: `NMAS_V2_TROUBLESHOOTING_IMPLEMENTATION_SPEC.md` (HC19, UT-038). Source pin: HEAD `cbb9c96` plus the uncommitted working tree (no commit made).

## Pipeline

`RuntimeDeps.qos_source(admission) -> reader` → `collectors.QosCollector` (one bounded `read()` per device per run, STATE_SNAPSHOT, no device command) →
`normalization.normalize_qos_state` (parser `qos.state` / `qos-source-1.0`, document `nmas.troubleshooting.qos-source/1`) → `qos.attachment` observations →
`runtime.map_observations` → `qos.state@<interface>-<direction>` → `runbooks.hc.hc19`. Classification helpers: `adapters/qos.py`. Evidence is stored through the existing
raw/evidence store and capability gates; there is no default reader and no invented platform command. Without `qos_source`, `qos.state` is an explicit NOT_CONFIGURED gap.

## Document contract

`schema`, `device`, `platform`, `os_version` (must equal the admitted device), `source_identity {id, kind ∈ qos-agent|qos-api|gnmi-qos|cli-structured, read_only:true}`,
`capability {status: SUPPORTED, api}`, `scope {vrf}`, `complete`, `provenance {label ∈ SIMULATED|RECORDED|LIVE_GATEWAY_PINNED, collected_at}`, `attachments[]`:
`{interface, direction in|out, policy, complete, vrf?, af?, classes[]}`; class: `{name, order, match {protocol, ports, src[], dst[], dscp[] | any:true}, match_complete,
unsupported?, policer_bps?, counters {boot_id, samples[{at, dropped_pkts, boot_id?}]}}`. Bounds: 128 attachments, 64 classes, 32 samples. Refusals become `qos.state` missing records
(PARSE_FAILED, UNSUPPORTED_OPERATION/PLATFORM, SCOPE_MISMATCH, EMPTY, transport/permission/budget errors).

## Rules

* A pre-computed `matches_flow` / `drop_rate_pps` field is **discarded** by normalization and never read. A legacy record without `direction`, match criteria and counter samples is INCONCLUSIVE.
* Attachment: the shared `_acl_attachment` proof (interface+direction, VRF, address family, completeness) against the production path hop `in_if`/`out_if`. Wrong direction or untraversed interface is recorded as not-traversed, never fault or pass.
* Classification: ordered first match from the class's own criteria against the production tuple (protocol, port, src/dst, DSCP only when the flow states it). Unsupported/incomplete class before a proven match, undecidable field, or no matching class (default treatment unknown) → INCONCLUSIVE.
* Counters: ≥2 strictly ordered samples, same boot id, non-decreasing, window ≥10 s, newest sample ≤120 s from collection. Reset / short / stale / missing → no delta → INCONCLUSIVE.
* FAIL (causal, F-qos-drop) requires all of the above, a positive drop delta in the proven class **and** `flow.health` production loss time-aligned (`counter_flow_correlation`, 120 s window, direction-matched). Drops without that measurement or alignment → INCONCLUSIVE.
* PASS requires ≥1 proven attachment/class with measured zero-delta counters and no unproven attachment; an intent `qos_devices` device on the path with no usable record is an evidence gap.

## Tests

`web/core/tests/test_troubleshooting_qos_source.py`, IDs QOSSRC-001..016 (normalization gates, counter states, classification, engine HC19 positive/negative, runtime with/without source, bounds).
Command: `cd web && DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_qos_source`.

## Limits (exact)

Master validation correction (attempt 8): counter boot IDs must be nonempty strings on every sample (or inherited from the counter document). Missing/invalid epochs yield MISSING with no delta; equality of two absent epochs does not prove continuity. QOSSRC-018 covers null, empty/whitespace, list, object, integer and boolean epochs. Local focused run: 18 tests passed in 34.437 s; simulated only.

* All fixtures are **SIMULATED**; nothing is gateway-recorded; no live verification is claimed. No QoS reader for cEOS 4.36.2F, IOS-XE 17.06.01a or FRR 8.4.4 exists or was qualified; external qualification (real counters, reset behaviour, hierarchical/child policies, shaping queues) is required before production use.
* Hierarchical service-policies, per-queue (rather than per-class) drops and ECMP multi-egress are not modelled; they must be reported as `unsupported`/incomplete by the source (→ INCONCLUSIVE).
## Fixture correction (operator-approved)

* **Change:** `web/core/tests/fixtures/troubleshooting_runbooks/scenarios.py` (`healthy_obs`, formerly line 102) emitted the legacy `qos.state@Eth2` record (`matches_flow`, `drop_rate_pps`, no direction/match/counter samples). It is replaced by the normalized `qos.state@Eth2-out` value (`interface Ethernet2`, `direction out`, `complete`, ordered class `AF31` matching tcp/443 10.1.1.0/24→10.2.2.0/24 plus `class-default`, two same-epoch counter samples 60 s apart with delta 0, SIMULATED provenance). `test_troubleshooting_engine.py` (ut053) now removes `Eth2-out` instead of the vanished `Eth2` key so it still tests an uncollected QoS state. `test_troubleshooting_qos_source.py::eng_obs` also drops the fixture record before installing its own.
* **Rationale:** HC19 correctly refuses to trust `matches_flow`; the old record could no longer prove a healthy outcome. The healthy scenario's intent (flow's class, no drops, EXPECTED_BEHAVIOR_CONFIRMED) is preserved by evidence HC19 can actually prove. No assertion was weakened; no production policy or live evidence was touched. QOSSRC-017 checks the hand-built fixture equals the output of `normalize_qos_state` for the equivalent document.
* **Before:** `core.tests.test_troubleshooting_engine` 28 tests, 4 failures (ut028/029, ut040, ut031, ut032/033: HC19 INCONCLUSIVE on the legacy record).
* **After:** `core.tests.test_troubleshooting_engine` + `core.tests.test_troubleshooting_qos_source` 45 tests OK (engine 28 incl. the four formerly failing; QOSSRC-001..017). One combined run of engine, qos_source, runbooks, runtime, forwarding_source and fib_source (120 tests) had a single failure, QOSSRC-012, which relied on the legacy fixture; it now installs the legacy record explicitly and passes. No remaining failures. Runner: `cd web && DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py test <modules>`; the gateway-attested run was not used here, so nothing is claimed as gateway-recorded.
