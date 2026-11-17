# NMAS V2 troubleshooting — bounded collectors and normalization (s2)

Code: `web/core/services/troubleshooting/collectors.py`, `normalization.py`, `adapters/`.
Tests: `web/core/tests/test_troubleshooting_collectors.py` (UT-013..UT-024, UT-053, plus `S2_*` adapter/contract/replay checks).
Fixtures: `web/core/tests/fixtures/troubleshooting_collectors/` (`capture_live.py` recorder, `live/*.bundle.json|raw.json` recordings).

Independent of the case ORM: inputs are plain objects and injected transports/sessions/readers; outputs are versioned, JSON-serializable dictionaries.

## Interface for s3 (correlation/testing)

A **collection bundle** is `{"run", "evidence", "observations", "missing"}`:

* `run` — status (e.g. COMPLETE / PARTIAL / REFUSED), budget used, `privileges: "read-only"`, admission verdict, `gateway` provenance (`live`, `gateway_evidence_seqs`, `fixture_id`, `pin_id`) when collected through the gateway.
* `evidence[]` — one per command/API/stream: `evidence_id`, `source_type`, `transport`, `adapter`, `command_or_api`, `device`, `platform`, `os_version`, `collected_at`, `raw_ref.hash` (sha256 of redacted raw text), `parser`, `coverage`, `freshness_max_age_s`, `redaction`, `status`.
* `observations[]` — `observation_id`, `key` (e.g. `interface.oper_state`, `interface.mtu`, `ospf.neighbor_state`), `target` (`device`, `interface`, …), `value`, `unit`, `observed_at`, `collected_at`, `freshness`, `quality` (OK / PARTIAL / UNTRUSTED_PARSE / …), `confidence`, `flags`, `clock`, `parser`, `source`, `raw_hash`.
* `missing[]` — reason code from `normalization.Missing` (PERMISSION_DENIED, UNSUPPORTED_OPERATION, UNSUPPORTED_PLATFORM, COMMAND_NOT_ALLOWED, NOT_ADMITTED, TIMEOUT, BUDGET_EXCEEDED, OUTPUT_TOO_LARGE, TRANSPORT_ERROR, PARSER_UNAVAILABLE, PARSE_FAILED, EMPTY, STALE_SOURCE, UNAUTHORIZED_CAPTURE, NOT_CONFIGURED). A failed or empty read is **always** a missing record, never "no problem"; consumers treat it as UNKNOWN.

Entry points:

| Source | Class / function | Input |
|---|---|---|
| CLI (allowlisted show) | `CliCollector.collect(target, keys, transport, params=)` | `transport.execute(rendered)->str` |
| gNMI Capabilities/Get/Subscribe | `GnmiCollector.subscribe(target, paths, source, ...)` | iterable of notifications (Set refused) |
| SNMP GET/WALK | `SnmpCollector.poll(target, session)` (persistent counter tracker) | `session.walk/get` |
| Syslog | `SyslogCollector.collect(target, lines)` | `(line, received_at)` |
| NetFlow/IPFIX | `FlowCollector.collect(target, records, selector, ...)` | recorded/collector records |
| Capture metadata | `CaptureMetadataCollector` | metadata + authorization; never starts a capture, never carries payload |
| NETCONF | `NetconfCollector.get(target, rpc, filter_key, session)` | only get / get-config |
| Snapshots/intent/golden | `ProviderCollector(source_type).collect(target, provider)` | read-only provider callable |
| Topology telemetry | `adapters.monitoring.TopologyTelemetryCollector` | existing health/topology snapshot |

Common: `Target(device, platform, os_version)`, `Budget`, `check_admission`, `describe_sources()`, `plan_telemetry()` (streaming preferred, polling fallback), `merge_bundles()`. Contract mapping: `adapters.contracts_bridge.to_contract_bundle(bundle, case_id=)` → s1 `collection_bundle/1`, `to_contract_observation`, `to_contract_missing`.

Normalization helpers: `normalize_interfaces`, `normalize_neighbors`, `normalize_gnmi_notification`, `normalize_snmp_poll` (+ `CounterTracker`/`analyze_counter`: wrap, reset, gap, implausible rate), `parse_syslog_line`/`normalize_syslog_events` (dedupe, clock correction), `normalize_flow_records`, `normalize_capture_metadata`, `normalize_snapshot`, `normalize_intent`, `compare_observations`/`mark_untrusted` (parser disagreement), `canonical_view`.

## Safety properties

* Admission first: unverified/withdrawn device or capability not SUPPORTED ⇒ REFUSED run, no transport call.
* Read-only: commands come only from `COMMAND_CATALOG` by key, are re-validated by `validate_read_only`; gNMI Set, SNMP SET, NETCONF edit-config etc. are refused as UNSUPPORTED_OPERATION.
* Budgets: commands, seconds, bytes, records, retries (transient only), min interval, per-command timeout; bounded buffers apply backpressure. Exhaustion yields BUDGET_EXCEEDED for remaining items.
* Parsers are selected by (id, platform, OS version) and fail closed (`ParserSelectionError` ⇒ PARSER_UNAVAILABLE). Plausibility failures (impossible MTU, oper up while admin down, negative counters) mark observations UNTRUSTED_PARSE. Disagreeing parsers/sources downgrade both.
* Secrets are redacted before hashing/storage; units normalised (e.g. bps, bytes); observation time vs collection time is flagged (`OBSERVATION_TIME_IS_COLLECTION_TIME`); device clock skew is estimated and corrected.

## Platform / source support (from `adapters/capabilities.py`; no placeholders)

* cEOS: CLI, gNMI/OpenConfig, SNMP (IF-MIB), syslog, NETCONF supported by existing repo modules; NetFlow/IPFIX **UNSUPPORTED/replay only** (no exporter or collector in the repository).
* Linux/FRR: CLI (vtysh/iproute2) , SNMP, syslog supported; NETCONF not available; NetFlow not configured.
* IOS XE (Catalyst 8000V 17.06.01a): CLI **only through the gateway fixture**; no production health session; gNMI, SNMP, syslog, NETCONF not onboarded in the repo ⇒ NOT attempted/UNSUPPORTED. `show interfaces … transceiver detail` is unsupported on the virtual platform (recorded as UNSUPPORTED).
* Platform independent: capture metadata, config/state snapshots, NetBox intent, golden config, topology telemetry.

## Live vs replay evidence

* Live: `fixtures/.../capture_live.py` runs `CliCollector` over `GatewayTransport` (read-only `show`/vtysh only; gateway `config` kind never used). The recordings in `live/` were captured through the gateway against real cEOS 4.36.2F (`r1`), Catalyst 8000V 17.06.01a (`iosxe`) and FRR 8.4.4 (`peer`); each carries `run.gateway.live=true` and gateway evidence sequence numbers. Recorded `pin_id` is `null` (the source pin could not be created in this run, see below), so the recordings are gateway-recorded but not source-pinned.
* Replay: `S2_ReplayOfRecordedGatewayEvidence` re-parses the recorded raw outputs offline. These tests are **replay**, not live evidence; unit tests with fakes (all other classes) are never live evidence.
* Observations in `linux_peer.bundle.json` were re-normalized from the recorded raw output after the loopback MTU plausibility bound was corrected (raw and evidence unchanged).
* Honest findings in the recordings: FRR ospfd/bgpd not running on the fixture ⇒ EMPTY (not "no neighbors"); cEOS `show ip bgp summary | json` ⇒ DEVICE_NOTE; IOS XE transceiver ⇒ UNSUPPORTED.

## Running

```
cd web && python3 -m unittest core.tests.test_troubleshooting_collectors   # 99 tests, OK (no Django needed)
```

The gateway attested test run (`aiorch_gw.py test clab_dualstack_lab …`) failed in this run with `source pin failed: PermissionError … monitoring/runtime/influxdb2-engine`; the result is therefore **not** gateway-attested. Re-run once the pin can read the tree.

## Open items

* No NetFlow/IPFIX exporter/collector exists in the repository (replay only).
* No gateway-attested test run or source pin (blocked by directory permission above).
* Live recordings were taken in the previous run; no fixtures were started in this run.
