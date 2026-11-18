# Routing-protocol evidence source (RB03 NB01 / NB04 / NB05 / NB06 / NB09)

Status: implemented against an **injected, read-only reader**; verified with **SIMULATED** fixtures only (`web/core/tests/test_troubleshooting_protocol_source.py`, IDs PROTOSRC-001..024).
No live/gateway-recorded claim is made. Source pins were not refreshed by this subtask. Preceding physical-source edits are untouched.

## Flow
`RuntimeDeps.proto_source(info) -> reader` → `collectors.ProtocolCollector` (STATE_SNAPSHOT, no device command, no default reader) →
`normalization.normalize_protocol_state` (parser `proto.state` / `protocol-source-1.0`) → observations → `runtime.map_observations` (generic path; `_subject` now falls back to `target.protocol`) →
engine keys consumed unchanged by RB03: `capability.protocol@<protocol>` (NB01), `protocol.config@<protocol>` (NB04/05/06, read on **both** ends), `routing.neighbor.detail@<peer device>` (NB09).
Request building: `adapters/protocol.py` (`requests_for_device`, `served_keys`, `gap_reason`).

## Scope (explicit, never inferred)
Taken from the case `service_intent.target`: `protocol ∈ {ospf, ospfv3, bgp, isis, rip, ripng}`, `af ∈ {ipv4, ipv6, evpn}` (default ipv4), `vrf` (default `default`), `device`, `neighbor_device`,
`interface` + `neighbor_interface` (required except BGP). One read per admitted device:
* target device → `{capability, config, neighbor}`, `interface`, `peer = neighbor_device`;
* neighbor device (must be in `affected_scope.devices` and admitted) → `{capability, config}`, `interface = neighbor_interface`, `peer = device`;
* any other device, or an incomplete/unsupported scope → no read; the keys are explicit gaps (`SCOPE_MISMATCH`, or `UNSUPPORTED_OPERATION` for e.g. EIGRP, which has no field contract). No source → `NOT_CONFIGURED`.

## Reader contract
`reader.read({protocol, af, vrf, interface, peer, include, device, platform, os_version}) -> document` (optional `reader.provenance()` → gateway dict stored on the run). Document `nmas.troubleshooting.protocol-source/1`:
* `schema`, `device`, `platform`, `os_version` – must equal the admitted device (platform canonicalised; version exact when inventory states one).
* `source_identity {id, kind ∈ gnmi-protocol|snmp-protocol|proto-agent|cli-structured, read_only: true}`.
* `capability {status: SUPPORTED, api, protocols: {<proto>: [<af>...]}}` – the requested protocol/AF must be listed, otherwise `capability.protocol` is emitted with `supported=false` (NB01 → UNAVAILABLE) and config/neighbor become `UNSUPPORTED_OPERATION` gaps.
* `scope {protocol, af, vrf, interface, peer}` – must equal the request exactly (else `SCOPE_MISMATCH` for every key).
* `provenance {label ∈ SIMULATED|RECORDED|LIVE_GATEWAY_PINNED, collected_at}`; older than 300 s at run time → `STALE_SOURCE`; >30 s in the future → `PARSE_FAILED`.
* `config_complete: true`, `config {collected_at, ...}` – required comparable fields per protocol: OSPF/OSPFv3 `area, network_type, stub(bool), timers{hello,dead}`; BGP `local_as, neighbor_remote_as, neighbor_vrf, neighbor_afs[]`
  (timers optional); IS-IS `level, timers{hello,hold}`; RIP/RIPng `version`; all: `auth {configured, key_id, algorithm, fingerprint}`.
* `neighbor {peer, state, since_s, last_error, observed_at, complete: true}` – `peer` must equal the request peer; state mapped to the runbook names (`Full`, `Established`, `ExStart`, `2-Way`, ...); unknown state → `PARSE_FAILED`.

## Fail-closed rules (all tested)
* Missing/failed read, denial, transport error, byte/command budget, bad identity/platform/version/capability/scope/provenance → explicit missing records bound to **engine key and subject**; never a value.
* **No inferred match:** RB03 compares `A.get(k) != B.get(k)`, so two absent fields would look equal. Any absent/malformed required field, or `config_complete` not exactly `true`, marks the **whole** `protocol.config` observation `UNTRUSTED_PARSE`
  (value retained with `uncertain` for audit; the engine refuses it, NB04/05/06 become INCONCLUSIVE). Sections age independently (config / neighbor `collected_at`/`observed_at` > 300 s → `STALE_SOURCE` gap).
* **Secrets:** `scrub_protocol_secrets` replaces secret-bearing keys (secret, password, authentication-key, key-string, community, token, md5, hmac, psk, private ...) with `<redacted>` and passes free text through `redact_text`
  **before** the document is stored as raw evidence or parsed; observations are flagged `SECRETS_REDACTED`. Authentication is compared only via `configured`, `key_id`, `algorithm` and a hash-shaped `fingerprint` (32–128 hex chars, optional `algo:` prefix);
  a non-hash-shaped fingerprint (possibly the secret) is refused (`UNTRUSTED_PARSE`, never echoed); `configured=true` without `key_id` is untrusted; `configured=false` discards key metadata.
* Neighbor block naming another peer is `SCOPE_MISMATCH`, never re-attributed. Restart: no collector state; each run re-reads and re-derives.

## Verification
`cd web && DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_protocol_source --noinput` → 24 tests OK (SIMULATED fixtures, in-process readers).

## INCOMPLETE_WORK / operational gaps
* No production reader: site implementations (gNMI OpenConfig `/network-instances/.../protocols`, SNMP OSPF/BGP4 MIBs, or structured CLI) and `deployment.py` wiring for `proto_source` are not done (outside this scope).
* No live qualification on cEOS 4.36.2F / IOS-XE 17.06 / FRR 8.4.4; the reader must compute key fingerprints on the device side or in a secret-aware component – NMAS never receives key material by design (and scrubs it if it does).
* `protocol.interface` (passive), `bgp.ttl`, `bfd.session` (NB08) and RIB/FIB (NB10) are not supplied by this source. EIGRP and other protocols stay unavailable. Source pins in compatibility documents were not refreshed.
* The reader is responsible for platform vocabulary normalisation (network type, level, AF names); NMAS compares normalised strings exactly.
