# Forwarding evidence source: RIB routes and ARP/ND neighbours (HC10 / HC15 / HC24)

Subtask f3-f3_route_src of JOB-9AA10B4E7CA7. Source HEAD cbb9c96 plus the existing uncommitted troubleshooting implementation. Changes are confined to the six assigned files. No device was contacted, and no production, gateway policy, topology, compatibility ledger, credential or remote repository was touched or read.

## Path

`CliCollector` (existing read-only catalogue) -> `normalization.normalize_routes` / `normalize_neighbor_table` -> `runtime.map_observations` -> engine keys read by RB02:

| Engine key (subject) | Value contract | Reader |
|---|---|---|
| `route.rib@<prefix>` | `present, prefix, matched_prefix, exact, vrf, family, protocol, next_hop, next_hops[{address,interface}], next_hop_device, next_hop_devices, ecmp, connected, table_complete, fib_evidence=false` | HC15 (forward, dst prefix), HC24 (return, src prefix) |
| `arp.entry@<address>` | `state, mac, dup_macs, interface, vrf, family, state_reported, entries` | HC10 (gateway of the source host) |
| `route.fib@<prefix>` | **never a value**: explicit `UNSUPPORTED_OPERATION` gap | HC16 (stays UNAVAILABLE) |

Commands (catalogue `CommandSpec.parser_id` now set): cEOS `show ip route | json`, `show ipv6 route | json`, `show ip arp | json`, `show ipv6 neighbors | json` (one new read-only catalogue entry, `ipv6_neighbors`); Linux `ip -j -4|-6 route show`, `ip -j neigh show`. IOS XE `ip_route`/`arp` remain evidence-only (no parser). Linux/FRR `vtysh show ip route json` is not in the catalogue and was not added.

Parsers (`route.table`, `neighbor.table`): cEOS `eos-json-1.0` gated to EOS 4.28 <= v < 5.0; Linux `linux-ip-route-json-1.0` / `linux-ip-neigh-json-1.0` gated to >= 5.0 (the same gate as the existing Linux address parser; FRR 8.4.4 passes). Unknown, unsupported or wrong-platform versions raise `PARSER_UNAVAILABLE` **before** the device is contacted. Malformed JSON gives `PARSE_FAILED`, an empty table `EMPTY`.

## Semantics (fail closed)

- **FIB is never synthesised.** The `ip_route`/`route4`/`ipv6_route`/`route6` commands now fill `route.rib` only (previously the map claimed they also filled `route.fib`). Linux `ip route` is labelled `table_kind: kernel-routing-table`, not independent FIB evidence. EOS `allRoutesProgrammed*` flags come from the same RIB command and are kept only as a note. A subject-bound `route.fib@<prefix>` gap is emitted per asked prefix.
- **Route lookup** is longest covering prefix in the flow's VRF and family; lowest preference/metric wins; equal best routes are ECMP; blackhole/unreachable/prohibit routes yield `present=false` (`discard`). A route is reported absent only from a **complete** table (no truncation at `FWD_MAX_ROUTES`=5000, no partial parse). A table of another VRF/family, or an incomplete one, gives an `EMPTY` gap and the runbook cannot PASS or FAIL.
- **Next-hop device** comes only from authoritative intent in `ForwardingContext` (`address_owners`, `link_peers`); never guessed. ECMP or any unresolved hop leaves `next_hop_device` null, so HC15/HC24 cannot invent a divergence.
- **Neighbours**: states come from the device. An absent entry is a cache fact (gap, not FAIL). `INCOMPLETE`/`FAILED` fail HC10. `dup_macs` lists other distinct MACs for the same address. cEOS ARP reports no state: a learned entry is shown as `STALE` with `state_reported=false` and flag `ARP_STATE_NOT_REPORTED` (resolved, liveness unconfirmed; HC10 accepts STALE). `PERMANENT`/`NOARP`, and a usable state without a MAC, are `UNTRUSTED` so HC10 returns INCONCLUSIVE rather than a false FAIL.
- **IPv6 / dual stack**: IPv6 tables are read only when the flow prefixes or caller-supplied gateways are IPv6 (`wanted_families`); IPv4 flows send no IPv6 command.
- **Bounds / provenance**: `FWD_MAX_ROUTES`, `FWD_MAX_NEIGHBORS` (4096), existing collector budgets, admission, output limits and read-only validation apply. Raw hash, parser id/version, transport gateway dict and `live` flag are copied verbatim to the evidence row by the existing runtime. Per-case `ForwardingContext` (`RuntimeDeps.forwarding_context`) is optional; without it routes are still judged but `next_hop_device` is null.
- Non-default VRFs are not read (no new `vrf all` command): such queries are an explicit gap.

## Provenance of validation: SIMULATED

All 20 tests (`FWSRC-001..020`, `web/core/tests/test_troubleshooting_forwarding_source.py`) use hand-written documents in the cEOS and iproute2 JSON shapes, injected through a fake transport whose gateway dict is `live=false`. **Nothing here is gateway-recorded or live-verified**; `adapters.forwarding.describe_source()` labels SIMULATED/RECORDED and yields LIVE_GATEWAY_PINNED only for boolean `gateway.live=true` (a label, not an attestation verifier). Coverage: v4/v6 parsing, VRF/AF, ECMP/discard, longest prefix, truncation/partial/version/platform refusal, no-contact on unsupported version, collector -> runtime -> RB02 for healthy, missing route, wrong next hop, unresolved/absent/duplicate/permanent neighbour, IPv6, asymmetric/missing return route, multi-hop, recovery, FIB gap, VRF gap.

Commands (repository root, local `.venv-ci`, development settings):

- `DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_forwarding_source --verbosity 1`: **20 tests PASS**.
- Same runner over `test_troubleshooting_{collectors,runtime,runtime_ports,stp_source,dns_source,flow_runtime,runbooks,engine}` plus the new module excluded: **247 tests PASS** (no regression).
- `python3 -m py_compile` on the touched modules: PASS.

## INCOMPLETE_WORK

- No cEOS 4.36.2F / FRR 8.4.4 output was captured through the gateway, so the JSON schemas are unverified against real devices (notably EOS `vias` fields for recursive/ECMP routes and the `ipV6Neighbors` field set). Pin gateway-recorded outputs, then relabel RECORDED/LIVE.
- FIB: no distinct validated source exists (HC16 remains UNAVAILABLE by design). Candidates: platform FIB/hardware programming commands, gNMI AFT.
- IOS XE route/ARP parsers, non-default VRF collection, FRR `vtysh` RIB (to separate zebra RIB from kernel table) and persistence of the intent-derived `ForwardingContext` by the deployment layer are not implemented.
- HC10 cannot distinguish "gateway never ARPed" from "entry aged out"; it correctly yields a gap.

## Source pins (SHA-256)

```text
d46fd3f8ed6d49c47074e2a41f43cc9520a4153af477580020d7404306be997f web/core/services/troubleshooting/normalization.py
939873501f8111e9ed13fd608d6b41351fec5befb8d0da764d719d0f588933d8 web/core/services/troubleshooting/collectors.py
32292a06504f447936ecb41397e6895fc2c2d67974e683ad49816c26eba2c4eb web/core/services/troubleshooting/runtime.py
8f248d1ca7c3ec8c69648ce96d29cbd619bdc15a749fd97faee802c21f3a7e94 web/core/services/troubleshooting/adapters/forwarding.py
99844bb78c02b93af53a3f44e7f32e9a192d4ba6888fbc84c8752116dd593e93 web/core/tests/test_troubleshooting_forwarding_source.py
```
