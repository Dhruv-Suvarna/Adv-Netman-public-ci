# Independent forwarding-table (FIB) source — HC16

Scope: `adapters/forwarding.py`, `collectors.FibCollector`, `normalization.normalize_fib_state`, `runtime.RuntimeDeps.fib_source`.
Tests: `web/core/tests/test_troubleshooting_fib_source.py` (FIBSRC-001 … FIBSRC-014).
Source pin: repository HEAD cbb9c96 plus the uncommitted working tree (no commit made by this subtask).

## Contract

`RuntimeDeps.fib_source(device_admission) -> reader | None`. The reader is an injected, read-only object with `read(request) -> dict` (and optional
`provenance()` returning the gateway dictionary). `request = {vrf, family, prefixes, device, platform, os_version}` — one bounded read per (VRF, address family)
per device pass, reusing `forwarding.route_queries` (the flow's `dst_prefix` / `src_prefix` in the flow VRF). No device command is issued by this path.

The reader returns `nmas.troubleshooting.fib-source/1`:

| field | requirement |
|---|---|
| `source_identity` | `id`, `kind` ∈ `normalization.FIB_SOURCE_KINDS`, `authoritative: true`, `derived_from_rib: false` |
| `device`, `platform`, `os_version` | equal to the admitted device (else `UNSUPPORTED_PLATFORM`) |
| `capability` | `{status: "SUPPORTED", api: "<read-only API>"}` (else `UNSUPPORTED_OPERATION`) |
| `scope` | `vrf`, `family`, `coverage` = `FULL_TABLE` or `PREFIX_LOOKUP` (+ `queried`); must equal the asked scope (else `SCOPE_MISMATCH`) |
| `complete`, `restart` | source-reported completeness and an explicit `restart.converging` boolean |
| `entries[]` | `prefix`, boolean `programmed`, `action`, `next_hops[{address, interface, resolved, adjacency}]` |
| `provenance` | `label` ∈ SIMULATED / RECORDED / LIVE_GATEWAY_PINNED, `collected_at` |

## Semantics (UNKNOWN is the default)

* A RIB, Linux `ip route` / kernel routing table, or any source with `derived_from_rib != false`, non-authoritative, or a non-forwarding `kind` is **refused**
  (`UNSUPPORTED_OPERATION`). `route.table` is never promoted to `route.fib`.
* Normalized to observation `route.fib.table`; the runtime maps it to `route.fib@<prefix>` = `{installed, next_hop, resolved, matched_prefix, coverage, source, provenance, fib_evidence: true}`,
  which HC16 compares with `route.rib` via `correlation.rib_fib_gap` (FIB_INSTALL_DISCREPANCY, NEXT_HOP_MISMATCH, UNRESOLVED_ADJACENCY).
* **Installed**: longest covering programmed entry (complete table) or exact entry (incomplete table).
* **Missing** (`installed:false`, `NO_FIB_ENTRY`) only from a *complete* table of the right VRF/AF (FULL_TABLE, or PREFIX_LOOKUP listing the query).
* **Partial / truncated / rejected entries / converging / restart state not reported**: quality PARTIAL; absence is UNKNOWN (explicit `route.fib@<prefix>` gap), a non-exact covering entry is not trusted.
* **Unsupported / wrong scope / wrong device or version / bad provenance / transport, permission, size failures**: explicit missing records bound to each asked `route.fib@<prefix>`.
* **Restart**: a device that is re-converging yields UNKNOWN, never FAIL; a rerun with the same `run_key` reuses finished devices (no re-read, no duplicate observations).
* No source configured → the pre-existing `UNSUPPORTED_OPERATION … never derived from the RIB` gap, unchanged.
* The collector uses source type `STATE_SNAPSHOT`, so the deployment capability probe must report `STATE_SNAPSHOT` SUPPORTED for the platform. The default
  `RuntimeBudget.max_collection_runs` was raised 40 → 60 because each device now adds one bounded evidence unit.

## Provenance honesty

All fixtures in the test file are **SIMULATED**; nothing is gateway-recorded, so no live verification is claimed. `describe_source()` still labels
LIVE_GATEWAY_PINNED only when the injected gateway dict has boolean `live: true`; the document's own `provenance.label` is carried but is not an attestation.

## External qualification still required (NOT done here)

1. Name the real source per platform (e.g. cEOS forwarding-agent/gNMI FIB view, IOS XE CEF, FRR + kernel FIB via an authoritative agent) and its minimum versions; supply a
   read-only adapter that emits `fib-source/1` without issuing configuration commands.
2. Record per-platform fixtures through the execution gateway (templates `ceos_pair`, `ceos_peer`, `iosxe_peer`) and pin them; verify installed, missing, ECMP, unresolved-adjacency and post-restart cases.
3. Confirm completeness/convergence semantics (what the platform reports while hardware programming is in progress) and the maximum table size / read cost.
4. Verify the deployment capability probe and authorization for the source, plus redaction of next-hop data.

## Test evidence

Run (unattested, local): `cd web && DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_fib_source` → 14 tests OK.
Regression: forwarding_source, runtime, engine, collectors, runbooks, evidence, acl/l2/dns/probe/stp sources, flow_runtime, runtime_ports, baseline_history → OK (222 tests in the second group).
The gateway `test clab_dualstack_lab …` attempt failed at source pinning (`Permission denied: monitoring/runtime/influxdb2-engine`), so no gateway-attested run exists for this change.
