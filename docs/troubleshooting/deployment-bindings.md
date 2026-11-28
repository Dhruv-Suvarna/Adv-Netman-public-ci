# Troubleshooting deployment bindings (read-only RuntimeDeps)

Module: `web/core/services/troubleshooting/deployment.py` · tests: `web/core/tests/test_troubleshooting_deployment.py` (DEP-001..DEP-013).

## The inconsistency this resolves
| consumer | setting | call |
|---|---|---|
| REST view `troubleshooting_views._runtime_deps` | `NMAS_TS_RUNTIME_FACTORY` | `import_string(path)()` |
| `manage.py troubleshooting_ai` (ai_runtime) | `TROUBLESHOOTING_RUNTIME_DEPS` / `--deps` | `getattr(module, attr)()` must be `RuntimeDeps` |

Both are zero-argument factories returning `RuntimeDeps`, so one factory serves both:
`core.services.troubleshooting.deployment.runtime_deps`. `deployment.consistency_problems()` returns `[]` only when both settings point at it.

## Exact configuration (settings, no secrets)
```python
NMAS_TS_RUNTIME_FACTORY = "core.services.troubleshooting.deployment.runtime_deps"
TROUBLESHOOTING_RUNTIME_DEPS = "core.services.troubleshooting.deployment.runtime_deps"
NMAS_TS_DEPLOYMENT = {
    "version_provider":   "site.nmas_providers.os_version",       # REQUIRED  (device_name, inventory_entry) -> "4.36.2F" | None
    "lifecycle_provider": "site.nmas_providers.lifecycle",        # REQUIRED  (device_name) -> {"state": "ACTIVE", "withdrawn": bool, "maintenance": bool} | None
    "inventory":          "site.nmas_providers.inventory",        # optional  () -> {name: {"platform": ...}}  (default: health.inventory.managed_devices)
    "cli_transport_factory": "site.nmas_providers.cli_transport", # (DeviceAdmission) -> object with execute(rendered)[, provenance()]
    "snmp_session_factory":  "site.nmas_providers.snmp_session",  # (DeviceAdmission) -> object with walk(oid)/get(oid)
    "syslog_source":         "site.nmas_providers.syslog_lines",  # (DeviceAdmission) -> iterable of (line, received_at)
    "gnmi_getter_factory":   "site.nmas_providers.gnmi_getter",   # (DeviceAdmission) -> callable(paths)->list
    "gnmi_paths": ("/interfaces/interface/state",),
    "gateway_platforms": [],            # fixture-only: platforms whose CLI is attested through the execution gateway
    "use_health_capability": True,      # CLI capability from core.services.health.live.get_capability
    "syslog_window_s": 3600,
}
```
Management command: `manage.py troubleshooting_ai continue ... [--deps core.services.troubleshooting.deployment.runtime_deps]`.
Programmatic: `deployment.build_runtime_deps(...)` takes the same providers as callables.

## Semantics (identical for API and AI; both go through `runtime.resolve_admission`)
* A device is `VERIFIED` only if: in inventory; platform in {ceos, iosxe, linux}; version provider returns a parseable version; lifecycle provider answers an admitted state and not `withdrawn`. Otherwise it is refused and never contacted: `UNKNOWN`, `UNSUPPORTED_PLATFORM`, `VERSION_UNKNOWN`, `LIFECYCLE_UNKNOWN`, `WITHDRAWN`, or the non-admitted lifecycle state.
* `os_version` embedded in the inventory or sent by clients is ignored. `TsCase.target_states` is overwritten from this resolution.
* Bad `inventory`/`version_provider`/`lifecycle_provider` config refuses every device; a bad transport provider yields no transport (evidence UNAVAILABLE). The factory never raises; problems are in `deps.deployment_problems` (exception class names only).
* Transports are wrapped (`ReadOnlyCli`: execute/provenance/close; `ReadOnlySnmp`: walk/get). Provenance is forwarded verbatim from the transport; nothing is synthesised, so only gateway-style provenance can make evidence live. `RuntimeDeps` has no write field; collection stays bounded by `RuntimeBudget`/`SERVER_CAPS` and collector command validation.
* The factory reads no credentials and contacts no device; providers run only for admitted devices during a run.

## Verification
`cd web && DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_deployment` → 13 tests OK (simulated transports; not live evidence). The gateway `test` op could not be used: source pin failed with PermissionError on `monitoring/runtime/influxdb2-engine`.

## Remaining external prerequisites
1. Site module implementing the providers above: an authoritative OS-version source (NetBox/inventory/gNMI-capability snapshot) and lifecycle source (NetBox status / change system). NMAS has none today, so with the shipped defaults nothing is admitted (fail closed).
2. Transport providers that obtain credentials from the operator's secret store (not in this repo), e.g. `adapters.transports.HealthLiveTransport`, or `GatewayTransport` for fixtures.
3. SNMP/syslog/gNMI feeds as needed; Django settings edit applying the two factory settings plus `NMAS_TS_DEPLOYMENT` (settings.py is outside this subtask's scope).
4. Live validation through gateway-recorded evidence (not performed here).

## Extended bindings (JOB-5826CD8395BC)

Add these optional keys to the same `NMAS_TS_DEPLOYMENT` dictionary. Both
consumer settings above continue to use the shared zero-argument factory.
Values are dotted callable paths (or callables for programmatic use):

| Key | Callable contract | Validation / unavailable behavior |
|---|---|---|
| `dns_runner_factory` | `(DeviceAdmission) -> DnsRunner or None` | Requires `execute(request)`; exposes only execute, optional original provenance, and close. Invalid result becomes absent runner. |
| `dns_context_provider` | `() -> adapters.dns.DnsContext` | Lazy, cached per deps object. Invalid result uses empty context and records a diagnostic; no extra/vantage servers are authorized. |
| `forwarding_context_provider` | `() -> adapters.forwarding.ForwardingContext` | Lazy and cached; supplies authoritative next-hop ownership and gateway scope. Missing/invalid provider invents no ownership or gateways. |
| `stp_context_provider` | `() -> adapters.stp.StpContext` | Lazy, cached per deps object. Invalid result uses empty history/VLAN aliases and records a diagnostic; no historical facts are invented. |
| `flow_input` | `(DeviceAdmission) -> adapters.flow_runtime.FlowRuntimeInput or None` | Requires typed binding, nonempty service selector, wire collect/health methods. Invalid binding becomes absent flow input. |
| `baseline_sources_provider` | `() -> baselines.BaselineSources` | Lazy; requires all six read methods: intent, golden, history, slo, changes, configs. Bad binding/results return explicit unavailable dictionaries, with no fallback to a different source. |

For example (paths are site-owned prerequisites, not shipped implementations):

```python
NMAS_TS_DEPLOYMENT.update({
    "dns_runner_factory": "site.nmas_providers.dns_runner",
    "dns_context_provider": "site.nmas_providers.dns_context",
    "stp_context_provider": "site.nmas_providers.stp_context",
    "flow_input": "site.nmas_providers.flow_input",
    "baseline_sources_provider": "site.nmas_providers.baseline_sources",
})
```

`build_runtime_deps` accepts those identical keyword names. Construction imports
bindings but invokes none of these providers. Provider modules must themselves
have no import-time I/O. Contexts load on first attribute use; baselines load on
first read. Device providers are called by runtime collection after authoritative
admission. Missing optional bindings retain RuntimeDeps defaults: no DNS runner,
no additional DNS context, no STP historical context, no flow input; omitted
baseline binding retains the existing Django baseline integration. Unavailable
sources remain UNKNOWN. Provider exceptions expose only exception class names in
deployment diagnostics, never exception messages. Successful baseline dictionaries,
flow bindings and transport provenance are returned unchanged.

External prerequisites: site-owned read-only DNS execution honoring the supplied
request timeout, operation and authorized-server allowlists; explicitly approved
DNS vantage/extra servers; case-scoped STP history ownership and verified VLAN
aliases; an existing bounded receiver queue supplying FlowWireInput and an
operator-authorized service selector; read-only baseline integrations with source
pointers, freshness, immutable golden revisions and approved-change/soak metadata.
Providers must enforce their own I/O deadlines and bounded response sizes; Python
callables cannot be forcibly time-limited by this factory. Existing collectors
continue to enforce capability refusal, command validation and runtime budgets.
FlowRuntimeInput enforces prefix privacy and passes the runtime record limit to
the existing receiver; wire volume is never promoted to production flow health.
No listeners, sockets, credentials, settings deployment or remote operations were
created or exercised by this change.

Focused verification (source HEAD `cbb9c96`, concurrent uncommitted source overlay;
simulated providers only, no gateway/live evidence):

- `DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python web/manage.py test core.tests.test_troubleshooting_deployment --noinput`
- DEP-001..DEP-018 cover existing admission/collection and the extended bindings.
- Initial run caught a test-only incorrect Target keyword; corrected to
  `lifecycle_state`. Final results recorded below.

INCOMPLETE_WORK outside this subtask: deployment settings/site providers and
live gateway validation remain external prerequisites; this is not overall NMAS
troubleshooting acceptance.

Final focused result: **18 tests passed** (1.503s); Django system check reported
no issues. `python3 -m py_compile web/core/services/troubleshooting/deployment.py web/core/tests/test_troubleshooting_deployment.py`
and `git diff --check -- web/core/services/troubleshooting/deployment.py web/core/tests/test_troubleshooting_deployment.py docs/troubleshooting/deployment-bindings.md`
also exited 0.

SHA-256 source pins for this focused run:

- deployment.py: `5745d0f0f8ee3e415b7a323510ee3b6290a9d53ac9e8fbd4e38346b0c8759b0e`
- test_troubleshooting_deployment.py: `2de20c74f8a4237c6adc5b06d81bf5dbb5623e0580e129d74c591e4ac2ac3c50`

## Master integration correction (attempt 5)

Added `forwarding_context_provider` to both factory paths after route-source integration. DEP-019/020 verify lazy construction, scoped ownership/gateway propagation through both consumers, and sanitized fail-closed provider errors. All 20 deployment tests passed locally in 1.282s with `.venv-ci`; no live claim. Updated source pins:

- `web/core/services/troubleshooting/deployment.py`: `3e302ff2beb4392f95198529ce4d6fb620627189c9f1c1d72f8c6cf0e2d9dd48`
- `web/core/tests/test_troubleshooting_deployment.py`: `b778fb3c55e715b97836cf5cb19267b6c9a722ee9dc79d9d59175066c404ffda`

## FIB and QoS reader bindings (f7-dep_readers)

Two optional `NMAS_TS_DEPLOYMENT` keys populate the existing `RuntimeDeps.fib_source` / `qos_source`:

| Key | Callable contract | Behaviour |
|---|---|---|
| `fib_reader_factory` | `(DeviceAdmission) -> reader or None` | reader needs `read(request) -> nmas.troubleshooting.fib-source/1` document |
| `qos_reader_factory` | `(DeviceAdmission) -> reader or None` | reader needs `read(request) -> nmas.troubleshooting.qos-source/1` document |

```python
NMAS_TS_DEPLOYMENT.update({
    "fib_reader_factory": "site.nmas_providers.fib_reader",
    "qos_reader_factory": "site.nmas_providers.qos_reader",
})
```
`build_runtime_deps(fib_reader_factory=..., qos_reader_factory=...)` takes the same names. Both consumers (`NMAS_TS_RUNTIME_FACTORY`, `TROUBLESHOOTING_RUNTIME_DEPS`) use the shared `runtime_deps` factory, so they receive identical bindings.

* Lazy: construction only imports the dotted path; the factory runs per admitted device during collection.
* Read-only: results are wrapped in `ReadOnlyReader`, exposing only `read` and (verbatim, if present) `provenance`. Documents are returned unchanged; nothing is synthesised.
* Fail closed: a missing path, a raising factory or a result without `read` yields `None` (the runtime then records its existing explicit `route.fib` / `qos.state` gap, UNKNOWN). Diagnostics hold only the exception class name (`fib(R1): RuntimeError`), never the message.
* Absent keys keep the previous behaviour (`fib_source`/`qos_source` = `None`, NOT_CONFIGURED gaps).

Tests: DEP-021..DEP-024 (absent, lazy + read-only, invalid/raising, both consumers). Command: `cd web && DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_deployment --noinput` → 24 tests OK (simulated readers only; not live evidence). Source pins (SHA-256) are not refreshed for this change.

INCOMPLETE_WORK / operational qualification remaining: site-owned read-only FIB and QoS reader implementations (see `fib-source.md`, `qos-source.md`) with their own I/O deadlines and gateway-attested provenance; the Django settings edit; live gateway-recorded qualification on real platforms. None was performed here and no gateway permissions were changed.

## Physical and protocol reader bindings (f8-phyproto_dep)

Three optional `NMAS_TS_DEPLOYMENT` keys (same names for `build_runtime_deps(...)`) populate `RuntimeDeps.phy_source`, `proto_source`, `phy_context`:

| Key | Callable contract | Behaviour |
|---|---|---|
| `phy_reader_factory` | `(DeviceAdmission) -> reader or None`; reader needs `read(request) -> nmas.troubleshooting.physical-source/1` | → `phy_source`; see `physical-source.md` |
| `proto_reader_factory` | `(DeviceAdmission) -> reader or None`; reader needs `read(request) -> nmas.troubleshooting.protocol-source/1` | → `proto_source`; see `protocol-source.md` |
| `phy_context_provider` | `() -> adapters.physical.PhysicalContext` | → `phy_context` via `LazyContext`; resolved on first attribute use, cached per deps object |

```python
NMAS_TS_DEPLOYMENT.update({
    "phy_reader_factory": "site.nmas_providers.phy_reader",
    "proto_reader_factory": "site.nmas_providers.proto_reader",
    "phy_context_provider": "site.nmas_providers.phy_context",
})
```
* Lazy: construction only imports dotted paths; reader factories run per admitted device during collection, so admission and target scope are unchanged.
* Read-only: readers are wrapped in `ReadOnlyReader` (`read`, and `provenance` verbatim if present); documents are returned unchanged.
* Fail closed: unloadable path, raising factory or result without `read` → `None` (existing explicit NOT_CONFIGURED gap, UNKNOWN). Invalid/raising context provider → empty `PhysicalContext` (no peer inferred). Diagnostics keep only exception class names (`phy(R1): RuntimeError`, `phy_context: RuntimeError`).
* Absent keys keep `None` defaults. `runtime_deps` (both consumer settings) and `build_runtime_deps` behave identically.

Tests: DEP-025..DEP-028 (`PhysProtoBindingTests`). Command: `cd web && DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_deployment --noinput` → 28 tests OK (simulated readers; not live evidence). Source pins not refreshed.

INCOMPLETE_WORK / operational prerequisites: site-owned read-only physical and protocol reader implementations (gNMI/SNMP/structured CLI, device-side key fingerprinting, own I/O deadlines, gateway-attested provenance), an authoritative link-map `PhysicalContext` provider, the Django settings edit, and live gateway-recorded qualification on cEOS 4.36.2F / IOS-XE 17.06 / FRR 8.4.4. None performed here.

## Authoritative NMAS providers in the public repository (port continuation, 2026-11-10)

`core.services.troubleshooting.adapters.nmas_providers` binds two of the REQUIRED admission providers to sources of truth that already
exist in `Adv-Netman-public-ci` (the legacy archive had none of them):

```python
NMAS_TS_DEPLOYMENT = {
    "inventory":          "core.services.troubleshooting.adapters.nmas_providers.inventory",   # resolver.engine_devices()
    "lifecycle_provider": "core.services.troubleshooting.adapters.nmas_providers.lifecycle",   # ManagedDevice + MaintenanceRecord
    # "version_provider": NOT AVAILABLE -- see below; every device therefore stays VERSION_UNKNOWN (refused, never probed)
}
```

| Registry answer (ManagedDevice + Maintenance Mode) | `lifecycle()` state | Admission |
|---|---|---|
| No row for the name | `UNREGISTERED` | refused: adopt the device first (existing *Adopt Existing Device* flow) |
| Only decommissioned / withdrawn rows | `DECOMMISSIONED`, withdrawn | refused (`WITHDRAWN`) |
| Production admission `WITHDRAWN` | `WITHDRAWN`, withdrawn | refused |
| Lifecycle not `IN_SERVICE` (ISOLATED, COMMISSIONING, DECOMMISSION_PENDING, FAILED, ...) | that state | refused |
| Production admission `NOT_ADMITTED` | `NOT_ADMITTED` | refused |
| Identity `UNVERIFIED` / `PENDING_VERIFICATION` / `MISMATCH` | `IDENTITY_<state>` | refused (spec §1.3: do not probe unverified devices) |
| `IN_SERVICE`, admitted or legacy pre-existing, identity `VERIFIED` | `IN_SERVICE` | admitted for READ-ONLY collection once a version is known |
| Any of the above with an active Maintenance Mode record (ENTERING / ACTIVE / RESTORING / RESTORE_FAILED) | maintenance = true | flagged `MAINTENANCE_MODE`; read-only diagnosis continues, remediation gates see it |

**Version provider: external prerequisite.** NMAS persists no authoritative per-device OS version. The infrastructure collector and the
management probes already run `show version | json` but keep only uptime/memory and the serial; the capability ledger holds the
*qualified* image per platform, not what a device runs. Using either would invent a version. The smallest authorized change is to
persist the observed `version` field where identity verification already reads `show version` (device-lifecycle subsystem, needs its
own review and migration), then point `version_provider` at it. Until then, admission is fail-closed for every device.

Tests: `core.tests.test_troubleshooting_nmas_providers` (NP01-NP09): real `adopt_existing`, registry-guarded state changes,
maintenance records, settings binding through the shared factory, and a guard that no device session class is constructed.

## Operational readiness report (`manage.py troubleshooting_readiness`)

Module: `web/core/services/troubleshooting/readiness.py` · command: `web/core/management/commands/troubleshooting_readiness.py` ·
tests: `web/core/tests/test_troubleshooting_readiness.py` (RDY01..RDY13).

```
manage.py troubleshooting_readiness [--json] [--device R1 ...] [--with-nmas-providers]
```

* Read-only: database and file reads only. It contacts no device, NetBox, gateway or credential store, and never adopts, verifies or
  admits a device (RDY02, RDY05, RDY12).
* `admission` is the unmodified `DeploymentAdmission.resolve` verdict from `deployment.runtime_deps`, the same factory a run uses.
* `DeploymentAdmission` stops at the first refusal. The report also evaluates every gate independently, so `blockers` lists **all** of
  them, each with an owner and the exact corrective action. `consistent` is true when the runtime verdict is `VERIFIED` exactly when
  no gate found a blocker.
* `warnings` are not admission gates. For example, `NO_MANAGEMENT_ADDRESS` means a transport could not reach the device.
* `--with-nmas-providers` evaluates the documented binding (NMAS `inventory` and `lifecycle`, with no version provider) without
  configuring it.
* Runbook readiness: `NOT_READY` (missing bindings, or no admitted device), `READY_PENDING_FIXTURE_APPROVAL`, or
  `EXTERNALLY_BLOCKED_HARDWARE` (RB07).

## Authoritative bindings and per-device qualification (JOB-E78CED9B29DE / s2)

`adapters/nmas_providers.py` now provides all three admission providers; `RECOMMENDED_BINDING` is the exact (reviewed-deploy, not yet applied) settings dict:

```python
NMAS_TS_DEPLOYMENT = {
    "inventory":          "core.services.troubleshooting.adapters.nmas_providers.inventory",
    "lifecycle_provider": "core.services.troubleshooting.adapters.nmas_providers.lifecycle",
    "version_provider":   "core.services.troubleshooting.adapters.nmas_providers.version",
}
```

* `version` lazily calls `core.services.devices.observations.observed_version(device)` (persisted authenticated read-only observation). Module missing, exception, `None` or unparseable value -> `None` -> `VERSION_UNKNOWN`. Image tags, inventory `os_version` and client values are never used.
* Management paths: production order is `DIRECT_OOB` > `VLAN_ADJACENT_SWITCH` (by adjacent-switch identity) > `ROUTED_VRF` (`core.services.management.paths`). The Containerlab management network, `auto` addresses and docker-exec are not production paths (`devices.resolver` refuses them; the matrix lists them as prohibited).
* `qualification.py` + `manage.py troubleshooting_readiness --matrix [--with-nmas-providers]` emit the device-by-device matrix (MANAGED / EXCLUDED / HOST / EXTERNAL_PEER / REGISTRY_ONLY), exact gates, version/platform collector qualification (baselines cEOS 4.36.2F, FRR 8.4.4; non-baseline versions flagged; eos-json-1.0 parsers gated to EOS 4.28 <= v < 5.0), declared-vs-observed version, and missing evidence. Operational state is always `UNKNOWN` unless an authoritative record says otherwise. Nothing is deployed or approved.

Evidence classes: tests `core.tests.test_troubleshooting_qualification` (QL01-QL09) are **local tests only**; no fixture and no production evidence was produced. See `validation/JOB-E78CED9B29DE-device-readiness.md`.
