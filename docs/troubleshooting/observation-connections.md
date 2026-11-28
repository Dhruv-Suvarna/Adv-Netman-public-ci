# Observation connections (broker-backed `connection_factory`)

`web/core/services/devices/observation_connections.py` supplies the `connection_factory(request)` consumed by
`observation_sessions.session_provider` (see `observation-sessions.md`, `observation-collector.md`).

## Wiring

```python
from core.services.devices import observation_collector, observation_connections, observation_sessions
provider = observation_sessions.session_provider(observation_connections.connection_factory(), authorization_ref)
observation_collector.collect(name, source_id=..., sources=..., session_provider=provider, evidence_sink=...)
```

No credential is read by this module: `runtime://` references are resolved inside the existing helpers
(`nsot_live.get_live_target` / `probes.auth_material` / `linux_ssh.target` + `modules.device_credentials`) at connect time.

## Behaviour

Before anything is contacted the factory requires a read-only request with an authorization ref and a valid `SHA256:` pin
(`PIN_MISSING` otherwise), then **re-resolves** device, platform, scope and `management.resolve.endpoint` and compares
source, address, port and path id with the request (`ENDPOINT_CHANGED`, `PATH_BLOCKED`, `ENDPOINT_PROHIBITED`, `TARGET_CHANGED`;
never a fallback route).

| Platform | Route | Mechanism |
|---|---|---|
| cEOS | approved PATH | `ssh_transport.active_path` re-read (pin must equal the request pin, else `PIN_CHANGED`), `connect_eos` with source/interface-bound socket and Paramiko pin policy before authentication |
| cEOS | LEGACY | `connect_eos` with the inventory pin -> `commissioning.transport.connect_pinned` (key-only; no key enrolled -> `KEY_AUTH_UNAVAILABLE`, no connection) |
| FRR | LEGACY only | `linux_ssh.target` (address/port/pin compared) + `linux_ssh.connect_found`; argv execution only; PATH -> `ROUTE_UNSUPPORTED` |

Host-key provenance: after connecting, the fingerprint is read back from the live transport
(`remote_conn_pre.get_transport().get_remote_server_key()` for Netmiko; same for Paramiko in `LinuxSession`), compared with the pin,
and only then exposed as `host_key` with `host_key_pinned=True`. Unreadable -> `HOST_KEY_UNOBSERVED`, different ->
`HOST_KEY_MISMATCH`; the connection is closed in both cases. The cEOS wrapper (`EosObservationConnection`) permits exactly
the platform's version command.

`linux_ssh` change: `LinuxSession(client, username, host_key="")` gained `host_key` / `host_key_pinned` (False unless observed);
new `connect_found(found, timeout, observe_host_key=True)`; `connect()` delegates with `observe_host_key=False`, so executor
behaviour is unchanged.

Failures are `ObservationConnectionError(code)` (also `factory.last_error`); no address, key, credential or output is included.
The provider reports them as `CONNECTION_FAILED`; the collector then returns `SESSION_UNAVAILABLE`.

## Verification

`core.tests.test_observation_connections` (mocked, no network): factory -> provider -> collector for cEOS legacy/path and FRR,
endpoint/port/source/path changes, missing/changed/mismatched pins, unobservable key, auth failure, cleanup, command restriction.
These are local tests, not live evidence.

## Remaining prerequisites (not done here)

1. Inventory `ssh_host_key` pins (legacy) or `ManagementPath.expected_host_key` must exist and come from an independent source;
   without one the factory refuses. This module never creates or approves pins.
2. Legacy cEOS devices need an enrolled `ssh_key_ref` (the pinned transport is key-only); FRR needs `username` + `ssh_key_ref`.
3. The provider's legacy FRR/cEOS endpoint port is `Endpoint.port` (22); an inventory `ssh_port` other than 22 is refused for FRR
   (`ENDPOINT_CHANGED`) until the resolver reports it.
4. A caller must inject the authorization reference, a signing source and an evidence sink; live use needs gateway-recorded
   sessions and is outside this subtask.
