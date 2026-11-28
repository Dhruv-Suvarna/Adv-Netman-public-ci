# Observation sessions (`devices/observation_sessions.py`)

A `session_provider(target, address)` for `observation_collector.collect`. It binds a read-only version-observation session to the
existing management policy. It selects nothing itself, approves nothing, reads no credential and opens no connection.

## Use

```python
provider = observation_sessions.session_provider(connection_factory, authorization_ref)
observation_collector.collect(name, source_id=..., sources=..., session_provider=provider, evidence_sink=...)
```

`connection_factory(ConnectionRequest)` is injected (device, platform, address, port, source `LEGACY|PATH`, path_id,
authorization_ref, `expected_host_key`). It must return a connection with `host_key` (the key the peer actually presented),
`host_key_pinned` (True only if that key matched `expected_host_key`/a pin), `close()`, and `send_command(str)` (cEOS) or
`run(argv, timeout) -> (status, output)` (FRR; `management.linux_ssh.LinuxSession` fits). `provider.last_refusal` holds the code
of the last refusal (the collector itself only reports `SESSION_UNAVAILABLE`).

## Policy applied (all existing code)

1. Endpoint = `management.resolve.endpoint(name, purpose=READ)`: the selector's ACTIVE, HEALTHY, APPROVED path (failover and
   hold-down are the selector's business), or the inventory address only when the device has no registered path (authorized
   legacy read-only path). A BLOCKED answer is final: no other address, legacy address, Docker or Containerlab is tried.
2. The requested address must equal the selected endpoint (else `ENDPOINT_NOT_REQUESTED`).
3. `guard.address_problems` refuses loopback, link-local, multicast, unspecified, reserved and Containerlab management networks;
   an approved path must also pass `guard.authorized_target` (approved path and attachment, live device, in-prefix).
4. Platforms: cEOS and Ubuntu/FRR only. Others (e.g. IOS XE, which has `observations.SPECS`) are refused as unsupported.
5. Host key is taken only from the connection. Missing/invalid -> refusal; unpinned -> refusal; if a pin exists (the approved
   path's `expected_host_key`, or inventory `ssh_host_key` for legacy) the presented key must equal it. The connection is closed
   on every refusal.
6. The returned session's `execute` accepts only `observations.SPECS[platform].command`; anything else raises
   `CommandNotPermitted`. FRR is sent as `linux_ssh.frr_show("show version")` argv (`vtysh -c "show version"`). Non-zero FRR exit
   raises; the collector reports `SESSION_FAILED`. After `close()` nothing executes.
7. No `lifecycle.verify_identity`, admission or path approval is called; the collector's `observations.ingest` stays the only writer.

## Existing capability limitations

- **Linux has no management-path support**: `paths.VERIFIED_PLATFORMS` is cEOS only. Ubuntu/FRR is reachable only through the
  LEGACY inventory source (`linux_ssh` requires `username`, `ssh_key_ref` and a pinned `ssh_host_key`); a Linux device that does
  have a path is refused (`PATH_PLATFORM_UNSUPPORTED`), not rerouted.
- **Address constraints**: the collector only accepts a session address that is an inventory-declared candidate (never `auto`,
  never a Containerlab network, e.g. 172.20.20.0/24). An approved path whose endpoint differs from the declared candidates is
  therefore rejected by the collector (`SESSION_ADDRESS_NOT_DECLARED`) even though this provider serves it. Docker bridge and
  Containerlab addresses are always refused, and layer-2 paths must lie inside their NMAS attachment prefix.
- Legacy port is 22 (the resolver returns no inventory `ssh_port`; `linux_ssh.target` reads it separately).
- `last_refusal` is per-provider, not thread-safe; use one provider per collection.

## Missing production prerequisites (not provided here)

- A real `connection_factory` that reads credentials by reference, enforces the host-key pin and reports the presented key. The
  gateway `NetmikoAdapter`/`PeerRunner` reach isolated fixtures, which have no inventory management address and no presented
  host key, so they cannot satisfy the address/provenance policy for the managed lab devices; they were not used here.
- An authorization reference issued by the operator; registered `NMAS_OBSERVATION_SOURCES` key; evidence sink.
- Inventory `ssh_host_key` pins for R3/R4 and (preferably) approved, healthy cEOS paths or pins; the production DB lineage
  (migration level) must be verified separately.

## Evidence

Local tests only (`core.tests.test_observation_sessions`); no live session was opened and none of this is live evidence.
