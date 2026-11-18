# Observation collector bridge

`core.services.devices.observation_collector.collect()` connects an **injected** authorized, host-key-pinned, read-only session to
`observations.ingest`. It is the producer side of [device-observations.md](device-observations.md); it does not replace it.

## What it does
1. Resolves the device with `resolver.resolve` (authoritative inventory/lifecycle). `READ_ONLY` (R5), `NOT_MANAGED_YET` and unknown
   devices are refused (`TARGET_NOT_MANAGEABLE`, `TARGET_UNKNOWN`). Containerlab-range and `auto` addresses are already dropped by the
   resolver, so such a device yields `NO_MANAGEMENT_PATH`; Docker/runtime paths are never used.
2. Selects the command from `observations.SPECS` for the platform (cEOS `show version | json`, FRR `vtysh -c 'show version'`,
   IOS XE `show version`). Other platforms: `PLATFORM_UNSUPPORTED`. No other command is ever sent.
3. Asks `session_provider(target, address)` for a session on a resolver-declared candidate address and checks the session's own attributes.
4. Executes the one command, retains the raw output via `evidence_sink(record)`, builds the envelope (fresh `secrets.token_hex` nonce,
   capture timestamp, **session-presented** host key, evidence reference), signs it with the source key and calls `ingest`.
5. `ingest` stays the only writer (authentication, parsing, freshness, replay, ordering, identity mismatch). Its codes are returned.

Never done: credential reads, host-key invention, `lifecycle.verify_identity`, admission, deployment/settings changes, config commands.
Observation only *records* identity claims (it can deny, never verify); a different human must still verify identity.

## Site-owned integration prerequisites
* **Source registration**: `NMAS_OBSERVATION_SOURCES = {source_id: {"key_env": "ENV", "platforms": [...]}}` with a key >= 32 bytes in the
  named environment variable; pass `sources=observations.trusted_sources()`. Key custody is site-owned; the bridge only signs with it.
* **Session provider** (e.g. built on the gateway `NetmikoAdapter` / the credentials broker, outside this repo's code): returns an object with
  `execute(command) -> str`, optional `close()`, optional `evidence_refs`, and attributes
  `transport == "SSH"`, `address` (one of the resolver's declared management addresses), `read_only is True`, `authorization_ref`
  (non-empty id of the operator authorization for the read-only session), `host_key_pinned is True` (the session verified the key against a
  pinned value), and `host_key` (the `SHA256:...` key the peer actually presented). The provider must refuse write-capable sessions.
* **Evidence sink**: `evidence_sink(record) -> ref` durably retains `record["output"]` (plus device, command, host key, nonce, timestamp,
  authorization_ref) and returns a non-empty reference (<= 200 chars, no secrets), e.g. a gateway evidence id. Retention failure means
  nothing is submitted (`EVIDENCE_UNAVAILABLE`). Evidence of a later-refused submission stays retained.
* **Clock/ordering**: observations must be within `ingest` max age and newer than the latest per device.
* Live evidence only counts when the session comes from the gateway-recorded, source-pinned path; local tests are not live evidence.

## Refusal codes
Collector: `SOURCE_UNCONFIGURED, TARGET_UNKNOWN, TARGET_NOT_MANAGEABLE, PLATFORM_UNSUPPORTED, NO_MANAGEMENT_PATH, SESSION_UNAVAILABLE,
SESSION_NOT_SSH, SESSION_ADDRESS_NOT_DECLARED, SESSION_NOT_READ_ONLY, SESSION_NOT_AUTHORIZED, HOST_KEY_NOT_PINNED, HOST_KEY_MISSING,
SESSION_FAILED, OUTPUT_EMPTY, EVIDENCE_UNAVAILABLE`; plus every `observations.REFUSALS` code from ingest.

## Tests
`DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python web/manage.py test core.tests.test_observation_collector`
