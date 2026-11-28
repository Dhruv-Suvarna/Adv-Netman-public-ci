# Authenticated device observations and NOS version persistence

Code: `web/core/services/devices/observations.py`; model `DeviceVersionObservation` (migration `0038_device_observations`).

## Flow
1. A trusted collector (authorized read-only, host-key-pinned session) runs the platform's version command and submits an
   envelope: `source_id, nonce, command, output, host_key, evidence_ref, observed_at, signature`.
   `signature = HMAC-SHA256(source key, canonical{device, source_id, nonce, command, observed_at(UTC), host_key, evidence_ref, sha256(output)})`
   (`observations.sign`). Keys come from `settings.NMAS_OBSERVATION_SOURCES = {source_id: {"key_env": "ENV", "platforms": [...]}}`;
   the key (>= 32 bytes) is read from the environment at use time, never stored. No registration = untrusted.
2. `observations.ingest(device_name, envelope)` authenticates, refuses excluded/unknown/terminal devices (READ_ONLY scope such as R5),
   unsupported platforms or non-allowlisted commands, stale (> 1 h), future-dated (> 60 s), replayed (source nonce, also
   DB-unique) and out-of-order observations, parses the version with the platform parser, and records the identity claims as an
   `AUTHENTICATED_SESSION` `DeviceObservation` via `lifecycle.record_observation` (claims can only deny). A contradicting
   identity is refused (`IDENTITY_MISMATCH`) and the device moves to MISMATCH as already designed.
3. Supported parsers: `arista_ceos` (`show version | json`), `cisco_c8000v_iosxe` (`show version`), `ubuntu_frr`
   (`vtysh -c 'show version'`). Image defaults, inventory `os_version` and capability-ledger versions are never used.

## Independent approval
Ingest never verifies identity or admits a device. `lifecycle.verify_identity` remains a separate human action and now refuses
(`ACTOR_NOT_AUTHORIZED`, reason `NOT_INDEPENDENT`) when the actor is the observation's recorder or a `source:` / `system:` principal.

## Consumer API (database reads only, no side effects)
* `observations.observed_version(device_name) -> str | None` - non-None only when the latest observation is fresh
  (`NMAS_VERSION_MAX_AGE_SECONDS`, default 86400), the device identity is VERIFIED, the observation's host key equals the verified one,
  the platform is unchanged and no later trusted identity mismatch exists.
* `observations.current(device_name) -> dict` - `version, usable, reason, fresh, age_seconds, observed_at, source_id, host_key,
  raw_digest, evidence_ref, platform, identity_observation`; `reason` in `NO_DEVICE, NO_OBSERVATION, STALE, IDENTITY_NOT_VERIFIED,
  HOST_KEY_CHANGED, PLATFORM_CHANGED, IDENTITY_CONTRADICTED`.
* `observations.reverify(row, raw_output)` re-checks digest, signature and parsed version against retained raw evidence.

## Remaining blockers
* A collector that holds the read-only sessions and a registered `NMAS_OBSERVATION_SOURCES` key must be provisioned (deploy/secret
  decision; not done here). Until then `observed_version` is None everywhere.
* Devices must be adopted (`adopt_existing`) and then verified by an independent operator before versions become usable.
* Migration 0038 is not applied to production; tests here are local, not gateway-attested live evidence.

Fresh independently signed observations may retain identical raw output: unchanged NOS output is not a replay. Source nonce uniqueness and signed timestamp ordering prevent envelope replay.
