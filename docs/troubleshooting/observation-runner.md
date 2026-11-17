# Observation runner: `device_observe`, observation authorizations and the local evidence sink

`device_observe` is an explicit, operator-invoked capture of one read-only NOS version observation. It composes the existing governed
pieces:
- `observations.trusted_sources()`
- `observation_authorizations.admit()`
- `observation_connections.connection_factory()`
- `observation_sessions.session_provider()`
- `observation_collector.collect()`

Its own addition is a durable local evidence sink (`web/core/services/devices/observation_evidence.py`).

## 1. Authorization: an enforceable record

`--authorization-ref` used to be a free-form label. It must now name an `ObservationAuthorization` (migration
`0039_observation_authorizations`) granted through `manage.py observation_authorize`.

| Property | Enforcement (`core.services.devices.observation_authorizations`) |
|---|---|
| Device scope | Explicit device list; every device must be in the resolver's WRITABLE scope when granted **and** again when used. R5, read-only and excluded devices give `DEVICE_EXCLUDED`. At most 16 devices. |
| Command scope | Command ids from `OBSERVATION_COMMAND_IDS` (`nos-version`, which maps to `SPECS[platform].command`). Anything else gives `COMMAND_UNKNOWN` / `COMMAND_NOT_AUTHORIZED`. |
| Expiry | `not_before` + TTL (60 s to 24 h). Checked before any session opens **and** again right before ingest (`pre_ingest_guard`), so expiry or revocation in between still refuses. |
| Budget | `max_observations` (default: one per device; at most 4 per device). Every reservation counts, failures included. Reservations take a `select_for_update` lock. |
| Separation of duties | The approver is an active NMAS account with APPROVE and is not the requester. The operator is an active account with EXECUTE and is not the approver. |
| Integrity | `scope_digest` = SHA-256 over scope, window, approver, requester and ticket. Observation execution requires the complete reference `OBSAUTH-NNNNNN#sha256=<digest>` and it must match. A bare id is accepted only by administrative show/revoke operations. A changed row gives `AUTHORIZATION_TAMPERED`. Rows cannot be deleted, and after creation the only permitted change is one revocation. |
| Audit | One `ObservationAuthorizationUse` row per attempt (`RESERVED` → `ACCEPTED`/`REFUSED`) with outcome codes, nonce, evidence reference and the linked `DeviceVersionObservation`. |

```
# approver (NMAS Approver) grants; the requester is a different person
manage.py observation_authorize grant --approver <approver> --requested-by <requester> --ticket CHG-1234 \
    --devices R6,R7,R8,S5 --commands nos-version --ttl-minutes 60 --reason "baseline NOS version for troubleshooting admission"
#  -> OBSAUTH-000001#sha256=<64 hex>
manage.py observation_authorize show OBSAUTH-000001#sha256=<64 hex> [--json]
manage.py observation_authorize revoke OBSAUTH-000001 --actor <approver> --reason "..."
```

## 2. Invocation

```
manage.py device_observe --device R6 --source nmas-observer-v1 --authorization-ref 'OBSAUTH-000001#sha256=<64 hex>' \
    --operator <executor> --evidence-dir /home/student/Scripts/<approved-evidence-dir>
```

All five options are required. The order of checks is:
1. source and key
2. evidence sink
3. resolver target and WRITABLE scope
4. platform spec
5. authorization admission (reserves a use)
6. connection
7. collection
8. evidence retention
9. authorization re-check
10. ingest

Every refusal before step 6 contacts nothing. The use row is always finished, including on `COLLECTOR_ERROR`.

The signing key is never an argument. It is read from the environment variable named in
`settings.NMAS_OBSERVATION_SOURCES[<source>]["key_env"]`. `config/settings.py` registers exactly one source, and only when
`NMAS_OBSERVATION_SOURCE_ID` is set:
`{<id>: {"key_env": "NMAS_OBSERVATION_KEY", "platforms": ["arista_ceos", "ubuntu_frr"]}}`.

`trusted_sources()` treats the source as untrusted in any of these cases:
- the entry carries extra fields, including a literal `key`
- the variable is outside the `NMAS_OBSERVATION_KEY[_SUFFIX]` namespace
- the key fails `observations.key_is_strong` (shorter than 32 characters, or fewer than 10 distinct characters; a `secrets.token_hex(32)` key fails with probability below 10⁻¹¹)
- the key equals `SECRET_KEY`

System checks `nmas.E010`–`nmas.E014`/`W013` report these conditions by name only, never by value.

### Where the key lives

The website does not need the key, so it is **not** placed in `/etc/nmas/nmas-web.env` or in any settings file. It lives in a
dedicated root-owned file, `/etc/nmas/nmas-observation.env` (0600), that only the observation runner loads:

```
sudo systemd-run --uid=student --gid=student --wait --collect --pipe --unit=nmas-observe-$(date -u +%s) \
    -p WorkingDirectory=/home/student/Scripts/clab_dualstack_lab-deploy/web \
    -p EnvironmentFile=/etc/nmas/nmas-web.env -p EnvironmentFile=/etc/nmas/nmas-observation.env \
    -p NoNewPrivileges=yes -p PrivateTmp=yes \
    /home/student/Scripts/.venv/bin/python manage.py device_observe --device R6 --source nmas-observer-v1 \
    --authorization-ref 'OBSAUTH-000001#sha256=<64 hex>' --operator <executor> --evidence-dir <approved dir>
```

systemd (PID 1) reads the file, so `student` never needs read access to it. The file is created by the operator (see
`compat-deployment.md` step A6), never by this repository.

Device credentials are unchanged. Sessions use the existing credential broker through `observation_connections`:
- path credentials via `credentials.resolver`, with legacy inventory credentials allowed only on the legacy route
- the pin is checked before authentication

Fleet-wide shared credentials are refused for observations (`SHARED_CREDENTIAL_REFUSED`):
- the production resolver's `FLEET_FALLBACK` profile
- `LEGACY_SHARED` path credentials

Failover order is unchanged: DIRECT_OOB > VLAN_ADJACENT_SWITCH > ROUTED_VRF.

## 3. Evidence sink guarantees

- The directory must be absolute and existing, must resolve (following symlinks) under `/home/student/Scripts` or
  `/home/student/clab-quickstart`, and must not be group- or world-writable.
- Filenames are generated (`obs-<device>-<utc>-<nonce>.json`, sanitized). Callers cannot choose names, and there is no traversal.
- Writes are atomic and exclusive: a private temp file (0600, fsync) is hard-linked into place, an existing file is never
  overwritten, and the directory is fsynced.
- The reference `local-unattested:<file>#sha256=<hex>` embeds the digest of the exact stored bytes. It is stored as the
  observation's `evidence_ref` and on the authorization use row.
- Any write failure makes the collector return `EVIDENCE_UNAVAILABLE`, and nothing is ingested.

## 4. What this is not

- Local storage is **not gateway attestation**. References are labelled `local-unattested`.
- The runner makes no identity verification, admission, lifecycle, pin or deployment change. Observations remain input to the
  separate, independently approved identity workflow. Pins are enrolled only as described in `host-key-pin-enrollment.md`.

## 5. Production prerequisites (not done by this repository)

1. The overlay is deployed and the DB is migrated to `0039` (`compat-deployment.md`).
2. The operator has created `/etc/nmas/nmas-observation.env` with `NMAS_OBSERVATION_SOURCE_ID` and a fresh
   `NMAS_OBSERVATION_KEY`.
3. The operator has approved an evidence directory.
4. Each device has an enrolled pin: a pinned management path for cEOS, or inventory `ssh_host_key` for Ubuntu/FRR. There are no
   pins today (`ManagementPath` = 0 rows), so every device is refused before authentication.
5. An `ObservationAuthorization` has been granted by an approver to a separate operator.

## Tests

`core.tests.test_device_observe`, `test_observation_authorizations` (OA01–OA16), `test_observation_connections` (incl. SC01–SC04),
`test_observation_evidence`, `test_deploy_bindings` (DB01–DB09).
