# Host-key pin enrollment from independent device-side evidence

Module: `web/core/services/devices/host_key_pins.py` · command: `manage.py host_key_pin_check` · tests:
`web/core/tests/test_host_key_pins.py` (HK01–HK11).

A pin (`SHA256:<43 base64 chars>`) is the trust anchor of every pinned NMAS session. `observation_connections` checks the pin
**before** authenticating, so a wrong or attacker-supplied pin would hand a credential to the wrong host. This means the pin must
never come from the network path it protects.

| Never used as pin evidence | Why |
|---|---|
| `ssh-keyscan`, a first SSH handshake, `known_hosts`, "accept on first use" | network path the pin protects (TOFU) |
| a fingerprint typed or pasted by a person | not key material; NMAS computes the fingerprint itself |
| inventory `os_version`/image tags, NetBox custom fields | not device-side key material |

## Roles (three different people or accounts)

| Role | Does | Must not |
|---|---|---|
| **Collector** | captures the device's own public host key over an independent channel and writes the evidence file | validate or approve their own capture |
| **Enroller** | runs `host_key_pin_check` (read-only) and, if it passes, records the pin through the existing route | be the collector |
| **Approver** (cEOS) | approves the registered management path (`approve_path`, which already refuses self-approval) | be the registrant |

## 1. Capture (collector)

Only these channels are accepted (`host_key_pins.CHANNELS`):

| Channel | How the key is read | Platforms |
|---|---|---|
| `DEVICE_CONSOLE` | out-of-band console: `show management ssh hostkey ed25519 public` (or `ecdsa-nistp256` / `rsa`) | cEOS |
| `CONTAINER_HOST_ADMIN` | the container host's authorized administrator reads the node's `/etc/ssh/ssh_host_ed25519_key.pub` (for example `sudo docker exec <container> cat /etc/ssh/ssh_host_ed25519_key.pub`) | Ubuntu/FRR, cEOS |
| `ZTP_ENROLLMENT` | NMAS's own ZTP enrollment record (`ZtpSession.enrolled_host_key`) for a natively onboarded device | ZTP devices |
| `CONFIG_ARCHIVE` | the key file from a configuration/flash archive copied by an authorized administrator | both |

Copy the **whole public key line** (`ssh-ed25519 AAAA… comment`). Write the evidence file with mode 0600, outside the deployed tree:

```json
{
  "schema": "nmas.host-key-pin-evidence/1",
  "device": "R6",
  "platform": "ubuntu_frr",
  "channel": "CONTAINER_HOST_ADMIN",
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… root@R6",
  "captured_by": "collector-name",
  "captured_at": "2026-11-14T05:00:00Z",
  "ticket": "CHG-…"
}
```

The capture is a read on the device side. It does not change, regenerate or rotate any SSH host key. Do not "fix" a key that
does not match. A mismatch is a finding that needs investigating.

## 2. Validate (enroller; read-only)

```
cd /home/student/Scripts/clab_dualstack_lab-deploy/web
/home/student/Scripts/.venv/bin/python manage.py host_key_pin_check --evidence /path/to/R6-hostkey.json --enroller <enroller> [--claimed-pin SHA256:…] --json
```

What the check does:

- It decodes the SSH wire-format blob, requires the embedded type to equal the declared type, and computes the pin. The computation
  is identical to `management.probes.fingerprint` (HK01 cross-checks it against paramiko).
- It refuses on any of these codes:

  | Code | Cause |
  |---|---|
  | `CHANNEL_NOT_INDEPENDENT` | keyscan, TOFU, `known_hosts`, a handshake or a network channel |
  | `CHANNEL_UNKNOWN` | any channel not in the list above |
  | `ENROLLER_NOT_INDEPENDENT` | the collector and the enroller are the same person |
  | `EVIDENCE_STALE` | the capture is older than 7 days |
  | `EVIDENCE_FUTURE` | the capture is dated more than 5 minutes ahead |
  | `PUBLIC_KEY_INVALID` | the input is a fingerprint or a malformed key |
  | `CLAIMED_PIN_MISMATCH` | a typed pin does not match the computed one |
  | `PLATFORM_MISMATCH` | the evidence platform is not the device's platform |
  | `DEVICE_EXCLUDED` | R5 and any other read-only or excluded device |

- It compares the computed pin with every pin NMAS already holds:
  - inventory `ssh_host_key`
  - `ManagementPath.expected_host_key`
  - `ZtpSession.enrolled_host_key`
  - `ManagedDevice.verified_host_key`
  - the latest `AUTHENTICATED_SESSION` observation

  Any disagreement makes it fail with `REGISTERED_PIN_CONFLICT`.
- It writes nothing, connects to nothing and approves nothing (HK10).

Record the printed `pin` and `evidence_sha256` in the change ticket.

## 3. Record the pin (existing mechanisms only)

| Platform | Route (printed as `enrollment_route`) |
|---|---|
| cEOS | Management page → register a management path with `expected_host_key=<pin>` (`management.paths.register_path`) → **a different NMAS Approver** approves it (`approve_path`; self-approval is refused). Failover order and path policy are unchanged (DIRECT_OOB > VLAN_ADJACENT_SWITCH > ROUTED_VRF). |
| Ubuntu/FRR | Reviewed Git change adding `network_devices.<device>.ssh_host_key: <pin>` to `inventory.yml`, citing `evidence_sha256`. Ubuntu/FRR observations use the legacy inventory route only. |

Nothing in this module calls `register_path`, `approve_path`, `verify_identity` or writes the inventory. Recording a pin does
**not** verify identity and does not admit a device. Identity verification remains the separate, independently approved
lifecycle action.

## Current production facts (snapshot 2026-11-14T05:07Z, read-only)

- `ManagementPath` has 0 rows, so no cEOS device has a pinned path yet.
- R6/R7/R8/S5 are `VERIFIED`. Their `verified_host_key` is one of the values `compare_registered` checks, so a new capture must
  **match** it or the check fails with a conflict.
- R2/R4 are `UNVERIFIED` legacy adoptions. Readiness reports `IDENTITY_NO_PRODUCER` for them, and a pin is a prerequisite for that
  producer.
- R5 stays excluded: the check refuses it with `DEVICE_EXCLUDED`.
