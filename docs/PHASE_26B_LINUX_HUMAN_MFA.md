# Phase 26B — R3/R4 Linux human MFA

## Scope and result contract

This phase extends the existing privacyIDEA 3.13.4 / FreeRADIUS human
password-plus-TOTP service to the Ubuntu 24.04 / FRR 8.4.4 routers R3 and R4.
It does not alter topology, addressing, VLANs, routing, monitoring, the seven
cEOS MFA policies, or credential rotation.

The reviewed identities are deliberately separate:

| Identity | SSH method | Privilege and purpose |
|---|---|---|
| `nmas-admin` | `keyboard-interactive:pam`; one password+TOTP response is checked by privacyIDEA through FreeRADIUS | sudo after central MFA; factors are never held by NMAS |
| `nmas-automation` | Ed25519 public key only, source-restricted to `192.168.200.100` | non-interactive machine identity; no TOTP and no unrestricted sudo |
| `r3-breakglass` / `r4-breakglass` | unique protected local password, source-restricted to `192.168.200.100` | emergency sudo path independent of central AAA |
| `root`, `ubuntu` | remote SSH denied | local/container recovery remains available through privileged `docker exec` |

The existing NMAS Health, configuration retrieval, monitoring, and structured
Linux readers continue to use their established fixed-argv `docker exec`
transport. Inventory nevertheless records the new public-key machine identity
truthfully, and a fresh SSH login is required during rollout to prove it.

## Actual platform integration

Ubuntu's supported `libpam-radius-auth` 2.0.1 package supplies
`pam_radius_auth.so`; Ubuntu's `sudo` package supplies the mandatory `visudo`
validator. The dependency preparation operation independently probes both
packages and executables, installs only missing packages with noninteractive
APT, and is idempotent when both are already satisfied. The module sends the
single protected PAM response to FreeRADIUS. The deployed privacyIDEA policy
`nmas-human-password-totp` splits the final six digits as the RFC 6238 TOTP
and validates the preceding password.
The module's `localifdown` fallback is intentionally absent: RADIUS
unavailability rejects the human path rather than falling through to a local
password.

`/etc/pam.d/sshd` branches only `nmas-admin` to RADIUS. Other password-capable
SSH users use `common-auth`; OpenSSH permits that path only for the named
device break-glass identity. `/etc/ssh/sshd_config.d/60-nmas-human-mfa.conf`
uses `AllowUsers` with the NMAS address and per-user `AuthenticationMethods`.
Effective configuration is checked with `sshd -t` and
`sshd -T -C user=...,addr=...,host=...`.

The generated files are:

- `/etc/pam_radius_auth.conf` (0600, unique per-device runtime secret);
- `/etc/pam.d/sshd` (human-only PAM branch);
- `/etc/ssh/sshd_config.d/60-nmas-human-mfa.conf`;
- `/etc/sudoers.d/60-nmas-mfa` (0440);
- `/home/nmas-automation/.ssh/authorized_keys` (0600).

Account database changes are made only through `useradd`, `chpasswd`, and
`passwd -l`. Protected password/key values enter the container on stdin, never
argv or the environment. Evidence contains booleans, hashes, usernames,
timestamps, audit IDs, and public/opaque identifiers only. Hashes are retained
only for non-secret configuration and operational state: neither the protected
device PAM RADIUS file nor the central RADIUS client file is hashed into
evidence.

## Transaction and rollback

The rollout is strictly R3 then R4. For each device:

1. Prepare only that device's protected key, break-glass password, RADIUS
   secret, and metadata.
2. Add only that RADIUS client while preserving every cEOS client and
   `local_fixture`; validate `freeradius -XC`, restart only FreeRADIUS, then
   perform a fresh cEOS human-MFA regression.
3. Install only missing `libpam-radius-auth` / `sudo` dependencies, prove
   installation did not change the existing PAM files, and require both
   `command -v visudo` and `visudo -V` to succeed.
4. Capture Health, NSOT, configuration retrieval, identity routing, recovery,
   FRR configuration, addresses, routes, and OSPF neighbor baselines.
   Precheck fails with bounded `REQUIRED_DEPENDENCY_MISSING` metadata if the
   PAM module, `sudo`, or `visudo` is absent. A latest passing precheck and a
   fresh live dependency probe are required before backup and timer arming;
   activation probes again before any account/PAM/SSH mutation.
5. Copy the exact files that may change into a mode-0700 device-local backup
   directory and record SHA-256 integrity hashes only for non-secret files.
   Record existence/backup state, not a hash, for the PAM RADIUS secret file.
6. Arm a ten-minute transient NMAS user-systemd timer which invokes the
   standalone, Django-independent rollback helper.
7. Create the three identities and atomically replace the reviewed files;
   require `visudo -c` and `sshd -t`, then HUP-reload sshd.
8. While the timer is armed, require public-key automation, local break-glass
   sudo, privileged docker recovery, root/ubuntu SSH rejection, Health, NSOT,
   configuration retrieval, unchanged FRR/network digests, and unchanged
   identity routing.
9. Require password-only rejection, deliberately incorrect-TOTP rejection,
   password+fresh-TOTP acceptance, sudo privilege, and matching privacyIDEA
   success/rejection audit rows.
10. Recheck file integrity and sshd syntax. Only then cancel the rollback
    timer and set the platform-neutral policy row to `VERIFIED / LIVE_VERIFIED`.

If the process exits or any required gate fails before step 10, the timer runs
`monitoring/scripts/linux_mfa_rollback.py`. It restores exact prior files with
atomic replacement, removes only the three Phase-26B-created accounts,
validates the restored sshd configuration, and reloads sshd. The central
RADIUS client entry may safely remain staged, but no Linux human path exists
after device rollback. An operator must inspect and retry as a new reviewed
transaction; success is never inferred.

### Bounded activation diagnostics

The device helper records started/completed/failed events for the actual
account, password-lock, SSH-key, PAM/RADIUS, PAM stack, sshd drop-in, sudoers,
validation, listener-discovery, and sshd-reload sequence. Child-process output
is captured rather than inherited. On failure, NMAS accepts only known stage
names, statuses, numeric return codes, timestamps, exception classes, fixed
command categories, and fixed diagnostic summaries. It never persists raw
stdout/stderr, a command line, environment data, or protected input. The
failure evidence also records whether the automatic rollback timer is still
armed and whether sshd reload started/completed.

The PAM module gate remains part of the passing precheck evidence, and its
evidence ID is correlated into an activation failure. Configuration inspection
after reload is a separate diagnostic stage. A diagnostic failure does not
cancel the rollback timer.

### Stable OSPF evidence

FRR neighbor output is normalized before comparison. IPv4 retains address
family, neighbor/router ID, peer address, interface, interface area, and the
converged adjacency state. IPv6 retains address family, neighbor/router ID,
interface, interface area, and adjacency state (FRR 8.4 does not expose a peer
IPv6 address in this command). The interface area is joined from the matching
IPv4/IPv6 OSPF interface JSON.

Dead timers, duration/uptime, election role, counters, sequence numbers,
timestamps, and JSON/field ordering are excluded. Validation requires both
families to contain non-empty, exact adjacency sets with every adjacency in
`Full`; loss/addition, identity/address substitution, interface or area moves,
and state regression remain blocking drift.

## Commands

All Django commands run from the canonical deployment checkout with its
protected runtime environment loaded. No password, TOTP, key, or RADIUS value
is an option.

```text
manage.py prepare_linux_mfa_rollout_metadata --device R3 --json
manage.py linux_mfa_rollout stage-radius --device R3
manage.py ceos_mfa_rollout verify-positive --device R1
manage.py linux_mfa_rollout install-module --device R3
manage.py linux_mfa_rollout precheck --device R3
manage.py linux_mfa_rollout backup --device R3
manage.py linux_mfa_rollout arm --device R3 --token <opaque-token>
manage.py linux_mfa_rollout activate --device R3 --token <opaque-token>
manage.py linux_mfa_rollout verify-machine-recovery --device R3 --token <opaque-token>
manage.py linux_mfa_rollout verify-operational --device R3 --token <opaque-token>
manage.py linux_mfa_rollout verify-human --device R3 --token <opaque-token>
manage.py linux_mfa_rollout finalize --device R3 --token <opaque-token>
```

Repeat with R4 only after R3 finalizes. The human verification command reads
both factors from a real terminal with echo disabled. It is the only point at
which operator interaction is required.

## Verification boundary

Unit/integration tests cover renderer and model constraints, platform scope,
fail-closed RADIUS behavior, identity separation, guarded timer ordering,
secret placement, negative-factor enforcement, operational-drift refusal,
finalization gates, R3/R4 isolation, and rollback invocation. A disposable
Ubuntu 24.04 container additionally validates the exact rendered sshd/PAM/
sudo bundle and effective per-user OpenSSH policy. It does not contact the
production provider, database, R3, or R4.
