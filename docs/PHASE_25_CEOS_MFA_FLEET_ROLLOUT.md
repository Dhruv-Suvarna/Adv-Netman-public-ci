# Phase 25 — managed cEOS human-MFA fleet rollout

Status (source): **GENERIC SUPPORT IMPLEMENTED; LIVE ROLLOUT REQUIRES ONE
EXPLICIT APPROVAL PER NEW DEVICE.** R1 is already live, persistent and
`LIVE_VERIFIED`; this phase does not repeat its completed closure.

## 1. Authoritative platform scope

The running container image, live `show version`, current topology, NetBox
device type/managed flag, and `inventory.yml` agree on this scope.

| Device | Current platform | Phase-25 decision |
|---|---|---|
| R1 | cEOS 4.36.2F | completed reference implementation |
| R2, S1, S2, S3, S4, `mgmt_swt` | cEOS 4.36.2F | eligible, migrate one at a time |
| R3, R4 | Ubuntu 24.04 / FRR 8.4.4 | deferred; no Linux/PAM work in Phase 25 |
| R5 | cEOS 4.36.2F, NetBox-unmanaged | explicitly outside scope |

Vlan200 remains static. The rollout reads its existing management address and
source-interface metadata; it never alters management addressing, DHCP, VLANs,
links, routing, or topology.

## 2. Least privilege decision

NMAS's machine identity must support privileged `show running-config`, Health,
NSOT and topology/state reads; aborted candidate-validation sessions; approved
configuration execution; verification; compensation; checkpoint recovery; and
post-confirm persistence. An arbitrary approved configuration candidate cannot
be represented by a stable narrow command allow-list without breaking the
already-live Configuration Changes and Remove Configuration contracts.

More importantly, this exact cEOS-lab 4.36.2F engineering image was already
tested with both the built-in `network-operator` role and a custom explicit
deny role. In both cases the identity could enter configuration mode and change
running state; the disposable test was reverted and never persisted. EOS role
authorization is therefore not an enforceable security boundary on this image.

| Identity | Placement | Effective privilege | Reason |
|---|---|---|---|
| `nmas-automation` | local, unique secret per device | privilege 15 / `network-admin` | NMAS execution and rollback require it; role restriction is defective |
| `nmas-admin` | central privacyIDEA/FreeRADIUS only | EOS `network-admin` VSA | named human, password+TOTP, no local bypass; lower EOS roles are not enforced |
| `<device>-breakglass` | local, unique sealed secret per device | privilege 15 / `network-admin` | emergency recovery must survive central AAA failure |
| `nmas-telemetry` | local telemetry plane | existing `network-operator` metadata | isolated credential/path; role defect is a documented residual risk |

This is not a claim that privilege 15 is least privilege in the abstract. It
is the smallest safe, actually enforceable reduction on the live platform:
purpose-bound identities, per-device secrets, central human MFA, removal of the
shared daily human account, management-path restriction, and audited atomic
execution. A future EOS image with working command authorization should replace
this exception with a tested custom role.

## 3. One device-aware implementation

`ceos_mfa_rollout --device <device> ...` binds every operation to one immutable
target: container, static management address, account names, provider refs,
checkpoint names, session names and approval phrase. The completed
`r1_mfa_pilot` remains a compatibility interface; no per-device copies exist.

The lifecycle is:

1. `precheck`: read-only digest/users/AAA/session/reachability/recovery and
   canonical credential-routing evidence.
2. `validate`: shape-matched fake canaries in aborted sessions; candidate,
   combined candidate, rollback and parser-echo/accounting behavior.
3. Original checkpoint: exact pre-Stage-1 configuration and hashes.
4. `stage1`: create only machine and break-glass identities; verify fresh
   logins, Health, NSOT, config retrieval and console recovery; automatically
   remove only those accounts on failure.
5. Post-Stage-1 checkpoint.
6. `stage2`: retire legacy `admin` and introduce RADIUS/AAA/SSH atomically
   under a ten-minute EOS commit timer.
7. Verify human password+TOTP, machine, break-glass, Health, NSOT, config
   retrieval and recovery.
8. Confirm only after passing evidence.
9. `persist`: `write memory`, unchanged running digest, startup equals running,
   and no open session.
10. `record-verification`: only then set central AAA `VERIFIED` and enforcement
    `LIVE_VERIFIED` from the recorded verification timestamp.

Rollback while the Stage-2 timer is armed is automatic timer reversion, not a
session abort. Outside that window, restore uses the recorded checkpoint MD5.
A successful restore clears stale verified metadata.

## 4. Credential and RADIUS routing

`modules/device_credentials.py` remains the single resolver. Every managed EOS
target declares a per-device `nmas-automation` reference. The legacy fleet
profile is tried second only during transition/recovery; after Stage 2 removes
`admin` it cannot authenticate. Missing per-device material therefore falls
back safely before migration without creating a page-specific resolver.

```text
runtime://device-credentials/<device>-nmas-automation
runtime://device-credentials/<device>-breakglass
runtime://human-mfa/radius/<device>
```

R1 retains its deployed names. All values are independent runtime secrets.

`monitoring/human_mfa/render_radius_clients.py` renders only explicitly selected
approved clients, from static inventory addresses and private
`radius_<device>_secret` files. Only device names appear in argv. The result is
an atomic mode-0600 ignored file. Add the next client only with that device's
approval; never weaken the existing R1 client.

The privacyIDEA backend, `nmas-admin`, token `TOTP0001522E`, token-specific
60-second window and global 30-second window remain common and unchanged. This
phase does not re-enroll the token, change its seed, enable AutoResync, or alter
the global policy.

## 5. Safety invariants

- Only `R1/R2/S1–S4/mgmt_swt` resolve as targets. R3/R4, R5, wrong platform,
  dynamic address and unknown targets fail closed.
- Secrets are provider/file reads into memory, stdin-only for EOS commands,
  absent from argv/child environment, redacted before output/evidence, and
  checked against process state plus bounded device paths.
- A canary parser failure prevents the matching real-secret command.
- Every device has unique session/checkpoint names; a failure cannot select or
  clean another device's state.
- Other devices' resolver routes are captured at precheck and must remain
  unchanged through verification.
- Validation and capture do not alter VLAN200 or forwarding state.
- Nothing is persisted until the commit timer is explicitly confirmed.

## 6. Approval boundary

Source tests, fake-secret simulation and aborted canary parser validation are
preparation. Before the first mutation for each new device, report its fresh
digest, users/auth state, checkpoint state, reachability, recovery path,
candidate summary, expected effect, timer and exact rollback, then obtain the
user's explicit approval. Approval for one device never carries to the next.
