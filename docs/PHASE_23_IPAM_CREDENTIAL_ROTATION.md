# Phase 23 — Objective 1: IPAM, Device Credentials, Password Rotation, Device-Login 2FA

Status (2026-09-27): **implemented and fixture-tested; NOT live-activated.**
No device password, account, AAA or SSH setting has been changed. Every live
step listed under "Live activation plan" needs explicit operator authorization.

> **Phase-24 supersession (2026-09-28):** The SSH public-key + password design
> in §5 is retained as historical implementation evidence and optional machine
> key support, but it is no longer the authoritative human 2FA architecture.
> Human administrators now require password + Microsoft Authenticator TOTP via
> local RADIUS/privacyIDEA. See
> `docs/PHASE_24_HUMAN_2FA_MICROSOFT_AUTHENTICATOR.md`. Current live status is
> still **NOT CONFIGURED / NOT ENFORCED / NOT LIVE-VERIFIED**.

## 1. Assignment and project scope

> Objective 1: Building the Automation Framework for IaC
> 1. IP Address Management (IPAM) — a. Store all network IPs (database or CSV)
> 2. Permissions — a. Store Device Management Information (UN/PW);
>    b. Passwords should be changed on a regular basis automatically;
>    c. Extra Credit: Use 2FA for device login

Project-owner override: **2(c) is REQUIRED for this project**, not extra credit.

| Requirement | Status |
|---|---|
| IPAM (NetBox) | Implemented earlier; Phase 23 adds read-only coverage evidence — **live PASS** |
| UN/PW storage | Metadata in Django, secret values in the protected runtime provider — implemented |
| Automatic rotation | Phase 26A safe EOS transaction + scheduler — implemented and fixture-tested, **not live-verified** |
| Device-login 2FA | Phase-23 key+password implementation superseded for humans by Phase-24 Microsoft Authenticator TOTP — **not live-enforced** |

## 2. IPAM — NetBox is the only IPAM

NetBox is the single, passive, authoritative IPAM/source of truth. Phase 23 does
**not** add a Django address table, a CSV IPAM, a second allocation engine or any
other parallel store.

Phase 23 adds read-only evidence tooling only:

* `modules/ipam_evidence.py` — compares the existing desired-state manifest
  `netbox/ipam.yml` (the input NetBox is populated from) with what NetBox holds.
  It uses only `.all()` / `.get()` / `.filter()`; a unit test asserts that the
  module contains no write calls or CSV/SQLite output.
* `netbox/scripts/verify_phase23_ipam.py` — prints JSON and exits non-zero on
  any discrepancy.

Live result (2026-09-27, read-only):

| Measure | Manifest | NetBox |
|---|---|---|
| Prefixes | 33 (18 IPv4 / 15 IPv6) | 33 |
| IP addresses | 83 = 78 interface (39 v4 + 39 v6) + 5 VRRP VIPs | 83 |
| DHCP ranges | 10 | 10 |
| Missing / unexpected / duplicate | — | 0 / 0 / 0 |
| VLAN 200 management, dual-stack | 9 managed devices | 9 / 9 |
| VLAN 200 assignment policy | static | **measured** `STATIC`, 0 reservation targets |

The VLAN 200 policy and the reservation-target count are measured from each
Vlan200 interface's NetBox assignment-mode custom fields; they are no longer
hard-coded constants. Runtime addresses (Containerlab bootstrap management,
IPv6 link-local, SLAAC and dynamic H1–H4 leases) are not fixed IPAM state and
are listed as documented exceptions rather than claimed as NetBox data.

Run it (the NetBox token is loaded from the ignored `netbox/.env`):

```bash
set -a; . netbox/.env; set +a
/home/student/Scripts/.venv/bin/python netbox/scripts/verify_phase23_ipam.py
```

## 3. Device management information (UN/PW)

### 3.1 Split between metadata and secrets

| Non-secret metadata (Django `DeviceCredential`) | Secret material (runtime provider only) |
|---|---|
| device, platform, username, role, privilege | account password |
| account kind: `SERVICE`, `HUMAN`, `BREAK_GLASS`, `LEGACY_SHARED` | NMAS service account SSH private key |
| auth method: `PASSWORD` or `PUBLICKEY_AND_PASSWORD` | |
| `secret_ref`, `ssh_key_ref` (opaque `runtime://device-credentials/<key>`) | |
| SSH **public** key and its `SHA256:` fingerprint | |
| rotation policy, interval, last rotation, next due, status | |

There is no password/secret/private-key field on any model (a test enforces
this). Model guards: human accounts can never have an NMAS-held private key;
only `SERVICE` accounts may have automatic rotation; two-factor accounts need an
enrolled public key; the password and key must be different references.

### 3.2 Protected runtime provider (`modules/device_credentials.py`)

* Store: `monitoring/runtime/device-credentials/store.json`, mode 0600, inside a
  dedicated mode-0700 directory. The shared `monitoring/runtime/` directory is
  **not** re-permissioned (Grafana and InfluxDB bind-mount subdirectories of it).
  The tree is ignored by `.gitignore` (`monitoring/runtime/*`).
* This is the project's existing secret boundary: filesystem permissions on the
  NMAS host. It is not encryption and no home-grown cryptography is used.
* Symlinked or group/world-accessible stores are refused. Reference keys are
  constrained (`[a-z0-9][a-z0-9_.-]{2,63}`), so traversal is impossible.
* Writes are atomic (temp file + `fsync` + `os.replace` + directory `fsync`) and
  every read-modify-write holds an exclusive `fcntl` lock, so the scheduler and
  an operator import cannot interleave.
* Two slots per reference: `current` and `pending`. A replacement is staged
  before the device is touched and promoted only after a fresh login succeeds.
  Error messages never contain values; versions are random opaque IDs.
* Import: `manage.py import_device_credential --ref <ref> --env-var NAME`
  (the value is read from an environment variable, never argv). Replacing a
  reference with an unresolved pending replacement is refused.

### 3.3 Current-tree plaintext removal

`inventory.yml`, `master.py`, `hostserv.py` and `address_report.py` contain no
device passwords. Managed cEOS devices resolve only their dedicated per-device
credential references. Lab Linux nodes and out-of-scope R5 use the fixed
host-side container console, so no shared Linux password or cEOS fleet fallback
is required. Linux bootstrap disables password/root SSH and locks the root
password. Tracked runtime artifacts (`Run_Logs.log`, `logs/R2.log`, a `.pyc`)
were removed from the tree and are ignored.

**Git history still contains the legacy values.** Removing them from `HEAD` does
not revoke them. Treat them as usable until invalidation has been independently
verified everywhere they were reused (see §7); historical-secret remediation is
**not** complete.

Before managed cEOS SSH workflows can run on a fresh checkout, each
device-specific replacement reference must be populated from an approved
secret source. For example, for R1 only:

```bash
read -rs R1_NMAS_AUTOMATION_PW && export R1_NMAS_AUTOMATION_PW
python web/manage.py import_device_credential --ref runtime://device-credentials/r1-nmas-automation --env-var R1_NMAS_AUTOMATION_PW
unset R1_NMAS_AUTOMATION_PW
```

Repeat with the matching per-device reference; never repopulate the retired
shared reference as an automation fallback.

### 3.4 Device scope, including the R5 decision

| Devices | Account | Seeded state | Why |
|---|---|---|---|
| R1 R2 S1 S2 S3 S4 mgmt_swt | `admin` (legacy shared) | `BLOCKED` / `SHARED_SECRET_REF` | One password is shared fleet-wide, so rotating it on one device would strand the others. |
| R5 | `admin` (legacy shared) | `BLOCKED` / `OUTSIDE_MANAGED_SCOPE` | R5 **does** hold the shared account, so it is recorded to keep the UN/PW inventory complete. It is outside the managed scope: its management address is Containerlab-assigned (`address: auto`) and it is `UNMANAGED` in NetBox/NSOT, so no trusted target exists for rotation or 2FA verification. This is a deliberate exclusion. |
| R3 R4 | `root` | `BLOCKED` / `ROOT_ACCOUNT_OUT_OF_SCOPE` | Only `root` exists; rotating the lab's root password is not a safe automation target. |

The live read-only audit also found `nmas-telemetry` (role `network-operator`),
the existing monitoring account whose secret already lives in the monitoring
runtime environment. It is outside Phase 23 rotation scope.

## 4. Automatic password rotation

### 4.1 Policy and scheduler

* `DeviceCredential.rotation_enabled`, `rotation_interval_days` (default 90),
  `next_due_at`. An account is due when it is enabled, `next_due_at <= now`,
  and its status is not `IN_PROGRESS`, `UNCERTAIN` or `BLOCKED`.
* `manage.py rotate_due_credentials [--json]` rotates every due account on its
  own; it exits 1 if any outcome is `FAILED`, `UNCERTAIN` or `BLOCKED`.
* `monitoring/config/nmas-credential-rotation.service.in` and
  `nmas-credential-rotation.timer`: a hardened
  oneshot run hourly (`Persistent=true`, 5-minute jitter). systemd never starts
  a second instance of a oneshot that is still running.
  `monitoring/scripts/install_credential_rotation_timer.sh` renders and installs
  both units and creates the runtime-only `credential-rotation.env` (a dedicated
  `DJANGO_SECRET_KEY`, mode 0600, never printed). The installer owns the single
  authoritative deployment-root constant and substitutes it into the service
  template; systemd does not perform shell-style variable expansion in these
  path directives.
* Checkout roles are deliberately separate:
  * `/home/student/Scripts/clab_dualstack_lab` is the preserved legacy/dirty
    historical workspace. It is not a deployment target and must not be
    modified or repurposed.
  * `/home/student/Scripts/clab_dualstack_lab-phase20_5` is the integration
    worktree which owns `main`. A Phase-number worktree is not permanent
    production architecture and cannot install the timer.
  * `/home/student/Scripts/clab_dualstack_lab-deploy` is the canonical clean
    deployed NMAS checkout. It is dedicated to reviewed deployment code and
    must not be used for feature development or experiments. The installer
    resolves its physical checkout and refuses installation from every other
    path.
* Promotion is explicit: reviewed `origin/main` -> detached clean deployment
  worktree -> runtime migrations and credential initialization -> service
  installation. Runtime initialization and service installation are separate
  controlled steps; creating the deployment worktree does neither.
* The unit uses an absolute `manage.py` path beneath that canonical checkout,
  sets the same checkout as `WorkingDirectory`, and reads only
  `monitoring/runtime/credential-rotation.env` for the non-interactive
  `DJANGO_SECRET_KEY`. It does not set or inherit a repository `PYTHONPATH`:
  `web/manage.py` bootstraps the repository root from its own resolved file
  location before Django discovers commands, independent of cwd or shell
  profiles.
* Nothing rotates on web start-up or page load. The UI is read-only and has no
  rotate button.

### 4.2 Secure generation

`secrets.choice` over `[A-Za-z0-9-_@%+=]`, 32 characters, with at least one
upper-case letter, lower-case letter, digit and symbol, then shuffled with
`SystemRandom`. Whitespace, quotes, backslash, `$` and `;` are excluded, so the
value is safe as one EOS CLI token.

### 4.3 Transaction (`web/core/services/credentials/engine.py`)

> **Phase-26A supersession:** the direct device-change transaction originally
> described here was found insufficient for live use and has been replaced by
> the recoverable transaction documented in
> `docs/PHASE_26_SAFE_CEOS_CREDENTIAL_ROTATION.md`. No production rotation was
> performed with the earlier implementation.

The current engine atomically claims one eligible row, stages a distinct
provider candidate, and then delegates to an EOS named-session transaction.
The EOS checkpoint and commit timer are established before the replacement is
accepted as applied. The engine then proves new-login acceptance, old-login
rejection, operational health and absence of unrelated drift. Only after it
confirms the EOS transaction, writes startup configuration, and proves
startup equals running does it promote the pending provider version. Database
finalization is the last step. Every boundary records only non-secret state and
opaque version IDs.

| Failure | Result |
|---|---|
| Device rejected the command before a timer was armed | `FAILED`; pending discarded; old value kept |
| EOS change or connection state is uncertain | `UNCERTAIN`; timer is not confirmed and both candidates are kept |
| New login, old rejection or operational validation failed | `UNCERTAIN`; EOS timer is left unconfirmed to revert and both candidates are kept |
| Persistence failed after confirmation | `UNCERTAIN`; verified pending is kept and reconciliation can persist/promote |
| Provider could not promote | `UNCERTAIN`; verified pending is kept and reconciliation can promote |
| Shared reference | `BLOCKED` before the provider or device is touched |

`UNCERTAIN` accounts are excluded from every scheduled and manual rotation.
Consumers (NSOT, Health, Execution, `master.py`) try `current` then `pending`,
so automation keeps working during recovery.

Recovery: `manage.py reconcile_device_credential --credential-id N` classifies
both provider candidates and inspects the recorded EOS session/digests. It
waits for an armed timer, discards pending after a proved automatic revert,
or completes validation/persistence/promotion after a proved confirmed device
change. It also finalizes a crash that occurred after provider promotion. An
ambiguous state remains `UNCERTAIN` for break-glass review and is never made
immediately eligible for another scheduled rotation.

### 4.4 cEOS adapter

The command remains `username <u> [privilege N] [role R] secret <new>`, but it
is now sent on stdin to the same restricted `docker exec -i` transport proven
by the cEOS MFA rollout. It is staged in a unique named EOS configuration
session and committed with a ten-minute timer. A pre-change flash checkpoint,
its digests, exact normalized pre/post running digests, session name and bounded
validation evidence are recorded. Secret-bearing commands and output are never
logged, placed in argv/environment, or written to evidence. Successful
rotation uses `write memory` and requires normalized startup and running
configuration to match before provider promotion.

| Platform | Rotation adapter |
|---|---|
| Arista cEOS 4.36.2F | Implemented and fixture-tested; **not live-verified** |
| Ubuntu/FRR (R3/R4) | Not implemented (`PLATFORM_NOT_IMPLEMENTED`); root-only |
| SR Linux, IOS XR, SONiC | Not implemented; not deployed in the Labs 2/3 baseline |

## 5. Device-login two-factor authentication (REQUIRED)

**Historical/superseded for human access.** The material below explains what
Phase 23 implemented. It must not be used to claim that current human 2FA uses
Microsoft Authenticator or is live. Phase 24 is authoritative.

### 5.1 Audit (read-only, 2026-09-27, R1 as representative)

* Login method lists: `LOGIN default = local`, `ENABLE default = local`. No
  RADIUS, TACACS+ or LDAP servers are configured. Local users are `admin`
  (network-admin, priv 15) and `nmas-telemetry` (network-operator).
* Management planes: SSH (22), NETCONF over SSH (830), gNMI (6030, TLS profile
  `NMAS_GNMI`), and eAPI HTTPS (443). eAPI comes from the cEOS default startup
  config; it is not in any template and NMAS does not use it.
* Grammar of the EOS 4.36.2F parser (`show cli commands` inside aborted sessions;
  running-config SHA-256 compared before and after — unchanged):
  * RADIUS, TACACS+ (including TLS) and LDAP server groups exist, but there is
    **no native OTP/TOTP grammar**.
  * `management ssh` → `authentication protocol ( … ) | multi-factor ( … )`
    exists. `multi-factor public-key password` and
    `multi-factor public-key keyboard-interactive` were accepted;
    an invalid method was rejected.
  * `username <u> ssh-key <key>` is accepted, and EOS validates the key material.
  * `aaa authentication login console local` and
    `management api http-commands` / `shutdown` are accepted.

### 5.2 Mechanism selected

**EOS vendor-native SSH multi-factor:**
`management ssh` / `authentication protocol multi-factor public-key password`.

Every SSH login must present both factors:

* **Possession:** an enrolled SSH private key, held by the operator (humans) or
  by the protected provider (the NMAS service account).
* **Knowledge:** the account password.

These are two genuinely different factor types, not two static secrets.

Alternatives considered:

* **RADIUS + TOTP (e.g. FreeRADIUS `rlm_totp`, password+OTP):** EOS supports
  RADIUS but has no native OTP. This option adds a new identity service to
  build, secure and keep running, and makes device login depend on it; an
  unattended NMAS account also cannot supply a rolling code. It remains a
  possible future centralization, but it is not required to meet the
  requirement and is riskier for this lab.
* **TACACS+ with an MFA backend:** same trade-offs; no MFA backend exists in
  the lab today.
* **Two passwords / password + enable secret:** both are knowledge factors, so
  they do not count as two factors. Rejected.

### 5.3 Human login vs. the automation service account

| | Human operator (`HUMAN` / `BREAK_GLASS`) | NMAS automation (`SERVICE`, e.g. `nmas-automation`) |
|---|---|---|
| Possession factor | Operator's own private key (NMAS stores the **public** key and fingerprint only) | Ed25519 private key in the provider (`ssh_key_ref`), loaded into memory only |
| Knowledge factor | Password the operator knows (NMAS never holds it) | Rotated password in the provider (`secret_ref`) |
| Interaction | Interactive SSH | Non-interactive: paramiko 4.0 completes publickey → *partial success* → password (verified in `paramiko/client.py::_auth`) |
| Rotation | Operator-managed | Automatic (§4) |
| Least privilege | Named per person | Dedicated account, never shared with humans |

For the service account, both factors are stored on the NMAS host. That is the
documented machine-to-machine model: the host is the trust boundary, and the
factors rotate and are kept separately. No interactive one-time code is ever
expected from unattended automation.

All Django device sessions (NSOT live read, Health, Execution), the rotation
adapter, `master.py` and `address_report.py` present the key when
`ssh_key_ref` / `ceos_ssh_key_ref` is configured. An enrolled key that cannot be
loaded **fails closed**; the session is never quietly downgraded to
password-only.

Phase 24 extends those consumers with one shared per-device cEOS profile
resolver. R1 selects `nmas-automation` and its R1-only protected reference;
other cEOS devices retain the global `admin` reference. The fleet profile is a
bounded R1 transition/rollback candidate only: activation removes `admin`, and
rollback restores it before removing `nmas-automation`.

### 5.4 Candidate device configuration (rendered, never applied)

`manage.py render_device_mfa_candidate --device R1 [--json] [--record-digest]`
produces a deterministic candidate and its rollback. Passwords appear only as
`<provider:runtime://…>` placeholders:

```text
aaa authentication login console local
username nmas-automation privilege 15 role network-admin secret <provider:runtime://device-credentials/r1-nmas-automation>
username nmas-automation ssh-key ssh-ed25519 AAAA… nmas-automation@nmas
username ops-<name> ssh-key ssh-ed25519 AAAA… <name>@<host>
management ssh
   authentication protocol multi-factor public-key password
management api http-commands
   shutdown
```

Rollback:

```text
management ssh
   default authentication protocol
management api http-commands
   no shutdown
no username ops-<name> ssh-key
no username nmas-automation
no aaa authentication login console
```

eAPI is shut down because HTTPS eAPI logs in with a password alone, which would
bypass the SSH policy. The renderer refuses to call a candidate lockout-safe
(it reports `blockers`) unless both an enrolled service account and an
enrolled human or break-glass account exist.

Ubuntu/FRR candidate: an OpenSSH drop-in with
`AuthenticationMethods publickey,password`. It is rendered and tested but
`BLOCKED` (`ROOT_ONLY_ACCOUNT`): R3/R4 need a dedicated non-root account first,
and they have no systemd (sshd is reloaded by signal).

Unsupported platforms render `supported: false` with no lines, and the model
refuses to mark them enforcing.

### 5.5 Emergency access, failure behavior and lockout risk

* **Emergency path:** the container console,
  `docker exec -it clab-srlceos01-<node> Cli` (Linux: `… bash`). It runs
  outside `management ssh`, so it keeps working if SSH, the provider or a key
  is lost. The candidate also pins `aaa authentication login console local`.
* **No external AAA dependency:** EOS enforces the policy locally. There is no
  RADIUS/TACACS+ server whose outage could lock out every device, and so no
  AAA-timeout fallback to configure.
* **Provider unavailable:** NMAS automation fails closed with sanitized errors.
  Human SSH is unaffected, and the console remains available.
* **Residual risks (documented, not hidden):** gNMI authenticates the read-only
  `nmas-telemetry` service with a password (a machine telemetry plane, not an
  interactive login). NETCONF-over-SSH behavior under the multi-factor policy
  must be verified in the live plan before activation.

### 5.6 Verification

`manage.py verify_device_mfa --device R1` makes four fresh SSH transport
attempts. It sends no command and changes no configuration:

| Probe | Must be |
|---|---|
| password only | refused |
| key only | refused (partial success only) |
| key + wrong password | refused |
| key + correct password | accepted |

Only that exact outcome records `LIVE_VERIFIED`. A later failed verification
demotes the device back to `ENFORCED`. The command refuses to run unless the
policy is already `ENFORCED`, which requires an authorized activation.

### 5.7 Commands

| Command | Contacts a device? |
|---|---|
| `enroll_service_ssh_key --credential-id N --key-ref <ref>` | No — generates an Ed25519 key; private half goes to the provider; prints the public key and fingerprint |
| `register_operator_ssh_key --device D --username U --public-key-file F [--break-glass]` | No — accepts a **public** key only; private keys are refused |
| `render_device_mfa_candidate --device D` | No |
| `verify_device_mfa --device D` | Yes — authentication attempts only; requires an `ENFORCED` policy |

### 5.8 Seeded 2FA policy

All ten devices are `required = True`:

* R1, R2, S1–S4 and mgmt_swt: `EOS_SSH_MULTI_FACTOR`, `NOT_ENFORCED`.
* R5: `BLOCKED` (`OUTSIDE_MANAGED_SCOPE`).
* R3 and R4: `OPENSSH_AUTHENTICATION_METHODS`, `BLOCKED` (`ROOT_ONLY_ACCOUNT`).

## 6. Operator UI and CI

* Automation → **Device Credentials** (`/automation/credentials/`, plus
  `status.json`): accounts, kinds, factor types, references, fingerprints,
  rotation policy and status, the rotation audit trail, and the 2FA policy
  table. It is read-only and shows metadata only; no key, seed or password is
  ever rendered (tests use `TEST_ONLY_*` values to check HTML, JSON, command
  output, audit rows and docs).
* Tier-3 change classification has two subsystems:
  * `device_secrets` (the provider) → credentials, execution, health, nsot, and
    the monitoring unit tests.
  * `credentials` (Django rotation/2FA layer) → `credential_rotation`,
    `device_mfa`, routes, admin, contracts.
  * `models_schema` reaches `credentials` but not NSOT.

## 7. Live activation plan (each step requires explicit authorization)

Nothing below has been done.

1. **Sandbox proof first:** run the rendered R1 candidate on a disposable cEOS
   4.36.2F sandbox container (not the lab topology). Prove the §5.6 probe
   matrix, Netmiko key+password sessions, NETCONF-over-SSH behavior, and
   console access.
2. **Per device (R1 first, then one at a time):**
   1. Import the device's dedicated `nmas-automation` password and enroll its
      key.
   2. Register at least one human or break-glass public key.
   3. Apply the account lines only.
   4. Verify a key+password session.
   5. Apply the `management ssh` policy and the eAPI shutdown.
   6. Run `verify_device_mfa`.
   7. Keep an open console session throughout.
   8. Roll back with the rendered rollback on any failure.
3. Switch `inventory.yml` to the dedicated account and key references, then
   enable rotation for the dedicated `SERVICE` rows (never the legacy shared
   `admin`).
4. Install the timer (`install_credential_rotation_timer.sh`).
5. Retire the shared `admin` credential, which is in Git history: change it to
   a new value held only by the break-glass owner, or remove it.

## 8. Remaining blockers

* No live rotation has been performed, and no dedicated service account exists
  on any device yet.
* 2FA is not enforced on any device, pending the sandbox proof and
  authorization.
* The legacy shared `admin` password and the Linux root password in Git history
  have not been revoked.
* R3/R4 need a dedicated non-root account before OpenSSH two-factor login can
  be enabled.
* NETCONF-over-SSH under the multi-factor policy is unverified.
