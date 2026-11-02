# Phase 24 — Reviewed R1 2FA pilot execution helper

Status: written 2026-09-28 as **source only**; the pilot was then applied on R1
through this helper and **confirmed** (2026-09-28 22:31Z, running-config
`364e09dd…`), persisted with `write memory`, and hardened after the pilot
(section 9). Scope is **R1 only**; R2, S1–S4 and mgmt_swt are unchanged.

Phase-25 continuation uses the device-aware `ceos_mfa_rollout` interface in
`PHASE_25_CEOS_MFA_FLEET_ROLLOUT.md`. This command remains the compatibility
interface for the completed R1 pilot; it is not copied for each device.

The helper is the single, reviewed apply path for the R1 candidate rendered by
`render_device_mfa_candidate` (see `PHASE_24_R1_PILOT_REMEDIATION.md`). It
exists so the live pilot is never improvised.

## 1. Interface

```text
python web/manage.py r1_mfa_pilot validate
python web/manage.py r1_mfa_pilot status
python web/manage.py r1_mfa_pilot checkpoint --name pre-2fa-pilot        # LIVE
python web/manage.py r1_mfa_pilot stage1                                  # LIVE (+ automatic post-stage1 verification)
python web/manage.py r1_mfa_pilot verify-logins --phase post-stage1
python web/manage.py r1_mfa_pilot checkpoint --name pre-2fa-stage2       # LIVE
python web/manage.py r1_mfa_pilot stage2                                  # LIVE (commit timer 00:10:00)
python web/manage.py r1_mfa_pilot verify-logins --phase post-stage2       # prompts for nmas-admin factors
python web/manage.py r1_mfa_pilot confirm                                 # LIVE
python web/manage.py r1_mfa_pilot replace --name pre-2fa-pilot|pre-2fa-stage2   # LIVE restore
python web/manage.py r1_mfa_pilot verify-positive                         # routine: ONE human login, no negatives
python web/manage.py r1_mfa_pilot record-verification                     # R1 policy metadata (DB only, approval)
```

Code: `web/core/services/credentials/r1_pilot.py` (transport, redaction, leak
detection, candidate staging, timer classification, gates) and
`r1_pilot_runner.py` (operations and evidence).
Post-pilot operations: section 9. Only `R1` /
`clab-srlceos01-R1` can be targeted.

## 2. Secret-safe transport

- Secrets are resolved from `runtime://device-credentials/*` (the protected
  `FileSecretProvider`) and `runtime://human-mfa/radius/r1`
  (`monitoring/runtime/human-mfa/secrets/radius_r1_secret`, which must be a
  private regular file) into process memory only.
- Secrets substituted into configuration (`r1-nmas-automation`, `r1-breakglass`,
  the R1 RADIUS key) must be one EOS token of 16–128 characters from
  `[A-Za-z0-9_+/=.-]` (the live RADIUS key is base64). `ceos-admin-shared` is
  login-only: the helper never substitutes it into configuration (restores use
  the checkpoint), and only uses it to prove `admin` is rejected after Stage 2.
- Validation and pre-flight canaries mirror each real config secret's shape
  (same length and punctuation characters at random positions), so the EOS
  parser sees the same token shape. The real value is read in memory only for
  that, and for local leak checks; it is never sent to R1.
- Commands are fed to `docker exec -i clab-srlceos01-R1 Cli -p 15` on **stdin**.
  argv is fixed; the child environment is a minimal allow-list (`PATH`, `LANG`,
  `HOME`, `DOCKER_*`). A secret that would reach argv or the child environment
  refuses the run.
- EOS Cli echoes a line that fails to parse. Every returned byte is therefore
  redacted in memory (known values, then structural `secret`/`key`/hash
  patterns) before it is kept or shown. A known secret in device output marks
  the operation failed.
- While a child runs, the process table (argv and readable environ) is scanned
  for known values. After a run, R1's `/mnt/flash`, `/var/log`, `/tmp` and
  `/var/tmp` are grep'd with patterns fed on stdin; only matching file names
  are reported. No unbounded host scan is performed.
- **EOS command accounting (observed on R1, 2026-09-28).** `/var/log/account.log`
  records every CLI command. For commands that parse, EOS masks the secret
  (`... secret *`, `radius-server host ... key 0 *`); a command that is
  **rejected** by the parser is recorded verbatim. A parse failure on a real
  secret line would therefore persist that secret on R1 even though the
  two-phase session is aborted. Consequently `stage1` and `stage2` first run a
  mandatory **canary pre-flight**: the exact lines, with fresh canaries, in an
  aborted session. Real secrets are sent only if that parse is clean. `validate`
  asserts that candidate/rollback canaries never persist on R1 and records that
  its deliberately rejected echo-probe canary appears in `account.log`
  (expected; a random test value, never a secret).
- Evidence (`AuditEvent` type `MFA_PILOT_STEP`) is refused if it would contain a
  known value. Approval and human factors are read from the terminal only; no
  secret or approval argument exists.

## 3. Two-phase configuration sessions

Each change opens and fills a named session in one Cli process **without
committing**, including `show session-config diffs`. Only if that produced no
parser error and no leak, and the session is still pending, is it committed
from exec mode in a second process. Otherwise it is aborted. A partially parsed
session is never committed, regardless of whether piped Cli stops at the first
error. `validate` proves on R1 that a pending session survives the end of the
filling process; `stage1` refuses without that proof.

EOS keeps the most recent completed session listed (`maxSavedSessions 1`); only
non-completed sessions count as open for the gates.

## 4. Gates for every mutating operation

In order: the approval phrase `APPLY THE R1 2FA PILOT` typed on the terminal;
device is R1; rendered candidate digest equals
`5bf1d22710503da1cec59c48935ba7fb1e1a37af863146fd8a005a1b9ac3dc92`; the running
config equals the expected pre-change digest for that step; no unexpected open
config session; all protected refs resolve; the human-MFA containers are
healthy/running; TCP/22 to 192.168.200.1 answers. Any failure refuses the step.

| Step | Expected pre-change state |
|---|---|
| `checkpoint pre-2fa-pilot` | reviewed original digest `148470d8…`; no pilot account exists; file absent |
| `stage1` | reviewed original digest; intact original checkpoint; passing `validate` |
| `checkpoint pre-2fa-stage2` | Stage 1 committed and verified; digest recorded after Stage 1; file absent |
| `stage2` | intact Stage 2 checkpoint; digest equals that checkpoint's running digest |
| `confirm` | timer ARMED with ≥30 s left; passing post-Stage-2 verification since arming |
| `replace` | intact checkpoint (SHA-256 and MD5 re-checked); no armed timer; no open session |
| `record-verification` | see section 9.2 (evidence + live-state gates); DB metadata only |

## 5. Checkpoints

`copy running-config flash:<name>.cfg`, then the file is read and hashed in
memory (SHA-256 and MD5 recorded; contents never shown) and compared with the
running config after dropping volatile headers and the `Cli -c` command echo.
An existing file is never overwritten. Restore is always
`configure replace flash:<name>.cfg md5 <recorded-md5>`.

- `pre-2fa-pilot`: true original state (before either pilot account exists).
- `pre-2fa-stage2`: after Stage 1 is verified, immediately before AAA/admin
  retirement.

A full original restore returns AAA/RADIUS, SSH authentication, `admin` (with
its original hash), and the absence of `nmas-automation` / `r1-breakglass` in
one operation. R1's credential routing needs no source change: the reviewed
PR #18 resolver tries `nmas-automation` first and falls back to the restored
fleet `admin`; `replace` verifies the NSOT read afterwards and resets the R1
policy row to its pre-verification state: `enforcement_state=PLANNED`,
`central_aaa_state=PLANNED`, `last_verified_at` empty and
`last_verification_result` empty, so a rollback never leaves stale
`LIVE_VERIFIED`/`VERIFIED` metadata.

## 6. Stage 1 and its verification contract

Creates exactly `nmas-automation` and `r1-breakglass` (protected refs). The
post-Stage-1 contract requires: fresh SSH login for both; R1's first NMAS
identity is `nmas-automation` and it authenticates (so the resolver's first
candidate is the one used); every other cEOS device still resolves only the
fleet `admin`; Health, NSOT and running-config retrieval PASS; docker-exec
privileged Cli PASS. On any failure both accounts are removed in a two-phase
session and the helper stops.

**Health PASS rule (revised after the first live Stage 1, 2026-09-28).** EOS
emits SNMP config-change notifications (`arista-config-man-event`,
`ent-config-change`, enabled by global default) on every committed session;
Health counts them as recent critical events for 15 minutes and reports
DEGRADED. The first live Stage 1 committed, both accounts logged in, NMAS used
`nmas-automation`, NSOT/config retrieval passed, and only Health (these traps
plus a transient 70% CPU sample) failed; both accounts were removed and R1
returned to `148470d8…`. Health now passes when there is no FAIL or UNKNOWN
check and the only warnings are `CRITICAL_EVENTS_RECENT` with zero critical
syslog events (traps only) and/or `CPU_HIGH` in the warning band. Any other
warning fails. Tolerated warnings are recorded in the evidence.

## 7. Stage 2 and the commit timer

One atomic session with the reviewed activation lines (`no username admin`,
RADIUS host/group/source, console/default login lists, local command
authorization, `management ssh` password protocol), committed with
`configure session R1-2FA-PILOT commit timer 00:10:00`. On EOS 4.36.2F the help
text for `commit timer` states: *"commit session with a timeout. If not
committed within this time, config will be reverted."* The arm time is recorded
before the commit, so the reported remaining time is never overstated.

The post-Stage-2 contract (all required before `confirm`):

- `nmas-admin` password + current TOTP → ACCEPT; password only → REJECT;
- `admin` remote login → REJECT;
- `nmas-automation` login, Health, NSOT, running-config retrieval → PASS;
- `r1-breakglass` login and docker-exec privileged Cli → PASS.

**Live EOS timer shape (observed 2026-09-28).** While the timer runs, the
session itself reads `"state": "committed"`; the pending timer is reported only
at top level of `show configuration sessions detail | json` as
`commitTimerSessionName` / `commitTimerExpireTime`. The helper marks that
session timer-pending (open for every gate) and reports the remaining time from
the device's own expiry.

**First live Stage 2 (2026-09-28).** Stage 2 applied the exact candidate under
the timer. privacyIDEA audit during the window: `admin` → rejected (*User
does not exist* — the local-miss fall-through to RADIUS works), `nmas-admin`
password only → rejected (*wrong otp pin*), `nmas-admin` password + TOTP →
accepted. The helper then refused to record its own verification evidence:
the lab's short `admin` password matched the ordinary username `admin` in the
evidence. Without recorded evidence `confirm` is refused, so the timer
reverted R1 automatically. Evidence refusal now checks only secrets of at
least 12 characters (short login-only values and 6-digit TOTPs are never
written to evidence and remain covered by output redaction).

`confirm` runs `configure session R1-2FA-PILOT commit` from exec mode. If any
check fails, do not confirm: the timer reverts automatically. `abort` is not
used to revert a running timer (unproven). `status` reports the timer as
`NOT_ARMED`, `ARMED` (with remaining seconds), `CONFIRMED`, `AUTO_REVERTED` or
`UNKNOWN`.

## 8. Tests

`web/core/tests/test_r1_mfa_pilot.py` uses an in-memory EOS simulator and fake
TEST-ONLY secrets: argv/environment/stdin-only transport, stdout/stderr and
parser-echo redaction, process-table detection, candidate/pre-state digest
mismatch, wrong device, missing approval, infrastructure/reachability/ref
gates, checkpoint ordering and overwrite refusal, account-stage gates, timer
state handling, failed verification preventing confirm, auto-revert, restore
MD5 use and tamper detection, fleet identity outside R1, and evidence secret
refusal.
Accounting behavior is simulated: masked secrets for parsed commands, verbatim
rejected commands; a failing canary pre-flight must never send a real secret.

`web/core/tests/test_r1_mfa_postpilot.py` covers section 9 with the same
simulator plus a fake privacyIDEA metadata runner and a simulated
SSH → RADIUS → privacyIDEA path (every result class, every guard and gate).

## 9. Post-pilot operations

### 9.1 `verify-positive` — routine, positive-only 2FA check

The factor matrix (`monitoring/runtime/human-mfa/nmas_admin_radius_matrix.py`,
runtime-only) deliberately produces about five failures and privacyIDEA locks
the token at 10, so it is reserved for controlled tests. `verify-logins
--phase post-stage2` also sends a deliberate password-only and `admin`
attempt. `verify-positive` is the routine check:

1. **Guards, all before anything is requested or sent:** FreeRADIUS container
   healthy; privacyIDEA containers healthy; token `TOTP0001522E` readable,
   type `totp`, owner `nmas-admin`, active, not locked, not revoked,
   `failcount < 9`; TCP/22 to R1 answers; R1 `show radius` counters and the
   privacyIDEA audit baseline are readable. A failed guard refuses with
   *NO login attempt was sent*.
2. **Factors** are then read with `getpass` from the terminal (not echoed);
   the code must be 6 digits or nothing is sent.
3. **Exactly one attempt:** one SSH connection, one
   `auth_password(..., fallback=False)` (no keyboard-interactive fallback, no
   keys/agent, no retry), then `show privilege`. No `admin`, password-only,
   wrong, expired or replayed factor is ever sent.
4. **Attribution** from read-only evidence only — R1 `show radius` counter
   deltas and the privacyIDEA audit rows written since the baseline:

   | Result | Evidence |
   |---|---|
   | `AUTH_SUCCESS` | SSH accepted; one RADIUS Access-Accept; privacyIDEA ACCEPT |
   | `AUTH_SUCCESS_COMMAND_DENIED` | as above, but `% Authorization denied` for the command (authentication succeeded) |
   | `PRIVACYIDEA_REJECT` | privacyIDEA REJECT row + one Access-Reject; sanitized reason (e.g. `wrong otp pin`) |
   | `RADIUS_TRANSPORT_FAILURE` | no privacyIDEA row and the request unanswered (EOS → FreeRADIUS), or rejected without a privacyIDEA decision (FreeRADIUS → privacyIDEA); or privacyIDEA accepted but R1 received no reply |
   | `EOS_REJECT_AFTER_RADIUS_ACCEPT` | privacyIDEA ACCEPT + Access-Accept, SSH login failed |
   | `R1_SSH_UNREACHABLE` | TCP/SSH handshake failed; nothing was authenticated |
   | `UNKNOWN` | more than one request/row since the baseline, SSH accepted without central evidence, or evidence unreadable |

5. Evidence step `verify:positive` (result, reason, SSH stage, counter deltas,
   sanitized audit rows, token flags before/after). Factors never reach argv,
   the environment, output or evidence. The policy row is **not** changed.

Lockout impact: a success consumes nothing (privacyIDEA resets the failcount);
a failure consumes exactly one.

### 9.2 `record-verification` — R1 policy metadata from recorded evidence

Model semantics (`DeviceLoginMfaPolicy`): `central_aaa_state` is
`PLANNED`/`CONFIGURED`/`VERIFIED`; `enforcement_state=LIVE_VERIFIED`
("applied and independently verified, single-factor refused") requires
`last_verified_at` and `central_aaa_state=VERIFIED`. `confirm` only sets
`ENFORCED`. `record-verification` performs the evidence-backed transition for
the **R1 row only** after the approval phrase is typed on the terminal, and
only when every gate holds:

- R1 row exists with mechanism `RADIUS_TOTP` and is `ENFORCED` (or already
  `LIVE_VERIFIED`);
- a passing `verify:post-stage2` exists since the last armed Stage 2, with
  every required check true (password + TOTP accepted, password-only
  rejected, `admin` rejected, both pilot accounts, NMAS identity, fleet
  identity unchanged, Health, NSOT, config retrieval, docker-exec);
- a passing `confirm` follows it, and its `running_digest_after` equals R1's
  current running-config digest;
- the commit timer is `CONFIRMED`; no checkpoint was restored since confirm;
- startup-config equals running-config (volatile headers excluded), i.e. the
  configuration is persistent;
- no configuration session is open.

Transition: `central_aaa_state PLANNED → VERIFIED`, `enforcement_state
ENFORCED → LIVE_VERIFIED`, `last_verified_at` = the **verification
evidence's own timestamp** (never the wall clock), `last_verification_result =
"verify:post-stage2 PASS evidence#<id>"`. The row change and its
`record-verification` evidence commit in one transaction; a failed gate
changes nothing and writes nothing. Other devices' rows are never touched.
Rollback: `replace` (section 5) resets the row.

### 9.3 Runtime state after the pilot (not source-controlled)

Recorded here so the runtime is reproducible; no secret values:

- R1 running-config persisted with `write memory` (startup equals running,
  volatile headers excluded). The checkpoints on flash are unchanged.
- privacyIDEA 3.13.4 overwrites a TOTP token's `timeShift` after every
  successful authentication, and `HMAC.checkOtp` checks `range(c - w, c + w)`
  (end-exclusive). With a 30 s window (w = 1) only the previous and current
  codes are checked, so a learned shift down to −29 s rejects the current
  code 29 s out of 30. Token `TOTP0001522E` therefore has a **token-level**
  `timeWindow=60` (w = 2, current code always accepted for shifts in
  [−29, 0]; up to four codes valid at a time; replay of a used code still
  refused) and its `timeShift` was reset to 0. Global `totp.timeWindow=30`,
  `AutoResync=False` and the fixture token are unchanged.
- The `nmas-admin` user-store password (exposed in a transcript) was rotated
  through a local no-echo prompt; the user store and
  `monitoring/runtime/human-mfa/secrets/nmas_admin_password` match, and the
  obsolete backup copies were deleted (logical deletion only).
