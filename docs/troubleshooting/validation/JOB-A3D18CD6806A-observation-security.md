# JOB-A3D18CD6806A — Observation security and provisioning package (subtask s2)

> Historical pre-authorization-registry review. The final compatibility package adds migration `0039` and enforceable
> `ObservationAuthorization` records. Observation execution now requires the full `OBSAUTH-…#sha256=…` reference. Use
> `independent-production-deployment-acceptance.md` and `observation-runner.md` for the accepted procedure.

Date: 2026-11-12. Author: worker `claude_b` (job JOB-409BD5E77C0B). Scope: documentation only, plus one empty protected directory.
**Nothing was deployed, granted, approved, connected or contacted.** No credential, key or `known_hosts` file was read; no
fingerprint was invented. Every statement is tagged **[code]** (read from source in this worktree), **[gateway-src]** (read from the
world-readable gateway source/client), **[run]** (observed in this run) or **[GAP]** (not confirmed; owner named).

Worktree: `/home/student/Scripts/nmas-public-dev-troubleshooting`, base `4f950b3`, migration `0038_device_observations` (depends on
`0037_troubleshooting`). Migration 0038 and `observation_*` are untracked/uncommitted work in this worktree [code].

## 1. Verdict

| Question | Answer |
|---|---|
| Can the nine devices be observed today? | **No.** Three independent fail-closed blockers (below). That is correct behaviour, not a bug. |
| Blocker A — host-key pins | `inventory.yml` in this worktree has **no `ssh_host_key` for any device**. Every legacy-route request is refused `PIN_MISSING`. Approved-path pins (`ManagementPath.expected_host_key`) live in the production DB, which was **not read** [GAP]. |
| Blocker B — trusted source | `settings.NMAS_OBSERVATION_SOURCES` is not defined in `web/config/settings.py` (neither here nor in `clab_dualstack_lab-deploy`), so `trusted_sources()` returns `{}` and `device_observe` fails `SOURCE_UNCONFIGURED` before connecting [code]. |
| Blocker C — production lineage | `nmas-web.service` runs `WorkingDirectory=/home/student/Scripts/clab_dualstack_lab-deploy/web`, `EnvironmentFile=/etc/nmas/nmas-web.env` (unit file read only). That tree's newest on-disk migration is **`0035_v2_phase7_9_decommission_dynamic.py`**, HEAD `129d3f0` (legacy). `DeviceVersionObservation` (0038) does not exist there. The live DB level was not queried [GAP]. 0036→0038 must be deployed by the operator first. |
| Gateway attestation of production observations | **Not possible with any existing gateway op.** `fixture_exec` only addresses nodes of gateway-owned disposable fixtures (`node must be one of detail["nodes"]`) [gateway-src `op_fixture_exec`]. There is no op, grant or template that reaches R1–R4/S1–S4/mgmt_swt. Evidence from `device_observe` is therefore **`local-unattested`** only. A new gateway op would be a gateway-owner request (§4). |
| R5 | Excluded and stays excluded (see §3). |

## 2. Gateway permissions

### 2.1 Observed in this run [run]

`python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py help` and `whoami` succeeded for this agent (role `worker`, project
`Scripts`, root `JOB-A3D18CD6806A`) and reported **`"grants": []`**. `help` listed these ops: `help whoami python_test python_test_status
source_pin fixture_start fixture_status fixture_exec fixture_stop evidence_manifest evidence_get github_ci_status github_branch_push
sandbox_start sandbox_status sandbox_exec sandbox_stop sandbox_checkpoint sandbox_export` and templates `ceos_pair`, `ceos_peer`,
`iosxe_peer`. (The master's note listed a shorter subset; the list above is what this call returned. Whether an op is *callable* also
depends on the unreadable `grant_required` map in the root-only gateway config [GAP].) No op was invoked other than `help`/`whoami`; **no
grant refusal was encountered** because nothing needing a grant was attempted.

### 2.2 What exists in gateway source [gateway-src]

* Per-request checks: job RUNNING under lease → role op allowlist → `grant_required[op]` against `grants(root_id, grant_name, expires_at)`.
* The admin CLI can grant exactly one name: **`github_write`** (`grant ROOT_JOB github_write [HOURS]`). No observation/device/collection grant name exists.
* `fixture_exec` kinds: `show` (single-pipe filter only, `json` pipe allowed on cEOS), `config`, and `argv` for FRR peers (`commands.check_peer_argv`). Fixture only.

### 2.3 Permission table

| Need | Status | Exact name / scope |
|---|---|---|
| Read-only version/identity on gateway **fixtures** (cEOS `show version | json`, IOS XE `show version`, FRR peer argv) | **Confirmed supported** | op `fixture_exec`, kind `show`/`argv`, after `fixture_start` + `fixture_wait`; evidence via `evidence_manifest`/`evidence_get`. Grant requirement for `fixture_exec`: not visible [GAP]; today `grants=[]`. |
| Source pin attestation | Confirmed supported | op `source_pin` (CLI `pin WORKTREE`) |
| Read-only observation of the **nine production devices** through the gateway | **Not supported — request to gateway owner** | Proposed (names are *requests*, not existing): op `production_observe` (or `device_show`), restricted to allowlist `{R1,R2,R3,R4,S1,S2,S3,S4,mgmt_swt}`, commands exactly `show version | json` (cEOS) and `vtysh -c 'show version'` argv (FRR), plus a time-boxed grant e.g. `device_observe_readonly` bound to root job + expiry, recording pin/fingerprint presented, management path id and authorization ref as gateway evidence. R5 must be absent from the allowlist. |
| `github_write` etc. | Not needed, **not requested** | — |

Do not assume any grant exists. `grants=[]` means that, right now, only the local-unattested route is available, and it needs no gateway
grant at all (it uses NMAS's own broker, §5).

## 3. Per-device pin and path matrix

Source of truth: `inventory.yml` (public snapshot, commit `e0e85e6` + worktree) [code]. "Legacy route" = inventory-declared management
address, used only when the device has no registered `ManagementPath` (`management.resolve`); a registered-but-unusable path set **blocks**,
it never falls back [code]. Production registry/paths: [GAP] — not read.

| Device | Platform → NOS | Mgmt address (Vlan200) | Credential ref type (name only) | Inventory `ssh_host_key` | Approved-path pin (`ManagementPath.expected_host_key`) | Route available to `device_observe` | Result today (derived from code) |
|---|---|---|---|---|---|---|---|
| R1 | `arista_ceos` | 192.168.200.1 | password-style `credential_ref` | **absent** | unknown [GAP] | PATH only in practice (legacy cEOS requires a key-only credential; this entry has no `ssh_key_ref`) | `PIN_MISSING` (legacy) / `KEY_AUTH_UNAVAILABLE`; PATH needs registered ACTIVE+HEALTHY+APPROVED path with a valid pin |
| R2 | `arista_ceos` | 192.168.200.2 | `credential_ref` | absent | unknown [GAP] | as R1 | as R1 |
| **R3** | `ubuntu_frr` (FRR) | 192.168.200.3 | `ssh_key_ref` (key-only) | **absent** | not supported — FRR is legacy-only (`PATH_PLATFORM_UNSUPPORTED` / `ROUTE_UNSUPPORTED`) | LEGACY only | `PIN_MISSING`: **fail closed until a verified pin is added to the inventory entry** |
| **R4** | `ubuntu_frr` | 192.168.200.4 | `ssh_key_ref` | **absent** | not supported (as R3) | LEGACY only | `PIN_MISSING`, as R3 |
| S1 | `arista_ceos` | 192.168.200.11 | `credential_ref` | absent | unknown [GAP] | as R1 | as R1 |
| S2 | `arista_ceos` | 192.168.200.12 | `credential_ref` | absent | unknown [GAP] | as R1 | as R1 |
| S3 | `arista_ceos` | 192.168.200.13 | `credential_ref` | absent | unknown [GAP] | as R1 | as R1 |
| S4 | `arista_ceos` | 192.168.200.14 | `credential_ref` | absent | unknown [GAP] | as R1 | as R1 |
| mgmt_swt | `arista_ceos` | 192.168.200.10 | `credential_ref` | absent | unknown [GAP] | as R1 | as R1 |
| R5 | `arista_ceos`, `address: auto`, Management0, `edge: true` | none | none | — | — | **none** — resolver scope READ_ONLY/out of writable scope → `TARGET_NOT_MANAGEABLE` before any connection | **Excluded. Must remain excluded; do not add to any allowlist, pin file or approval.** |

Provenance of pins: **none are registered in the files I may read.** Fingerprints that appear in `docs/evidence/**` (e.g. v2-phase3/5-6/7/8
closure JSON) belong to ZTP/fixture/isolation evidence of other devices and runs; they are **not** provenance for R1–R4/S1–S4/mgmt_swt and
must not be copied into the inventory. Verified status per device: **UNVERIFIED / ABSENT (fail closed)** for all nine, including FRR R3/R4.
Conflicting-pin handling is already enforced in code: inventory pin ≠ request pin → `PIN_CHANGED`; presented ≠ pin → `HOST_KEY_MISMATCH`;
`PIN_MISSING` for anything not matching `^SHA256:[A-Za-z0-9+/]{43}$`.

### 3.1 How a pin may legitimately be obtained (operator, out of band)

A pin is acceptable only from a trusted channel, never from this agent and never from first contact with the device:
1. cEOS: read the device's own host-key fingerprint on the device console / via the existing authorized NMAS commissioning/ZTP record
   (the registered `ManagementPath.expected_host_key`, set through the existing path-registration workflow), or from the device config
   archive's `ssh-keygen -lf` of the device public key file taken from the device filesystem by an authorized admin.
2. FRR R3/R4: on the host (console or the Containerlab host's authorized administrator): `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
   inside the node (`SHA256:` form), recorded in a change ticket with operator name/time.
3. Add as `ssh_host_key: "SHA256:<43 chars>"` under `network_devices.<name>` in the **approved** inventory (a reviewed change; this task
   did not edit `inventory.yml`). Two-person review of each value against the device-side output. Never use `ssh-keyscan`, TOFU or
   `known_hosts` — the code ignores them by design.

## 4. Requests requiring gateway-owner confirmation

1. Is any grant required for `fixture_exec`/`evidence_*` for root `JOB-A3D18CD6806A`? (`grant_required` is root-only.)
2. Feasibility and design of a production-read op (§2.3), including: command allowlist reuse of `commands.check_show`, per-device allowlist,
   pin supplied from NMAS-approved metadata and compared by the gateway, evidence record with presented fingerprint and path id.
3. Whether `observation_connections.ObservationConnectionFactory` should be replaced by (or wrapped in) a gateway `NetmikoAdapter`
   equivalent for production nodes. Until then the only attestable runs are fixture runs, which prove code paths, not device identity.

## 5. Security architecture (as implemented) [code]

| Control | Implementation |
|---|---|
| Broker credential isolation | `ObservationConnectionFactory` never reads credentials; references (`runtime://device-credentials/...`) are resolved inside `nsot_live.get_live_target` / `linux_ssh.target` at connect time. `device_observe` accepts no secret argument. Errors carry only stable codes. |
| Authorized management path | Endpoint re-resolved twice (provider and factory) via `management.resolve.endpoint(purpose=READ)`; address/port/source/path-id change → `ENDPOINT_CHANGED`; BLOCKED → `PATH_BLOCKED`, no fallback to legacy/Docker/Containerlab; PATH must pass `guard.authorized_target`; `guard.address_problems` forbids loopback/link-local/Docker/clab. |
| Host-key pinning | Pin must be well-formed; cEOS PATH uses the path's own pin; legacy uses inventory pin; presented key read back from the live transport and must equal the pin before any command is sent. |
| Command restriction | Only `observations.SPECS[platform].command` (`show version | json`; FRR argv from `linux_ssh.frr_show("show version")`); anything else → `CommandNotPermitted`/`PermissionError`. |
| Source pinning / signing | HMAC-SHA256 over device, source id, nonce, command, instant, host key, evidence ref, raw digest. Key ≥32 bytes read from the env var named in `NMAS_OBSERVATION_SOURCES[<id>]["key_env"]` at use time; nonce replay and out-of-order refused; stale >3600 s refused. |
| Scope | Resolver `WRITABLE_SCOPES` only; R5 refused pre-connection. Identity is only *recorded* (`AUTHENTICATED_SESSION`, can only deny); `verify_identity`/admission remain separate human actions by someone other than the recorder. |
| Authorization reference | Required non-blank string retained in the evidence JSON. The signed evidence_ref includes the file digest, indirectly binding that string; it is not a field of the canonical HMAC envelope. **Code does not validate its scope or expiry** — it is a label. Scope/expiry must be enforced procedurally (§7) and recorded in the evidence file; a code-enforced approval registry is a recommended follow-up, not present. |
| Evidence | Local sink: absolute existing dir under `/home/student/Scripts` or `/home/student/clab-quickstart`, not group/world-writable, exclusive atomic write 0600, `local-unattested:<file>#sha256=<hex>` reference, re-verifiable with `observation_evidence.verify_reference`. Local ≠ gateway-attested; only gateway-recorded evidence counts as live. |

Known limitations to state in any report: (a) the sink checks the directory is not group/world-*writable* but does **not** require 0700 or
check ownership; (b) the authorization ref is not validated; (c) the sink does not enforce retention.

## 6. Protected evidence directory

Created by worker (empty): `/home/student/Scripts/JOB-A3D18CD6806A-observation-evidence`, mode **0700**, owner `aiagent-claude-b` (the sandbox identity
that created it). Path did not exist beforehand; no existing path was touched or loosened. Parent `/home/student/Scripts` is `drwxrwxr-x`
owned by `aiagent-claude-b`.

Validator stat on 2026-11-12 reports mode 0700 and owner/group `aiagent-codex:aiagent-codex` in this execution namespace; the worker reported `aiagent-claude-b`. Neither establishes access for production user `student`. No ownership change was performed.

**Ownership gap [GAP]:** `nmas-web.service` and the operator run as user `student` (uid 1001). A 0700 directory owned by another uid is not
writable by `student`, so `validate_directory` would answer `DIRECTORY_NOT_WRITABLE`. Operator action (privileged, not done here):
`sudo chown student:student /home/student/Scripts/JOB-A3D18CD6806A-observation-evidence` (keep 0700). Never `chmod g+w`/`o+w` — the sink
refuses that anyway (`DIRECTORY_TOO_PERMISSIVE`).

Retention policy (proposal for operator approval): keep files ≥ 400 days, read-only after write (`chmod 0400` is applied by the operator
after capture; the sink never overwrites), append the sha256 of each file to a signed change record, back up to a location outside the
approved development roots only by authorized operator action; do not delete during an open identity-verification case.

## 7. Provisioning template (placeholders only)

Do not run anything here until the operator approves. No secret value appears in this document, shell history or arguments.

```
# 1. Operator-only: generate the HMAC key into the service environment file, without echoing it. (Run as root by the operator.)
#    Variable name is a placeholder choice; it must match key_env below. Minimum 32 characters.
umask 077
printf 'NMAS_OBSERVATION_KEY_<SOURCE>=%s\n' "$(openssl rand -hex 32)" | sudo tee -a /etc/nmas/nmas-web.env.new >/dev/null   # review and merge into /etc/nmas/nmas-web.env per change process
# (Never print, commit or paste the value. For the one-shot command use an environment export in a protected shell, not an argument.)

# 2. Reviewed settings change (web/config/settings.py or the deployment overlay):
NMAS_OBSERVATION_SOURCES = {
    "<source-id>": {                       # [A-Za-z0-9._-]{1,64}, e.g. nmas-operator-observer-v1
        "key_env": "NMAS_OBSERVATION_KEY_<SOURCE>",
        "platforms": ["arista_ceos", "ubuntu_frr"],
    },
}
```

Authorization reference format (convention; enforced by operator review, not code):
`<ticket-id>|devices=<comma list from R1,R2,R3,R4,S1,S2,S3,S4,mgmt_swt>|cmd=version-readonly|approver=<name>|expires=<UTC ISO>`
— at most 24 h validity, devices must not include R5, one reference per approval window, recorded in the change ticket; the same string is
passed as `--authorization-ref` and stored in every evidence file (`authorization_ref`). Any file captured after `expires` is rejected in review.

## 8. Operator procedure after approval

Prerequisites, in order (each is an operator/approver action; this package performs none):
1. Deploy public lineage migrations 0036→0038 to production per the deployment runbook; confirm `showmigrations core | tail -3` shows 0038 applied.
2. Verify, for each of the nine devices, a pin (§3.1) — either `ssh_host_key` in inventory (FRR R3/R4 mandatory; cEOS legacy) or a registered, ACTIVE/HEALTHY/APPROVED `ManagementPath` with `expected_host_key` (cEOS preferred).
3. Confirm credential enrollment in the broker (cEOS PATH: any enrolled candidate; cEOS legacy and FRR: key reference enrolled). Do not read the secrets.
4. Apply §7 settings and key; chown the evidence directory (§6).
5. Dry preflight (no connection): command of §9.1 expected refusals prove each gate.

Per-device command (run by `student` in `web/`, with the production env loaded by the operator's shell, never inline secrets):

```
cd <approved NMAS checkout>/web
for D in R1 R2 R3 R4 S1 S2 S3 S4 mgmt_swt; do
  python manage.py device_observe --device "$D" --source <source-id> \
    --authorization-ref "$AUTH_REF" \
    --evidence-dir /home/student/Scripts/JOB-A3D18CD6806A-observation-evidence || { echo "REFUSED $D"; break; }
done
```
Do not loop over R5, do not use `--device` values outside the list. Stop the loop on the first unexpected failure.

### 8.1 Expected outputs

* Success: `observed <dev>: version=<x.y.z> evidence_ref=local-unattested:obs-<dev>-<utc>-<nonce>.json#sha256=<hex> (local, unattested; identity NOT verified, device NOT admitted)`; then `observation_evidence.verify_reference` must pass.
* Refusals before connection (`CommandError`): `SOURCE_UNCONFIGURED`, `DIRECTORY_*` (`NOT_ABSOLUTE`, `MISSING`, `OUTSIDE_APPROVED_ROOTS`, `TOO_PERMISSIVE`, `NOT_WRITABLE`), `TARGET_UNKNOWN`, `TARGET_NOT_MANAGEABLE` (R5).
* After resolution: `observation refused: <code> (session: <code>)`, e.g. `SESSION_UNAVAILABLE` + `PATH_BLOCKED` / `ENDPOINT_*`, `CONNECTION_FAILED` with factory codes `PIN_MISSING`, `PIN_CHANGED`, `KEY_AUTH_UNAVAILABLE`, `CREDENTIAL_UNAVAILABLE`, `AUTH_FAILED`, `HOST_KEY_MISMATCH`, `HOST_KEY_UNOBSERVED`.
* Collector/ingest: `EVIDENCE_UNAVAILABLE`, `OUTPUT_EMPTY`, `PARSE_FAILED`, `REPLAY`, `OBSERVATION_STALE`, `IDENTITY_MISMATCH`, `DEVICE_EXCLUDED`.

Predicted *today* (no settings, no pins): every device ends `SOURCE_UNCONFIGURED` before any connection. After step 4 but without pins: R3/R4 `SESSION_UNAVAILABLE`/`PIN_MISSING`; cEOS legacy `PIN_MISSING`. These are predictions from code, not live results.

## 9. Verification and rollback

### 9.1 Safe preflight (no network)
Using only a temporary directory and the development test DB:
`cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_observation_evidence core.tests.test_device_observe core.tests.test_observation_collector core.tests.test_observation_connections core.tests.test_observation_sessions core.tests.test_device_observations --noinput --parallel 1`

### 9.2 Operational risks
* Credentials: a mis-resolved broker ref could authenticate the wrong account; mitigated by read purpose and fixed service-account names (`nmas-automation`).
* Wrong pin is accepted if entered wrongly (the pin *is* the trust anchor) → two-person review.
* Authorization ref is a label; scope/expiry drift is possible without procedure.
* Evidence files contain full raw `show version` output (serials, MACs) → keep 0700/0400, do not copy outside approved roots.
* cEOS legacy route cannot work without an enrolled key; do not "fix" by enabling password auth on the pinned legacy transport.
* Observations are **not** identity verification; do not describe results as admission or live gateway evidence.
* Production migration/restart (0036–0038) is a service-impacting deployment; schedule and roll back separately.

### 9.3 Rollback (all reversible without touching devices)
1. Remove the `NMAS_OBSERVATION_SOURCES` entry and its env variable (rotate/delete key) → `SOURCE_UNCONFIGURED`.
2. Revert the inventory pin additions / unregister the observation-related path changes through their existing workflows.
3. Leave captured evidence in place (do not delete); `chmod 0400` if still writable. Optionally `rmdir` the directory only while empty.
4. `DeviceVersionObservation` rows are append-only; do not delete by hand. Un-applying 0038 (`migrate core 0037`) drops the observation table and is an operator-approved production action only.

## 10. Test results (local, development-only, no network, no production settings)

`cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_observation_evidence core.tests.test_device_observe core.tests.test_observation_collector core.tests.test_observation_connections core.tests.test_observation_sessions core.tests.test_device_observations --noinput --parallel 1`
→ **Ran 84 tests, OK** (7.2 s), temporary test DB, injected fakes. **Local only — not gateway-attested, not live evidence.**
Gateway grant refusals encountered: **none** (no grant-gated op attempted). Gateway live evidence produced: **0**.

## 11. Evidence gaps (summary)

1. No pins exist in readable inventory for any of the nine devices (R3/R4 included).
2. Production DB: migration level, device registry and `ManagementPath` rows not read.
3. `grant_required` mapping and any `fixture_exec` grant requirement not visible.
4. No gateway op reaches production devices; gateway attestation of live observation needs a gateway-owner change.
5. Authorization-reference scope/expiry is not code-enforced; sink does not require 0700/ownership.
6. Evidence directory ownership must be changed to `student` by an operator.
