# JOB-A3D18CD6806A / s1 — production deployment audit and migration/runtime approval runbook

> Historical pre-package audit. The accepted compatibility candidate now includes migration `0039`, the deployment tool and the
> independent package review. Use `independent-production-deployment-acceptance.md` and `compat-deployment.md` for current approval and
> execution evidence.

Date: 2026-11-12. Author: worker `claude_a` (subtask s1 of JOB-A3D18CD6806A, NMAS V2 Task 1). Worktree
`/home/student/Scripts/nmas-public-dev-troubleshooting`, HEAD `4f950b3`, uncommitted overlay preserved. Related: original admission job
JOB-E78CED9B29DE (checkpoint #28) and troubleshooting job JOB-9AA10B4E7CA7 (checkpoint #23). Both are preserved and not restarted.

**Nothing was deployed, migrated, granted, provisioned, verified, admitted, committed or staged. No production database, `.env` file or credential
file was opened. No device or network host was contacted.** Every command in §6 onward is a *proposal for an operator*; none was run
against production.

## 0. Evidence classes used in this file

| Tag | Meaning |
|---|---|
| **FRESH** | Observed in this session by credential-free, read-only inspection (file listing, tracked source, unit-file directives, local `cmp`/`diff`). |
| **LOCAL** | Result of a local command against the worktree's own dev SQLite (`web/db.sqlite3`, not production). Proves code shape, not production state. |
| **HISTORICAL** | Claimed in an earlier report; **not** re-confirmed here. Do not rely on it for approval. |
| **UNAVAILABLE** | Cannot be established from this sandbox. The operator must run the protected audit in §5. |

## 1. Fresh facts (FRESH / LOCAL)

### 1.1 Production deployment source

| Fact | Evidence |
|---|---|
| `nmas-web.service` runs `gunicorn ... config.wsgi:application` as `User=student` from `WorkingDirectory=/home/student/Scripts/clab_dualstack_lab-deploy/web`, with `EnvironmentFile=/etc/nmas/nmas-web.env` (mode 0640; **not opened**). | `grep` of `/etc/systemd/system/nmas-web.service` for directive names `WorkingDirectory/ExecStart/User/EnvironmentFile` only. FRESH |
| `maintenance_tick` and `probation_soak_tick` oneshot units use the same working directory and env file; `nmas-credential-rotation.service` runs `manage.py rotate_due_credentials` from the same tree with `monitoring/runtime/credential-rotation.env` (**not opened**). | Same method. FRESH |
| Other NMAS units (`nmas-topology`, `nmas-syslog-ingest`, `nmas-gnmi-collector`, `nmas-traffic-runner`, `nmas-demo-telemetry`) do **not** run the Django `core` package from the deploy tree (they run files under `/etc/nmas-*`, `/usr/local/lib/nmas-traffic-runner`, or a separate `clab_dualstack_lab-v2-decommission-p7` script). Exception: `nmas-demo-telemetry` is a separate tree and is unaffected. | Same method. FRESH |
| The deploy tree is a git checkout at `129d3f090f8b94b982178b1e8f3ec51047278068`, branch `deploy/lab8-production-20261102`, origin `https://github.com/Dhruv-Suvarna/Adv-Netman.git` (the **legacy/private** lineage, not `Adv-Netman-public-ci`). | `git rev-parse/branch/remote -v` in the deploy tree. FRESH |
| The deploy tree is **dirty**: 16 status lines, of which 13 are modified tracked files (`deploy/scripts/install_traffic_runner.sh`; `web/core/services/{commissioning/admission.py, commissioning/service.py, health/evaluators.py, isolation/{eos,intent,service}.py, provisioning/lifecycle.py, provisioning_service.py, topology_service.py, traffic/runner/config.py, ztp/workflow.py}`; `web/core/tests/test_provisioning.py`) and 3 untracked (`DELIVERABLE_1_IAC_FRAMEWORK_SUMMARY.md`, `web/core/tests/test_isolation_admission_ospf_release.py`, `web/db.sqlite3.pre-phase5-20261006T080441Z`). All 13 modified files differ from the public worktree. | `git status --short` plus `cmp` against the worktree. FRESH |
| Whole-package divergence: `diff -rq web/core` between deploy tree and worktree reports **247** differing/only-in-one-side entries (excluding `__pycache__`); `git ls-files web/core` counts 910 (deploy) versus 951 (worktree). The public worktree is therefore **not** a patch on the running tree. | `diff -rq`, `git ls-files`. FRESH |
| `inventory.yml` differs between the trees. The deploy copy carries `ceos_username`, `ceos_credential_ref: runtime://device-credentials/ceos-admin-shared` and `linux_root_credential_ref: runtime://device-credentials/linux-root-shared` (reference names only; no secret values are in the file) and comments describing a legacy shared-fleet fallback; the public copy removes these and states "no shared fallback". Neither copy has a literal `ssh_host_key` for any device (count 0 in both). | `diff`, `grep -c ssh_host_key`. FRESH |
| The production SQLite file `web/db.sqlite3` is 26,181,632 bytes with mtime `2026-11-12 12:58` (today), which alone does not prove active use. Its content was **not** read. | `ls -la`. FRESH |
| `web/config/settings.py` (tracked source, not the loaded production settings) contains **no** `NMAS_OBSERVATION_SOURCES`, `NMAS_TS_DEPLOYMENT` or `NMAS_TS_RUNTIME_FACTORY`. A source cannot be registered by an environment variable alone; a reviewed settings change is required (see §3.2). | `grep` in the worktree `web/config/settings.py`. FRESH |
| systemd is not booted in this sandbox (`systemctl: Failed to connect to bus`) and no `gunicorn` process is visible. Whether `nmas-web.service` is active now is **UNAVAILABLE**. | `systemctl list-units`, `ps`. FRESH |

### 1.2 Migration lineage

| Fact | Evidence |
|---|---|
| Latest migration file in the deploy tree is `0035_v2_phase7_9_decommission_dynamic.py`; the tree holds 37 files in `web/core/migrations` (including `__init__.py`). | `ls`. FRESH |
| Migrations `0001`–`0035` are **byte-identical** between the deploy tree and the public worktree (`cmp` reported no difference). The public worktree adds exactly `0036_v2_phase9_relay_option82_readback` (CreateModel `DhcpRelayReadback`), `0037_troubleshooting` (18 `Ts*` models, 4 constraints, 2 indexes) and `0038_device_observations` (CreateModel `DeviceVersionObservation`). | `cmp` loop; `ls`. FRESH |
| Dependency chain: `0036 -> 0035`, `0037 -> 0036` (per `docs/troubleshooting/deployment-rollback.md`), `0038 -> 0037` (file header of `web/core/migrations/0038_device_observations.py`). `0038` also requires `core.manageddevice` and `core.deviceobservation`; the latter is created in `0031_v2_lifecycle_device_identity.py`. **0038 cannot be applied without 0036 and 0037.** | Source files. FRESH |
| `0038` is a single `CreateModel`: unique constraint `unique_version_observation_nonce (source_id, nonce)`, index `(device, -observed_at)`, `PROTECT` foreign keys to `ManagedDevice` and `DeviceObservation`. `sqlmigrate core 0038` emits one `CREATE TABLE core_deviceversionobservation` and two FK indexes plus the composite index inside `BEGIN/COMMIT`. It touches no existing table. | `manage.py sqlmigrate core 0038` (LOCAL, dev DB). |
| `makemigrations core --check --dry-run`: "No changes detected in app 'core'". | LOCAL |
| The *applied* migration level of the production database is **UNAVAILABLE** (database not opened). The file set ends at 0035, so 0035 is the highest level the deploy tree's code could have applied, but it could be lower. | See §5.3 to obtain it. |

### 1.3 Observation code that the deployment must bring

Present in the worktree only (the deploy tree's `web/core/services/devices/` contains no `observation*.py`): FRESH
- `web/core/services/devices/observations.py` — signed-envelope ingest, `trusted_sources()` reading `settings.NMAS_OBSERVATION_SOURCES[<id>]["key_env"]` (key length ≥ 32, never stored), `observed_version()`.
- `observation_connections.py` — broker-backed connection factory. Reuses `management.resolve.endpoint`, `nsot_live.get_live_target`, `ssh_transport.connect_eos`, `linux_ssh.connect_found`. Re-resolves the endpoint right before connecting, checks the pin before authentication, refuses on any change, and reads no credential itself (`runtime://` references are resolved inside the existing helpers). cEOS legacy route is key-only; FRR is legacy source only (`ROUTE_UNSUPPORTED` otherwise). A pin must match `^SHA256:[A-Za-z0-9+/]{43}$`.
- `observation_sessions.py`, `observation_collector.py`, `observation_evidence.py` (local, `local-unattested:` sink under `/home/student/Scripts` or `/home/student/clab-quickstart`, directory not group/world-writable), and `management/commands/device_observe.py` (`--device --source --authorization-ref --evidence-dir`, all required).
- Runtime binding provider `services/troubleshooting/adapters/nmas_providers.py` with `RECOMMENDED_BINDING = {inventory, lifecycle_provider, version_provider}`.
- `docs/troubleshooting/observation-runner.md` states "Production database must be at the migration that provides `DeviceVersionObservation` (0038_device_observations); verify, do not assume."

### 1.4 Device registry and management resolver (as shipped in the worktree; LOCAL/FRESH)

`inventory.yml` in the worktree declares `network_devices` R1–R5, S1–S4, `mgmt_swt`. R5 is `edge: true` with monitoring address `auto` and is excluded from writable scope (`resolver.adoption_scope` -> `OUT_OF_WRITABLE_SCOPE`, per `JOB-9AA10B4E7CA7-phase1-readiness.md` §4 and the resolver's `WRITABLE_SCOPES = {WRITABLE, WRITABLE_RESTRICTED}`). Eligible set = 9 devices: R1–R4, S1–S4, `mgmt_swt`. Neither inventory file holds a host-key pin; the cEOS "approved path" route takes its pin from a registered `ManagementPath.expected_host_key` row in the database (unknown), and the legacy route reads `ssh_host_key` from the inventory (currently **absent**, so the legacy route returns `PIN_MISSING`/`PIN_CHANGED`). The database-side registry (`ManagedDevice`, `ManagementPath`, lifecycle/identity state) is **UNAVAILABLE**; the saved matrix `JOB-E78CED9B29DE-device-readiness.json` is development DB state and is not production evidence.

### 1.5 Gateway (FRESH)

`python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py help` in this worker returned `"grants": []`. The ops list in this worker's response additionally included `python_test`, `python_test_status`, `fixture_*`, `sandbox_*`, `github_branch_push`; the master's brief listed a shorter set. No active grants were reported; that alone does not establish which operations require grants. The exact grant is outside this file's scope (security/provisioning report). The Slack-style assumption that a grant is available is **not** made.

## 2. Historical claims that this audit does not rely on (HISTORICAL)

- "Production is at migration 0035 on the legacy origin at `129d3f0`" (phase1-readiness §1): source tree and HEAD are re-confirmed (§1.1/1.2); the *applied DB level* is not.
- "Production registry could not be read" (phase1-readiness §4): still true here.
- "837 gateway-attested regressions" (JOB-E78CED9B29DE checkpoint): cover earlier code, not the 0038/observation overlay.
- Local test counts in continuation/phase1-readiness (719–720 troubleshooting tests, 8,746 `core` tests, 153 connection tests, 126/60 s1/s2 tests): local, unrepeated here.
- Baseline "4.36.2F" in `AGENTS.md`: documentation, not an observation; unused by the code.

## 3. Findings that block or shape deployment

1. **Lineage mismatch is the primary approval risk.** Production tree = legacy origin `Adv-Netman` with 13 uncommitted modified files; the new schema/code lives in the public lineage (`Adv-Netman-public-ci`, HEAD `4f950b3` + uncommitted overlay). The overlay is not committed or pushed, so there is no reviewable immutable revision to deploy. Migrations 0001–0035 are identical, so the schema history is compatible; the *code* is not (247 differing entries). Copying the worktree over production would silently drop the 13 uncommitted production edits. No such copy is proposed without explicit decision (§7, option A/B).
2. **No source registration exists.** `NMAS_OBSERVATION_SOURCES` is read via `getattr(settings, ...)` and is absent from `config/settings.py`; `trusted_sources()` therefore returns `{}` and `device_observe` stops with `SOURCE_UNCONFIGURED` before contacting anything. Provisioning needs (a) a reviewed settings change registering `{source_id: {"key_env": "<ENV>", "platforms": [...]}}`, and (b) a ≥32-byte key placed in the *process environment that runs the collector* by the operator (never in a repository, argument, or this report). The HMAC key must equally be available to whichever process runs `ingest`; `device_observe` does both in one process.
3. **Runtime binding is also absent.** `NMAS_TS_DEPLOYMENT` is undefined, so troubleshooting admission answers `LIFECYCLE_UNKNOWN` for every device; `version_provider` stays fail-closed until observations are ingested, identities are VERIFIED and host keys match (`observations.observed_version`). This is the intended fail-closed state; binding it is a reviewed settings step, separate from schema deployment.
4. **Pins are not present in the inventory.** Legacy cEOS route needs `ssh_host_key` (absent in both inventories); approved-path route needs `ManagementPath.expected_host_key` (DB, unknown). R3/R4 (Ubuntu/FRR) use the legacy source only and likewise need a pin. Accepting a host key is a separate human decision and is **not** done here.
5. **Credentials.** The factory resolves `runtime://` references inside existing helpers at connection time, under the OS user running the command. The web unit runs as `student` with `/etc/nmas/nmas-web.env`; whether the broker is reachable from a manual shell is **UNAVAILABLE**. Do not source `/etc/nmas/nmas-web.env` into an interactive shell to "make it work"; use the operator-approved mechanism.
6. **Public inventory removes the shared credential fallback** that the deploy `inventory.yml` documents as a transition path. Switching the deploy tree to the public inventory is a behaviour change for device access, not only a schema change; it must be reviewed by the credential owner (§7, option A).

## 4. Affected services (if the reviewed code + 0036–0038 are deployed)

| Service | Effect | Action |
|---|---|---|
| `nmas-web.service` (gunicorn, imports `core`) | Loads new models/URLs/middleware; must be restarted after code + migrate. Brief unavailability. | Controlled restart in approved window. |
| `nmas-maintenance-tick`, `nmas-probation-soak-tick` (timers; oneshot Django) | Run against the same DB and tree; a tick during migration may hit a half-migrated schema (SQLite file lock). | Stop the two timers before backup/migrate, start after verification. |
| `nmas-credential-rotation` (oneshot Django) | Same tree/DB; same race. | Stop/pause timer if one exists for it; otherwise confirm no run is scheduled in the window. |
| `nmas-topology`, `nmas-syslog-ingest`, `nmas-gnmi-collector`, `nmas-traffic-runner`, `aiorch-gateway`, `cloudflared-nmas` | Do not import `core` from the deploy tree per §1.1. `nmas-traffic-runner` is installed by `deploy/scripts/install_traffic_runner.sh`, one of the 13 dirty files; do not re-run the installer. | No restart; verify unchanged. |
| Orchestrator jobs JOB-E78CED9B29DE (#28), JOB-9AA10B4E7CA7 (#23) | Not touched by a deploy. | Keep paused/preserved; no restart. |

## 5. Protected read-only production audit (operator commands; UNAVAILABLE here)

Run as the production service owner on VM1 with the approvals in §8 row R. These commands only read. Do not paste any output that contains a secret; the commands below are chosen to print none.

```bash
cd /home/student/Scripts/clab_dualstack_lab-deploy/web
PY=/home/student/Scripts/.venv/bin/python

# 5.1 Source identity (expect 129d3f09..., branch deploy/lab8-production-20261102, 13 modified + 3 untracked, as in §1.1)
git -C .. rev-parse HEAD; git -C .. branch --show-current; git -C .. status --short

# 5.2 Active unit state and which tree is actually serving
systemctl is-active nmas-web.service nmas-maintenance-tick.timer nmas-probation-soak-tick.timer nmas-credential-rotation.timer 2>&1
systemctl show nmas-web.service -p ExecStart -p WorkingDirectory -p MainPID --no-pager
sudo readlink /proc/$(systemctl show -p MainPID --value nmas-web.service)/cwd   # expect .../clab_dualstack_lab-deploy/web

# 5.3 Applied migration level. Reads django_migrations only; does NOT print settings or env.
#     The unit's EnvironmentFile must be supplied by systemd-run or an approved wrapper, not echoed.
sudo systemd-run --pipe --wait -p User=student -p WorkingDirectory=$PWD \
    -p EnvironmentFile=/etc/nmas/nmas-web.env $PY manage.py showmigrations core 2>&1 | tail -8
# Expected today if HISTORICAL claim holds: [X] through 0035; no 0036/0037/0038 lines (files absent in the deploy tree).
# Any unapplied earlier migration (an [ ] before 0035) is a STOP: do not proceed to §6.

# 5.4 Registry counts only (no field values). Read-only SQLite URI; no row content is printed.
sqlite3 'file:db.sqlite3?mode=ro' "select count(*) from core_manageddevice; select lifecycle_state, count(*) from core_manageddevice group by 1;" 2>&1
sqlite3 'file:db.sqlite3?mode=ro' "select count(*) from core_deviceobservation;" 2>&1
sqlite3 'file:db.sqlite3?mode=ro' "select name from sqlite_master where name in ('core_deviceversionobservation','core_dhcprelayreadback') or name like 'core_ts%';" 2>&1
# Expected before deployment: none of the three table families exist. If they exist, a prior partial deploy happened: STOP.

# 5.5 Management path / pin presence, names and booleans only
sqlite3 'file:db.sqlite3?mode=ro' "select device_id, approval_state, health_state, is_active, length(expected_host_key)>0 from core_managementpath;" 2>&1 | head -40
# (column names must be confirmed against 0033; adjust only the SELECT list, never use SELECT * and never select credential columns)

# 5.6 Key presence in the process environment WITHOUT printing it (run only in the process that will execute device_observe)
python3 -c 'import os,sys; v=os.environ.get(sys.argv[1],""); print("present" if len(v)>=32 else "absent")' NMAS_OBS_KEY_ENV_NAME_FROM_PROVISIONING
```

Expected outcomes: 5.1 and 5.2 match §1.1; 5.3 shows the true level (fills the UNAVAILABLE row of §1.2); 5.4 gives the registered-device count and lifecycle distribution; 5.5 shows which of the nine devices have an approved path and a pin. Record results in a new, separate evidence file (not this one). Note: these are operator-run reads, not gateway-recorded evidence; they establish state for approval and do not count as live device evidence.

## 6. Reviewed deployment sequence (NOT executed; requires approvals in §8)

### 6.0 Preconditions (all must be true)
1. §5.3 shows production at 0035 with no pending earlier migration; §5.4 shows none of the new tables.
2. A reviewed immutable revision exists (commit/PR of the worktree overlay) — currently **false**: nothing is committed, pushed or staged. Creating it needs separate authorization (no remote Git writes by this subtask).
3. The decision in §7 about the production dirty files and the lineage (options A/B) is made and recorded.
4. Maintenance window; checkpoint #28 and #23 preserved (see §9).

### 6.1 Source-lineage / schema preflight (on a **copy**, never on production)
```bash
# In a throw-away directory under /home/student/Scripts, with a copy of a production backup (see 6.2) —
# never the live file. Use -I and a separate cwd for the interpreter as the harness rules require.
cp -p /home/student/Scripts/<backup-file>.sqlite3 /home/student/Scripts/<scratch-dir>/preflight.sqlite3
# Point a scratch settings override / DATABASE path at the copy (operator mechanism), then:
$PY manage.py migrate core --plan                    # expect exactly: 0036, 0037, 0038 (3 operations)
$PY manage.py migrate core 0036 && $PY manage.py migrate core 0037 && $PY manage.py migrate core 0038
$PY manage.py showmigrations core | tail -4          # expect [X] 0035 0036 0037 0038
$PY manage.py makemigrations core --check --dry-run  # expect "No changes detected in app 'core'"
$PY manage.py check                                  # expect "System check identified no issues"
$PY manage.py sqlmigrate core 0038                   # expect one CREATE TABLE core_deviceversionobservation + 3 indexes
```
Expected: stepwise `0036 -> 0037 -> 0038` succeeds on the backup copy; row counts of pre-existing tables are unchanged before/after (compare `select count(*)` for `core_manageddevice`, `core_deviceobservation`, `core_change`). If any step fails, stop; production is untouched.

### 6.2 Backup (production, read-consistent)
```bash
cd /home/student/Scripts/clab_dualstack_lab-deploy/web
sudo systemctl stop nmas-maintenance-tick.timer nmas-probation-soak-tick.timer   # plus rotation timer if present
sudo systemctl stop nmas-web.service                                              # quiesce writers
umask 077  # backups, patches and archives may contain sensitive production data
TS=$(date -u +%Y%m%dT%H%M%SZ)
sqlite3 db.sqlite3 ".backup '/home/student/Scripts/nmas-db-backup-${TS}-pre-0036-0038.sqlite3'"
chmod 600 /home/student/Scripts/nmas-db-backup-${TS}-pre-0036-0038.sqlite3
sqlite3 "file:/home/student/Scripts/nmas-db-backup-${TS}-pre-0036-0038.sqlite3?mode=ro" "pragma integrity_check;"   # expect: ok
sha256sum /home/student/Scripts/nmas-db-backup-${TS}-pre-0036-0038.sqlite3
# Source rollback anchor (no dirty-file loss):
git -C .. diff > /home/student/Scripts/nmas-deploy-dirty-${TS}.patch; git -C .. status --short > /home/student/Scripts/nmas-deploy-dirty-${TS}.status
tar -C /home/student/Scripts -czf /home/student/Scripts/nmas-deploy-tree-${TS}.tgz --exclude='*/__pycache__' --exclude='web/var' --exclude='monitoring/runtime' clab_dualstack_lab-deploy
```
Expected: integrity check `ok`; backup size ≈ 26 MB; this naming matches the existing `nmas-db-backup-*` convention in `/home/student/Scripts`. (Excluded `web/var` and `monitoring/runtime` hold runtime/credential state: back those up only through the owner's approved procedure.)

### 6.3 Deploy reviewed code and migrate (the production-mutating step)
Do **only** after 6.0–6.2. The exact code-transfer mechanism depends on §7 and is not prescribed here. Then:
```bash
cd /home/student/Scripts/clab_dualstack_lab-deploy/web
sudo systemd-run --pipe --wait -p User=student -p WorkingDirectory=$PWD -p EnvironmentFile=/etc/nmas/nmas-web.env \
    /home/student/Scripts/.venv/bin/python manage.py migrate core --plan      # expect 0036, 0037, 0038 only
sudo systemd-run ... manage.py migrate core 0036   # then 0037, then 0038 one at a time; stop on the first error
sudo systemd-run ... manage.py showmigrations core | tail -4                   # expect [X] 0035..0038
```
Then settings, as a **separate reviewed change** (not part of schema deployment): add `NMAS_TS_RUNTIME_FACTORY`/`TROUBLESHOOTING_RUNTIME_DEPS` and `NMAS_TS_DEPLOYMENT = nmas_providers.RECOMMENDED_BINDING` (per `docs/troubleshooting/deployment-bindings.md`) and `NMAS_OBSERVATION_SOURCES = {"<source-id>": {"key_env": "<ENV>", "platforms": ["arista_ceos", "ubuntu_frr"]}}`. Do not set a `version_provider` other than `nmas_providers.version`. Do not put a key value in settings. Key provisioning is the security/provisioning report's scope.

Start services: `sudo systemctl start nmas-web.service` then the two timers.

### 6.4 Post-deploy verification (read-only)
```bash
systemctl is-active nmas-web.service                                   # expect: active
curl -sk -o /dev/null -w '%{http_code}\n' https://<approved-local-url>/  # expect 200/302 to login; operator-chosen URL, no credentials sent
sudo systemd-run ... manage.py check                                   # expect 0 issues
sudo systemd-run ... manage.py device_observe --help                   # expect the 4 required args
sqlite3 'file:db.sqlite3?mode=ro' "select count(*) from core_deviceversionobservation;"  # expect 0 (no observation yet)
sqlite3 'file:db.sqlite3?mode=ro' "select count(*) from core_manageddevice;"             # expect == §5.4 pre-count
```
Pre-existing counts (devices, observations, changes) must equal the §5.4 baseline. A difference means data-affecting side effects: roll back.

### 6.5 Regression commands (non-production; run in the worktree, LOCAL evidence, plus gateway when granted)
```bash
cd /home/student/Scripts/nmas-public-dev-troubleshooting/web
export DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test; PY=/opt/ai-orchestrator/nmas-env/bin/python
$PY manage.py makemigrations core --check --dry-run
$PY manage.py check
$PY manage.py test core.tests.test_device_observations core.tests.test_observation_evidence core.tests.test_observation_sessions \
   core.tests.test_observation_connections core.tests.test_observation_collector core.tests.test_device_observe \
   core.tests.test_troubleshooting_deployment core.tests.test_troubleshooting_nmas_providers core.tests.test_troubleshooting_readiness \
   core.tests.test_troubleshooting_qualification core.tests.test_contracts --noinput --parallel 1
# Gateway-attested variant (after the gateway owner confirms test authorization; grants=[] alone does not prove tests need a grant):
python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting <same dotted labels>
```
These were not re-run by this subtask (it edits no code; the focused LOCAL checks actually run are `makemigrations --check`, `showmigrations`, `sqlmigrate 0038`, `device_observe --help`). Prior counts are HISTORICAL. Never run tests against the production database.

## 7. Source-lineage decision (operator must choose; not decided here)

| Option | What | Risk |
|---|---|---|
| A. Move production to the public lineage | Commit/review the overlay on `troubleshooting/job-9aa10b4e7ca7-port`, merge, deploy that revision. | 247 differing core entries incl. isolation/commissioning/ZTP code and the 13 dirty production edits (would be lost unless first reviewed and merged or deliberately discarded); inventory loses the shared-credential fallback. Largest blast radius; needs a full regression and credential-owner sign-off. |
| B. Prepare a minimal public-lineage deployment artifact | Develop and review a minimal compatibility port in the authoritative public repository; preserve reviewed production differences in the deployment artifact. Never create new development branches or commits in the legacy repository. | `0036` needs its model and any code referencing `DhcpRelayReadback`; `models.py` in the overlay is +603 lines and also touches `middleware.py`, `urls.py`, `identity/policy.py`, `ci/rules.py`, `lifecycle.py`, `linux_ssh.py`; a partial port can break the access-policy contract test. Needs its own contract/regression run. |
| C. Stay at 0035 | No deployment. | Observations cannot be stored; `observed_version` stays unknown; all nine devices stay `VERSION_UNKNOWN`. |

Repository policy forbids new development in the legacy origin (AGENTS.md and docs/AUTHORITATIVE_REPOSITORY.md). Both options must be reviewed in the public repository. Recommendation: do not deploy until option A or B is reviewed as a commit; Option B is smaller operationally but needs more engineering; both require explicit approval. This audit cannot determine which the owner prefers.

## 8. Approval matrix

"Approver" is the role that must approve; the operator is the human owner of the lab/production. Nothing below has been approved by this document.

| # | Action class | Examples | Production effect | Approval required | Status now |
|---|---|---|---|---|---|
| R | **Safe read-only inspection** | §5 commands (read-only SQLite URI, `showmigrations`, `systemctl is-active`, git status); `device_observe --help`; local tests on dev DB | None (reads only; no secrets printed) | Operator acknowledgement of the exact §5 commands | Done only for credential-free file/unit/git inspection (§1). DB-level reads UNAVAILABLE. |
| W | **Observation DB writes** | `device_observe` (inserts `DeviceObservation` + `DeviceVersionObservation`, writes local evidence file) | Rows appended to the production DB; creates identity-observation rows that can only deny; opens SSH sessions to devices | Operator approval per run set: schema deployed (D), source/key provisioned (P), authorization reference, evidence directory, device list, gateway grant if gateway-recorded evidence is required | Not approved; blocked by D, P |
| D | **Schema/runtime deployment** | Backup, code transfer, `migrate` 0036–0038, settings binding, service restart | Schema + code + brief downtime | Operator + lineage decision (§7) + committed/reviewed revision + backup verified + maintenance window; credential owner for inventory change | Not approved; no committed revision exists |
| P | **Grants / provisioning** | `NMAS_OBSERVATION_SOURCES` registration, HMAC key placement, gateway grants, evidence directory creation, broker credentials/pins | Security-control change | Security owner / orchestrator administrator (security-provisioning report). Never by this worker. | Not approved; `grants=[]` |
| I | **Identity verification** | `lifecycle.verify_identity` by a person other than the recorder; host-key pin acceptance | Changes lifecycle trust state | Separate human approver per device; independent from recorder; after observation | Not approved; not performed |
| A | **Adoption / admission** | *Adopt Existing Device*, production admission/IN_SERVICE | Lifecycle state change | Separate human approval per device; R5 cannot be adopted | Not approved; not performed |
| N | **Network changes** | Any device config, management path, route, VLAN, ACL, host-key replacement | Device mutation | Out of scope for Task 1; separate Change workflow | None proposed |
| J | **Job continuation** | Resume JOB-E78CED9B29DE (#28) or JOB-9AA10B4E7CA7 (#23), gateway tests | Orchestrator state | Orchestrator/master only | Not restarted here |

Minimum approvals to take the first real observation: **D** (or an explicitly approved alternative: a separate non-production NMAS instance restored from a backup copy, which needs only P and an operator note) + **P** + **W**. Identity verification and admission (I, A) are *not* prerequisites for collecting an observation, and they are not implied by it: `observed_version` returns a version only after identity is VERIFIED by someone other than the recorder.

## 9. Rollback and data-retention risks

| Situation | Action | Risk |
|---|---|---|
| Failure before 0036 applied | Restart services on the untouched tree/DB. | None. |
| Failure during/after migrate, no new data written | Stop `nmas-web`, restore `nmas-db-backup-<TS>-pre-0036-0038.sqlite3` over `web/db.sqlite3`, restore the tree from `nmas-deploy-tree-<TS>.tgz`, start services. | Loses any production writes made since the backup (so keep the window quiet; stop writers first). SQLite WAL/`-journal` side files must be removed with the restore. |
| Roll back only 0038 | `manage.py migrate core 0037` drops `core_deviceversionobservation`. | **Destroys all version observations** (append-only evidence trail for admission); the `DeviceObservation` rows created by ingest remain (PROTECT FK is on the dropped table only). Copy the table and the local evidence files before. |
| Roll back through 0037/0036 | `migrate core 0036` / `0035`. | 0037 drops all `Ts*` case history (export first via `ts_api_export`); 0036 drops `DhcpRelayReadback` option-82 readbacks. Do not roll back below the lowest level the old code can run on (0035). |
| Data retention | Observations are `PROTECT`-linked to `ManagedDevice`/`DeviceObservation`, `editable=False`, immutable by design. Local evidence files are `local-unattested`, never overwritten, 0600, and are the only copy of raw output. | Deleting a device row or evidence file after ingest breaks the `evidence_ref` digest link. Retain both for the audit period. Back up the evidence directory with the DB. |
| Mixed state (new code, old schema) | The new `core` package imports models without tables → request errors. | Never start the new code before `migrate` completes. |

## 10. Checkpoint #28 and completed troubleshooting work

Nothing in this file or in the checks run touched the worktree overlay, the job state, or the gateway. The overlay (5 modified tracked files, ~43 untracked paths including the 30 completed troubleshooting subtasks and the 0037/0038 migrations) is unchanged. The only file written by this subtask is this document.

## 11. Evidence gaps and handoff for the master

Open (UNAVAILABLE, must come from an operator or another worker):
1. Applied migration level, registered devices and their lifecycle/identity state, management paths and pins in the production DB (§5.3–5.5).
2. Whether `nmas-web.service` and the timers are active, and the real working directory of the running process (§5.2).
3. Broker reachability and credential availability for the nine devices (security/provisioning report).
4. Exact gateway grant names/scope for read-only version and identity observations (security/provisioning report). This worker's `help` shows `grants: []`.
5. A committed/reviewed revision and the §7 lineage choice.
6. Source id, key placement and evidence directory (security/provisioning report). Suggested input to it: the settings entry shape in §6.3 and the directory rules in §1.3.

Conflicts for the master to resolve: (a) the brief's op list differs from this worker's `help` output (§1.5); (b) the `docs/troubleshooting/deployment-rollback.md` text speaks of `migrate core 0036` as the full rollback, while 0038 must be rolled back first (§9) and now sits above 0037; (c) the deploy tree's inventory includes a shared-credential fallback that the public inventory deliberately removes (§3.6).

Recommended next steps: (1) operator approves and runs §5, (2) record results, (3) decide §7, (4) commit a reviewed revision, (5) request P and D approvals, (6) run §6.1 preflight on a backup copy, (7) only then §6.2–6.4, (8) first observation via `device_observe` under W, (9) I and A as separate human steps.
