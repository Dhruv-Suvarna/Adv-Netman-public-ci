# Production compatibility deployment: troubleshooting and authenticated device-version observation

**Status: prepared and rehearsed on copies only. Nothing in this document has been run against production.** Every step that
changes production needs the named approval in §5 and is run by an operator.

Tool: `deploy/compat/nmas_compat_overlay.py`, standard library only. Tests: `deploy/compat/test_nmas_compat_overlay.py` (CO01–CO17).
Evidence: `docs/troubleshooting/validation/compat-deployment-validation.md` (migration preflight, source reconciliation, test
results, exact diff).

## 1. Why an overlay and not a checkout

Production (`/home/student/Scripts/clab_dualstack_lab-deploy`, legacy lineage `129d3f0` plus 13 uncommitted and 3 untracked files)
holds behaviour that the public tree does not have, and the live data depends on it:
- Lab 8 cutover
- control-plane ACL isolation
- the admission OSPF release
- `close_configured`
- the upstream relay read-back fallback
- pinned traffic hosts `H1-1`/`H5`/`H6`
- `ssh_telemetry`
- `settings_demo.py`
- the fleet credential fallback
- and more (47 production-unique files in total; see the matrix)

Moving production to the public tree would discard that behaviour. The overlay instead:

| Action | Count | Rule |
|---|---|---|
| ADD | 171 | path must be absent in production: troubleshooting services/views/templates, observation services and commands, `linux_ssh.py`, `checks.py`, migrations 0036–0039, tests, docs |
| REPLACE | 7 | production file must have the reviewed SHA-256: `models.py`, `urls.py`, `middleware.py`, `apps.py`, `config/settings.py`, `identity/policy.py`, `devices/lifecycle.py`. For each, production equals public `4f950b3` (or that minus the 0036 model), so the change is the reviewed overlay hunk alone. Two lines are widened (a middleware JSON-route test and the `urls.py` import list); nothing else is removed. |
| MERGE | 1 | `ci/rules.py`: only the overlay's hunks (`4f950b3` → reviewed tree) are transplanted onto the production file, each at a unique anchor; production-only rule lines are kept |

All 47 production-unique files are byte-identical before and after.

## 2. What the package is

```
<package>/manifest.json      entries: action, path, pre_sha256 (production), post_sha256, mode, removed lines, patch
<package>/payload/<path>     frozen post-content of every entry (checked against post_sha256 on every load)
<package>/patches/*.patch    unified diffs for the 8 shared files (the exact production diff)
<package>/nmas_compat_overlay.py   the tool, hash-pinned in the manifest
```

The **review identity** is `entries_sha256`. It covers every path, action, hash, mode and removed line, and is reproducible from the
reviewed commit and the unchanged production tree (CO13, CO17). The reviewed value is recorded in
`deploy/compat/reviewed-manifest.json` and in the validation report. `apply --confirm` requires a prefix of it.

## 3. Units and restart scope

Units that import the production tree are stopped for the change window; `apply` and `db-restore` refuse while any is active:
- `nmas-web.service` (the website is down only during the window)
- `nmas-maintenance-tick.timer`/`.service`
- `nmas-probation-soak-tick.timer`/`.service`
- `nmas-credential-rotation.timer`/`.service`
- `nmas-demo-telemetry.timer`/`.service` (Lab 8 poller; it runs `manage.py nmas_infrastructure`)

These are **not** touched, because they run code outside the tree:
- `nmas-gnmi-collector`
- `nmas-syslog-ingest`
- `nmas-topology`
- `nmas-traffic-runner` (and its socket)
- `nmas-demo-ssh-proxy-r6/r7`

No device, ZTP, DHCP, isolation, NetBox or gateway action happens in any step.

## 4. Procedure

Variables used below:

```
CHG=<change id>            PROD=/home/student/Scripts/clab_dualstack_lab-deploy        PY=/home/student/Scripts/.venv/bin/python
BK=/home/student/nmas-backups/$CHG                    PUB=<reviewed public checkout at the reviewed commit>
ENTRIES=<reviewed entries_sha256 from deploy/compat/reviewed-manifest.json>
DJ="sudo systemd-run --uid=student --gid=student --wait --collect --pipe -p WorkingDirectory=$PROD/web -p EnvironmentFile=/etc/nmas/nmas-web.env $PY manage.py"
```

`$DJ` runs `manage.py` with exactly the service environment (`config.settings_demo`), and nobody prints the env file.

### Phase A: preparation (read-only; outside the change window)
| # | Step | Expected |
|---|---|---|
| A1 | `mkdir -m 700 -p $BK && python3 -I $PUB/deploy/compat/nmas_compat_overlay.py build --public $PUB --production $PROD --package $BK/package` | `problems: []`, `entries_sha256` **equals `$ENTRIES`**. Any difference means production or the source changed since review: **stop**. |
| A2 | `python3 -I $BK/package/nmas_compat_overlay.py verify --package $BK/package --tree $PROD --phase pre` | `VERIFIED (pre): all 179 entries match` |
| A3 | `git -C $PROD rev-parse HEAD; git -C $PROD status --porcelain` | `129d3f0…`; the same 13 `M` and 3 `??` as recorded |
| A4 | `$DJ showmigrations core \| tail -5` | last applied `0035_v2_phase7_9_decommission_dynamic` |
| A5 | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8002/healthz` and `…/troubleshooting/` | `200` and `404` (pre-deploy baseline) |
| A6 | *(Phase C only; may be prepared now)* Create the observation key file. Do **not** paste or echo the key: `sudo install -m 600 -o root -g root /dev/null /etc/nmas/nmas-observation.env && { echo NMAS_OBSERVATION_SOURCE_ID=nmas-observer-v1; printf 'NMAS_OBSERVATION_KEY=%s\n' "$(python3 -c 'import secrets;print(secrets.token_hex(32))')"; } \| sudo tee /etc/nmas/nmas-observation.env >/dev/null` | file 0600 root:root. It is never added to `nmas-web.env`. |

### Phase B: change window (approval B required)
| # | Step | Expected / gate |
|---|---|---|
| B1 | `sudo systemctl stop nmas-maintenance-tick.timer nmas-probation-soak-tick.timer nmas-credential-rotation.timer nmas-demo-telemetry.timer` then wait until `systemctl is-active nmas-maintenance-tick.service nmas-probation-soak-tick.service nmas-credential-rotation.service nmas-demo-telemetry.service` shows no `active`/`activating` | timers stopped, no one-shot running |
| B2 | `sudo systemctl stop nmas-web.service` | website down (window starts) |
| B3 | `python3 -I $BK/package/nmas_compat_overlay.py db-backup --db $PROD/web/db.sqlite3 --out $BK/db.pre-$CHG.sqlite3` | `integrity_check: ok`, `core_migration_head: 0035_…`; record `sha256` |
| B4 | `python3 -I $BK/package/nmas_compat_overlay.py source-archive --production $PROD --out $BK/source.pre-$CHG.tar.gz` | about 1,750 files; record `sha256`. Includes the 13 dirty and 3 untracked files; never the DB, `web/var`, `monitoring/runtime` or `netbox/.env`. |
| B5 | `python3 -I $BK/package/nmas_compat_overlay.py apply --package $BK/package --production $PROD --backup-dir $BK/apply --change-id $CHG --confirm ${ENTRIES:0:16}` | `APPLIED 179 entries`; journal `$BK/apply/journal.json` |
| B6 | `python3 -I $BK/package/nmas_compat_overlay.py verify --package $BK/package --tree $PROD` | `VERIFIED (post)` |
| B7 | `$DJ check` and `$DJ makemigrations --check --dry-run` | `no issues`; `No changes detected` |
| B8 | `$DJ migrate --plan` | **exactly** `core.0036`, `0037`, `0038`, `0039` (nothing else): otherwise go to rollback R3 |
| B9 | `$DJ migrate core 0039 --noinput`, then `$DJ showmigrations core \| tail -5` and `python3 -I -c "import sqlite3;d=sqlite3.connect('file:$PROD/web/db.sqlite3?mode=ro',uri=True);print(d.execute('pragma integrity_check').fetchone(), d.execute('pragma foreign_key_check').fetchall())"` | 0036–0039 `[X]`; `('ok',) []` (rehearsal: about 25 s in total) |
| B10 | `sudo systemctl start nmas-web.service` then `curl …/healthz`, `…/troubleshooting/`, `…/accounts/login/` | `200`, `302 → /accounts/login/?next=/troubleshooting/`, `200`; `journalctl -u nmas-web -n 50` shows no traceback |
| B11 | `sudo systemctl start nmas-maintenance-tick.timer nmas-probation-soak-tick.timer nmas-credential-rotation.timer nmas-demo-telemetry.timer` | next `MAINTENANCE_TICK` logs normally; the Lab 8 poller run succeeds |
| B12 | `$DJ troubleshooting_readiness --json` and `$DJ nmas_reconcile_inventory --json` | binding `settings.NMAS_TS_DEPLOYMENT` (unbound: every device `LIFECYCLE/VERSION_PROVIDER_UNBOUND`); reconcile `REGISTERED 6 / ADOPTION_PENDING 7 / EXCLUDED 1` |
| B13 | Operator smoke of existing workflows, read-only pages only: Devices, Commissioning overview, ZTP networks, Maintenance, Traffic, Health | pages render as before |

### Phase C: enablement (each a separate approval; each reversible on its own)
| # | Step | Approval | Effect |
|---|---|---|---|
| C1 | Add `NMAS_TS_BINDING=nmas-v1` to `/etc/nmas/nmas-web.env`, `sudo systemctl restart nmas-web`, `$DJ check` | C1 | Troubleshooting admission uses the NMAS inventory, lifecycle and observed-version providers. R6/R7/R8/S5 then report only `VERSION_UNKNOWN`; R2/R4 report identity blockers; R5 stays excluded (rehearsal output). |
| C2 | Enroll host-key pins per `host-key-pin-enrollment.md` (collector ≠ enroller; cEOS path approval by a different approver) | C2 per device | pins exist; nothing is verified or admitted |
| C3 | `$DJ observation_authorize grant --approver A --requested-by Q --ticket $CHG --devices … --ttl-minutes 60` | C3 (approver A) | `OBSAUTH-…#sha256=…` |
| C4 | Run `device_observe` as operator O (≠ A) through `systemd-run` with `EnvironmentFile=/etc/nmas/nmas-observation.env` (`observation-runner.md` §2) | C4 | one read-only `show version` per device; local-unattested evidence; `DeviceVersionObservation` recorded |

### Rollback (any time; reverse order)
| # | Step |
|---|---|
| R1 | Undo C1: remove `NMAS_TS_BINDING`, restart `nmas-web`. Undo C3: `observation_authorize revoke`. Undo C4/A6: remove `/etc/nmas/nmas-observation.env`. |
| R2 | Stop units (B1, B2). If any `Ts*`, observation or authorization rows must be kept, export them first. |
| R3 | `$DJ migrate core 0038`, then `0037`, then `0036`, then `0035` (rehearsed; schema returns byte-identical) |
| R4 | `python3 -I $BK/package/nmas_compat_overlay.py rollback --journal $BK/apply/journal.json --db $PROD/web/db.sqlite3`. It refuses while any of 0036–0039 is still recorded; otherwise it restores 8 files, removes 171 and verifies the pre-state. |
| R5 | `$DJ check`, start units (B10, B11); `/troubleshooting/` returns `404` again |
| R-last | If R3 fails: `python3 -I $BK/package/nmas_compat_overlay.py db-restore --backup $BK/db.pre-$CHG.sqlite3 --db $PROD/web/db.sqlite3 --confirm <sha prefix>` (keeps the replaced DB as `.pre-restore-<utc>`), then R4 with the restored DB. **Writes made after B3 are lost.** |

## 5. Operator approval checklist

| Gate | Approver role | Evidence to check before signing |
|---|---|---|
| **P1: package review** | code reviewer (not the author) | `deploy/compat/reviewed-manifest.json`; the 8 patches (`production-deployment.diff`); `removed_text` has only the two widened lines; no production-unique file in the entries |
| **P2: test gates** | QA / reviewer | Validation report §4: overlay focused suites green; full production suite on the candidate has **no new failure** compared with the production baseline (production itself fails 260 tests and errors in 6 (263 distinct test ids); the candidate must reproduce exactly that set and nothing more); CO01–CO18 green |
| **P3: migration preflight** | DB owner | Validation report §2: plan is exactly 0036–0039; additive only; 87 existing tables unchanged; reversible to identical schema; integrity and FK clean |
| **B: change window** | change manager + operator | A1 `entries_sha256` = reviewed; A2 pre-verify; A3 git state unchanged; a maintenance window announced (website down for the duration) |
| **C1: binding** | NMAS owner | B12 output; readiness shows the expected blockers only |
| **C2: per-device pin** | enroller + (cEOS) path approver | `host_key_pin_check` `ok: true`, no `REGISTERED_PIN_CONFLICT`; collector, enroller and approver are three different people |
| **C3/C4: observations** | approver A; operator O ≠ A | authorization scope, TTL and budget; evidence directory approved; key file 0600 root |
| **Never in this change** | — | no credential provisioning, adoption, identity approval, SSH host-key change, gateway security change, push, merge, legacy-repo edit, Containerlab action |

Production readiness may be claimed only after P1–P3 are signed **and** B5–B13 pass in production.
