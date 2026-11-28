# NMAS V2 Gate B change-window checklist

State: **PREPARED — NOT AUTHORIZED — ALL EXECUTION ITEMS UNCHECKED**  
Package: `8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70`  
Manifest SHA-256: `5d30929d1d197eca9dabeb449d198455b74683b18e641a37a4c35d958b2de252`

This is an operator record for a future explicitly authorized maintenance window. Preparing this checklist did not stop a service,
write production source, back up or migrate the live database, provision a credential, approve a device or perform a network action.

**Governance hold:** the existing change-manager/operator authorization below is preserved, but P1 was not satisfied when it was
entered. It is not operable until the separate
[`sole-owner-p1-exception-and-gate-b-approval.md`](sole-owner-p1-exception-and-gate-b-approval.md) is explicitly completed with a
valid owner exception, external-authority declaration and final Gate B decision. The original P1 attestation remains unsigned.

## 1. Roles, window and immutable variables

Complete before authorization:

| Field | Value |
|---|---|
| Change ID (`CHG`) | CHG-NMAS-20261114-001 |
| Window start/end and timezone | 2026-11-14 01:00 - 02:00 MST |
| Change manager | Dhruv Ramesh Suvarna |
| Production operator | Dhruv Ramesh Suvarna |
| DB owner / rollback authority | Dhruv Ramesh Suvarna |
| Communications owner | Dhruv Ramesh Suvarna |
| P1/P2/P3 packet location | `docs/troubleshooting/validation/production-p1-p3-signoff-packet.md` |

Use these exact immutable values after replacing only `<change-id>`:

```bash
CHG=<change-id>
PROD=/home/student/Scripts/clab_dualstack_lab-deploy
PY=/home/student/Scripts/.venv/bin/python
PKG=/home/student/Scripts/nmas-compat-release-20261114T072224Z/package
BK=/home/student/nmas-backups/$CHG
ENTRIES=8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70
```

Management commands use the production service environment without displaying it:

```bash
sudo systemd-run --uid=student --gid=student --wait --collect --pipe \
  -p WorkingDirectory=$PROD/web -p EnvironmentFile=/etc/nmas/nmas-web.env \
  $PY manage.py <arguments>
```

## 2. Gate B authorization

- [ ] P1 is signed APPROVE against the exact `ENTRIES` value.
- [ ] Or, instead of claiming independent P1, the package-specific sole-owner exception and final Gate B record is fully signed and
      its external-authority declaration is non-blocking.
- [ ] P2 is signed APPROVE and explicitly accepts the unchanged 260 failures plus six errors across 263 parent IDs.
- [ ] P3 is signed APPROVE and acknowledges destructive schema rollback and last-resort restore risks.
- [ ] Change ID is assigned and the website maintenance window is announced.
- [ ] Production operator and DB rollback authority are present for the entire window.
- [ ] Backup filesystem has adequate capacity and `mkdir -m 700 -p "$BK"` succeeds.
- [ ] No Phase C operation is included: no binding, credential, host-key, authorization, observation, adoption or identity approval.

| Authorization | Completion |
|---|---|
| Change manager Gate B decision | **AUTHORIZE** |
| Change manager signature / time | Dhruv Ramesh Suvarna — 2026-11-14 00:53:42 MST |
| Production operator acceptance / time | Dhruv Ramesh Suvarna — 2026-11-14 00:53:42 MST |

**Stop here unless both Gate B authorization fields and the governance-hold conditions above are complete.**

## 3. Reconfirm Phase A immediately before the window

- [ ] Recompute `sha256sum "$PKG/manifest.json"`; result is exactly `5d30929d…e252`.
- [ ] `sha256sum -c "$PKG/SHA256SUMS"` reports the manifest and tool `OK`.
- [ ] Manifest has 179 entries, `problems: []`, and `entries_sha256` exactly equals `$ENTRIES`.
- [ ] Run `python3 -I "$PKG/nmas_compat_overlay.py" verify --package "$PKG" --tree "$PROD" --phase pre`;
      result is `VERIFIED (pre): all 179 entries match`.
- [ ] `git -C "$PROD" rev-parse HEAD` is `129d3f090f8b94b982178b1e8f3ec51047278068`.
- [ ] `git -C "$PROD" status --porcelain` is the reviewed 13 modified tracked and three untracked paths.
- [ ] `showmigrations core` ends at applied `0035_v2_phase7_9_decommission_dynamic`; 0036–0039 are not applied.
- [ ] `http://127.0.0.1:8002/healthz` is 200 and `/troubleshooting/` is 404.

Any mismatch is an automatic stop. Do not rebuild, reinterpret or approve a different package during the window.

## 4. Expected service impact

| Component | Expected impact |
|---|---|
| NMAS website | Unavailable from B2 until B10. |
| Maintenance, probation-soak, credential-rotation and Lab 8 poller timers | Stopped from B1 until B11; no one-shot may remain active when apply begins. |
| gNMI collector, syslog ingest, topology, traffic runner/socket and demo SSH proxies | Remain running; they execute outside the changed production tree. |
| Network devices and topology | No configuration, ZTP, DHCP, isolation, NetBox, gateway, Containerlab or Docker lifecycle action. |
| Database | Offline backup at B3; additive migrations 0036–0039 at B9. |

Record announced impact and audience: ________________________________________________

## 5. Gate B execution record

Do not combine steps. Record command output, timestamps and hashes in the change record without copying secrets or row contents.

### B1 — quiesce import-owning timers

- [ ] Run:

```bash
sudo systemctl stop nmas-maintenance-tick.timer nmas-probation-soak-tick.timer \
  nmas-credential-rotation.timer nmas-demo-telemetry.timer
systemctl is-active nmas-maintenance-tick.service nmas-probation-soak-tick.service \
  nmas-credential-rotation.service nmas-demo-telemetry.service
```

- [ ] Wait until none of the four one-shots reports `active` or `activating`.
- [ ] Record completion time: ____________________

### B2 — stop the web service

- [ ] `sudo systemctl stop nmas-web.service`
- [ ] Confirm it is inactive. Website outage begins.
- [ ] Record completion time: ____________________

### B3 — make the authoritative production database backup

- [ ] Run:

```bash
python3 -I "$PKG/nmas_compat_overlay.py" db-backup \
  --db "$PROD/web/db.sqlite3" --out "$BK/db.pre-$CHG.sqlite3"
```

- [ ] Output records `integrity_check: ok` and core head `0035_v2_phase7_9_decommission_dynamic`.
- [ ] Backup mode is 0600; no WAL/journal sidecar condition is reported.
- [ ] Record `sha256sum "$BK/db.pre-$CHG.sqlite3"`: ________________________________________________

### B4 — archive the complete production source baseline

- [ ] Run:

```bash
python3 -I "$PKG/nmas_compat_overlay.py" source-archive \
  --production "$PROD" --out "$BK/source.pre-$CHG.tar.gz"
```

- [ ] Archive includes the reviewed 13 dirty and three untracked paths.
- [ ] Archive excludes the database, `web/var`, `monitoring/runtime` and `netbox/.env`.
- [ ] Record file count (expected about 1,750): ____________________
- [ ] Record archive SHA-256: ________________________________________________

### B5 — apply the reviewed source package

- [ ] Run:

```bash
python3 -I "$PKG/nmas_compat_overlay.py" apply \
  --package "$PKG" --production "$PROD" --backup-dir "$BK/apply" \
  --change-id "$CHG" --confirm 8a4111f7b9f9553
```

- [ ] Output is `APPLIED 179 entries`.
- [ ] `$BK/apply/journal.json` exists and records a successful apply.

### B6 — verify every postcondition

- [ ] Run `python3 -I "$PKG/nmas_compat_overlay.py" verify --package "$PKG" --tree "$PROD"`.
- [ ] Output is `VERIFIED (post): all 179 entries match`.

### B7 — Django static checks

- [ ] Run service-environment `manage.py check`; output has no issues.
- [ ] Run service-environment `manage.py makemigrations --check --dry-run`; output is `No changes detected`.

### B8 — inspect the live migration plan

- [ ] Run service-environment `manage.py migrate --plan`.
- [ ] The plan contains exactly core 0036, 0037, 0038 and 0039, in that order, and no other migration.

Any difference is an automatic stop. Do not migrate; proceed to the applicable rollback steps.

### B9 — migrate and validate

- [ ] Run service-environment `manage.py migrate core 0039 --noinput`.
- [ ] `showmigrations core` shows 0036–0039 as `[X]`.
- [ ] A read-only SQLite `PRAGMA integrity_check` returns `ok`.
- [ ] A read-only SQLite `PRAGMA foreign_key_check` returns no rows.
- [ ] Record migration completion time: ____________________

### B10 — restore website service

- [ ] `sudo systemctl start nmas-web.service`; unit becomes active.
- [ ] `http://127.0.0.1:8002/healthz` returns 200.
- [ ] `/troubleshooting/` returns 302 to `/accounts/login/?next=/troubleshooting/`.
- [ ] `/accounts/login/` returns 200.
- [ ] `journalctl -u nmas-web.service -n 50` contains no traceback or startup error.
- [ ] Record website restoration time and outage duration: ____________________

### B11 — restore timers and observe the next runs

- [ ] Start the four timers stopped at B1.
- [ ] All four timers are active.
- [ ] The next `MAINTENANCE_TICK` completes normally.
- [ ] The next Lab 8 `nmas-demo-telemetry` poller run succeeds.

### B12 — unbound readiness and reconciliation

- [ ] Run service-environment `manage.py troubleshooting_readiness --json`.
- [ ] Deployment binding is `settings.NMAS_TS_DEPLOYMENT`; every device remains blocked by
      `LIFECYCLE/VERSION_PROVIDER_UNBOUND` before separately approved C1.
- [ ] Run service-environment `manage.py nmas_reconcile_inventory --json`.
- [ ] Counts are exactly `REGISTERED 6 / ADOPTION_PENDING 7 / EXCLUDED 1`.
- [ ] No identity, lifecycle or adoption state was changed by these read-only commands.

### B13 — read-only production smoke

- [ ] Devices page renders as before.
- [ ] Commissioning overview renders as before.
- [ ] ZTP networks renders as before.
- [ ] Maintenance renders as before.
- [ ] Traffic renders as before.
- [ ] Health renders as before.
- [ ] No write workflow, device contact or configuration action was used for smoke testing.

## 6. Automatic stop and rollback triggers

Stop immediately for any of these conditions:

- package, manifest, entry identity, pre-hash or production Git-state mismatch;
- an import-owning timer/service remains active at apply time;
- B3 backup integrity/head/mode failure or inability to record its SHA-256;
- source archive failure;
- apply journal reports partial/failed state or B6 does not verify all 179 entries;
- Django check or migration-autodetector failure;
- migration plan differs from exactly 0036–0039;
- migration, integrity or foreign-key failure;
- web/timer restart failure, traceback, readiness/reconciliation mismatch or read-only smoke regression.

Record trigger, time and last completed step: ________________________________________________

## 7. Rollback record

Rollback is performed in reverse order under the DB owner's direction.

- [ ] If any new troubleshooting, observation or authorization rows must be retained, export them before reverse migration.
- [ ] Stop the four timers and wait for one-shots; stop `nmas-web.service`.
- [ ] Run service-environment migrations one at a time: `migrate core 0038`, then `0037`, then `0036`, then `0035`.
- [ ] Confirm core head 0035, integrity `ok` and no FK violations.
- [ ] Run:

```bash
python3 -I "$PKG/nmas_compat_overlay.py" rollback \
  --journal "$BK/apply/journal.json" --db "$PROD/web/db.sqlite3"
```

- [ ] Confirm rollback restores eight shared files, removes 171 additions and verifies all preconditions.
- [ ] Run service-environment `manage.py check`; start web and timers; confirm `/healthz` 200 and `/troubleshooting/` 404.

Reverse migrations drop all data written to the new 0036–0039 tables and leave stale Django content types and permissions. If schema
rollback fails, the last-resort restore is:

```bash
python3 -I "$PKG/nmas_compat_overlay.py" db-restore \
  --backup "$BK/db.pre-$CHG.sqlite3" --db "$PROD/web/db.sqlite3" \
  --confirm <recorded-backup-sha-prefix>
```

The operator must first confirm the recorded B3 hash. Restore preserves the replaced DB as a timestamped 0600 file, but loses every
database write made after B3. Record DB-owner authorization for last-resort restore: ______________________________

## 8. Window disposition

| Field | Completion |
|---|---|
| B1–B13 result | **NOT EXECUTED** |
| Rollback used | ______________________________ |
| Operator signature / completion time | ______________________________ |
| Change manager closeout | ______________________________ |
| Remaining live soak / acceptance evidence | ______________________________ |

Passing B1–B13 records a successful authorized deployment window. It does not by itself fabricate gateway-attested device evidence or
complete Phase C. **PRODUCTION_DEPLOYED_AND_ACCEPTED** must not be claimed until the authorized deployment and required in-production
acceptance/soak evidence actually exist.
