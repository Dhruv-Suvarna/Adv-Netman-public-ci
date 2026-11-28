# NMAS V2 corrected 210-operation Stage A production authorization

Prepared: 2026-11-15 (America/Denver)  
Evidence refreshed: 2026-11-15 15:58 MST  
State: **STAGE_A_BLOCKED — OWNER DECISIONS, ROLE ACCEPTANCE, AND RECOVERY CONFIRMATION MISSING**  
Execution state: **NOT DEPLOYED — B1–B13 NOT EXECUTED**

This is the final unsigned Stage A review record. It covers only the
application-source overlay, database migrations 0036 through 0039, and
restoration of the existing web service and four existing timers. It does not
authorize service identities, worker units, IPC keys, namespaces, veths, host
firewall/NAT, research egress, model access, device operations, observations,
credentials, host-key enrollment, `ManagementPath` approval, Containerlab
actions, or AI execution.

No production backup, source archive, service action, migration, database
write, networking change, worker activation, Containerlab action, or vSphere
contact was performed while preparing this record.

## 1. Exact release identity and hardened media

| Item | Exact value |
|---|---|
| Package | `/home/student/Scripts/nmas-vm-local-veth-release-20261115T214507Z/package` |
| Operations | 210: 201 ADD, 8 REPLACE, 1 MERGE |
| Entries SHA-256 | `b6c636301d3cfa48429a373662d748738b07e5daba58c7bf76db62c1d383aa39` |
| Manifest SHA-256 | `9dfc9ae4c0c213b454f639a88dd0fc1a714cdf8d90c028c946b7ca5fe29d5570` |
| Tool SHA-256 | `46db050bd863183498203b796a21bb563026b97a829d1cdbe4678f0e5dd99a0e` |
| `SHA256SUMS` SHA-256 | `9b8e72e0ca2544a31cfb514a96cd8eb974e9b05197063506f35ce9910fd64d16` |
| Production root | `/home/student/Scripts/clab_dualstack_lab-deploy` |
| Required production HEAD | `129d3f090f8b94b982178b1e8f3ec51047278068` plus the reviewed 13 modified and 3 untracked paths |
| Required DB head | `0035_v2_phase7_9_decommission_dynamic` |
| Forward migrations | `0036_v2_phase9_relay_option82_readback` → `0037_troubleshooting` → `0038_device_observations` → `0039_observation_authorizations` |

### Permission change and post-change verification

The release bytes were not changed. The minimal mode-only correction cleared
the group-write bit from 256 group-writable objects under the release and from
its group-writable `/home/student/Scripts` parent. Existing owner, group,
execute, read, and other-access bits were otherwise preserved.

| Check | Observed result |
|---|---|
| Ownership | All 257 release objects are `student:student` |
| Symlinks | 0 under the release |
| Release directory | mode 0755 |
| Package directory | mode 0755 |
| `/home/student/Scripts` parent | mode 0755; no group write through the containing directory |
| Higher ancestors | `/home/student` is 0750; `/home` and `/` are 0755; none is group-writable |
| Group-writable release objects | 0 |
| Other-writable release objects | 0 |
| ACL write grants | owner entries only; no named-user or group ACL write grant observed |
| Package checksum file | manifest and tool both `OK` |
| Canonical entries digest | recomputed and exactly matched the value above |
| Payload hashes | 210/210 independently recomputed and matched |
| Paths / manifest problems | 210 unique safe relative paths; `problems: []` |
| Production preconditions | `VERIFIED (pre): all 210 entries match` |

This is non-group-writable content-pinned media, not hardware WORM storage. The
owning `student` account can still change or replace objects, so the complete
identity and 210/210 precondition check remains mandatory immediately before
execution. Any byte, identity, production baseline, migration-plan, ownership,
or permission drift after signature is an automatic stop and requires a fresh
review. No new release candidate is needed from this permission-only change.

## 2. Historical approvals are evidence, not approval for this release

The older records remain unchanged as historical evidence. Their names,
signatures, decisions, and dates must not be copied into the fields in this
record.

| Historical record | Determination for this release |
|---|---|
| 179-operation P1 | **INVALID / NOT TRANSFERABLE** — unsigned and bound to entries `8a4111…8f70` |
| 179-operation P2 | **INVALID / NOT TRANSFERABLE** — signed for a different package and test population |
| 179-operation P3 | **INVALID / NOT TRANSFERABLE** — migrations are unchanged, but its signature is package-bound; evidence may be cited |
| Sole-owner exception | **INVALID / NOT TRANSFERABLE** — unsigned and limited to entries `8a4111…8f70` |
| Old Gate B authorization/window | **INVALID / EXPIRED** — different package and 2026-11-14 window |
| Earlier 210-operation acceptance | **NOT TRANSFERABLE AS APPROVAL** — bound to entries `5dab9d…520f` |
| Corrected VM-local-veth acceptance | **VALID TECHNICAL EVIDENCE ONLY** — exactly identifies entries `b6c636…aa39` and manifest `9dfc9a…5570`, but expressly leaves live approval pending |

The historical records remain at:

- `production-p1-p3-signoff-packet.md`;
- `sole-owner-p1-exception-and-gate-b-approval.md`;
- `gate-b-change-window-checklist.md`;
- `final-210-operation-release-acceptance.md`; and
- `final-vm-local-veth-release-acceptance.md`.

## 3. Exact application scope, outage, and downtime budget

The overlay performs:

- 201 additions: inactive sandbox/unit/policy templates and controller/test
  artifacts, troubleshooting documents, and web application, migration,
  command, service, template, fixture, and test files;
- 8 exact replacements: `web/config/settings.py`, `core/apps.py`,
  `core/middleware.py`, `core/models.py`,
  `core/services/devices/lifecycle.py`, `core/services/identity/policy.py`,
  `core/tests/runner.py`, and `core/urls.py`; and
- 1 guarded merge into `web/core/services/ci/rules.py`.

Migrations create 22 new application tables: one relay-readback table, 18
troubleshooting tables, one device-version-observation table, and two scoped
observation-authorization tables, plus their indexes, constraints, content
types, and permissions. Rehearsal found no alteration of existing application
tables or rows.

Expected service impact:

- `nmas-web.service` is unavailable from its approved stop until post-migration
  health and login validation completes;
- the maintenance, probation-soak, credential-rotation, and demo-telemetry
  timers are paused, and their one-shots must finish before source apply;
- gNMI collection, syslog ingest, topology, traffic runner/socket, demo SSH
  proxies, Docker, Containerlab, and network devices remain running and
  untouched; and
- no new worker, socket, namespace, network policy, research destination,
  model provider, credential, or device path is activated.

Only the migration portion has a measured rehearsal duration, approximately 25
seconds. The complete stopped-service sequence has not been measured in
production. The proposed budget is therefore:

| Item | Proposed bound |
|---|---|
| Maintenance window | 60 minutes |
| Announced website outage | Up to 30 minutes, beginning when `nmas-web.service` is stopped |
| Rollback decision point | 30 minutes after the website stop, or immediately on any stop condition |
| Proposed window | 2026-11-15 22:00–23:00 MST (America/Denver), pending explicit acceptance and notice |

## 4. Migration and rollback risk acceptance

- Reverse migration to 0035 drops all data in the 22 new tables. Export any
  post-deployment Troubleshooter or observation records that must be retained
  before reversal.
- Reverse migration leaves stale Django content types and permissions. Do not
  remove them until group assignments are reviewed.
- Last-resort database restore loses every database write after the stopped-
  service backup. The actual database owner must accept that loss point.
- Source rollback follows successful reverse migration and uses only the
  package journal to remove 201 additions and restore 9 shared files. A
  destructive Git reset or checkout is prohibited.
- Production is intentionally dirty. Any difference from the reviewed 13
  modified and 3 untracked paths is a stop, not authority to overwrite or
  rebuild during the window.
- The production baseline contains accepted legacy test debt. P2 must decide
  whether the exact corrected package may rely on that evidence and on the
  focused corrected-delta tests without a new broad regression run.
- Dormant worker, namespace, research, model, and device code is included in
  the source tree. An unexpected binding, unit, socket, namespace, process, or
  listener is a stop and rollback condition.

## 5. Backup destination, encryption, retention, and disposable restore

### Read-only destination and capacity verification

No backup directory or backup file was created.

| Item | Observed result at evidence refresh |
|---|---|
| Proposed directory | `/home/student/nmas-backups/CHG-NMAS-20261115-STAGE-A-001` |
| Directory state | Absent; it must be created only after authorization |
| Existing parent | `/home/student`, owner `student:student`, mode 0750, current operator writable |
| Filesystem | `/dev/sda3`, ext4, mounted read-write at `/` |
| Available space | 25,144,172 KiB |
| Production tree size | 246,836 KiB |
| Production DB | 26,181,632 bytes, owner `student:student`, mode 0644 |
| Package size | 4,216 KiB |
| Current DB read-only check | migration 0035; integrity `ok`; zero FK violations |
| Guest-visible encryption | No dm-crypt/LUKS layer is visible; underlying vSphere datastore encryption cannot be inferred |
| Available encryption tool | GnuPG is installed; no approved recipient key/fingerprint is recorded |

Capacity is sufficient for the expected DB backup, disposable restore, source
archive, apply journal, and temporary encrypted-copy verification. Recheck
immediately before the window and require at least 1 GiB free. The proposed
path is on the same guest filesystem as production and therefore is not an
independent disk/VM-loss backup unless an approved backup service copies the
encrypted artifact outside this failure domain.

### Future execution procedure — not authorized now

1. After authorization and before the window, record the approved owner,
   permitted readers, retention expiry, deletion owner, encryption method, and
   off-VM retention requirement. Confirm the change ID is unique.
2. At the window, stop only the four package-importing timers, wait for their
   one-shots to become inactive, and stop only `nmas-web.service`. Do not stop
   collectors, Docker, topology, or network services.
3. With `umask 077`, create the exact change directory mode 0700. Refuse a
   symlink, wrong owner, wrong mode, wrong filesystem, or pre-existing file.
4. Create the consistent mode-0600 SQLite backup with the package tool:

   ```sh
   python3 -I "$PKG/nmas_compat_overlay.py" db-backup \
     --db "$PROD/web/db.sqlite3" \
     --out "$BK/db.pre-$CHG.sqlite3"
   ```

   Record the backup and sidecar modes, SHA-256, byte count, integrity `ok`,
   zero FK violations, and core migration head 0035.
5. Restore that exact backup only to a new disposable path outside the deployed
   tree, never over the live database:

   ```sh
   python3 -I "$PKG/nmas_compat_overlay.py" db-restore \
     --backup "$BK/db.pre-$CHG.sqlite3" \
     --db "$BK/restore-test/db.sqlite3" \
     --confirm "$BACKUP_SHA256_PREFIX" \
     --scratch-target
   ```

   Recompute the restored byte hash, run read-only SQLite integrity and foreign-
   key checks, and confirm migration head 0035. Record the results before
   removing only the explicitly named disposable restore-test artifacts.
6. Create the mode-0600 source archive:

   ```sh
   python3 -I "$PKG/nmas_compat_overlay.py" source-archive \
     --production "$PROD" \
     --out "$BK/source.pre-$CHG.tar.gz"
   ```

   Record its SHA-256 and file count. List and review its members to confirm it
   preserves the reviewed dirty/untracked source and the worktree `.git`
   pointer, while excluding the live database and SQLite sidecars, `web/var`,
   `monitoring/runtime`, `netbox/.env`, bytecode, and cache directories.
7. Encrypt at rest using one explicitly approved method:

   - preferred: an infrastructure-approved encrypted backup target with
     documented recovery ownership; or
   - package the backup, both JSON sidecars, source archive, and its sidecar,
     then encrypt to a pre-recorded GnuPG recipient fingerprint whose private
     key and recovery procedure are stored outside VM1.

   Verify ciphertext SHA-256 and perform a disposable decrypt-and-hash test
   before treating encryption as complete. Do not claim the current ext4 path
   is encrypted merely because the VM is hosted in vSphere. Do not store a
   passphrase or private key in the repository, change record, shell history,
   or backup directory.
8. Retain the verified DB backup, source archive, apply journal, and shared-file
   backups through acceptance and the approved rollback period. Proposed
   retention is 30 days after successful closeout, or longer if required by
   university policy or an unresolved incident. Deletion requires the named
   owner to verify the change is accepted, the rollback period expired, and no
   legal, audit, or incident hold applies.

No production database backup may be created until the DB owner and Stage A
change manager authorize this procedure.

## 6. Console and recovery-channel finding

Repository documentation requires a tested vSphere console or equivalent OOB
channel but contains no attributable confirmation that one is accessible to a
named operator.

Local non-mutating checks establish only that:

- VM1 identifies as VMware (`csci5840-vm1-dhsu9160`);
- `open-vm-tools` is installed, enabled, and active;
- a local desktop seat/TTY exists; and
- no local `govc`, `vim-cmd`, or `esxcli` client or local vSphere configuration
  was found in the checked paths.

Guest tools, a desktop seat, sudo access, and an existing SSH/tmux session do
not prove vSphere-console entitlement or successful recovery access. No
vSphere/vCenter/ESXi endpoint was contacted. Console/OOB status is therefore
**UNCONFIRMED**.

Before authorization, an actually entitled operator must record the exact
method, their identity, the successful non-mutating access-test time, and the
escalation contact. Recovery must not flush firewall tables, change default
routes, restart Docker, deploy/destroy Containerlab, reboot network containers,
or operate devices. For Stage A, recovery should first restore the existing web
service and application state; host-network recovery actions remain outside
this authorization.

## 7. Authority boundary

Authority follows the role and applicable policy, not filesystem ownership,
sudo access, technical capability, or the label “project owner.” The same
person may fill multiple roles only if project and institutional policy permit
it; no such permission is inferred here.

| Decision | Project owner may decide only if they actually hold this role | Requires university/infrastructure or other external authority |
|---|---|---|
| One-time package-specific P1 exception | Yes, only if authorized to amend project governance; it is not an independent review | Any higher-level separation-of-duties rule cannot be waived locally |
| P2 exact-release QA acceptance | Yes, if the signer is the accountable QA owner | External QA/security review if institutional policy requires it |
| P3 migration/restore/data-loss acceptance | Yes, if the signer is the actual production DB owner/restore authority | Institutional backup, records, encryption, or retention requirements |
| Stage A application-only GO | Yes, if authorized as application change manager for VM1 | Required external change approval if university/VM-owner policy applies |
| Window, outage notice, project operators | Project owner/change manager may propose and assign within their authority | Infrastructure staff availability or institutional maintenance rules |
| Project backup contents and rollback period | DB/source owners may propose and accept | Off-VM backup service, datastore encryption, records holds, institutional retention |
| vSphere/OOB access confirmation | Project owner may name a proposed operator and record an actual test they personally performed if entitled | Console entitlement, recovery escalation, and infrastructure-side actions belong to the infrastructure owner |
| Worker identities, namespace/veth, firewall/NAT, research, device access, model/live AI | Not authorized by Stage A | Separate later-stage university/infrastructure and per-resource approvals |

The repository does not establish whether the project owner has institutional
authority to approve an application/database change on this VM. The Stage A
signer must either provide an attributable external approval reference or
attest, within their actual authority, that no additional approval applies.

## 8. Package-specific P1, P2, and P3 decision fields

All fields below are intentionally unsigned. Complete one P1 route, not both.

### P1 route A — independent human package/security review

> I independently reviewed the exact 210-operation package identified in §1,
> including its corrected two-file namespace delta, full manifest, shared-file
> patches, dormant privileged-code risk, production preservation rules, and
> rollback controls. I did not author the package. I decide whether it may
> advance to a separately authorized Stage A window. This is not deployment or
> infrastructure authorization.

| Field | Explicit completion |
|---|---|
| Decision | **PENDING — select APPROVE or REJECT** |
| Reviewer full name | ______________________________ |
| Role / organization | ______________________________ |
| Independent of package author | ______________________________ |
| Conditions | ______________________________ |
| Signature | ______________________________ |
| Date/time and timezone | ______________________________ |

### P1 route B — package-specific sole-owner governance exception

> I am authorized to amend NMAS project governance. No independent human
> reviewer is available. For entries
> `b6c636301d3cfa48429a373662d748738b07e5daba58c7bf76db62c1d383aa39`
> and manifest
> `9dfc9ae4c0c213b454f639a88dd0fc1a714cdf8d90c028c946b7ca5fe29d5570`
> only, I accept a one-time exception to independent P1 review and the reduced
> separation-of-duties assurance. I do not claim independence and do not waive
> P2, P3, Stage A preconditions, backup/restore controls, or external policy.

| Field | Explicit completion |
|---|---|
| Exception decision | **APPROVE EXCEPTION** |
| Authority to amend project governance | **YES** |
| Owner full name / role | Dhruv Ramesh Suvarna / NMAS Project Owner and Administrator |
| Conditions / expiry | Exact package only; void on identity, baseline, migration-plan, or permission drift. Additional: None |
| Signature | /s/ Dhruv Ramesh Suvarna |
| Date/time and timezone | 2026-11-15 16:33:13 MST |

### P2 — exact-release QA and baseline-debt acceptance

> I reviewed the exact corrected-package technical acceptance. I understand
> that the broad production-copy population was not rerun for the final two-file
> namespace correction; the correction instead passed its 19-group disposable
> namespace suite, the foreign-object race regression, focused 44/44 tests,
> 210/210 apply/rollback checks, and unchanged migration rehearsal. I explicitly
> accept or reject reliance on the preserved non-green baseline evidence (260
> failures, 6 errors, and 45 skips) and the focused corrected-delta evidence for
> this Stage A release only. No failure is relabelled as passing.

| Field | Explicit completion |
|---|---|
| Decision | **APPROVE** |
| QA owner full name | Dhruv Ramesh Suvarna |
| Role / organization | NMAS Project QA Owner and Administrator |
| Baseline debt and limited rerun accepted | YES |
| Conditions / defect references | Accept documented pre-existing baseline failures and focused corrected-package validation for this Stage A release only. No failures reclassified as passing. |
| Signature | /s/ Dhruv Ramesh Suvarna |
| Date/time and timezone | 2026-11-15 16:37:55 MST |

### P3 — database migration, backup, and recovery acceptance

> I reviewed migrations 0036 through 0039 and the disposable forward/reverse
> evidence. I understand that reverse migration drops all data in the 22 new
> tables and leaves stale content types/permissions, while last-resort backup
> restore loses all database writes after the stopped-service backup. I require
> the mode-0600 consistent backup, verified sidecar, disposable restore test,
> source archive, approved encryption/retention, and any required data export
> before destructive rollback.

| Field | Explicit completion |
|---|---|
| Decision | **APPROVE** |
| DB owner / restore authority full name | Dhruv Ramesh Suvarna |
| Role / organization | NMAS Project Owner and Database Administrator |
| Backup directory | /home/student/nmas-backups/CHG-NMAS-20261115-STAGE-A-001 |
| Retention / encryption / permitted readers | 30 days after successful closeout; local backup on VM1; directory mode 0700; files mode 0600; encryption: none; permitted readers: NMAS DB owner and authorized recovery operator only; no off-VM copy; Local-only, unencrypted backup explicitly approved by the accountable DB owner for Stage A; VM/disk-loss exposure accepted; no additional encryption or off-VM requirement applies under the applicable policy. |
| Last-resort restore loss point accepted | **YES** |
| Required post-deployment export | Export new records before destructive rollback, where feasible |
| Conditions | Require verified database backup, SHA-256 hash, integrity and foreign-key checks, successful disposable restore test, and source archive before deployment. Stop immediately if any verification fails. |
| Signature | /s/ Dhruv Ramesh Suvarna |
| Date/time and timezone | 2026-11-15 16:40:16 MST |

## 9. Final Stage A authorization — explicit review only

The proposed change is `CHG-NMAS-20261115-STAGE-A-001`, subject to uniqueness
confirmation. The proposed window, outage, package, migrations, risks, backup
procedure, and recovery requirements are exactly those in §§1 and 3–6.

> I have reviewed the exact package identity, 30-minute website outage budget,
> 60-minute maintenance window, migration and rollback risks, production dirty-
> tree preservation, stopped-service backup and disposable restore test,
> encryption and retention decision, console/OOB confirmation, assigned roles,
> automatic stop conditions, and Stage A-only scope. I make only the decision
> recorded below and do not authorize later infrastructure stages.

| Field | Explicit completion |
|---|---|
| Decision | **PENDING — select AUTHORIZE, REJECT, or DEFER** |
| Authority basis | Authorized NMAS application and database owner/administrator for assigned VM1 |
| External approval reference, or `NONE — authorized application-owner attestation` | NONE — authorized application-owner attestation |
| P1 route and decision reference | Section 8, P1 Route B — APPROVE EXCEPTION, signed 2026-11-15 16:33:13 MST |
| P2 QA decision reference | Section 8, P2 — APPROVE, signed 2026-11-15 16:37:55 MST |
| P3 DB decision reference | Section 8, P3 — APPROVE, signed 2026-11-15 16:40:16 MST |
| Change ID confirmed unique | CHG-NMAS-20261115-STAGE-A-001 |
| Effective window and timezone | 2026-11-15 22:00–23:00 MST |
| Website outage notice / audience / sent-at | Sole NMAS user/operator — self-notified; no external users to notify |
| Production operator | Dhruv Ramesh Suvarna |
| Reviewer or exception owner | Dhruv Ramesh Suvarna — P1 Route B |
| DB backup / restore operator | Dhruv Ramesh Suvarna |
| Rollback owner | Dhruv Ramesh Suvarna |
| Communications owner | Dhruv Ramesh Suvarna |
| Console/OOB method, entitled operator, tested-at time, escalation contact | vSphere Client Web Console; entitled operator: Dhruv Ramesh Suvarna; access successfully verified: 2026-11-15 16:44:34 MST; escalation: dhsu9160@colorado.edu |
| Backup directory / retention / encryption / readers / deletion owner | Directory: /home/student/nmas-backups/CHG-NMAS-20261115-STAGE-A-001; retention: 30 days; encryption: none; storage: VM1 local only; readers: Dhruv Ramesh Suvarna; deletion owner: Dhruv Ramesh Suvarna |
| Conditions | Workers, namespaces, host firewall/NAT, research, model/live AI, device operations, credentials, Containerlab, VM1 networking, and all later stages remain disabled. Additional: Require successful backup, restore rehearsal, hash verification, and Stage A-only deployment |
| Approver full name and role / organization | Dhruv Ramesh Suvarna — NMAS Project Owner and Administrator |
| Approver signature | /s/ Dhruv Ramesh Suvarna |
| Production operator acceptance / signature | /s/ Dhruv Ramesh Suvarna |
| DB owner signature | /s/ Dhruv Ramesh Suvarna |
| Date/time and timezone | 2026-11-15 17:08:53 MST |

If an electronic `/s/ Name` is used, the signer must confirm that the
applicable project and institutional process accepts that signature form.

## 10. Immediate pre-window and execution controls

These are future operational prerequisites, not owner decision fields and not
evidence that execution occurred.

### Immediate pre-window stop/go

- [ ] Package checksum file, manifest, tool, entries digest, all 210 payload
      hashes, `problems: []`, ownership/modes, and 210/210 preconditions pass.
- [ ] Production HEAD and the exact reviewed dirty/untracked paths match.
- [ ] DB is at 0035 with integrity `ok` and zero FK violations.
- [ ] Web, four timers, unrelated collectors, and all 15 topology containers
      match baseline; health and login are 200 and `/troubleshooting/` is 404.
- [ ] No worker/runtime/research/model unit, socket, namespace, listener, or
      Stage A-external environment binding is active.
- [ ] At least 1 GiB is free and the new backup directory has exact owner, mode
      0700, no symlink component, approved encryption, and approved readers.
- [ ] Assigned operators are present, notice is complete, and console/OOB
      recovery confirmation remains current.

### Authorized execution record — future window only

- [ ] Stop only the four named timers, wait for their one-shots, then stop only
      `nmas-web.service` and record outage start.
- [ ] Create, hash, validate, encrypt as approved, and disposable-restore-test
      the authoritative DB backup; create and hash the source archive.
- [ ] Apply exactly 210 operations with the exact entries-confirmation prefix;
      retain a successful journal and verify 210/210 postconditions.
- [ ] `manage.py check` passes; `makemigrations --check --dry-run` reports no
      changes; migration plan contains only core 0036–0039.
- [ ] Migrate only through 0039; confirm head, integrity `ok`, and zero FK
      violations.
- [ ] Start only the existing web service; verify health 200, login 200,
      authenticated troubleshooting redirect, and no startup traceback.
- [ ] Start only the four pre-existing timers and verify their expected runs.
      Unrelated collectors, topology, and traffic remain healthy.
- [ ] Verify existing read-only workflows and all 15 containers; prove no
      device contact, worker, namespace, firewall, research, model, or live AI
      activation occurred.
- [ ] Record outage end/duration, hashes, results, operator signature, reviewer
      acceptance, and change-manager closeout.

Automatic stop/rollback applies to identity, permission, precondition, or
baseline drift; backup, encryption, or restore-test failure; unexpected
migration; integrity/FK error; application/timer/collector/topology regression;
unexpected socket/process/namespace/listener; credential exposure; console/OOB
loss; or scope expansion. Reverse migrations one at a time to 0035, export
required new records first, then use the package journal. Use last-resort DB
restore only with the DB owner's recorded decision.

## 11. Remaining authorization and operational prerequisites

**STAGE_A_BLOCKED. Do not execute.**

1. Choose and complete one exact-package P1 route: independent review, or an
   authorized package-specific sole-owner governance exception.
2. Record fresh P2 QA and P3 DB-owner decisions for this exact package.
3. Establish the Stage A approver's actual authority basis and any required
   university/VM-owner approval reference; project ownership alone is not proof.
4. Confirm the change ID and maintenance window, send the outage notice, and
   obtain acceptance from the production operator, rollback owner,
   communications owner, DB backup/restore operator, and reviewer/exception
   owner.
5. Decide backup encryption, permitted readers, off-VM requirement, retention,
   deletion owner, and accept or reject the last-resort restore loss point.
6. Obtain actual non-mutating console/OOB access confirmation from an entitled
   named operator, including tested-at time and escalation contact.
7. At the authorized window, pass every immediate pre-window check and complete
   the stopped-service backup and disposable restore test before source apply.

No field in this record is a signature, inferred decision, or authorization.
