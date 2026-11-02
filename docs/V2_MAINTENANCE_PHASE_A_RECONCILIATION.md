# V2 Maintenance — Phase A: state reconciliation

Phase A establishes a trustworthy source / deployment / current-state baseline before any Maintenance Mode work.
**This is not Maintenance Mode.** It adds no maintenance model, state, permission or test.

## 1. The problem it solves

On 2026-10-06 nine Changes (`CHG-20261006-0003` … `-0011`) drained R2 and added temporary routes on S2 through NMAS.
The devices were later returned to service by hand. Those runs really happened and stay exactly as recorded, but their
resulting state is no longer what the devices hold:

| Device | What NMAS history leaves as the expectation | What the device holds (2026-10-09) |
|---|---|---|
| R2 | Vlan103/Vlan104 detached from OSPFv2/OSPFv3 (`-0007`); Ethernet2 `DRAINED`, shut (`-0008`); Ethernet1 routed, `Down with Verification`, shut (`-0011`) | Ethernet1 trunk `OSPF_L2_FABRIC_TRUNK` up, Ethernet2 up, Vlan103/104 in area 0; OSPFv2 and OSPFv3 Full to R3 and R4; RIP neighbour S2 |
| S2 | `ip route 172.30.50.10/32 192.168.110.4`, `ipv6 route 2001:db8:3050::10/128 2001:db8:10::2` (`-0006`) | neither route present |

Both devices' running and startup configurations are identical, and both match the tracked intended architecture
(remaining template differences are EOS renderings of the same intent and exist equally on R1/S1).

## 2. The reconciliation record

`core.models.StateReconciliation` (migration `0028`) is one append-only statement: *the resulting state of these runs is
no longer the accepted baseline; this observed state is.*

| Field | Meaning |
|---|---|
| `record_id` | `REC-000001` … |
| `device_name`, `cause`, `actor`, `reason`, `created_at` | who accepted what, and why |
| `acknowledgement` | the exact phrase supplied: `ACCEPT <device> <first 12 digits of the observed digest>` |
| `observed_at` | when the device was read |
| `previous_expected_digest`, `previous_expected_basis` | what NMAS expected before, identified by what produced it |
| `accepted_digest`, `section_digests`, `startup_digest` | the observed sanitized running configuration and startup configuration |
| `affected_sections` | the configuration sections the superseded runs touched |
| `execution_run_ids` | the finished runs whose resulting state is superseded |
| `evidence`, `record_digest` | observation metadata and a digest of the record itself |

NMAS stores no full expected configuration, so the previous expectation is a digest of its provenance: the prior
reconciliation of the device, if any, followed by the superseded runs, each pinned by plan hash and outcome. Only
digests and references are stored — configuration is sanitized before hashing and never kept.

Guarantees, each covered by a test in `core/tests/test_reconciliation.py`:

- A record cannot be updated or deleted (row, queryset and manager level).
- Creating one changes no Change, ExecutionRun, Configlet, execution result, validation run or check run.
- Accepting is explicit: actor, reason, the device-and-digest acknowledgement, runs and sections are all required.
- An unreadable device, or one whose running and startup configuration are not proven identical, is refused.
- Runs must exist, be finished and have targeted the device.
- Accepting the same observed state over the same expectation twice returns the existing record and writes nothing.
- A later outside change chains from the previous record.
- Every acceptance writes one `STATE_RECONCILIATION_ACCEPTED` audit event carrying actor, device, record, reason, both
  digests, affected sections, referenced executions and the observation time.
- A website user needs the existing `nmas_approve` permission. No new permission exists.

## 3. NetBox status is projected, never inferred

`project_netbox_status` sets one NetBox device's `status` because a named reconciliation record says the device is in
service. The status is stated by the caller. The service reads no device and no interface, touches no other device and
no other field, needs explicit confirmation, and writes a `NSOT_STATUS_PROJECTED` audit event that references the
record. A refused or failed write is not audited as done.

This replaces the abandoned drain-sync experiment, which set a device `offline` or `active` from its data-port state at
the end of every execution run. That code was never merged; it is preserved on the evidence-only branch
`evidence/nsot-drain-sync-20261006` (**never to be merged**) and was removed from the deployment.

## 4. Operating it

```
python manage.py nmas_reconcile observe --device R2
python manage.py nmas_reconcile accept  --device R2 --actor <name> --reason "<why>" --ack "ACCEPT R2 <digest12>" \
        --run <run id> [--run ...] --section "interface Ethernet1" [--section ...]
python manage.py nmas_reconcile project-status --record REC-000001 --status active --actor <name> --confirm
```

`observe` is read-only. `accept` writes one row and one audit event. Neither writes to a device.

## 5. Dry run against a copy of the live database (2026-10-10)

The live database was copied with the SQLite backup API to a scratch file, migration `0028` was applied to the copy
only, and R2 and S2 were observed through the normal read-only device sessions.

| Device | Observation | Record | Runs superseded | Sections |
|---|---|---|---|---|
| R2 | OK, running == startup | created; second call returned it unchanged | `-0007` … `-0011` (5) | `interface Ethernet1`, `interface Ethernet2`, `interface Vlan103`, `interface Vlan104` |
| S2 | OK, running == startup | created; second call returned it unchanged | `-0006` (1) | the two temporary static routes |

History compared equal before and after; two audit events were written; the NetBox projection reported
`R2: offline -> active (SET)` against a client whose write was intercepted. The scratch copy was deleted. The live
database and NetBox were not written.

## 6. What Phase A did to production, and what is still open

Done: drain-sync evidence preserved and pushed; the uncommitted drain-sync code removed from the deployment (tree equals
`8875bbe`); one controlled `nmas-web` restart, healthy afterwards.

**Completed 2026-10-10** after PR #45 merged (main `4528971`) and the deployment was promoted to it:

- Live database backed up (`monitoring/runtime/backups/db.sqlite3.pre-0028-20261010T031239Z`, sha256
  `6a3123d86f53bdf88eeb49da55528cd248260ad43ad9982dc69a61bceebb19ba`), migration `0028` applied from deployed code.
- `REC-000001` — R2, accepted digest `d6340576d69b…`, supersedes the runs of `CHG-20261006-0007` … `-0011`.
- `REC-000002` — S2, accepted digest `a7b53d7506fa…`, supersedes the run of `CHG-20261006-0006`.
- Both digests equal the dry run's. A digest over every Change, execution run, Configlet, execution result, validation
  run and lifecycle event was identical before and after.
- NetBox R2 `offline -> active`, projected from `REC-000001` and audited as `NSOT_STATUS_PROJECTED`; every other device
  status unchanged.

Still true afterwards, and reported rather than hidden:

- The nine October 6 Changes remain in lifecycle `DRAFT` with their drain intent. Nothing executes them automatically,
  but an operator could still run them; the reconciliation record does not, and must not, alter them.
- No NMAS view consumes the reconciliation record yet. The NSOT drift page compares NetBox with Git addressing and has no
  notion of an accepted device baseline.
- The stored reports of the runs for `-0010` and `-0011` still contain the historical `nsot_sync` key written by the
  abandoned drain-sync code. It is no longer displayed.

No network device configuration was written by Phase A.
