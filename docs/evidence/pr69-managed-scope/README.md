# PR #69 live acceptance — NMAS-active managed scope

Run on 2026-10-27 against disposable fixtures only. Production NMAS, its database, the production NetBox (`127.0.0.1:8000`),
DHCP, VLAN 200 and the Containerlab topology were not touched.

## What was real

| Piece | Source |
|---|---|
| Device under test | Factory-default cEOSLab 4.36.2F `NEW1` taken through native ZTP behind trusted-upstream isolation, governed commissioning and controlled admission (`labs/isolation-commissioning-isolated`, stages `prepare isolate ztp onboard commission admit`) |
| NetBox | A disposable NetBox v4.7 (same pinned images as `netbox/docker-compose.yml`), seeded with the repository's own `netbox/scripts/populate_netbox.py --apply` plus the fixture's three prefixes (`labs/managed-scope-isolated/netbox.sh`). Reached only over one veth into the fixture's NMAS namespace. |
| NetBox writes | The production `ipam.NetboxGateway` (reservation, NSOT synchronization, managed-scope activation); the managed scope is read back through the production reader `netbox_ipam.get_managed_devices` |
| Lifecycle records | The fixture's SQLite database, written by the real services (no hand-built rows) |
| Probation | `provisioning_service.start_probation` (the normal 7-day policy), the soak collector's own tick, and a real out-of-band edit on NEW1 |

Notifications from the soak were recorded, not sent. Each negative case changes one link of the genuine records and restores it.

## Results

`55-scope-before-admission.json` — commissioned, not yet admitted: NetBox holds only the PLANNED reservation (tag
`nmas-provisioning`, no `managed`, `iac_managed` unset); NEW1 is absent from NetBox's managed list; `managed_scope_refusal`
is `NOT_ACTIVE_PROVISIONED`; the configuration-validation scope check is BLOCKED and the execution gate reports
`TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE`.

`65-managed-scope-admitted.json` — after admission (run `NSOT_SYNCED`, registry `ACTIVE`):

* NetBox device: `active`, tags `csci5840-iac` + `managed`, `iac_managed = true`; NEW1 is in `get_managed_devices`.
* With NetBox's list lacking NEW1 (the PR #68 scenario) and with the live list: refusal `""`, scope check PASS
  (`nmas_active: [NEW1]` in the first case), no execution-gate scope blocker.
* 20 negative cases, each refused with its reason and blocked by both consumers: inactive / retired registry entry,
  disposable, missing NetBox id, unsynchronized run, no recorded identity, planned-only identity, another real NetBox
  device's id, another name, unconfirmed scope, conflicting NetBox id on the device, not admitted, revoked lifecycle
  (DECOMMISSION_PENDING / FAILED / DECOMMISSIONED), identity MISMATCH, cleared host key, recorded drift, aborted
  commissioning, commissioning bound to another run. After restoring each link the device qualifies again.
* NetBox activation: re-activation is idempotent (the device record is identical before and after); a device tagged
  `unmanaged` is refused with no write; with the scope lost (tag and field removed), an activation that references a
  missing object is refused before any write, and the retry restores the scope (NEW1 back in the managed list).

`68-managed-scope-probation.json` — `start_probation` succeeded (`BND-PROB-000001`, `SOAK-000001` bound to it, 7-day
window). During the RUNNING soak NEW1 qualifies; identity MISMATCH, an aborted commissioning or an unbound probation
still refuse it. After an out-of-band description change on NEW1 the soak collector's tick invalidated the soak with
`CONFIGURATION_DRIFT`; NEW1 is then refused (`PROBATION_UNTRUSTED`) by the registry, the scope check and the
execution gate. The edit was reverted on the device afterwards.

## Reproduce

```bash
labs/managed-scope-isolated/netbox.sh up
labs/isolation-commissioning-isolated/fixture.sh up
labs/isolation-commissioning-isolated/run-harness.sh migrate
labs/isolation-commissioning-isolated/run-harness.sh prepare isolate ztp onboard
labs/managed-scope-isolated/netbox.sh link "$(labs/isolation-commissioning-isolated/fixture.sh svc-pid)"
NMAS_ISO_LIVE_NETBOX_ENV=$PWD/labs/managed-scope-isolated/runtime/fixture-client.env \
  labs/isolation-commissioning-isolated/run-harness.sh commission scope-pre admit scope probation report
labs/isolation-commissioning-isolated/fixture.sh down; labs/managed-scope-isolated/netbox.sh down
```
