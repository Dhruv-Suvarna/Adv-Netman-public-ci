# NMAS V2 — Device lifecycle, ZTP, commissioning and isolation

Branch `lifecycle/commissioning-isolation` (base `99282bc`, the deployed Troubleshooter release). This document maps the
conceptual lifecycle to the authoritative NMAS records. It also records what this branch adds and states, for each capability,
whether it is deployed, fixture-only, blocked by platform or topology, or needs a separate disruptive-change authorization.

## 1. Conceptual stages → authoritative records (no duplicate state machine)

| Conceptual stage | Owning record / field | Notes |
|---|---|---|
| REGISTERED | `ManagedDevice` (`origin`, `registered_by`) | `LEGACY_ADOPTION` for adopted devices |
| DISCOVERED | `ZtpSession.discovery`, `DhcpLeaseObservation` (CORRELATED, trusted relay), lifecycle `DISCOVERED` | DHCP is an observation, never identity proof |
| IDENTITY_VERIFIED | `ManagedDevice.identity_state` + expected / verified serial, MAC, host key | claims (DHCP/LLDP) can only contradict |
| AUTHORIZED | `BootstrapAuthorization` (time-bounded, scoped, use-counted, binding digest) | bootstrap scope only, never production admission |
| BOOTSTRAPPED | `ZtpSession` BOOTSTRAPPED, lifecycle `BOOTSTRAPPED`, `ztp_state` | minimal management only |
| ISOLATED | `IsolationPolicy` (ENFORCED / VERIFIED → RELEASED) | upstream port ACLs, control-plane ACL, OSPF passive |
| COMMISSIONING | `CommissioningRecord` + `ProductionAdmission` | routing enabled only by admission |
| IN_SERVICE | lifecycle `IN_SERVICE` + `admission_state` | |
| MAINTENANCE | `MaintenanceRecord` (`core.services.maintenance_mode`) | never duplicated on the device row |
| DECOMMISSIONED | `DecommissionRecord`, lifecycle `DECOMMISSIONED` | |

`core.services.devices.stage_report` derives the ten stages per device from these records and writes nothing. It reports
five **separate** verdicts: identity (expected / claimed / observed / verified), bootstrap authorization (with expiry),
observation (attachments and topology evidence), admission, and operational readiness (stored records only). It also reports
management-path selection, maintenance and decommission eligibility, failures and rollback evidence, and the result of the
hash-chain verification.

**Legacy truthfulness.** An adopted device's discovery, authorization, bootstrap, isolation and commissioning stages are
`PREDATES_NMAS`, never `COMPLETE`. Its admission stays `LEGACY_PREEXISTING`. `nmas_lifecycle_report --verify` exits 2 when an
adopted device reports `ADMITTED` or any evidence chain is broken.

Every transition already appends a hash-chained `DeviceLifecycleEvent` (`devices.events.record`). The ORM refuses updates to
these rows (`DeviceLifecycleEvent records are immutable`). Out-of-band tampering is detected, never repaired; see
`test_lifecycle_stage_report.EvidenceTests`.

## 2. Secure ZTP (existing, extended)

| Step | Implementation |
|---|---|
| 1 Pre-register identity + attachment | `devices.lifecycle.register_device`, `devices.attachments` (two-person approval) |
| 2 Time-bounded bootstrap authorization | `devices.authorization` (`valid_from`/`valid_until`, `max_uses`, binding digest) |
| 3 Secure upstream provisioning policy | `isolation.service` (require → plan → approve → apply → verify); `ztp.dependencies` gates the bootstrap path on it |
| 4 Discovery + DHCP/TFTP/HTTP bootstrap | `ztp.discovery` (trusted relay + option 82 read-back), `ztp.artifacts` (delivery bound to a live lease) |
| 5 Minimum management config | `ztp.adapters.*` render key-only enrollment; `verify_management` refuses production services / routing |
| 6 Isolation from production routing | the isolation policy (filters, control-plane ACL, OSPF passive), verified with traffic |
| 7 Independent identity verification | `ztp.workflow.verify_management` over a pinned host key enrolled out of band |
| 8 Approved commissioning configuration | `commissioning.service` through the ordinary ProvisioningRun + Change |
| 9 Routing only after admission | `commissioning.admission` releases the isolation (and, Lab 9, the admission's OSPF passive) |
| 10 ZTP disabled | adapter `determine_ztp_disable_capability`; `ztp_state = DISABLED_VERIFIED` from a read-back |

Adapters declare evidence classes (`SUPPORTED_AND_LIVE_VERIFIED`, `IMPLEMENTED_UNIT_TESTED`, `NOT_IMPLEMENTED`, …). Only cEOS
4.36.2F is live-verified. No capability is claimed for any other OS.

### 2.1 New: DHCP lease lifetime and controlled re-discovery (`ztp/lease.py`)

- **Lapse.** When a DISCOVERED (pre-delivery) session's correlated binding expires or ends, the session returns to
  `AWAITING_DISCOVERY` and a `ZTP_LEASE_LAPSED` event is chained. The stale facts are kept under `discovery.previous`. The
  device's lifecycle state is not rewritten.
- **After delivery** a release is expected and live-observed: cEOS applies the artifact's static bootstrap address and frees
  its lease. It is reported, never treated as a regression. The open session keeps the reserved address exclusively.
- **Renewal.** A genuine renewal (a newer `lease_starts` on the same binding) re-advances a lapsed session only after the
  bootstrap authorization is decided again (`ZTP_LEASE_RENEWED` RECORDED or REFUSED). A re-read of the lease file is never a
  renewal.
- **Delivery** additionally refuses a binding whose state is released/free, even if its end time is in the future.
- **Controlled re-discovery** (the R7 provisioning interface becomes usable once R6 is admitted). `expect_renewal`
  re-evaluates the bootstrap path (`dependencies.evaluate`) and opens a window bounded by the adapter's *documented* native
  retry interval (cEOS: 30 s × 4 = 120 s). `renewal_status` then reports PENDING, OBSERVED or OVERDUE from lease evidence
  alone. OVERDUE returns only the adapter's native recovery actions. NMAS never flaps a link to provoke a DHCP request.
- **Refusals.** DHCPv6 SOLICIT is refused (`DHCPV6_DISCOVERY_NOT_IMPLEMENTED`), because no adapter discovers over DHCPv6. An
  adapter without a documented interval cannot open a window (`NATIVE_RETRY_UNDOCUMENTED`).

## 3. R6 → R7 onboarding (generic dependency rules)

- R7's authorized attachment names R6's port. The rule `attachments.commissioned_upstream_problems` refuses that attachment,
  R7's isolation and R7's bootstrap path until R6 is IN_SERVICE and ADMITTED, and the bootstrap network must list R6 as a
  trusted relay (`ztp.dependencies`).
- R7's link toward R6 is isolated by an R6-side isolation policy, which is a managed neighbour enforcing the boundary. That
  policy combines ingress/egress ACLs, the upstream control-plane ACL (Lab 9) and OSPF passive. A rogue adjacency and route
  advertisements are refused before admission.
- **VLAN 200.** It is refused as a bootstrap or production purpose (`VLAN200_PURPOSE_FORBIDDEN`). It is allowed only on
  approved MANAGEMENT attachments.
- **Management of devices without out-of-band access.** These use `VLAN_ADJACENT_SWITCH` (VLAN 200 tagged subinterface
  through an approved adjacent switch) or `ROUTED_VRF` paths; see §4.
- **Admission evidence.** It is never inferred from device-reported state. It comes from NMAS read-backs on the upstream:
  OSPF FULL with the expected router id, the expected routes and reachability.

## 4. Management-path resilience (existing: `management/paths.py`, `selector.py`)

1. `DIRECT_OOB`. 2. `VLAN_ADJACENT_SWITCH`, ordered by natural switch name and then DEV id. 3. `ROUTED_VRF`.

Failover is decided by hysteresis on layered probes. A security failure (host key or identity) causes an immediate failover
and is never retried onto an impostor. Paths are never switched under an in-flight write. Failback waits for a hold-down. Each
path is an approved expectation, never inferred from names. The stage report shows the selection per device.

## 5. Maintenance and decommissioning (existing: `maintenance_mode`, `decommission`)

These use existing redundancy (FHRP/VRRP/VARP, ECMP, MLAG, BGP multihoming) as evidence. NMAS has no drain protocol of its
own.

- Active production traffic without a proven lossless move blocks the change (`ACTIVE_TRAFFIC_NO_LOSSLESS_DRAIN`).
- An idle device may transition (`READY_IDLE`).
- `UNKNOWN` traffic is never read as quiet.
- Every refusal records its precise reason.

## 6. Website

The new read-only routes below sit under the existing authentication, MFA and RBAC middleware (`identity/policy.py`). The
JSON routes are sensitive reads and are audited.

- `automation/provisioning/lifecycle/`: the fleet stage matrix.
- `…/lifecycle/<DEV>/`: identity (expected / claimed / observed / verified), authorization and its expiry, attachment and
  topology evidence, management-path selection, isolation and commissioning, admission, readiness, maintenance and
  decommission eligibility, failures and rollback, and the hash chain.
- `…/api/`: the JSON documents.

The existing pages for every workflow (devices, ZTP, management, commissioning, maintenance, decommission) are linked from
there.

## 7. Lab 9 work integrated on this branch (preserved patch `912f65a7…`)

- Upstream control-plane ACL while isolated. On cEOS 4.36.2F the per-service ACLs do not filter eAPI, gNMI or NETCONF, so a
  copy of the built-in ACL with the bootstrap denies prepended is used instead.
- Release of an admission's explicit OSPF passive.
- `close_configured`, for commissioning aborted after configuration.
- The health engine treats loopbacks as never-adjacent.

## 8. Status classification

See `docs/lifecycle/ACCEPTANCE.md` for the evidence of each row.
