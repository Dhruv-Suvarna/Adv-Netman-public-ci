# NMAS V2 Phases 5 + 6: trusted-upstream isolation, governed commissioning and production admission

The lifecycle these phases complete:

    untrusted device -> authorized discovery -> native ZTP (Phase 3) -> isolated management bootstrap -> verified identity
    -> bootstrap credential retired (Phase 4 BCRED) -> approved commissioning -> production configuration (still isolated)
    -> verified connectivity -> production admission (controlled isolation release)

Live evidence: `docs/evidence/v2-phase5-6-isolation-commissioning/` (isolated cEOS fixture `labs/isolation-commissioning-isolated/`).
No production device, NetBox record, DHCP, VLAN 200, monitoring or deployed database was changed by this work.

## 1. Data model (migration `0034_v2_phase5_6_isolation_commissioning`)

| Model | Identifier | Purpose |
|---|---|---|
| `IsolationPolicy` | `ISO-000001` | One device + its approved routed attachment + a trusted upstream port. Holds the derived intent, exact operations, plan hash, digests, apply/release Changes and state (REQUIRED, PLANNED, BLOCKED, APPLYING, ENFORCED, VERIFIED, DRIFTED, UNCERTAIN, RELEASE_PENDING, RELEASED, CANCELLED) |
| `IsolationCheck` | per policy, per element | The last result of each element check (ATTACHMENT, L2, IPV4, IPV6, CONTROL_PLANE, MANAGEMENT_PLANE, TRAFFIC, DRIFT) with `with_device` |
| `CommissioningRecord` | `COM-000001` | Governed commissioning of one ISOLATED device. It is bound to exactly one `ProvisioningRun` (transport `ZTP_MANAGEMENT`) |
| `ProductionAdmission` | `ADM-000001` | The controlled isolation release with its expectations, evidence hash, release Change and restoration report |
| `CommissioningDependency` | row id | A declared or derived edge "device depends on upstream" |
| `LifecycleOutboxEvent` | idempotency key | A durable hand-off of an admitted device to the Phase 8 consumers |

Additive changes: `ProvisionedDevice.transport` and `ProvisioningRun.bootstrap_transport` gain `ZTP_MANAGEMENT`, and new audit event
types are added. The migration is additive and reversible.

## 2. Isolation (Phase 5): `core.services.isolation`

Enforcement happens only on the **trusted upstream's** port, never on the untrusted device. An upstream is trusted when it is
an in-service cEOS device that is managed by NMAS: a legacy pre-existing device, or a device NMAS admitted. An unadmitted
device as upstream is refused with `UPSTREAM_NOT_TRUSTED` / `ISOLATION_UPSTREAM_UNTRUSTED`.

- **Intent** (`intent.py`, pure). Derived from the upstream's own running configuration. It has four separately verified
  elements:
  - L2: a dedicated routed port.
  - IPV4 / IPV6: ingress and egress ACLs that permit only DHCP/relay, the bootstrap delivery and NMAS → device management.
  - CONTROL_PLANE: OSPF made passive on the port.
  - MANAGEMENT_PLANE: the upstream's own SSH denied to the bootstrap side over v4, v6 and link-local.

  Anything the builder cannot prove safe is a stable blocker. Examples: a shared port, a foreign ACL, RIP, IS-IS, OSPFv3,
  BGP on the port, or other exposed services. NMAS statements that already exist are never "adopted".
- **Renderer / parsers** (`eos.py`, pure). Every statement was exercised on cEOS 4.36.2F first (see §8). Each operation
  carries its exact inverse. The passive-interface inverse is `default passive-interface X` (finding 14).
- **Transaction** (`transaction.py`). One governed single-device transaction in the product's own Change records: Change →
  ChangeValidationRun → immutable ChangePlan / Configlets → precheck → approval bound to the plan hash by a different
  operator → execute under the device lock. Each operation is assessed, applied and read back. On failure, everything is
  compensated newest-first with digest verification.

  The generic engine refuses these Changes (`TRANSITION_CHANGE_NOT_GENERIC`). The isolation apply and the admission release
  are both this transaction.
- **Service** (`service.py`) is the one writer of `IsolationPolicy`: require → plan → precheck → approve → apply → verify.
  Then drift / reconcile / cancel → release (admission only).
  - Verification reads back every element. When a traffic source exists, it probes permitted and denied flows, and the
    enforcement point's per-entry deny counters corroborate them.
  - Drift is reported and never re-applied automatically. Reconcile never removes isolation.
- **Fail closed.** If NMAS is down, the policy stays enforced on the upstream. NMAS remains a single point of
  administration, and nothing proves the upstream itself is uncompromised: it is trusted because it is managed and in
  service.

ZTP gating: `ztp/policy.build_policy` and `ztp/dependencies` require an ENFORCED or VERIFIED isolation policy for a
PRODUCTION attachment before the DHCP class is authorized. `provisioning/bootstrap` and `devices/lifecycle` move a verified
device to ISOLATED.

## 3. Commissioning (Phase 6): `core.services.commissioning.service`

Commissioning reuses `ProvisioningRun`, `ManagedDevice` lifecycle events, Device Builder and the generic execution engine. No
separate engine exists. `provisioning/commissioning_gate.py` is the provisioning-side hook.

1. **open.** The device is ISOLATED behind a VERIFIED policy. A `ProvisioningRun` with transport `ZTP_MANAGEMENT` is
   created and bound to the record.
2. **The run's ordinary stages.** Bootstrap classification runs over the commissioning transport. Then come capability,
   IPAM, the Device Builder candidate, validation, the plan, and the precheck.
3. **assess → READY.** The readiness checks are identity_verified, host_key_enrolled, attachment_verified,
   bootstrap_authorization, native_bootstrap, management_transport, credential_transitioned (BCRED COMPLETE),
   isolation_verified, dependencies, lifecycle and production_candidate. Their evidence is frozen and hashed. Lifecycle
   ISOLATED → READY_FOR_COMMISSIONING.
4. **approve.** A different operator confirms the evidence hash (`COMMISSIONING_SELF_APPROVAL`,
   `COMMISSIONING_CONFIRMATION_MISMATCH`), and the provisioning run is approved by the same act. Lifecycle → COMMISSIONING.
   A stale plan or stale evidence is refused (`COMMISSIONING_STALE`, `COMMISSIONING_EVIDENCE_STALE`).
5. **Execution** goes through the generic engine. The commissioning gate re-checks freshness at execution.
6. **record_configuration.**
   - If the run POSTCHECKED and isolation still reads back intact, the record is CONFIGURED (still isolated).
   - A restored failure gives ABORTED, and the lifecycle returns to ISOLATED.
   - An unproven failure gives UNCERTAIN.
7. **reconcile.** UNCERTAIN becomes ABORTED only when a fresh device read equals the run's pre-execution digest
   (`restoration_problems`). Otherwise the record stays UNCERTAIN.

**Transport** (`transport.py`). A natively onboarded device is not in `inventory.yml`. It is reached only through the pinned,
enrolled host key plus the key-only service credential that BCRED installed. READ is allowed from BOOTSTRAPPED onward with
identity VERIFIED. WRITE is allowed only while commissioning is APPROVED / CONFIGURING, or once the device is admitted.
`nsot_live.get_live_target(..., platform="ceos")` falls back to this transport, so the cEOS executor, the cEOS health reader and
the provisioning digest work unchanged. The fallback is opt-in: only those cEOS callers pass `platform="ceos"`. The IOS XE and
SR Linux executors, route shield and the running-config route never consult the device registry for a name that is missing
from the inventory. The consolidated Tier-3 regression caught the first, unscoped version, which made those readers report
`CONNECTION_FAILED` instead of `NOT_CONFIGURED`.

## 4. Production admission: `core.services.commissioning.admission`

- **plan.** Validated expectations: the routing protocol, OSPF neighbours (router ids), routes learned through the policy
  port, and reachable addresses. The release Change is planned. The admission evidence is hashed: commissioning evidence,
  release plan hash, enforced upstream digest and expectations.
- **precheck.** The upstream still holds exactly the enforced policy, the isolation evidence is fresh, and dependencies are
  satisfied.
- **approve.** A different operator confirms the evidence hash.
- **execute.** The release runs through the isolation transaction on the trusted upstream. Its postcheck polls the
  expectations there.
  - Success gives **ADMITTED**: the device is IN_SERVICE, the policy RELEASED, and three outbox events are written in the
    same database transaction. Then the provisioning run's NSOT activation runs.
  - Any failed expectation means every removed statement is re-applied and digest-verified, giving **RESTORED**. The
    device stays COMMISSIONING behind an ENFORCED policy that must be verified again.
  - An unprovable restoration gives **UNCERTAIN**, with no automatic retry. `reconcile` proves the state.
- Isolation is never removed to "restore management". Admission never writes to the device being admitted.

## 5. Dependencies: `core.services.commissioning.dependencies`

A generic directed graph with no device names in the code. Edges come from declared `CommissioningDependency` rows, or are
derived from an approved attachment whose upstream is itself a natively onboarded device. A legacy upstream yields no edge.

Cycles are refused (`COMMISSIONING_DEPENDENCY_CYCLE`). An upstream is satisfied when it is IN_SERVICE and either ADMITTED
or LEGACY_PREEXISTING. An unmet dependency blocks assessment and admission (`COMMISSIONING_DEPENDENCY_UNMET`). A downstream
device is never commissioned automatically when its upstream becomes ready.

## 6. Outbox (contracts for Phase 8): `core.services.commissioning.outbox`

Topics: `NSOT_DEVICE_ADMITTED`, `TOPOLOGY_DEVICE_ADMITTED`, `MONITORING_TARGET_ADMITTED`. Each has a versioned contract
(`CONTRACT_VERSION = 1`) of identifiers, addresses and digests only; extra or missing fields are refused. Delivery is at least
once, and consumers apply each event at most once by `idempotency_key`. This phase records and validates the events. It does
not deliver them to production NetBox, the topology or monitoring.

## 7. UI / API, RBAC, CSRF, audit

`core/commissioning_views.py`:
- Pages: `/automation/provisioning/commissioning/` (overview), `…/devices/<id>/commissioning/`, and its JSON API (`…/api/`).
- Mutating views are thin CSRF POSTs, each calling one service function and redirecting with stable refusal codes.
- Authorization comes from `identity/policy.py`, and unknown routes are denied:
  - EDIT: require, plan, open, dependency add/remove, admission plan.
  - VALIDATE: prechecks, verify, drift, assess, record.
  - APPROVE: approvals, cancel, abort, reconcile.
  - EXECUTE: isolation apply, admission execute.
- Every service call records its own lifecycle event and audit row. Page views read the NMAS database only.

## 8. cEOS 4.36.2F platform findings (ETBA, disposable namespaces)

1. `ip/ipv6 access-group <acl> in` on a routed port denies FORWARDED v4/v6 traffic. `counters per-entry` gives per-entry
   counters.
2. The ingress ACL does not filter traffic addressed to the switch itself (ping to the port address, TCP/22).
3. An OSPF adjacency stays FULL through `deny ip any any` inbound, and the device's loopback route leaks to the upstream.
4. `router ospf N / passive-interface <port>` removes the adjacency and the leaked route.
5. `management ssh / ip access-group <acl> in` closes the upstream's SSH to the denied prefix. NMAS still reaches it.
6. `router rip` has no `passive-interface` on 4.36.2F ("% Invalid input"), so RIP on an isolation port is refused.
7. With the return `tcp sport 22` permitted, NMAS → device SSH works, while core → device SSH fails.
8. `ip/ipv6 access-group <acl> out` denies forwarded traffic toward the device port, with per-entry counters.
9. The egress ACL does not filter switch-originated traffic, so DHCP relay replies, RAs and the switch's own pings pass.
10. The bootstrap side reaches the upstream's SSH over IPv4, global IPv6 (SLAAC from the port's RAs) and link-local IPv6.
11. `management ssh / ipv6 access-group <acl6> in` (deny the port v6 prefix, deny fe80::/10, permit any) closes v6 global
    and link-local SSH, while NMAS's own SSH to the upstream is unaffected.
12. OSPF needs `ip routing`, and the ZTP bootstrap configuration carries `no ip routing`. Device Builder renders
    `ip routing` before the first IPv4 routing process of a NEW cEOS device (`configlet_factory._routing_prerequisite`).
13. Netmiko `use_keys=True` combined with an in-memory `pkey` and no `key_file` failed on the legacy inventory branch. Fixed
    in `ssh_transport.connect_eos`: Paramiko receives the pkey and `use_keys` is False.
14. `no passive-interface X` is stored as an explicit line. `default passive-interface X` restores the default. Isolation and
    the executor use `default`.
15. ZTP delivery is not application. EOS applies the downloaded startup-config afterwards, and contacting the device
    immediately hits the factory SSH (`MANAGEMENT_AUTH_FAILED`, retryable). Verification retries.
16. After ZTP, `aaa authorization exec default local` denies the console `Cli`. `Cli -A` bypasses AAA for the fixture's
    console stand-in.
17. The executor computed configuration-block inverses at assess time (pre-plan state), so a multi-Configlet plan could not
    prove its compensation. Inverses are now computed at apply time.
18. `passive-interface` lines coexist under a routing process; one is not a replacement for a sibling (`COEXISTING_STEMS`).
19. The health verifier compared OSPF areas un-normalized ("0.0.0.0" vs "0"). Fixed with
    `routing_config.normalized_area`.
20. The planner never labelled routing or relay Configlets with a capability feature, so plans were refused with
    `CAPABILITY_UNCLASSIFIED`. Fixed with `configlet_factory.routing_feature` and the DHCP relay feature.
21. The postcheck demanded an adjacency on the port that trusted isolation holds passive. Ports under an ENFORCED or VERIFIED
    policy are now NOT_APPLICABLE for adjacency checks (`evaluators.isolated_ports`).
22. A failed live run records LIVE capability FAIL evidence (`network_config_validation._record_live_capabilities`). That is
    correct behaviour, and the fixture had to account for it (evidence file 43).

Observation, not changed: a Phase 3 ZTP session keeps its stale retryable `failure` dict after a later success.

## 9. Real versus simulated in the live acceptance

Real:
- cEOS UP1, CORE, NEW1 and NEW2
- ISC dhcpd and the UP1 relay
- the NMAS bootstrap delivery server
- SSH with pinned host keys
- the cEOS executor, the isolation transaction, the ProvisioningRun and the generic execution engine
- OSPF, ACL counters and traffic probes

Substituted (each one is documented in the evidence README):
- the fixture SQLite database
- the fixture inventory (UP1 only)
- the fixture secret store
- `FakeGateway` instead of NetBox
- disabled GitHub Configuration Validation
- a synthetic precheck health snapshot
- a notification recorder
- capability evidence copied read-only from the deployed database
- probes standing in for hostile devices

Not exercised live:
- NEW2's own native ZTP. Device Builder cannot render `ip dhcp relay information option` on NEW1.
- IPv6 routing admission
- RIP / IS-IS / BGP isolation, which is refused by design
- Phase 8 delivery of the outbox events

The full lifecycle was therefore proven live for one device (NEW1) and up to ZTP authorization for its downstream (NEW2).

## 10. Limits and follow-ups

- Isolation is implemented for Arista cEOS and, since V2 Phase 9, Ubuntu/FRR upstreams (nftables; `V2_FRR_TRUSTED_ISOLATION.md`).
  Other platforms are refused with `ISOLATION_PLATFORM_NOT_IMPLEMENTED`.
- Admission expectations are OSPF (named neighbour router ids plus routes) or RIP (route-based). Anything else is refused at
  plan time (`ADMISSION_EXPECTATIONS_INVALID`). Only OSPF admission was exercised live.
- Device Builder gap: DHCP relay `information option` (Option 82), needed for a native-ZTP downstream of a commissioned
  device.
- Phase 7 (decommission / exact restoration) and Phase 8 (consumers of the outbox) are not part of this work.
