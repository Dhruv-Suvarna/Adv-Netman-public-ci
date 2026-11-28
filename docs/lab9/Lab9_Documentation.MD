# Lab 9 — Dual-Stack Network Expansion with Native ZTP, Governed IaC and Production Admission

**Course:** Advanced Network Automation (CSCI 5840), CU Boulder
**System:** NMAS V2 (Network Management & Automation System)
**Repository:** `Dhruv-Suvarna/Adv-Netman-public-ci`
**Evidence captured:** 2026-11-03, 05:54–09:35 UTC (every time in this document is UTC)
**Production NMAS:** `http://localhost/` (Apache → Gunicorn :8002). The `:8003` demo instance has been stopped since the Lab 8 production cutover, so it is not used here.

Every status in this document carries one of these labels:

| Label | Meaning |
|---|---|
| **IMPLEMENTED_AND_VERIFIED** | Executed through NMAS and proven by a read-back, a postcheck or a live observation |
| **IMPLEMENTED_BUT_NOT_VERIFIED** | In place, but its effect has not been proven |
| **PREPARED_NOT_EXECUTED** | Prepared and dry-run, but not applied |
| **BLOCKED** | Attempted, and it does not work |
| **NOT_APPLICABLE** | Does not apply to this element |

---

## 1. Title, objective and scope

Lab 9 adds a new branch to the existing production network:

* a router **R8**, attached to R2 and running **OSPFv2 and OSPFv3 in area 20**;
* an access switch **S5** behind R8;
* two new end hosts, **H1-1** and **H6**, in **VLAN 10** behind S5.

The assignment asks three questions:
1. What happens when these devices are added, and how is the automation framework implemented and updated?
2. What does unit testing and code coverage look like for this work?
3. What are concrete examples of the tools in use?

**Scope rules followed:**
* Lab 1 (R1–R5, H1–H4) is frozen. H1 is untouched, and so is R2's DHCP-server role.
* Lab 8 (R6, R7, H5) is left exactly as it was.
* Every change to a network device went through NMAS: validation, precheck, approval by a second person, execution, then postcheck. Four documented recovery exceptions are listed in §28.

## 2. Existing network baseline

| Area | Devices | Notes |
|---|---|---|
| Lab 1 core | R1–R5 (R2 = Arista cEOS; R3/R4 = Ubuntu + FRR), S1–S4, H1–H4 | OSPF area 0 between R2 and R3/R4 over VLAN 103/104 trunks on S4. R2 is the secondary DHCP server for VLANs 10/20/30. |
| WebServer | `clab-srlceos01-WebServer` | 172.30.50.10 and 2001:db8:3050::10 on its loopback. Reached through R3/R4 eth2 (eth2 is NAT'd). |
| Lab 8 | R6, R7 (cEOS), H5 | Production since 2026-11-02. Dual-stack H5 → WebServer works. |
| Management | NMAS service namespace `nmas-demo-svc` | ZTP / DHCP / HTTP services and SSH proxies |

## 3. Lab 9 expansion topology

```text
                 Existing network (Lab 1 core: R3, R4 → WebServer)
                                   |
                     R2 Ethernet4 (10.254.82.1/29, 2001:db8:254:82::1/64)
                                   |   OSPFv2 area 0.0.0.20  (point-to-point)
                                   |   OSPFv3 area 0.0.0.20  (point-to-point)
                     R8 Ethernet1 (10.254.82.2/29, 2001:db8:254:82::2/64)
                     R8 RID 192.168.255.8
               Ethernet2 (routed mgmt/bootstrap + OSPFv2)     Ethernet3 (access VLAN 10, data)
               10.254.85.1/29, 2001:db8:254:85::1/64            |
                                   |                             |
                     S5 Ethernet1 (10.254.85.2/29)          S5 Ethernet2 (access VLAN 10)
                     S5 Loopback0 192.168.255.95/32 (RID)
                                 S5 Ethernet3 (VLAN 10)  ── H1-1  10.254.20.11/24 + SLAAC
                                 S5 Ethernet4 (VLAN 10)  ── H6    10.254.20.12/24 + SLAAC
   VLAN 10 gateway = R8 Vlan10: 10.254.20.1/24 and 2001:db8:254:20::1/64 (IPv6 RA source)
   R2 Ethernet5 (10.254.84.1/30) ── NMAS ZTP service 10.254.84.2 (bootstrap DHCP/HTTP, relay target)
```

**How the hardware was added.** R2 had no free ports. Every neighbour of R2 is cEOS, so no port could be hot-added on that side either. The approach:
1. Two veth links were hot-added to R2's network namespace.
2. cEOS's `ProcMgr` was restarted under a governed maintenance window, **MNT-000004**. This makes EOS discover Ethernet4 and Ethernet5 while keeping the container, its namespace and its links. This was proven first on a fixture (`evidence/lab9_fixture_restart_M1.txt`).
3. OSPFv2 and OSPFv3 returned to FULL in about 87 s. Traffic runs after the restart all passed (`evidence/lab9_r2_window_20261102_223913.txt`).

R8 (`nmas-lab9-r8`) and S5 (`nmas-lab9-s5`) are cEOS 4.36.2F containers, each with a holder namespace. H1-1 (`nmas-lab9-h1-1`) and H6 (`nmas-lab9-h6`) are Linux containers.

## 4. Device and interface inventory

| Device | NMAS ID | Platform | Lifecycle / admission | NetBox ID | Role |
|---|---|---|---|---|---|
| R8 | DEV-000005 | arista_ceos | IN_SERVICE / ADMITTED | 33 (active) | area-20 router, VLAN 10 gateway, DHCP relay for S5 |
| S5 | DEV-000006 | arista_ceos | IN_SERVICE / ADMITTED | 38 (active) | VLAN 10 access switch |
| R2 | DEV-000004 (adopted) | arista_ceos | IN_SERVICE | 13 | upstream, ABR (area 0 ↔ 20) |
| H1-1 | — (end host) | Linux | not managed (same as H1–H5) | — | VLAN 10 host |
| H6 | — (end host) | Linux | not managed | — | VLAN 10 host |

| Interface | Address(es) | Purpose |
|---|---|---|
| R2 Et4 | 10.254.82.1/29, 2001:db8:254:82::1/64 | R8 uplink, OSPFv2+v3 area 20 p2p, DHCP relay → 10.254.84.2 with option 82 |
| R2 Et5 | 10.254.84.1/30 | link to the NMAS ZTP service (no routing protocol) |
| R8 Et1 | 10.254.82.2/29, 2001:db8:254:82::2/64 | uplink to R2 |
| R8 Et2 | 10.254.85.1/29, 2001:db8:254:85::1/64 | S5 bootstrap/management port, OSPFv2 area 20, DHCP relay + option 82 |
| R8 Et3 | access VLAN 10 | data link to S5 Et2 |
| R8 Vlan10 | 10.254.20.1/24, 2001:db8:254:20::1/64 | host gateway. Passive in OSPFv2 and OSPFv3. Sends IPv6 RAs. |
| S5 Et1 | 10.254.85.2/29, 2001:db8:254:85::2/64 | routed uplink, OSPFv2 area 20 |
| S5 Et2–Et4 | access VLAN 10 | R8 data link, H1-1, H6 |
| S5 Vlan10 | 10.254.20.2/24 | in-band IPv4 on VLAN 10 (no IPv6, so it never competes with R8's RAs) |
| S5 Loopback0 | 192.168.255.95/32 | router ID. Advertised in OSPF so admission can prove an S5-owned route. |

## 5. IPv4 address plan

| Prefix | Use | NetBox prefix ID / status |
|---|---|---|
| 10.254.82.0/29 | R2 Et4 – R8 Et1 | 76 / RESERVED |
| 10.254.84.0/30 | R2 Et5 – NMAS ZTP service | 78 / RESERVED |
| 10.254.85.0/29 | R8 Et2 – S5 Et1 | 79 / RESERVED |
| 10.254.20.0/24 | VLAN 10: R8 .1 (gateway), S5 .2, H1-1 .11, H6 .12 | 81 / RESERVED |
| 192.168.255.8/32, .95/32 | R8 and S5 router IDs (S5's is on Loopback0) | — |

## 6. IPv6 address plan

| Prefix | Use | NetBox prefix ID / status |
|---|---|---|
| 2001:db8:254:82::/64 | R2 Et4 ::1 – R8 Et1 ::2 | 77 / RESERVED |
| 2001:db8:254:85::/64 | R8 Et2 ::1 – S5 Et1 ::2. S5 default `::/0` → ::1 | 80 / RESERVED |
| 2001:db8:254:20::/64 | VLAN 10. R8 ::1. Hosts use SLAAC (e.g. H1-1 `…:6cef:d9ff:fec7:c215`, H6 `…:7c84:f1ff:fe75:62b5`) | 82 / RESERVED |

The prefix records are still RESERVED. Changing them to active is PREPARED_NOT_EXECUTED (§20).

## 7. Native ZTP architecture

The source is `web/core/services/ztp/` (`workflow.py`, `adapters/arista_eos.py`, `dhcp/{isc,kea}.py`, `relay_option82.py`, `management.py`), plus `provisioning/bootstrap.py`.

How cEOS native ZTP works (from the docstring of `ztp/adapters/arista_eos.py`, observed on cEOSLab 4.36.2F):
1. A device with no startup-config sends DHCPv4 DISCOVER requests. They carry option 60 `Arista;<model>;<serial>`, option 61 (the system MAC) and option 77, and request options 66 and 67.
2. The device fetches the option 67 URL. A file that isn't a script is saved as the startup-config; EOS reloads into it and ZTP disables itself.
3. The bootstrap artifact installs only an **SSH public key** for a dedicated enrollment user (`nmas-svc`), plus a password hash of discarded random bytes that nobody can log in with. The private key stays in NMAS's secret provider.
4. **The host key is not trusted on first contact.** An approver enrolls it from an out-of-band console read (`show management ssh hostkey ed25519 public`). SZTP (option 143 vouchers) is not implemented.

The NMAS sequence for each new device:

```text
register (DEV) → isolation policy on the upstream port, enforced and verified with traffic (ISO)
 → bootstrap authorization (BAUTH, bound to the expected identity)
 → DHCP relay with option 82 on the upstream port (governed Change) → ZTP session (ZTP)
 → contact → host-key enrollment (out of band) → management verification (identity matches the expected serial/MAC)
 → bootstrap-credential transition (BCRED: enrollment key → per-device nmas-svc credential)
 → commissioning (COM: governed provisioning Change, still ISOLATED)
 → production admission (ADM: governed release of the isolation on the upstream)
```

**Why ZTP doesn't admit a device.** ZTP only proves that a device with the expected identity reached a management session. Until admission, the upstream port keeps the device isolated:
* NMAS filters plus a control-plane ACL, so the device cannot reach R8/R2's own SSH, eAPI or gNMI services;
* OSPF on the port is passive;
* only bootstrap fetch is permitted.

Admission releases that isolation only after the new device's routing is proven.

## 8. R8 bootstrap process — IMPLEMENTED_AND_VERIFIED

| Step | Record | Result |
|---|---|---|
| R2 Et4/Et5 addressing and DHCP relay to 10.254.84.2 | CHG-20261103-0013, run `5d667e5d-e026-40c1-971b-e6563f1fe442` | SUCCEEDED 05:54 |
| R2 relay option 82 on Et4 | CHG-20261103-0014, run `a00be3e1-75cb-4196-a6be-e8ab2ae92602` | SUCCEEDED 06:16 |
| Isolation of R8 on R2:Ethernet4 | ISO-000003. CHG-0015 FAILED_ROLLED_BACK, then CHG-0016 `1ccf5d95-28f6-41e3-b205-b3c2fdfc3edc` SUCCEEDED 06:17 | now RELEASED (after admission) |
| ZTP network `lab9-r8-ztp` (service 10.254.84.2) and ZTP session | ZTP-000003, verified. Host key enrolled (ED25519). | verified |
| Bootstrap authorization, credential transition | BAUTH (id 3) CONSUMED, BCRED-000003 COMPLETE | |
| Commissioning | COM-000007 ABORTED (see §28), **COM-000008 ADMITTED** | |
| Admission | ADM-000004 RESTORED (rolled back), **ADM-000005 ADMITTED** (CHG-0025 `c1c93877-…` 07:42) | |

## 9. S5 bootstrap process — IMPLEMENTED_AND_VERIFIED

S5 bootstraps the same way as R8, but its trusted upstream is **R8 Ethernet2**, a device that was itself onboarded by ZTP:

| Step | Record | Result |
|---|---|---|
| R8 Et2 DHCP relay with option 82 | CHG-20261103-0030, run `d4f8382e-d091-45e2-856a-befd0ffcefc8` | SUCCEEDED 08:08 |
| Isolation of S5 on R8:Ethernet2 | ISO-000004 via CHG-0034 `46a51b57-dafd-4123-b6c5-d6abc570c3e5` | ENFORCED → VERIFIED with traffic sent from S5 (bootstrap fetch permitted; other service ports, R8's own SSH/eAPI and the NMAS host denied). Re-verified 09:21 after the failed admission. Now RELEASED. |
| ZTP session | ZTP-000004, host key console-checked (`evidence/lab9_s5_console_hostkey.txt`) | verified |
| BAUTH (id 4) CONSUMED, BCRED-000004 COMPLETE | per-device credential | |
| Commissioning | COM-000009 to COM-000012 ABORTED (§28), **COM-000013 ADMITTED** (CHG-0044 `1fc80297-91db-47d2-a29a-f10d397c964e`, SUCCEEDED 09:24) | |
| Admission | ADM-000006 and ADM-000007 RESTORED, **ADM-000008 ADMITTED** (CHG-0045 `219f95df-772b-41f8-87dd-322c4d3ba2ac`, 09:26) | |

**How S5 differs from R8:**
1. **Management reachability.** S5's management address (10.254.85.2) sits behind R8. NMAS reaches it through a host route via R2, plus a pinned SSH proxy in the service namespace.
2. **Host checksums.** The ZTP service interface needed TX checksum offload turned off, because cEOS's forwarding plane passes on partial checksums.
3. **Commissioning content.** S5's intent is a switch profile: three access ports, an SVI, and a routed uplink with a loopback router ID.

## 10. H1-1 and H6 provisioning

**NOT_APPLICABLE to ZTP.** H1-1 and H6 are unmanaged end hosts, just like H1–H5. They did not go through NMAS ZTP or commissioning, and this document does not claim they did.
* IPv4: static 10.254.20.11/24 and 10.254.20.12/24, gateway 10.254.20.1. These were set at host creation, outside NMAS governance.
* IPv6: SLAAC from R8 Vlan10's router advertisements. The default route is `fe80::5a:deff:fe00:8`, R8's Vlan10 link-local address.
* Hostnames are exactly `H1-1` and `H6`, distinct from Lab 1's `H1`, which is untouched (`clab-srlceos01-H1` still runs).
* The hosts appear in the NMAS topology as declared end hosts: H1-1 below S5, H6 to the right of S5, health UNKNOWN as for every unmanaged host.
* They appear in the Traffic workbench dropdowns because the traffic runner pins them as `H1-1=nmas-lab9-h1-1` and `H6=nmas-lab9-h6`.

## 11. NMAS IaC design and configuration generation

Intent is structured data. Each device has a **Device Builder** intent revision (`Change → DeviceIntent → revision.sections`), with these sections:
* `interfaces` (ROUTED_PHYSICAL / ACCESS / SVI / LOOPBACK, addresses, access VLAN);
* `routing.ospf` (process, router ID, interface bindings with area and passive flag);
* `routing.static_routes`;
* relay, NAT and other objects.

Every field is committed through a validating writer (`core/services/field_commit_service.py`, `interface_intent_service.py`, `routing_intent_service.py`). An invalid value never reaches the candidate.

| Stage | Module | What it does |
|---|---|---|
| Candidate render | `core/services/candidate_renderer.py` (`render`, `_interfaces_from_sections`, `_routing_from_sections`) | Builds the accepted state from the intent sections |
| Templates | `core/services/config_templates/`, `feature_template_renderer.py` | Platform feature templates (Jinja). cEOS and FRR are rendered differently. |
| Plan | `core/services/planning/builder.py`, `configlet_factory.py`, `ordering.py`, `priorities.py` | Splits the change into ordered **Configlets** (CFG-001 …), each with a verification spec and an exact inverse |
| IPAM | `core/services/provisioning/ipam.py` | Reserves NetBox prefixes and addresses for provisioning runs |
| Capability gate | `core/services/provisioning/capability_gate.py`, `capabilities/` | Refuses any (platform, feature) cell that LIVE evidence doesn't show as supported |
| Isolation render | `core/services/isolation/eos.py`, `isolation/frr.py` | Upstream filters, control-plane ACL, passive OSPF, the release ops |

Example: the rendered candidate for R8 (CHG-20261103-0020, PROV-000008), excerpted:

```text
! CFG-003 R8
interface Ethernet3
   switchport
   switchport mode access
   switchport access vlan 10
! CFG-005 R8
interface Vlan10
   ip address 10.254.20.1/24
! CFG-008 R8
interface Vlan10
   ipv6 address 2001:db8:254:20::1/64
! CFG-011 R8
ip routing
router ospf 1
   router-id 192.168.255.8
! CFG-012 R8
interface Ethernet2
   ip ospf area 0.0.0.20
router ospf 1
   passive-interface Ethernet2      ← stays passive until S5 is admitted
! CFG-014 R8
interface Ethernet1
   ip ospf area 0.0.0.20
```

Example: the rendered candidate for S5 (CHG-20261103-0044, PROV-000013, 14 Configlets), excerpted:

```text
interface Ethernet3
   switchport mode access
   switchport access vlan 10
interface Loopback0
   ip address 192.168.255.95/32
ipv6 route ::/0 2001:db8:254:85::1
router ospf 1
   router-id 192.168.255.95
interface Ethernet1
   ip ospf area 0.0.0.20
interface Loopback0
   ip ospf area 0.0.0.20
```

**NAT and return routing as code** (CHG-20261103-0035). FRR on R3 renders the NAT rule as nftables:

```text
! CFG-002 R4
ipv6 route 2001:db8:254:20::/64 2001:db8:100:104::1
! CFG-004 R4
router bgp 65004
   address-family ipv6 unicast
      network 2001:db8:254:20::/64
! CFG-005 R3
table ip DEVICE_BUILDER_PAT { chain postrouting { type nat hook postrouting priority srcnat;
    oifname "eth2" ip saddr 10.254.20.0/24 masquerade } }
```

## 12. GitHub Configuration Validation

* **Trigger.** Planning a Change dispatches a `repository_dispatch` to `.github/workflows/configuration-validation.yml` in the public CI repository, carrying the immutable candidate snapshot (`core/services/configuration_validation/`).
* **Gate.** NMAS stores the run ID and conclusion, and execution eligibility refuses a Change until its CV passes (`CONFIGURATION_VALIDATION_NOT_PASSING`).
* **What it checks.** The rendered candidate (syntax/semantic checks on the snapshot). It never touches a device.
* **Scope.** This is runtime validation of one Change, which is different from source-code CI (§25).

| Change | Device | CV run (GitHub) | Conclusion |
|---|---|---|---|
| CHG-20261103-0013 | R2 | 41586433339 | PASS |
| CHG-20261103-0014 | R2 | 41586814020 | PASS |
| CHG-20261103-0020 | R8 | 41593953264 | PASS |
| CHG-20261103-0030 | R8 | 41599751557 | PASS |
| CHG-20261103-0032 | R2, R8 | 41600636069 | PASS |
| CHG-20261103-0035 | R3, R4 | 41602423996 | PASS |
| CHG-20261103-0037 | R2, R8 | 41604031574 | PASS |
| CHG-20261103-0044 | S5 | 41610492853 | PASS |

Run URLs take the form `https://github.com/Dhruv-Suvarna/Adv-Netman-public-ci/actions/runs/<id>`.

Transition Changes (isolation and admission: CHG-0016, 0025, 0034, 0045) are not generic Changes. They follow the governed single-device transaction path (`isolation/transaction.py`): validation, an immutable plan hash, a precheck from a fresh read, approval of that hash, and a read-back postcheck.

## 13. Governance, human approval and commissioning

* **Two people.** Requests are made as `nmas-demo-operator` and approvals as `dhruv`. Self-approval is refused (`COMMISSIONING_SELF_APPROVAL`, `ADMISSION_SELF_APPROVAL`). The operator authorized running these approvals through the NMAS website so the execution logs stay visible.
* **Commissioning approval** binds to a SHA-256 **evidence digest** covering identity, attachment, isolation, credential, dependencies and candidate (`commissioning/service.py::readiness`, `digest`, `approve`). If anything changes after approval, execution is refused:
  * `PROVISIONING_APPROVAL_STALE` happened for real on COM-000010;
  * staleness also covers approval age (`staleness`).
* **Commissioning vs admission.** Commissioning configures the device *while it is still isolated*, so the record ends CONFIGURED. Admission (`commissioning/admission.py`) is a separate governed release of the upstream isolation. It requires operator-stated expectations: the OSPF neighbor router ID, routes the device itself owns learned through the port, and reachable addresses. It is checked by a postcheck poller with a settle window. If any expectation fails, the release is compensated and the device stays isolated.

## 14. Configuration execution and postchecks

* **Executor.** `core/services/execution/engine.py` with cEOS SSH executors (`execution/executors`, pinned host keys through the commissioning transport).
  * It holds a per-device lock (`device_mutex.py`).
  * It captures the pre-change config digest (`provisioning/lifecycle.py::before_first_mutation`).
  * It applies Configlets in order.
* **Postcheck.** `core/services/health/requirements.py` maps each Configlet's requirements to checks: INTERFACE_*, ADDRESS_PRESENT, STATIC_ROUTE_PRESENT, OSPF_NEIGHBOR_EXPECTED, and so on. `health/evaluators.py` judges them against **fresh live reads**. Adjacency checks retry during a settle window (`execution/codes.py::SETTLING_CHECKS`).
* **Failure handling.** Compensation runs newest-first with each Configlet's inverse. The run outcome distinguishes `POSTCHECK_FAILED_ROLLED_BACK` (restore proven) from `POSTCHECK_FAILED_COMPENSATION_INCOMPLETE` (restore not proven).
* **Capability evidence.** Every execution records LIVE capability evidence for the features it touched (`network_config_validation.py::_record_live_capabilities`).

## 15. OSPFv2 area 20 — IMPLEMENTED_AND_VERIFIED

* R2 process 10 (RID 192.168.255.2) is the area 0 ↔ 20 ABR. R8 runs process 1 (RID 192.168.255.8); S5 runs process 1 (RID 192.168.255.95).
* R2 Et4 ↔ R8 Et1 is point-to-point (CHG-0037, run `05756d21-240a-434a-9a4c-6c935df72798`). R8 Et2 ↔ S5 Et1 is broadcast, with the passive flag removed by the S5 admission release.

Live read-back at 09:32 (`evidence/lab9_final_operational_0932.txt`):

| Router | Neighbor ID | State | Address | Interface |
|---|---|---|---|---|
| R2 | 192.168.255.8 (R8) | FULL | 10.254.82.2 | Ethernet4 |
| R8 | 192.168.255.2 (R2) | FULL | 10.254.82.1 | Ethernet1 |
| R8 | 192.168.255.95 (S5) | FULL/DR | 10.254.85.2 | Ethernet2 |
| S5 | 192.168.255.8 (R8) | FULL/BDR | 10.254.85.1 | Ethernet1 |

R8's IPv4 OSPF table includes `O 192.168.255.95/32 via 10.254.85.2, Ethernet2`, which is S5's loopback. It also includes `O E2 172.30.50.10/32 via 10.254.82.1`, the WebServer, plus the area 0 inter-area routes.

## 16. OSPFv3 area 20 — IMPLEMENTED_AND_VERIFIED (R2–R8)

* CHG-20261103-0032 (run `c895d278-713f-42a3-afc8-8e6202da0ab3`) configured:
  * `ipv6 ospf 10 area 0.0.0.20` with `network point-to-point` on R2 Et4;
  * `ipv6 ospf 1 area 0.0.0.20` on R8 Et1;
  * R8 Vlan10 as passive.
* R8 reports neighbor 192.168.255.2 in area 0.0.0.20 on Ethernet1 as **Full**, and R2 lists R8 the same way.
* R8's IPv6 OSPF routes include `O3 E2 2001:db8:3050::10/128` (the WebServer), the Lab 1 `2001:db8:100:10x::/64` inter-area routes and the `2001:db8:10/20/30::/64` user LANs.
* **S5 does not run OSPFv3.** By design, its IPv6 is a static default to R8 (`::/0 → 2001:db8:254:85::1`), and the hosts' IPv6 gateway is R8 itself.

## 17. S5 switching and VLAN 10 — IMPLEMENTED_AND_VERIFIED

`show vlan` on S5: `10 VLAN0010 active Et2, Et3, Et4, Cpu`.

`show interfaces status`: Et1 is `routed` (description `NMAS bootstrap uplink ZTP-000004`), and Et2, Et3 and Et4 are `connected` in VLAN 10.

R8 Et3 is an access port in VLAN 10, so VLAN 10 extends from R8's SVI through S5 to both hosts.

## 18. IPv4 NAT and return routing — IMPLEMENTED_AND_VERIFIED for ICMP

* The WebServer is reached via R3/R4 eth2, which carry NAT. From R8, `172.30.50.10/32` is an OSPF E2 route through R2.
* R3 and R4 both hold `oifname "eth2" ip saddr 10.254.20.0/24 masquerade`. R4 already had it; R3's was added by CHG-0035.
* R3 and R4 learn `10.254.20.0/24` through OSPF via R2 (VLAN 103/104).
* H1-1 and H6 → 172.30.50.10 ICMP: 2/2 and 2/2. NMAS Traffic workbench ICMP runs PASSED: H1-1 run `f6a142b6`, H6 run `e1e4882a`.

## 19. Native IPv6 routing and WebServer — ICMP VERIFIED, TCP BLOCKED

* **Outbound.** Host → R8 (RA default) → R2 via OSPFv3 → area 0 → R3/R4 → WebServer.
* **Return.** R4 holds `ipv6 route 2001:db8:254:20::/64 2001:db8:100:104::1` and advertises it in BGP (CHG-0035).
* **Why the return static was needed.** FRR 8.4.4's ospf6d on R3/R4 kept R2 in its border-router table without the B bit, so it ignored R2's inter-area LSA for this prefix.
* **R3.** It cannot take a static route because `staticd` isn't reachable from vtysh (`% Unknown command`, CHG-0033 FAILED_NO_MUTATION). R3 is Lab 1 equipment and was left alone. R3 returns IPv6 traffic via R5 → R4 BGP.
* **ICMP works.** H1-1 and H6 → 2001:db8:3050::10 ICMP: 2/2 each. Workbench ICMPv6 runs PASSED: H1-1 `11a928ad`, H6 `1ae27602`.
* **BLOCKED: TCP/HTTP.** HTTP from H1-1 and H6 to the WebServer **fails over both families**: `wget … download timed out`; workbench TCP_CONNECT gives CONNECTION_TIMEOUT. H5 HTTP over both families succeeds from the same network.
  * Likely cause, *not yet verified*: TX checksum offload is **on** for H1-1's and H6's `eth1` and **off** for H5's.
  * The same cEOS partial-checksum behaviour was seen and fixed on the ZTP service interface.
  * The fix (`ethtool -K eth1 tx off` in each host's namespace) was not applied, because this documentation phase is read-only.

## 20. NetBox IPAM integration — PARTIAL

| Object | State (read back via the NetBox API at 09:33) |
|---|---|
| Device R8 (id 33) | active, Ethernet1 with 10.254.82.2/29 (active) |
| Device S5 (id 38) | active, Ethernet1 with 10.254.85.2/29 (active) |
| Lab 9 prefixes (ids 76–82) | **RESERVED** (created by `nmas-lab89/lab9_netbox_reserve.py`) |
| R8/S5 IPv6, loopback, VLAN 10 SVI addresses, cables, Lab 9 VLAN 10 | **not recorded** |
| Hosts | not represented (the same convention as H1–H5) |

* Provisioning records the management address only (`provisioning/ipam.py`).
* Activating the 7 prefixes (`nmas-lab89/lab9_netbox_activate.py --apply`) passed a dry run: **PREPARED_NOT_EXECUTED**.

## 21. NMAS topology and Grafana monitoring — IMPLEMENTED_AND_VERIFIED

* **NMAS topology** (`/api/topology/`, the home page). After `nmas_infrastructure dispatch --consumer topology|monitoring` (16 events APPLIED for each):
  * R8 and S5 are HEALTHY and monitored;
  * H1-1 is directly below S5 (x 375, y 650) and H6 to its right (x 525, y 520);
  * the edges R8–R2, S5–R8, H1-1–S5 and H6–S5 are all UP.
* **Grafana** (`http://localhost:3000`, data source `nmas-influxdb`, bucket `network-monitoring`). Fresh rows for **R8 and S5 at 09:31 UTC**:
  * `nmas_device_ssh`: memory, uptime;
  * `nmas_device_ssh_interface`: link_up, octets/packets/errors;
  * `gnmi_telemetry` (pinned SSH): CPU and interface admin status;
  * `nmas_device_lifecycle`: admitted, monitored.

  The dashboard is `NMAS Commissioned Device SSH Telemetry` (`/d/nmas-commissioned-ssh/...`). Read-back helper: `nmas-lab89/lab9_grafana_check.py`.

## 22. Unit-testing methodology

* **Framework.** Django's test runner (`manage.py test`, built on Python `unittest`). It uses `SimpleTestCase` for pure functions and `TestCase` for database-backed services. pytest is not used.
* **Mocks and fixtures.** Services expose replacement points that tests substitute. Examples:
  * `commissioning/service.py: CONFIG_READER, GATEWAY_FACTORY`;
  * the admission `access=` parameter;
  * fake executors and config sessions (`self.flow.access`, `self.flow.session.config`);
  * `SimpleNamespace` policy fixtures.

  No test touches a live device or NetBox.
* **Test categories:**
  * *render tests*: exact EOS/FRR lines and their inverses;
  * *validation tests*: invalid intent and expectations refused with codes such as `ADMISSION_EXPECTATIONS_INVALID`;
  * *parser and read-back tests*: `eos.routes_via`, `ospf_neighbors_on`, control-plane ACL parsing;
  * *negative tests*: self-approval, stale evidence, wrong state;
  * *rollback and compensation tests*: a failed postcheck restores the exact pre-change config, and the record ends RESTORED/ABORTED.
* **Unit vs integration vs live.** Unit and service tests run in CI. Live behaviour is proven only by NMAS postchecks and the operational evidence (§26).

## 23. Device-specific testing examples

The tests are **platform-level (arista_ceos / ubuntu_frr), not device-named**. No test names R8, S5, H1-1 or H6, and none is claimed here. The table maps what each device relies on to the tests that cover that behaviour.

| Device behaviour | Test(s) (`web/core/tests/`) |
|---|---|
| R8/S5 admission releases an explicit `passive-interface` on the upstream port (new in Lab 9) | `test_isolation_admission_ospf_release.py` (6 tests): `test_explicit_passive_on_the_port_is_released`, `test_passive_default_is_never_touched`, `test_release_op_removes_with_default_and_restores_the_passive`, `test_release_ops_append_the_recorded_routing_release_after_the_filters`, … |
| R2/R8 isolation closes eAPI, gNMI, SNMP and NETCONF with an NMAS control-plane ACL (new in Lab 9) | `test_isolation_eos.py`: `test_other_services_are_closed_by_an_nmas_control_plane_acl_and_released_exactly`, `test_control_plane_v6_denies_link_local_tcp_and_snmp_only`, `test_management_plane_exposed_by_a_custom_control_plane_acl_or_nmas_lockout` |
| S5 aborted after configuration → its provisioning run is closed (new in Lab 9) | `test_provisioning.py`: `test_a_configured_run_whose_commissioning_was_aborted_is_closed`, `test_close_configured_refuses_any_other_stage` |
| S5 Loopback0 in OSPF: no adjacency expected on a loopback (new in Lab 9) | `test_health_engine.py`: case `ospf loopback interface` → NOT_APPLICABLE |
| Admission expectations, approval separation, stale approval, verification failure → RESTORED | `test_commissioning.py` (35 tests): `test_approval_is_separated_and_bound_to_the_evidence`, `test_execute_refused_when_unapproved_or_stale`, `test_plan_refused_with_invalid_expectations_creates_nothing` |
| Dual-stack (IPv6) admission | `test_ipv6_admission.py` (18 tests) |
| Interface, VLAN and access-port rendering and postchecks | `test_access_routing_postchecks.py`, `test_phase13_routing.py`, `test_execution_executors.py` |
| H1-1 / H6 | **No unit tests.** Hosts are unmanaged. Their coverage is the live traffic harness (Traffic workbench runs) and the ping/HTTP evidence. The production-only traffic-runner fix for hyphenated names (`traffic/runner/config.py::_PINNED_ENDPOINT`) has no test yet. |

**Lab 9 regression run** (public-ci working tree, 2026-11-03, serial runner): the 14 affected suites ran **415 tests, OK**:
`test_isolation_admission_ospf_release`, `test_isolation_eos`, `test_isolation_service`, `test_ipv6_admission`, `test_frr_isolation`, `test_tg_isolation_closure`, `test_provisioning`, `test_commissioning`, `test_tg_commissioning_closure`, `test_tg_commissioning_views_closure`, `test_health_engine`, `test_access_routing_postchecks`, `test_phase13_routing`, `test_execution_executors`.

## 24. Code coverage methodology and actual results

* **How it's collected.** `coverage.py` 7.16.2 with **statement and branch** coverage (`.coveragerc`: `branch = True`). The Lab 7 test-governance runner collects it in Tier-3 CI (`web/core/services/test_governance`).
* **Omitted:** `*/tests/*`, `*/migrations/*`, `*/docs/*`, virtual environments, runtime output.
* **Report scope:** only artifacts in the governance inventory.

**Repository-wide (all of NMAS, not Lab 9 specific).** Tier-3 run [41535436076](https://github.com/Dhruv-Suvarna/Adv-Netman-public-ci/actions/runs/41535436076) on main `4f950b3` (2026-11-02):

| Metric | Value |
|---|---|
| Line coverage (governed scope) | **89.16 %** (64,812 / 72,689 statements) |
| Branch coverage (governed scope) | **82.32 %** (19,911 / 24,186 branches) |
| Raw coverage.xml | line-rate 0.8942, branch-rate 0.8249 |
| Tests | 8,877 total: 8,869 pass, 8 skip |
| Positive / negative cases required | 4,241 / 3,351. Debt: 69 / 38 (gate result PASS_WITH_DEBT) |

**Per module at main 4f950b3**, for the modules Lab 9 depends on (from the same coverage.xml):

| Module | Line | Branch |
|---|---|---|
| `isolation/eos.py` | 92.38 % | 86.82 % |
| `isolation/service.py` | 90.98 % | 84.57 % |
| `commissioning/admission.py` | 88.48 % | 86.81 % |
| `commissioning/service.py` | 88.31 % | 81.82 % |
| `provisioning/lifecycle.py` | 94.16 % | 83.80 % |
| `provisioning/bootstrap.py` | 92.52 % | 92.11 % |
| `ztp/workflow.py` | 91.87 % | 79.76 % |
| `health/evaluators.py` | 92.28 % | 84.44 % |
| `health/requirements.py` | 100 % | 100 % |

**Lab 9 working tree (uncommitted changes), measured locally on 2026-11-03.** coverage.py 7.16.2 with `--branch`. Only the 14 Lab 9-affected suites were run (415 tests, OK), so these figures are *lower* than the full-suite numbers above. Modules exercised mainly by other suites (ZTP, bootstrap, evaluators) are covered elsewhere.

| Module | Line | Branch |
|---|---|---|
| `isolation/eos.py` | 92.42 % | 85.98 % |
| `isolation/service.py` | 90.24 % | 83.93 % |
| `isolation/intent.py` | 95.40 % | 93.48 % |
| `commissioning/admission.py` | 87.98 % | 85.81 % |
| `commissioning/service.py` | 85.02 % | 76.67 % |
| `provisioning/lifecycle.py` | 91.61 % | 79.45 % |
| `provisioning/bootstrap.py` | 72.90 % | 73.68 % |
| `health/evaluators.py` | 69.80 % | 60.95 % |
| `health/requirements.py` | 100.00 % | 100.00 % |
| `ztp/workflow.py` | 67.49 % | 45.24 % |

**These numbers are not device coverage.** They are not "R8 coverage" or "S5 coverage", and high coverage does not prove the network works. Coverage only shows which lines ran under fakes. The defects found during Lab 9 (§28) all sat in **covered** code:
* the OSPF loopback adjacency evaluator;
* the admission route check that accepts the upstream's connected subnet.

They surfaced only against real devices.

## 25. CI/CD pipeline and hosted validation

| Workflow (`.github/workflows/`) | Trigger | Purpose |
|---|---|---|
| `tier3-validation.yml` | pull_request, push to main | Change-effect, integration and regression selection (`tier3.py` → `web/core/services/ci`) plus Lab 7 governance: test catalog, Pylint, coverage evidence. Uploads `test-governance-report.json`, `coverage.xml`, `tier3-report.json`. Validation only: no deployment, no lab access, no secrets. |
| `configuration-validation.yml` | `repository_dispatch` from NMAS | Runtime per-Change candidate validation (§12) |
| `secret-scanning.yml` | push / PR | Secret scanning |
| `repository-integrity.yml` | push / PR | Repository integrity checks |

* Main is protected: required status checks, and PRs are squash-merged.
* Recent Tier-3 runs: 41535436076 (main 4f950b3, success), 41569024388 (PR #11 `a804ad7`, success).
* **Source CI vs runtime validation.** Source CI proves the code; runtime CV proves a candidate; only the NMAS postcheck proves a device. A green GitHub run does **not** mean any device was configured.
* **Lab 9 code status.** The Lab 9 changes in branch `lab9/isolation-control-plane` are **uncommitted**, so they have not run in hosted CI yet.

## 26. Operational testing and connectivity evidence (09:32, `evidence/lab9_final_operational_0932.txt`)

| Test | H1-1 | H6 |
|---|---|---|
| IPv4 address / gateway | 10.254.20.11/24, default via 10.254.20.1 | 10.254.20.12/24, default via 10.254.20.1 |
| IPv6 address (SLAAC) / default | `2001:db8:254:20:6cef:d9ff:fec7:c215`, via `fe80::5a:deff:fe00:8` | `2001:db8:254:20:7c84:f1ff:fe75:62b5`, same gateway |
| ping gateway 10.254.20.1 | 2/2 | 2/2 |
| ping6 gateway 2001:db8:254:20::1 | 2/2 | 2/2 |
| ping WebServer 172.30.50.10 | 2/2 | 2/2 |
| ping6 WebServer 2001:db8:3050::10 | 2/2 | 2/2 |
| Workbench ICMP v4 / v6 | PASSED / PASSED | PASSED / PASSED |
| HTTP v4 / v6 (wget, workbench TCP 80) | **FAIL / FAIL** | **FAIL / FAIL** |

## 27. Security and isolation safeguards

* **Isolation before trust.** Upstream filters plus an NMAS **control-plane ACL**. Per-service ACLs were not enough: an eAPI ACL had no effect, gNMI has no IPv6 ACL and NETCONF has none. So isolation copies EOS's built-in `default-control-plane-acl` in running-config form, plus bootstrap denies (`isolation/eos.py`).
* **Traffic-proven isolation.** ISO-000004 was verified by probes sent **from S5**: bootstrap fetch allowed, everything else denied.
* **Credentials.** Enrollment uses a public key only, and the host key is enrolled out of band. Bootstrap credentials are rotated to a per-device credential (BCRED). No private key or password appears in any record or in this document.
* **Governance.** Two-person approval bound to digests. Staleness and age refusal. Capability gating on LIVE evidence. Device locks.

## 28. Failure handling, rollback and recovery (challenges faced)

| # | Challenge | What happened / how it was resolved |
|---|---|---|
| 1 | No free ports on R2 | Ports were hot-added to R2's namespace and `ProcMgr` was restarted under maintenance window MNT-000004, after a fixture proof. OSPF reconverged in ~87 s with no lost Lab 8 traffic. |
| 2 | First R2 isolation (CHG-0015) | FAILED_ROLLED_BACK. Fixed, then CHG-0016 SUCCEEDED. |
| 3 | R8 provisioning PROV-000007 (CHG-0017) | POSTCHECK_FAILED_COMPENSATION_INCOMPLETE. COM-000007 aborted and PROV-000008 (CHG-0020) succeeded. |
| 4 | OSPFv3 on an isolation port is refused | By design, OSPFv3 area 20 became a post-admission Change (CHG-0032). |
| 5 | OSPF network-type mismatch (cEOS broadcast vs the R2 port) | CHG-0019 and CHG-0029 POSTCHECK_FAILED_ROLLED_BACK. Both families moved to point-to-point (CHG-0032, CHG-0037). |
| 6 | First R8 admission ADM-000004 (CHG-0023) | Release postcheck failed and the release was rolled back. R2 Et4 was made passive until admission (CHG-0024), then ADM-000005 was admitted. |
| 7 | IPv6 return path | FRR 8.4.4 ospf6d ignored R2's inter-area LSA (missing B bit). R3 has no reachable `staticd` (CHG-0033 FAILED_NO_MUTATION). Fixed with an R4 IPv6 static + BGP and R3 NAT44 (CHG-0035). |
| 8 | cEOS forwarding passes on partial checksums | The ZTP service interface needed `ethtool -K tx off`. Probably also the cause of the open host HTTP issue (§19). |
| 9 | ADM-000006 (S5): wrong expectations | The expected neighbor was R8's own RID, and no S5-owned route existed. Restored. Fix: S5 Loopback0 192.168.255.95/32 in OSPF. |
| 10 | COM-000010: approval stale | The plan was rebuilt after approval, so execution was blocked (`PROVISIONING_APPROVAL_STALE`) before anything was sent. Aborted. |
| 11 | CHG-0041 (COM-000011): evaluator defect | All 13 Configlets applied and 26 checks passed, but `OSPF_NEIGHBOR_EXPECTED` failed on **Loopback0**. A loopback never has a neighbor, so NMAS rolled back. **Code fix:** `health/evaluators.py::_never_adjacent` (OSPF and IS-IS) plus a regression test. The failed run had also stored FAILED LIVE capability evidence for 6 cEOS features. These were corrected by appending (operator-approved) rows with source `evaluator-defect-correction`, referencing postcheck `898ab31d`. The ledger is append-only. |
| 12 | COM-000012 / ADM-000007: incomplete intent | A SQLite `database is locked` error truncated intent construction, so the Loopback0 OSPF binding and `::/0` were missing. Commissioning passed, but admission correctly failed ("192.168.255.95/32 not learned through Ethernet2") and was restored. A completeness guard was added to `lab9_s5_commission.py`. COM-000013 then succeeded. |
| 13 | Rollback could not be proven after #11 and #12 | The device digest didn't match its pre-run state, so a fresh run refused `DEVICE_ALREADY_CONFIGURED`. Recovered with operator-authorized, digest-guarded one-off inverse writes: `lab9_s5_revert_chg0036.py` / `_finish.py`, `lab9_s5_revert_chg0041.py`, `lab9_s5_revert_chg0042.py`. Each matched the recorded pre-run digest exactly (`evidence/lab9_s5_revert_*.json`), and NMAS reconciled the records. |
| 14 | Admission route check weakness (open) | `eos.routes_via` excludes connected subnets only when they're passed in. Admission passes `[]`, so the upstream's own connected subnet would count as "learned". The S5 admission avoided this by expecting the loopback /32. |

**Code changes made for Lab 9** (uncommitted, public-ci branch `lab9/isolation-control-plane`):
* `isolation/eos.py`: control-plane ACL; `render_admission_ospf_release`.
* `isolation/intent.py`.
* `isolation/service.py`: `admission_ospf_release`, `release_ops(policy, ospf_release)`.
* `commissioning/admission.py`: the plan records the upstream's OSPF release.
* `commissioning/service.py`: `abort` closes a configured run.
* `provisioning/lifecycle.py` and `provisioning_service.py`: `close_configured`.
* `health/evaluators.py`: the loopback fix.
* Tests in the files listed in §23.

## 29. Existing-network preservation

* Lab 1 hosts H1–H4 and the H1 container are untouched. H1 → WebServer was not repaired, as instructed.
* R2's `dhcp server` was never touched.
* The only R2 changes were on the new ports Et4 and Et5. R2's restart went through MNT-000004 with traffic verification before and after.
* Lab 8 R6, R7 and H5 are unchanged. H5 HTTP to the WebServer still succeeds over both families (09:3x).
* On R3 and R4, only additive changes were made (CHG-0035): an R4 IPv6 static plus a BGP network, and an R3 masquerade for 10.254.20.0/24.

## 30. Tool-by-tool demonstration examples

| Tool | Where | What it shows |
|---|---|---|
| NMAS topology | `http://localhost/` | R8/S5 HEALTHY, host placement |
| NMAS device lifecycle | `/automation/provisioning/devices/DEV-000005/`, `/DEV-000006/` | lifecycle and admission state, events |
| ZTP | `/automation/provisioning/devices/DEV-000006/ztp/ZTP-000004/api/`, `/automation/provisioning/ztp/networks/` | session, verification |
| Commissioning | `/automation/provisioning/devices/DEV-000006/commissioning/`, `/automation/provisioning/commissioning/` | COM-000009 to COM-000013, ADM-000006 to ADM-000008 |
| Device Builder / CV | `/device-builder/changes/CHG-20261103-0044/`, `…/configuration-validation/` | intent, candidate, GitHub CV |
| Execution | `/device-builder/changes/CHG-20261103-0044/executions/1fc80297-91db-47d2-a29a-f10d397c964e/` | per-Configlet apply and postcheck |
| Failure + rollback | `/device-builder/changes/CHG-20261103-0043/executions/8647d93d-2a80-4703-8389-1e67471d8777/` | admission postcheck failure, compensation |
| NSoT | `/nsot/devices/R8/`, `/nsot/devices/S5/`, `/nsot/ipam/` | NetBox-backed views |
| Monitoring | `/monitoring/`, Grafana `http://localhost:3000/d/nmas-commissioned-ssh/…` | R8/S5 telemetry |
| Traffic | `/automation/traffic/` | H1-1/H6 → WebServer runs |
| NetBox | `http://localhost:8000/dcim/devices/33/`, `/38/`, `/ipam/prefixes/?q=10.254.8` | device/IP/prefix records |
| GitHub | `…/actions/runs/41610492853` (CV), `…/actions/runs/41535436076` (Tier-3) | validation, tests, coverage |

Read-only CLI used for evidence. cEOS, through NMAS's pinned SSH (commissioning transport) or `docker exec <R2> Cli -p 15 -c`:
* `show ip ospf neighbor`, `show ipv6 ospf neighbor`;
* `show ip route ospf`, `show ipv6 route ospf`;
* `show ip interface brief`, `show ipv6 interface brief`;
* `show vlan`, `show interfaces status`.

FRR: `vtysh -c "show ip route 10.254.20.0/24" -c "show ipv6 route 2001:db8:254:20::/64"` and `nft list ruleset`.

Hosts: `ip addr`, `ip route`, `ping`, `wget`.

## 31. Execution history and evidence references

| Change | Devices | Lifecycle record | CV run | Execution run | Outcome | Demonstrates |
|---|---|---|---|---|---|---|
| CHG-20261103-0013 | R2 | — | 41586433339 | 5d667e5d-e026-40c1-971b-e6563f1fe442 | SUCCEEDED | new ports, DHCP relay |
| CHG-20261103-0014 | R2 | — | 41586814020 | a00be3e1-75cb-4196-a6be-e8ab2ae92602 | SUCCEEDED | option 82 |
| CHG-20261103-0016 | R2 | ISO-000003 | (transition) | 1ccf5d95-28f6-41e3-b205-b3c2fdfc3edc | SUCCEEDED | R8 isolation |
| CHG-20261103-0017 | R8 | PROV-000007 / COM-000007 | 41591774220 | 4f4718e1-d20a-4d8b-a7d0-88d3a1b2ac02 | POSTCHECK_FAILED_COMPENSATION_INCOMPLETE | failure path |
| CHG-20261103-0020 | R8 | PROV-000008 / COM-000008 | 41593953264 | 932232b6-e239-43e1-a800-3902d647adf9 | SUCCEEDED | R8 commissioning |
| CHG-20261103-0024 | R2 | — | 41597147660 | d117a29f-c073-44a9-8e2c-1832c34cacbc | SUCCEEDED | passive OSPF until admission |
| CHG-20261103-0025 | R2 | ADM-000005 | (transition) | c1c93877-7b23-40b8-8c11-a11be2b53a0e | SUCCEEDED | R8 admission |
| CHG-20261103-0030 | R8 | — | 41599751557 | d4f8382e-d091-45e2-856a-befd0ffcefc8 | SUCCEEDED | S5 relay + option 82 |
| CHG-20261103-0032 | R2, R8 | — | 41600636069 | c895d278-713f-42a3-afc8-8e6202da0ab3 | SUCCEEDED | OSPFv3 area 20 |
| CHG-20261103-0034 | R8 | ISO-000004 | (transition) | 46a51b57-dafd-4123-b6c5-d6abc570c3e5 | SUCCEEDED | S5 isolation |
| CHG-20261103-0035 | R3, R4 | — | 41602423996 | 3b697ebc-8384-4a19-a8ce-5b6d09d797e6 | SUCCEEDED | WebServer return path, NAT |
| CHG-20261103-0036 | S5 | PROV-000009 / COM-000009 | 41603759683 | 2e8054e3-803c-4945-8c4f-80195fe0fd98 | SUCCEEDED (then aborted, see §28 #9) | |
| CHG-20261103-0037 | R2, R8 | — | 41604031574 | 05756d21-240a-434a-9a4c-6c935df72798 | SUCCEEDED | OSPFv2 p2p |
| CHG-20261103-0041 | S5 | PROV-000011 / COM-000011 | 41607597550 | d464880f-e738-480e-8680-02f31df2bb44 | POSTCHECK_FAILED_COMPENSATION_INCOMPLETE | evaluator defect |
| CHG-20261103-0043 | R8 | ADM-000007 | (transition) | 8647d93d-2a80-4703-8389-1e67471d8777 | POSTCHECK_FAILED_ROLLED_BACK | admission refuses unproven routing |
| CHG-20261103-0044 | S5 | PROV-000013 / COM-000013 | 41610492853 | 1fc80297-91db-47d2-a29a-f10d397c964e | SUCCEEDED | S5 commissioning |
| CHG-20261103-0045 | R8 | ADM-000008 | (transition) | 219f95df-772b-41f8-87dd-322c4d3ba2ac | SUCCEEDED | S5 admission |

Execution URL pattern: `http://localhost/device-builder/changes/<CHG>/executions/<run>/`. All of the above returned HTTP 200 for an MFA-verified session (09:35).

Evidence files (`/home/student/Scripts/nmas-lab89/evidence/`):
* `lab9_final_operational_0932.txt`
* `lab9_fixture_restart_M1.txt`
* `lab9_r2_window_20261102_223913.txt`
* `lab9_s5_console_hostkey.txt`
* `lab9_s5_revert_*.json`
* `lab9_s5_after_revert*.cfg`
* `lab9_R2_running_config.txt`

## 32. Known limitations and unresolved items

| Item | Status |
|---|---|
| H1-1/H6 HTTP (TCP) to the WebServer, both families | **BLOCKED**. Likely host TX checksum offload; fix identified, not applied. |
| NetBox Lab 9 prefixes active; full interface/IPv6/VLAN records for R8/S5 | PREPARED_NOT_EXECUTED / not implemented |
| Lab 9 code in hosted CI (commit and PR) | IMPLEMENTED_BUT_NOT_VERIFIED in CI (local suites pass) |
| Production-only ports: traffic-runner hyphen names, topology host placement, legacy relay read-back | IMPLEMENTED_AND_VERIFIED in production. Not portable to public-ci until the Lab 8 cutover commit lands there. |
| Admission `routes_via` counts the upstream's connected subnet | open defect (§28 #14) |
| R3 `staticd` not reachable from vtysh | Lab 1, left alone |
| R2 Et4/Et5 and the ZTP service plumbing are runtime state (host routes, nft DNATs, SSH proxies, ZTP serve) | lost on host reboot |
| Host IPv4 addressing | static, set outside NMAS |

## 33. Conclusion and assignment-requirement mapping

R8 and S5 were added **only through governed automation**:
* native ZTP with identity proof;
* traffic-verified isolation;
* intent-generated configuration validated in GitHub;
* two-person approval;
* SSH execution with live postchecks and automatic compensation;
* a production admission that releases isolation only when the new device's routing is proven.

The failures along the way show the safeguards working as designed: four rolled-back admissions and provisioning attempts, a stale approval refused, and a defective check caught. The network never ended in an unproven state.

| Requirement | Where | Status |
|---|---|---|
| I. Device addition and framework operation (discovery, ZTP, IaC, governance, network behaviour) | §3–§19, §27–§29 | R8 and S5 VERIFIED. Hosts are unmanaged (NOT_APPLICABLE to ZTP). ICMP over both families VERIFIED; HTTP BLOCKED. |
| II. Unit testing and code coverage | §22–§25 | 415 Lab 9 suite tests OK. Repository coverage 89.16 % line / 82.32 % branch (whole NMAS, not per device). |
| III. Tool examples (NMAS, NetBox, Grafana, GitHub, CLI) | §20, §21, §25, §26, §30, §31 | NMAS, Grafana and GitHub VERIFIED. NetBox PARTIAL. |

**Acceptance checklist**

| Criterion | Status |
|---|---|
| R8 onboarded by native ZTP + commissioning + admission | IMPLEMENTED_AND_VERIFIED |
| S5 onboarded by native ZTP + commissioning + admission | IMPLEMENTED_AND_VERIFIED |
| R8 OSPFv2 and OSPFv3 area 20 | IMPLEMENTED_AND_VERIFIED |
| H1-1, H6 → WebServer over IPv4 and IPv6 (ICMP) | IMPLEMENTED_AND_VERIFIED |
| H1-1, H6 → WebServer over HTTP | BLOCKED |
| R8, S5 in topology and monitoring; H1-1, H6 placed and in the traffic workbench | IMPLEMENTED_AND_VERIFIED |
| NetBox IPAM for Lab 9 | PARTIAL (devices + management IPs; prefixes reserved) |
| H1 and Lab 8 untouched | IMPLEMENTED_AND_VERIFIED |
