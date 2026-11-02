# Version 2 Phase 4 full-platform capability matrix

## Final contract

The operator matrix has exactly two terminal states:

* **SUPPORTED**: every one of the eleven mandatory axes is satisfied. The
  automated-test, live-read, live-write, post-write, compensation, and runtime
  axes require empirical evidence; registry declarations cannot satisfy them.
* **UNSUPPORTED**: at least one mandatory axis is absent, failed, unverified,
  or unavailable in the current NMAS environment.

The eleven preserved axes are semantic model, Device Builder UI, renderer,
network-config validation, parser/import, automated tests, live read, live
write, post-write validation, compensation, and runtime validation. Internal
evidence retains diagnostic states, but `CapabilityRecord.status` and the main
matrix expose only the two states above. Stronger evidence wins over newer
weaker evidence (`LIVE` > `FIXTURE` > `STATIC`), while the newest result wins
within the same evidence type.

At the Phase 4 validation point the catalogue contains 66 modeled features
across six distinct platforms: 396 cells total, 2 **SUPPORTED** and 394
**UNSUPPORTED**. The two green cells are `interface.LOOPBACK` on Arista cEOS
and Ubuntu/FRR. Every other cell is red because at least one required
end-to-end axis is not fully implemented and empirically verified. This is an
intentional fail-closed result, not an assertion that the underlying network
operating system lacks the feature.

## Platform resolution

| Platform | Final result | Current evidence boundary |
|---|---|---|
| Arista cEOS 4.36.2F | `interface.LOOPBACK` SUPPORTED; all other modeled features UNSUPPORTED | The managed R1 workflow rendered, wrote, read back, compensated, and proved final absence for temporary `Loopback444` / `198.18.44.1/32`. Other renderable features remain red until their exact feature workflow has equivalent empirical evidence. |
| Ubuntu 24.04 / FRR 8.4.4 | `interface.LOOPBACK` SUPPORTED; all other modeled features UNSUPPORTED | The Linux executor gained strict dummy-loopback creation. Managed R3 created, read back, compensated, and proved final absence for `loopback44` / `198.18.44.3/32`. FRR routing and nftables features have no safe incremental executor/postcheck contract and remain red. |
| Nokia SR Linux 24.10.7-191 | `interface.LOOPBACK`, `interface.ROUTED_PHYSICAL`, `interface.SUBINTERFACE`, `routing.STATIC_IPV4`, `routing.STATIC_IPV6` SUPPORTED; all other modeled features UNSUPPORTED | The registered `SrLinuxExecutor` sends each Configlet as one atomic gNMI CLI-origin Set, derives its inverse from a gNMI Get of the running configuration taken immediately before apply, and proves compensation by an identical configuration tree. Each cell ran on a pristine node and on a node already holding related configuration: operator postcheck over gNMI state, live import through `parser_srlinux`, traffic from the node's own network-instance, then exact restoration. `interface.MANAGEMENT` was exercised and stays red: `mgmt0` is DHCP-addressed and SR Linux refuses a static address while the DHCP client is present. OSPF, BGP, ACL and DHCP-relay statements are refused by the executor because their list keys are not part of the verified model. |
| Cisco Catalyst 8000V / IOS XE 17.6.01a | `interface.LOOPBACK`, `interface.ROUTED_PHYSICAL`, `interface.SUBINTERFACE`, `routing.STATIC_IPV4`, `routing.STATIC_IPV6` SUPPORTED; all other modeled features UNSUPPORTED | A disposable vrnetlab Catalyst 8000V (`nmas-cap-iosxe`) provides a reliable privilege-15 SSH session. The registered `IosXeExecutor` applies each Configlet in Netmiko configuration mode, derives its inverse from the running configuration captured immediately before apply, and proves compensation by an identical running configuration. Each cell ran on a pristine router and on one already holding related configuration (including a replaced primary address): operator postcheck over allowlisted `show` output, live import through `parser_iosxe`, pings from the router, exact restoration. `interface.MANAGEMENT` stays red by design: the executor refuses at preflight (`MANAGEMENT_SESSION_AT_RISK`) to replace the primary address of the interface carrying its own SSH session. OSPF, BGP and RIP have no IOS XE executor path. Nothing here applies to IOS XR. |
| Cisco IOS XR | all modeled features UNSUPPORTED | Valid fixture renderer/parser support is retained under the separate `cisco_iosxr` identity. There is no IOS XR runtime artifact, live transport, executor, or postcheck in this environment. Catalyst 8000V evidence is never reused for XR. |
| SONiC master.1236848-ad5af6706 | all modeled features UNSUPPORTED | The supplied virtual-switch image booted in an isolated snapshot. `Loopback44` / `198.51.100.44/32` was created, observed in CONFIG_DB and operational output, removed, and proved absent. NMAS has no SONiC live transport/executor/postcheck, so all cells remain red. |

## Image and isolated-runtime evidence

* cEOS archive: `cEOS-lab-4.36.2F.tar.xz`, 696,991,020 bytes; runtime image
  `ceos:4.36.2F`.
* SR Linux runtime: `ghcr.io/nokia/srlinux:24.10`, observed release
  `24.10.7-191`. The isolated lab used management subnet `172.31.44.0/24` and
  was destroyed by its exact topology path after validation.
* Catalyst artifact:
  `c8000v-universalk9_8G_serial.17.06.01a.qcow2`, 1,595,277,312 bytes,
  8 GiB virtual size, SHA-256
  `1b05559f7a24db4a7e2ac3cf1dc203dacbcf0d431d418eee9a3763b501ab5a68`.
  It was booted read-only with QEMU snapshot semantics; no vendor artifact was
  copied into the repository.
* SONiC artifact: `sonic-vs.img.gz`, 2,538,193,432 bytes, SHA-256
  `9189370d02948c5801fa7101fa32daa5130d0e2e7401d3d0c3d6ca28c00be828`.
  The temporary decompressed qcow2 was booted with QEMU snapshot semantics and
  removed after validation; the original gzip remains unchanged.

The isolated environments used separate names and management/NAT networks.
They never joined VLAN200 and never modified or destroyed the production lab.

## Feature-family disposition

The matrix accounts for all currently modeled interface, routing, and
service-policy entries. Interface kinds include routed physical, access,
trunk, subinterface, SVI, management, loopback, LAG, MLAG, bond, bridge,
tunnel, GRE, VXLAN/VTEP, virtual, and radio/WLAN. Routing includes IPv4/IPv6
static, RIPv2/RIPng, OSPFv2/v3, IS-IS, EIGRPv4/v6, and BGPv4/v6. Service and
policy entries cover the modeled FHRP, NAT/PAT, DHCP, DNS/monitoring override,
ACL, and PBR variants.

Only the two loopback workflows meet the complete operational contract.
Important red families resolve as follows:

* cEOS routed interfaces, static routing, OSPF, BGP, ACL, relay, and VARP may
  have model/renderer/executor components, but lack feature-specific empirical
  evidence across all mandatory axes in this Phase 4 run.
* Ubuntu/FRR static routing, OSPF, BGP, redistribution, and NAT/PAT lack an
  incremental execution plus trustworthy post-write/compensation workflow.
* SR Linux has a registered gNMI executor and gNMI state reader for interfaces,
  addresses and static routes only (see the platform table). SR Linux semantics
  are kept: L3 lives on numbered subinterfaces, the canonical MTU is the
  subinterface `ip-mtu`, address families are enabled explicitly, and a port
  that carries tagged subinterfaces holds no untagged subinterface 0.
* IOS XE has a registered Netmiko executor and show-command state reader for
  interfaces, addresses and static routes only (see the platform table).
* IOS XR and SONiC have no registered NMAS executor and no NMAS post-write
  verifier. Fixture parsers/renderers or successful manual isolated CLI trials
  are deliberately insufficient, and IOS XE evidence is never reused for XR.
* Features not represented in the 66-row catalogue (for example new broad
  QoS, BFD, multicast, STP, or VRF domains) were not invented merely to enlarge
  the matrix. Existing LAG and related interface entries are included and
  fail closed where incomplete.

## Cisco identity correction

`cisco_c8000v_iosxe` and `cisco_iosxr` are separate stored platform values.
The data migration maps legacy `cisco_ios8000v` records to IOS XR because the
legacy implementation and fixtures were XR-oriented; it does not relabel them
as IOS XE. Catalyst 8000V now uses `C8000vIosXeDriver`, IOS XE templates, and
an IOS XE parser. XR uses `IosXrDriver`, XR templates, and the retained XR
parser. IOS XE static-route/interface grammar and XR hierarchical grammar have
cross-negative tests so one parser cannot silently prove the other platform.

## Exact loopback classification

Planning configlets now persist the exact `capability_feature`. Both the
loopback interface configlet and its address configlet are classified as
`interface.LOOPBACK`; live evidence recording no longer falls back to
`interface.ROUTED_PHYSICAL` based on the broad `interface` object type.

## Reproducible evidence refresh

Static or fixture verification is non-destructive by default:

```text
python manage.py nmas_capabilities verify \
  --platform arista_ceos --feature interface.LOOPBACK \
  --test-type fixture --runtime-version ceos:4.36.2F
```

Live mutation requires both `--live` and `--allow-write`, is restricted to the
two allowlisted managed devices and the loopback feature, and always attempts
compensation:

```text
python manage.py nmas_capabilities verify \
  --platform ubuntu_frr --feature interface.LOOPBACK \
  --live --allow-write --device R3 \
  --runtime-version ubuntu:24.04+FRR-8.4.4
```

Each recorded row includes platform, feature, axis, result, source, evidence
type, timestamp, repository HEAD, optional evidence reference, runtime
version, actor, and notes. Every write creates an audit event. Admin evidence
rows are immutable, and there is no manual “mark supported” override. The
matrix detail disclosure shows the effective evidence and the deterministic
first unsupported reason without exposing the diagnostic vocabulary as a
terminal cell state.
