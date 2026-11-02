# NMAS V2 Phase 9 — Trusted isolation on an Ubuntu/FRR upstream (nftables)

Code: `web/core/services/isolation/frr.py` (pure: render, parse, read-back, findings), the executor
`web/core/services/execution/executors/frr_isolation.py`, the SSH transport `web/core/services/management/linux_ssh.py`, and the
platform dispatch in `isolation/service.py` and `commissioning/admission.py`. Live evidence: `docs/evidence/v2-phase9-closure/frr-isolation/`.

Phase 5 refused every non-cEOS upstream with `ISOLATION_PLATFORM_NOT_IMPLEMENTED`. That refusal still applies to Nokia SR Linux,
Cisco IOS XE / IOS XR and SONiC. Ubuntu/FRR upstreams (the R3/R4 build) now run through the same governed lifecycle as cEOS: plan →
precheck → second-operator approval of the plan hash → apply → verify → release, digest-verified compensation, drift and
`UNCERTAIN` handling.

## Enforcement

One NMAS-owned table per device, `table inet nmas_iso_devNNNNNN`, with a base chain on `forward`, `input` and `output`
(priority `filter`, `policy accept`). Every rule matches the bootstrap port by name, so no other interface is affected (core
OSPF links, VLAN 200, uplinks, the management interface). An `inet` table covers IPv4 and IPv6 together; the hooks are registered
in both the `ip` and `ip6` families (read back from `nft list hooks`).

| Chain | Accepted (port only) | Everything else on the port |
|---|---|---|
| forward | device → bootstrap HTTP (service:8080); device's SSH **replies** to the NMAS service (`tcp sport 22 ct state established,related`); service → device on those two flows | counted and dropped, IPv4 and IPv6, any protocol (production, lateral, internet) |
| input | DHCP to the relay (`udp 68 → 67`); IPv6 neighbour discovery from link-local | counted and dropped: OSPF / OSPFv3 hellos, RIP, BGP, SSH, SNMP and every other upstream service — no premature adjacency, no management-plane access |
| output | DHCP replies; IPv6 RA / NS / NA | counted and dropped |

Bootstrap exceptions are IPv4 (DHCPv4 + HTTP), matching the native ZTP flow. IPv6 traffic is limited to neighbour discovery.

Facts found live and enforced in code:
- **Re-sending a table merges.** `table inet X { … }` sent to nft again duplicates every rule. The table is created only when
  absent, and an exact listing counts as already enforced.
- **The SSH reply rule needs conntrack.** A bare `tcp sport 22 accept` let a device that forged source port 22 reach any port on
  the service host (`40a-variant-without-conntrack-leaks.json`: SYN seen at the service, `ISOLATION_LEAK`). With
  `ct state established,related` that flow is dropped (seen 0), and NMAS's SSH to the device still opens. The first candidate
  implementation used the bare rule; the second scoped it with conntrack. The traffic-path result decided between them.
- **IS-IS is not IP.** `inet` cannot filter it, so IS-IS (or OpenFabric) on the port is refused (`ISOLATION_ROUTING_UNSUPPORTED`),
  never assumed suppressed.
- **ISC dhcrelay uses a packet socket** below netfilter, so relaying works with or without the DHCP rules. The DHCP rules exist for
  the upstream's own stack.

## Planning, read-back and verification

Planning reads, in one snapshot: nft version and `nft -c` capability, the ruleset (text and JSON), `nft list hooks`, FRR running
config, addresses / routes / route-get for the NMAS sources, OSPF and OSPFv3 neighbours, the relay process list, and neighbour
entries. Planning refuses a port that already carries routes or adjacencies (`ISOLATION_PORT_SHARED`), refuses a foreign table on
the port, an unreadable upstream, or a port kind nftables cannot scope (bridge, bond, VLAN, VRF, tunnels …).

Verification requires all of the following:
- an exact table read-back (rules and chain hooks / policy);
- hooks registered in both families;
- no adjacency or learned route through the port;
- the NMAS source not routed via the port;
- an observed traffic matrix in which every deny is matched by a drop-counter increase.

A deny with no counter increase is not trusted. Drift is a read-back mismatch: the policy becomes `DRIFTED` and ZTP is blocked
(`ISOLATION_DRIFTED`).

Release deletes the table and must re-verify admission (routing / adjacency present as intended). If the post-check fails, the
table is restored and the ruleset is byte-identical. Every apply / release step is compensated to the exact baseline digest
(`sha256` of the ruleset and FRR config). If that cannot be proven, the policy goes `UNCERTAIN` and every later isolation change
on that upstream is refused until reconciled.

## Transport (no Docker console)

`linux_ssh.connect(name)` requires all of the following:
- the inventory resolver's `linux` target in WRITABLE scope;
- the legacy management source (Linux devices cannot register management paths yet);
- a dedicated account (`username`) and a provider **reference** to its key (`ssh_key_ref`);
- a pinned host key, `ssh_host_key: SHA256:…`, in the device's inventory entry.

Authentication is key-only (no agent, no key files, no password); an unknown or different host key refuses the session
(`CONNECTION_FAILED`). Commands are argv lists, each token shell-quoted. A multi-line ruleset stays one single-quoted word. Only
`nft` and `vtysh` are run through `sudo -n`. The device grants the account exactly those two programs; everything else runs
unprivileged.

## Live acceptance (`labs/frr-isolation-isolated`, FRR 8.4.4 + nftables 1.0.9, the R4 build)

The fixture is isolated: Docker `none` networks and veth pairs only, container prefix `nmasfrrfx-`. The upstream runs a key-only
`nmas-svc` account (sudoers: `/usr/sbin/nft`, `/usr/bin/vtysh`). NMAS runs inside the service host's network namespace and
reaches the upstream's loopback over SSH. As in every isolated fixture, the fixture settings disable the
configuration-validation gate (`NMAS_CONFIGURATION_VALIDATION_ENABLED = False`).

| Evidence | Result |
|---|---|
| 05 transport | session from 10.254.92.2 to 10.254.255.4:22 as `nmas-svc`; nft / vtysh elevated, any other `sudo` refused; wrong pin → `CONNECTION_FAILED`, no pin / not writable → `NOT_CONFIGURED`; the executor source has no `docker exec` |
| 10 baseline | without isolation, all 12 flows pass (the fixture really forwards) |
| 20 plan blocked | a hostile OSPF speaker already learned routes through the port → `ISOLATION_PORT_SHARED` |
| 30 apply | table applied once; hooks in `ip` and `ip6`; self-approval and wrong hash refused |
| 40 verify | 12 flows as intended: bootstrap HTTP and NMAS SSH permitted; production (IPv4 / IPv6), lateral, service SSH, forged source port 22, the upstream's own SSH / ICMP, and production → device (IPv4 / IPv6) denied; drop counters rose (forward 12, input 39, output 29); DHCP lease through the relay |
| 40a | the bare `tcp sport 22` variant: forged source port forwarded → `ISOLATION_LEAK` |
| 50 release fail | post-check failed → table restored, ruleset byte-identical |
| 60 release | released and admitted; admission checks empty |
| 70 fault | apply fault → compensated, ruleset byte-identical |
| 80 uncertain | a foreign table appeared during compensation → `UNCERTAIN`; reconcile stays `UNCERTAIN` (digest ≠ baseline); a new policy on the upstream is refused (`ISOLATION_EXISTS`); the open run blocks further changes |
| 90 drift | an out-of-band deletion of the drop rule → `DRIFTED`, UDP reaches production, ZTP gate refuses |

## Limitations

- **Production R4 is not enabled.** `inventory.yml` has no `ssh_host_key` for R3/R4, and production R4 has no sudoers entry for
  `nft` / `vtysh`, so `linux_ssh.target` answers `NOT_CONFIGURED` and isolation through R4 is refused. Enabling it means pinning
  the host key and granting those two programs to the automation account, through the normal operator-approved change. Not
  done here.
- IPv4 bootstrap only (no DHCPv6 / SLAAC bootstrap exceptions).
- Linux devices have no registered management paths, so the transport uses the legacy management address only.
