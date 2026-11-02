# Maintenance Mode: read-only live observation of the production lab (2026-10-18, post-merge of PR #58)

Deployed main `6eb214b`, migration `0030_maintenance_record` applied, `nmas-maintenance-tick.timer` installed. **No
network-device write, no entry, no approval.** `summary.json` is the per-target result of `collector.observe` plus an
in-memory, never-saved `Record.evaluate` (no database row, no executor session, no plan capture). Running and startup
configuration fingerprints of R1, R2, R5, S1-S4 and mgmt_swt, and the R3/R4 FRR configuration and static/kernel routes, were
identical before and after.

Two samples:

| Sample | Traffic | R1 | R2 | S1 | S2 | R3 | R4 | mgmt_swt |
|---|---|---|---|---|---|---|---|---|
| `quiet` | none: every host 0 unicast packets in the 20 s window, all four cells | READY (all cells CLEAR) | BLOCKED: DHCP backup (false, see below) | READY | READY | BLOCKED: gateway evidence not readable (FRR) | same as R3 | BLOCKED: management reachability of R1-R4, S1-S4; evidence UNKNOWN |
| `bounded_icmp_H2_H3` | ICMP 4 pps, IPv4 + IPv6, H2 and H3 to the web server, 200 s deadline | BLOCKED in all four cells | BLOCKED in all four cells + DHCP | BLOCKED: `ACTIVE_TRAFFIC_NO_LOSSLESS_DRAIN` | same as S1 | - | - | - |

Under traffic, R1/R2 IPv6 alternates were healthy in both directions yet both cells blocked on the mechanism alone
(`ISIS_ACCESS_METRIC_STEER` PROVEN_NOT_AUTHORIZED northbound, `OSPFV3_CORE_STEER` NOT_READY southbound); IPv4 blocked on
`RIP_IPV4_DRAIN` NOT_READY and an unverified alternate. Northbound redundancy never made a device ready.

Findings:

* **Defect (fixed in this change):** the backup-DHCP dependency read `{"active": ...}` from the verifier, which reports
  `{"ipv4": <systemctl is-active>, "ipv6": ...}`; every live R2 evaluation was `CRITICAL_DEPENDENCY_STRANDED` ("primary
  not active") while both `isc-dhcp-server` units were active. Fail-closed (over-blocking), never under-blocking.
* H4's only global address (`2001:db8:30::18e5/128`, DHCPv6) is deprecated (`preferred_lft 0`), so the collector traces no
  path for H4. Fail-safe: a host without an address is QUIESCED only with 0 packets, otherwise UNKNOWN (blocks). Existing
  lab state, not changed.
* R3/R4 block because FRR exposes no virtual-address evidence (`stranded=None`), not because of a reasoned "no maintenance
  path"; their writes are refused regardless (platform `linux` is not a maintenance platform; cores are `CoreReader`).
* R3/R4 carry no `/63` cover, no static route and no kernel route beyond the management default; every client `/64` is
  OSPFv3 ECMP via R1 and R2 (post IS-IS migration state).
