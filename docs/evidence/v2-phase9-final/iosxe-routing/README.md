# IOS XE routing: live capability proof (V2 Phase 9)

Recorded on 2026-10-28 at repository head `d70c256` against the disposable `iosxe` node of the isolated capability lab
`nmas-cap-iosxe`. The node is a Catalyst 8000V running `vrnetlab/cisco_c8000v:17.06.01a` (IOS XE 17.06.01a), linked
GigabitEthernet2 ↔ eth1 to an FRRouting 8.4.4 peer. No production device, database or service was touched.

NMAS wrote through the registered `IosXeExecutor`, the same path a governed change takes: Netmiko configuration mode
with a pinned host key, and compensation from the captured running configuration. The Configlets come from the
planner's own `configlet_factory.HANDLERS`, and the postchecks are the engine's own descriptors of those Configlets.
Lab prerequisites (link addressing, the static anchor a BGP network advertises, the peer's daemons) are written
natively and are never part of the claim.

Each cell runs twice:

- **pristine router**: nothing related is configured;
- **configured router**: a related, unrelated-owner process already exists and must survive.

| Cell | Assessment | What was proven (both scenarios) |
|---|---:|---|
| `routing.OSPFV2` | 1379 | DUT adjacency FULL on GigabitEthernet2; the peer's 192.0.2.0/24 installed from OSPF; the peer sees the DUT FULL |
| `routing.OSPFV3` | 1380 | DUT OSPFv3 adjacency FULL; the peer's 2001:db8:99::/64 installed from OSPF; the peer sees the DUT FULL |
| `routing.RIPV2` | 1381 | the peer's 192.0.2.0/24 installed from RIP, and the peer installs the DUT's 198.18.0.129/32 from RIP |
| `routing.BGP_IPV4` | 1377 | session ESTABLISHED (remote-as 65045); the peer's prefix installed from BGP; the peer's BGP table holds 203.0.113.0/24 from the DUT |
| `routing.BGP_IPV6` | 1378 | session ESTABLISHED; the peer's 2001:db8:99::/64 installed from BGP; the peer's BGP table holds 2001:db8:113::/64 from the DUT |

In every scenario of every cell:

- the operator postcheck passed;
- the live running-configuration import (`parser_iosxe` 1.2) recovered the rendered intent;
- every Configlet compensated (`COMPENSATED`);
- the running configuration equals the capture taken before NMAS wrote anything;
- the adjacency, session and learned route were withdrawn afterwards;
- the pre-existing process was preserved;
- the lab baseline was restored.

The RIP withdrawal takes about 180 s, which is the RIP route timeout.

## Defects found and fixed on the live node

- **IPv4 activation by default.** IOS XE activates every BGP neighbor in IPv4 by default. That defeated the planner's
  separate address-family activation Configlet, and an IPv6 peer was also activated for IPv4. The renderer now emits
  `no bgp default ipv4-unicast`, and its inverse restores the default exactly.
- **Empty address-family left behind.** IOS XE keeps an explicitly entered, empty `address-family` section displayed.
  Compensation now removes a section the Configlet created.
- **Read during deconfiguration.** About 61 s after `no address-family`, IOS XE prints
  `% Topology ... is currently being deconfigured` inside the running configuration. The read is retried for up to
  100 s instead of being treated as a changed configuration.
- **Slow TCP table read.** The management-session check used `show tcp brief`, which spends about 8 s per foreign
  address on reverse DNS. Once a BGP peer added TCP entries, it timed out past 30 s, which surfaced as an intermittent
  `PREVIOUS_STATE_UNAVAILABLE`. It now reads `show tcp brief numeric`.

## Reproduce

Lab credentials come from the environment and are never stored. From `web/`:

```
NMAS_CAP_IOSXE_PASSWORD=... DJANGO_DEBUG=1 python manage.py nmas_capabilities verify-matrix \
  --platform cisco_c8000v_iosxe --feature routing.OSPFV2 --reassess --isolated-live --allow-write \
  --allow-incomplete --actor phase9-iosxe-routing
```

The full per-scenario detail of each cell is stored in `docs/evidence/v2-phase4-exhaustive/progress-ledger.json`
(probes and evidence references) and is summarised in `docs/evidence/v2-phase7-9/phase9/capability-summary.md`.
