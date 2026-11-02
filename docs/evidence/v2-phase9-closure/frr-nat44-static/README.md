# Ubuntu/FRR static NAT44: live capability proof (V2 Phase 9)

`assessment.json` was produced by `labs/phase9-frr-nat44-static-isolated/run.py` against the disposable `frr` and `peer`
containers of the isolated capability lab `nmas-cap-validation` (FRRouting 8.4.4 / Ubuntu 24.04, nftables 1.0.9
installed by the probe and purged afterwards). It ran with an ephemeral NMAS database. No production device, database
or service was touched. The record pins the SHA-256 of every source file it exercised (`uncommitted_source_sha256`).

## What NMAS renders

One dedicated table per device, with both directions of each 1:1 host mapping on the outside interface:

```
table ip DEVICE_BUILDER_NAT44_STATIC {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "<outside>" ip daddr <global> dnat to <inside>
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "<outside>" ip saddr <inside> snat to <global>
    }
}
```

Only an IPv4 host mapped to an IPv4 host is rendered. NMAS refuses the following with an unsupported marker, keeping
the intent, instead of approximating them: a prefix, a port or protocol filter, a missing outside interface, or an
address that another mapping already uses.

The executor accepts only this exact shape. Rule k of `prerouting` must be the reverse of rule k of `postrouting`.
A new table is created in one atomic nft transaction and deleted as a whole. A mapping added to an existing NMAS
table goes in as one atomic `add rule` pair. Compensation flushes both chains and restores the captured mappings in
one transaction. A table of that name in any other shape, or a mapping that reuses an owned inside or global address,
has no provable inverse and is never written.

## Live result (both scenarios PASS)

| Scenario | What was proven |
|---|---|
| new table | outbound: the outside endpoint saw 198.18.0.2 as 203.0.113.44. Inbound: a datagram to 203.0.113.44 reached 198.18.0.2, and its reply came back from 203.0.113.44. An unrelated source (198.18.9.2) and an unowned global address (203.0.113.45) were not translated. |
| existing NMAS table (mapping appended) | same as above, while the pre-existing mapping 198.18.9.2 ↔ 203.0.113.99 kept translating. Before the change, a conflicting mapping (198.18.9.2 → 203.0.113.44) was assessed `APPLY/False/COMPENSATION_NOT_PROVABLE`. |

In both scenarios:

- the operator postcheck required the exact address pair and passed;
- the import parser recovered the `STATIC` rule with its translated address;
- the Configlet compensated (`COMPENSATED`);
- the nft ruleset was identical to the capture taken before the write;
- the traffic matched the pre-change controls again;
- the lab's addresses, routes, namespace and package set returned to baseline.

A blackhole route for 203.0.113.0/24 on the DUT is a lab prerequisite. It keeps an untranslated control datagram
from leaving the lab through the management network, and it is removed with the rest of the lab state.

## Reproduce

From the repository root, with the capability lab running:

```
DJANGO_DEBUG=1 /path/to/venv/bin/python labs/phase9-frr-nat44-static-isolated/run.py
```
