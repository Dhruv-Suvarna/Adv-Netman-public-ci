# Ubuntu/FRR ACLs as nftables: live capability proof (V2 Phase 9)

The six JSON records here were produced by `labs/phase9-frr-acl-isolated/run.py` against the disposable `frr` (DUT) and
`peer` containers of the isolated capability lab `nmas-cap-validation` (FRRouting 8.4.4 / Ubuntu 24.04, nftables 1.0.9
installed by the probe and purged afterwards). The run used an ephemeral NMAS database. No production device, database
or service was touched. Each record pins the SHA-256 of every source file it exercised (`uncommitted_source_sha256`).

| Cell | Scenarios |
|---|---|
| `service_policy.ACL_IPV4_STANDARD` | pristine node; existing NMAS ACL table |
| `service_policy.ACL_IPV4_EXTENDED` | pristine node; existing NMAS ACL table |
| `service_policy.ACL_IPV6_STANDARD` | pristine node; existing NMAS ACL table |
| `service_policy.ACL_IPV6_EXTENDED` | pristine node; existing NMAS ACL table |
| `service_policy.ACL_ATTACH_IPV4` | pristine node; existing NMAS ACL table; pristine node attached OUT |
| `service_policy.ACL_ATTACH_IPV6` | pristine node; existing NMAS ACL table; pristine node attached OUT |

All 14 scenarios passed.

## What NMAS renders

One dedicated table per device (grammar: `web/core/services/nft_acl.py`):

```
table inet DEVICE_BUILDER_ACL {
    chain acl4_<NAME> {                       # acl6_<NAME> for an IPv6 list
        ip saddr 198.18.0.66 meta l4proto 1 drop comment "seq 10"
        ip daddr 198.18.0.1 tcp sport 1024-2048 tcp dport 80 log drop comment "seq 15"
        accept comment "seq 20"
        drop comment "implicit-deny EXTENDED"
    }
    chain filter_in {                         # IN; OUT uses filter_out on postrouting with oifname
        type filter hook prerouting priority filter; policy accept;
        iifname "eth3" meta nfproto ipv4 jump acl4_<NAME>
    }
}
```

- Entries are evaluated in sequence order, and the first match decides.
- An unmatched packet hits the explicit final `implicit-deny`, which also records the list type for import.
- An IPv6 list permits neighbour solicitation and advertisement just before that final drop, so attaching it cannot
  break neighbour discovery.
- The family guard sits on the jump rule. nftables 1.0.9 drops a redundant `meta nfproto` from some list rules when it
  lists them, so a guard inside the list would not read back as written.

NMAS renders only rules that nft lists back unchanged. The one difference allowed is the protocol of `meta l4proto`:
nft lists it as a name when `/etc/protocols` exists and as a number when it does not.

NMAS refuses the following with an unsupported marker, keeping the intent, instead of approximating them:

- an entry with no exact form (for example a port match without TCP/UDP, a wrong-family address, or a descending port
  range);
- two entries that share a sequence number;
- a duplicate chain name;
- an attachment whose list did not render, or that has no interface name;
- a second list of one family on one interface and direction.

## Execution and compensation

Each Configlet is one atomic nft transaction:

- An ACL definition creates or replaces its list chain. It also creates the table when the table is absent.
- An attachment adds one jump to the IN or OUT hook chain. It also creates the hook chain when that chain is absent.

The inverse either deletes what the Configlet created, or restores the captured rule list or jumps. After the inverse,
the whole ruleset must equal its captured digest.

The executor never writes in two cases, because neither has a provable inverse:

- a table of that name in any other shape;
- an attachment where another list of the same family already filters that interface and direction.

## What each scenario proved

- **Operator postcheck:** the Phase-15 evaluators passed on a fresh live read, with the ACL definition and attachment
  read back from `nft list ruleset`.
- **Live import:** `parser_frr` recovered the list with its type and every entry, and its attachment on the interface.
- **Behaviour, IN:** the peer reached the DUT from the permitted source, and pings from the denied source were dropped.
  - Standard list: TCP from the denied host was dropped too.
  - Extended list: only ICMP from the denied host was dropped. The logged entry dropped TCP to port 80 from source
    ports 1024-2048, while the same flow from another source port, and TCP from the denied host, still connected.
- **Behaviour, OUT:** the DUT's own pings left the interface from the permitted source and not from the denied one.
- **Existing NMAS ACL table:** a native list `LEGACY` was already attached IN on another interface.
  - It was preserved unchanged.
  - A conflicting attachment, on that interface, was assessed `APPLY/False/COMPENSATION_NOT_PROVABLE`.
- **Compensation:** both Configlets reported `COMPENSATED`, and the nft ruleset was identical to the capture taken
  before the write.
  - Every flow was answered again.
  - Kernel addresses, routes and the package set returned to their captured baselines.

## Reproduce

From the repository root, with the capability lab running:

```
DJANGO_DEBUG=1 /path/to/venv/bin/python labs/phase9-frr-acl-isolated/run.py [cell ...]
```
