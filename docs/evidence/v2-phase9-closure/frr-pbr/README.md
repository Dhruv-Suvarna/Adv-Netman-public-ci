# Ubuntu/FRR policy-based routing with pbrd: live capability proof (V2 Phase 9)

The four JSON records here were produced by `labs/phase9-frr-pbr-isolated/run.py` against the disposable `frr` (DUT) and
`peer` containers of the isolated capability lab `nmas-cap-validation` (FRRouting 8.4.4 with zebra and pbrd, Ubuntu
24.04). The run used an ephemeral NMAS database. No production device, database or service was touched. Each record
pins the SHA-256 of every source file it exercised (`uncommitted_source_sha256`).

| Cell | Scenarios |
|---|---|
| `service_policy.PBR_IPV4` | pristine node; existing policy attached elsewhere |
| `service_policy.PBR_IPV6` | pristine node; existing policy attached elsewhere |
| `service_policy.PBR_ATTACH_IPV4` | pristine node; existing policy attached elsewhere |
| `service_policy.PBR_ATTACH_IPV6` | pristine node; existing policy attached elsewhere |

All 8 scenarios passed.

## What NMAS renders

One `pbr-map` sequence per PBR sequence, then the interface attachment (grammar: `web/core/services/frr_pbr.py`):

```
pbr-map CAP_PBR seq 10
   match src-ip 198.51.100.0/24
   match dst-ip 192.0.2.0/24
   set nexthop 198.18.7.2
!
interface eth3
   pbr-policy CAP_PBR
```

- A sequence matches on a source prefix, a destination prefix, or both, and sends the traffic to one next-hop address
  of the policy's family.
- An attachment applies the policy to traffic received on one interface (IN). An interface carries one `pbr-policy`.

NMAS renders only forms that FRR 8.4.4 lists back unchanged and installs. It refuses the following with an unsupported
marker, keeping the intent, instead of approximating them:

- an `ip-protocol` match. FRR 8.4.4 resolves protocol names through `/etc/protocols`, which this runtime does not have,
  so the match is not proven;
- a next-hop interface;
- a sequence with no match (pbrd never installs one), a sequence number outside 1-700, or two sequences that share a
  number;
- a prefix or next hop of the other family;
- a duplicate policy name;
- an attachment whose policy did not render, that is not IN, that has no interface name, or that would be a second
  policy on one interface.

## Execution and compensation

The registered `LinuxExecutor` writes PBR through vtysh, with the same grammar and captured-configuration inverse as the
FRR routing protocols. It refuses before any write if pbrd is not running.

- A `pbr-map` sequence absent before the write is removed as a whole (`no pbr-map NAME seq N`).
- An attachment is removed by its own `no pbr-policy NAME`.
- After compensation, the FRR running configuration must equal its captured digest.

The executor never writes in two cases, because neither has a provable inverse:

- a sequence that already exists with other leaves (for example another next hop);
- an attachment on an interface where another policy is already applied.

## What each scenario proved

- **Control before the write:** with no policy, the peer's pings to the probe destination were dropped by the DUT's
  blackhole route. Nothing reached the policy next hop.
- **Operator postcheck:** the Phase-15 evaluators passed on a fresh live read (`show pbr map json`,
  `show pbr nexthop-groups json`, `show pbr interface json`). The policy was valid, its sequence was installed with
  the intended next hop, and the attachment was valid on eth3.
- **Kernel state:** zebra installed the rule `from SRC to DST iif eth3 lookup <table>`.
- **Live import:** `parser_frr` recovered the policy, every sequence and the attachment from the running configuration.
- **Behaviour:** while attached, all 6 echo requests from the policy's source prefix were steered to the policy next
  hop. The DUT's egress dummy counted them. Requests from another source were not steered.
- **Existing policy attached elsewhere:** a native policy `LEGACY` was already applied on eth2.
  - It stayed configured as written, installed and applied.
  - Attaching the cell's policy on eth2 was assessed `APPLY/False/COMPENSATION_NOT_PROVABLE`, and nothing was written.
- **Compensation:** both Configlets reported `COMPENSATED`, and the FRR running configuration was identical to the
  capture taken before the write.
  - Nothing was steered any more.
  - Policy rules, PBR routes in every table, kernel addresses and routes, and eth3 `force_forwarding` returned to their
    captured baselines. The daemons the lab started were stopped.

## Lab prerequisites

The lab writes and then removes these natively. They are not NMAS writes.

- The FRR pair (`FrrPair`): link addresses, the peer's originating prefix, and zebra and pbrd on both containers.
- The DUT's egress dummy `nmaspbr0`, which carries 198.18.7.1/30 and 2001:db8:77::1/64. A dummy device counts every
  packet it transmits and discards it.
- A blackhole for the probe destination on the DUT, so unsteered traffic is dropped and never leaves through the
  management network.
- The peer's route to the probe destination through the DUT.
- IPv6 forwarding for packets received on eth3 only (`force_forwarding`). The DUT's global IPv6 forwarding stays off.

## Reproduce

From the repository root, with the capability lab running:

```
DJANGO_DEBUG=1 /path/to/venv/bin/python labs/phase9-frr-pbr-isolated/run.py [cell ...]
```
