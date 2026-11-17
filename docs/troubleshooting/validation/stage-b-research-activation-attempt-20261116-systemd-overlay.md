# Stage B corrected-systemd-overlay activation attempt

Change: `CHG-NMAS-20261115-STAGE-B-001`

Approved overlay SHA-256:
`c037e81a17e0f31981dd72270f0fd200a48cf8a11612ffe687f490031d39349a`

Final disposition: **ROLLED BACK**. Research networking and the worker service
were not activated. Diagnostic networking, live models, device writes,
autonomous remediation and `break.py` remained disabled.

## Authorization and window

The authorization receipt was observed at `2026-11-16T13:53:12-07:00`
(`2026-11-16T20:53:12Z`). The owner supplied an immediate 60-minute window
ending at `2026-11-16T14:53:12-07:00` and personally attested current VM1
vSphere Client Web Console access. No vSphere endpoint was contacted.

## Passed prechecks

- The overlay, its four entries, source manifest, runtime lock, namespace
  controller, resolver-root helper, nft policy and corrected unit hashes
  matched the reviewed plan.
- VM1 ran systemd 255. The corrected unit hash was
  `f4aea87ff4cd12fe47e6efa40dc84e579dafecd9a22d213b0ebe3a20682aea89`.
- `ens33` remained `10.224.77.0/22`, `nmas-mgmt` remained
  `192.168.200.100/24`, and the IPv4 default remained through
  `10.224.76.1` on `ens33`.
- The original inbound SSH session was established. NMAS health/login returned
  200, all eight checked services were active, and all 15 frozen
  `clab-srlceos01-*` containers were running.
- All three approved resolvers returned exactly the five reviewed A records.
  Hostname-verified HTTPS returned the expected 302, 301 and 200 responses for
  all five literal destinations. No address was added.
- The runtime installed and verified. All four installed overlay files matched
  the source hashes byte-for-byte. Locked identities retained nologin shells
  and no sudo, Docker or containerd membership.
- `resolver_root.py` created and verified the exact root-owned mode-0755
  `/etc/netns` inode and its mode-0600 ownership receipt.
- The unit, namespace configuration, nft policy, secret-bearing broker
  environment and sysusers fragment were installed with the reviewed modes.
  All five installation-receipt hashes passed. Secret values were not logged.

## Fail-closed lifecycle defect

At `2026-11-16T13:56:09-07:00`, both the initial and idempotency
`prepare-resolver` calls refused before creating a resolver file:

```text
REFUSED: resolver preparation found an incompatible activation state
```

The preserved root-only receipt from the earlier ownership-scoped rollback had
the same activation ID and configuration digest, `status=rollback`, and every
namespace/link/table/resolver ownership flag false. The reviewed
`prepare_resolver()` implementation accepts an existing receipt only when its
status is `resolver-prepared`; it refuses a matching inactive rollback receipt.

The reviewed test suite permits another cycle by calling `activate` directly.
For this state, however, `activate` creates the resolver near the end of
network activation. Using it would violate this plan's required
resolver-before-network ordering. The receipt was therefore not deleted,
rewritten, renamed, adopted or bypassed, and no silent retry occurred.

## Ownership-scoped rollback

Rollback completed at `2026-11-16T13:56:52-07:00`:

1. The inactive service was stopped defensively.
2. Namespace rollback returned `already-rollback` with zero mutations.
3. `resolver_root.py rollback` removed only its recorded directory and receipt.
4. All five installation-receipt hashes passed before exact unlink.
5. The unit, environments, policy and sysusers fragment were removed.
6. The exact corrected runtime overlay uninstalled successfully.

The prior namespace lifecycle receipt remains root-owned mode 0600 as audit
evidence. It records `status=rollback` and false ownership flags.

## Post-rollback verification

Verification completed at `2026-11-16T13:57:19-07:00`:

- IPv4 routes, IPv4/IPv6 policy rules, the stateless nftables ruleset and SSH
  configuration matched the pre-attempt files exactly.
- Addresses and IPv6 routes matched structurally after removing only volatile
  address lifetimes and route expirations.
- The original inbound SSH session remained established; host forwarding
  remained `1/1`.
- NMAS health/login returned 200, all eight checked services remained active,
  and all 15 frozen containers remained running.
- `/etc/netns`, `/opt/nmas`, the resolver receipt, installed unit,
  configurations, policy, sysusers fragment and installation receipt were
  absent.
- No research namespace, veth, nftables table, process or active service
  remained. Foreign networking resources were unchanged.

## Required correction

The lifecycle needs a reviewed, ownership-safe transition that starts a new
resolver-before-network cycle from a matching inactive `rollback` receipt
while preserving the prior audit evidence. Any corrected overlay and live
retry require a new explicit authorization and current maintenance window.

`STAGE_B_RESEARCH_ROLLED_BACK`
