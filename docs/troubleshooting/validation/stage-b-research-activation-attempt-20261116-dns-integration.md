# Stage B research DNS-integration activation attempt

Change: `CHG-NMAS-20261115-STAGE-B-001`

Final disposition: **ROLLED BACK**. The research broker did not reach its main
executable. No diagnostic namespace, live AI model, device write, autonomous
remediation or `break.py` execution was attempted.

## Authorization and window

The owner authorized the complete corrected research-only bundle with overlay
manifest SHA-256
`45a3f5a2c084367d0d8d229580a055e7356265d62742875d72e157d45ebcfc36`.
Authorization receipt was observed at `2026-11-16T12:22:48-07:00`
(`2026-11-16T19:22:48Z`), opening an immediate 60-minute window ending at
`2026-11-16T13:22:48-07:00`. The owner's current statement that VM1 vSphere
Client Web Console access had been personally verified was recorded as the
authoritative recovery attestation; no vSphere endpoint was contacted by this
procedure.

## Pre-activation verification

The baseline was captured at `2026-11-16T12:23:07-07:00`. `ens33` remained
`10.224.77.0/22` with the default route through `10.224.76.1`; `nmas-mgmt`
remained `192.168.200.100/24`. The established SSH session, all eight checked
NMAS/host services, and all 15 `clab-srlceos01-*` containers were healthy.
Neither research namespace, Stage B-owned nftables table, resolver root,
runtime, unit nor configuration was present. The locked nologin identities
matched the reviewed identities and had no sudo or container-runtime access.

The exact source, overlay, runtime lock, namespace controller, service unit,
resolver-root helper and research policy hashes matched the reviewed plan.
All three approved resolvers returned exactly the reviewed A-address set:

- `docs.frrouting.org`: `104.16.253.120`, `104.16.254.120`
- `www.arista.com`: `199.232.66.132`
- `www.rfc-editor.org`: `104.18.20.81`, `104.18.21.81`

Hostname-verified TLS succeeded directly to all five reviewed IPv4 addresses.
No destination was added.

## Authorized execution observed

- `12:23:32`: the exact reviewed worker runtime and four-file overlay installed
  and verified, including source-to-installed byte comparisons.
- `12:23:57`: `resolver_root.py` created `/etc/netns` as `root:root 0755` and
  its mode-0600 ownership receipt; verification passed.
- `12:24:41`: resolver preparation and its idempotency check passed. The
  root-owned resolver file contained only the three approved nameserver lines;
  its SHA-256 was
  `5e216f77dcc38217f0a8216b9eee714f15ede9cdf73a19f468a72edad0b815c1`.
- `12:24:52` through `12:24:53`: the research namespace, IPv4-only VM-local
  veth, namespace policy, host policy and scoped masquerade activated and
  validated. IPv6 forwarding and RA were disabled inside the namespace and
  namespace IPv6 was disabled. Only the exact DNS UDP/TCP-53 and HTTPS
  TCP-443 tuples were allowed.
- `12:24:58`: systemd started the research unit. Root-only
  `service-preflight` passed with the reviewed nft policy and exact resolver
  digest.

## Fail-closed service defect

At `2026-11-16T12:24:59.103295-07:00`, systemd rejected the main process before
the broker executable ran:

```text
nmas-research-broker.service: Failed to set up mount namespacing:
/etc/nmas/troubleshooter-device-worker.env: No such file or directory
```

The process exited with `status=226/NAMESPACE`. The unit's restart policy made
three identical attempts and systemd stopped retrying at
`2026-11-16T12:25:05.679082-07:00`. Every root-only service preflight passed,
which proves the namespace, reviewed resolver source, read-only resolver bind,
IPv6 state and nft policy were correct before each main-process attempt.

The exact remaining defect is the research unit's mandatory
`InaccessiblePaths=/etc/nmas/troubleshooter-device-worker.env` entry. The
diagnostic environment is intentionally absent, but the path was not marked
optional, so systemd could not construct the research service's mount
namespace. This is distinct from the corrected DNS integration and prevents
functional `getaddrinfo()` and HTTPS validation in the actual running worker.

## Ownership-scoped rollback

The stop condition was applied without repair or retry outside the authorized
artifact. Rollback began at `2026-11-16T12:25:12-07:00` and cleanup completed
at `2026-11-16T12:25:33-07:00`:

1. The service was stopped.
2. The namespace lifecycle removed only its owned namespace, veth, resolver
   objects and two nftables tables.
3. `resolver_root.py rollback` removed only the recorded `/etc/netns` inode and
   ownership receipt.
4. All five installation-receipt hashes passed before exact unlink.
5. The unit, policy, environment, sysusers fragment and runtime overlay were
   removed; systemd was reloaded and failed state reset.

The mode-0600 namespace state receipt remains under the mode-0700
`/var/lib/nmas-ts-namespaces` directory as inert audit evidence. It records
`status=rollback` and no remaining owned namespace, link, nftables table,
marker, resolver directory or resolver file.

## Post-rollback verification

Post-rollback checks completed at `2026-11-16T12:26:37-07:00` and afterward:

- the pre-activation IPv4/IPv6 route and policy-rule hashes matched exactly;
- `ens33`, `nmas-mgmt`, their addresses and the default route were preserved;
- the original SSH session remained established on `10.224.77.0:22`;
- host IPv4/IPv6 forwarding remained `1/1`;
- all eight checked NMAS/host services remained active;
- `/healthz` and `/accounts/login/` returned 200, while unauthenticated
  `/troubleshooting/` returned the expected 302 login redirect;
- all 15 frozen `clab-srlceos01-*` containers remained running;
- no research namespace, research veth, Stage B nftables table, resolver root,
  runtime, unit, policy, environment or installation receipt remained; and
- foreign namespaces, interfaces, nftables tables and application state were
  not modified by rollback.

Raw address and nftables hashes are not stable comparisons because IPv6
address lifetimes and nftables counters advance. The corresponding structural
objects were inspected: the original addresses/tables remained, and every
Stage B-owned object was absent.

## Required next action

Do not retry this overlay or plan. A correction must make the intentionally
absent diagnostic environment path optional for the research unit, or use an
equivalently narrow supported systemd expression, then repeat disposable and
focused integration tests and produce a new content-addressed overlay. A new
owner authorization and current maintenance window are required for any live
retry.

`STAGE_B_RESEARCH_ROLLED_BACK`
