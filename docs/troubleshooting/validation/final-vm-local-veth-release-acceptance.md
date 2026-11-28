# NMAS V2 final VM-local-veth release acceptance

Date: 2026-11-15 (America/Denver)

## Decision

**TECHNICALLY_ACCEPTED — LIVE_APPROVAL_PENDING**

This decision applies only to the corrected immutable successor identified
below. The submitted `838514a6…` package is rejected because its pending-step
cleanup could delete an unowned resolver path or namespace. The defect was
reproduced with disposable objects, corrected without changing the production
tree, and the corrected boundary was independently revalidated.

This is not production deployment authorization, Gate B approval, university
infrastructure authorization, worker activation authorization, or proof of live
containment. No worker, production namespace, host firewall rule, route,
address, service, device session, Containerlab link, or university endpoint was
activated or changed.

## Package identities

Submitted package (identity verified, **rejected**):

- path: `/home/student/Scripts/nmas-vm-local-veth-release-20261115T212420Z/package`
- entries SHA-256: `838514a6d92dc359a12558f5c4237f22305653fe731e01a2dd4246e96c7190c4`
- manifest SHA-256: `0d339ae850567cf81cbaabe57135fe06f3252f2709c14e9e6ef4af766f91a944`

Corrected immutable package (**technically accepted**):

- path: `/home/student/Scripts/nmas-vm-local-veth-release-20261115T214507Z/package`
- entries SHA-256: `b6c636301d3cfa48429a373662d748738b07e5daba58c7bf76db62c1d383aa39`
- manifest SHA-256: `9dfc9ae4c0c213b454f639a88dd0fc1a714cdf8d90c028c946b7ca5fe29d5570`
- tool SHA-256: `46db050bd863183498203b796a21bb563026b97a829d1cdbe4678f0e5dd99a0e`
- operations: 210 — 201 ADD, 8 REPLACE, 1 MERGE; `problems: []`

Previously accepted comparison package (identity verified):

- path: `/home/student/Scripts/nmas-independent-namespaces-release-20261115T050919Z/package`
- entries SHA-256: `5dab9de7e6af5d29fcfb23bb194ae65bde944c276f72cb8b3afe2c6bc0bd520f`
- manifest SHA-256: `47c98c1a0952bf0cd52e2271685dfa1d2e3891409d1e3989072702efa8da6242`

For all three packages, `SHA256SUMS`, the canonical entries digest, unique safe
relative paths, manifest problem list, and every payload hash were checked
independently. Both old and corrected packages verify 210/210 production
preconditions against the unchanged production source.

## Eight-entry comparison

The submitted VM-local release changed exactly these eight entries relative to
the previously accepted package; no entry path, action, mode, or production
precondition changed:

1. `deploy/sandbox/namespace_activation.py`
2. `deploy/sandbox/diagnostic-namespace.env.in`
3. `deploy/sandbox/research-namespace.env.in`
4. `deploy/sandbox/render_policy.py`
5. `deploy/sandbox/test_namespace_activation.py`
6. `docs/troubleshooting/namespace-activation.md`
7. `docs/troubleshooting/deployment-rollback.md`
8. `web/core/tests/test_troubleshooting_sandbox_artifacts.py`

The corrected successor differs from the submitted package in only two of
those entries: the controller and its disposable integration test. All
application, migration, worker, IPC, broker, credential, and target-policy
payload hashes remain those of the submitted package.

## Blocking defect and correction

In the submitted controller, `pending_step=dns` authorized deletion of a
resolver file and directory even when the journal said neither object had been
created. A deterministic disposable reproducer placed foreign content in the
race window; cleanup deleted it. `pending_step=netns` had the analogous unsafe
deletion authority over an unmarked namespace.

The correction makes a pending command intent non-authoritative. Namespace
deletion now requires a successfully journaled `netns` completion/ownership
flag. Resolver unlink/rmdir now requires the corresponding successfully
journaled file/directory ownership flag; content/type checks still apply.
Ambiguous crash windows fail closed for explicit operator reconciliation.

The regression creates foreign namespace/resolver race objects and proves they
survive cleanup. The original reproducer against the corrected package reports
both objects preserved.

## Security and compatibility assessment

### Diagnostic path

- The namespace receives only a VM-local point-to-point veth address and exact
  host routes for approved literal `IP . TCP port` targets; it has no default
  route and no DNS.
- The namespace and host tables independently enforce the same exact tuples.
  The host side admits only traffic entering the owned veth and leaving the
  configured management interface, and source-NATs it only to the exact existing
  approved management address. Wrong ports, adjacent addresses, public/campus
  destinations, simulated vSphere/student endpoints, and VM1 services were
  denied in the disposable topology.
- Source NAT preserves VM1 addressing but means a device cannot distinguish a
  worker session from other NMAS sessions by source address. Attribution must
  therefore come from the retained root-owned activation configuration and
  NMAS operation/audit records.

### Research path

- The namespace receives a VM-local default route to the host. The host table
  admits DNS only to approved literal resolvers over both UDP and TCP, drops the
  built-in private/special sets plus operator-supplied `EXTRA_DENY_CIDRS`, then
  admits TCP/443 only through the configured external interface and source-NATs
  behind VM1's existing external address.
- The unchanged broker additionally requires an exact hostname allowlist,
  double resolution/IP pinning, TLS hostname verification, redirect
  reauthorization, bounded read-only methods/media/size/time, no proxy
  inheritance, and sanitized audit records.
- IPv4-mapped IPv6, private/campus/Containerlab/host destinations, non-HTTPS,
  and an operator-protected public range were denied in the disposable tests.
  IANA notes that special-purpose registry entries are not guaranteed routable
  in a given context; the institution's complete public protected ranges must
  therefore be supplied explicitly rather than inferred from generic special
  registries ([IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry),
  [IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry)).
- Research IPv6 remains an activation stop condition: VM1 has no global IPv6
  address/default through `ens33`; its observed IPv6 default leads into the lab.
  The approved production config must set `IPV6_MODE=disabled` and leave every
  IPv6 link/NAT/approval value empty. A future enablement requires a new review
  proving a legitimate public IPv6 path and updated current special/protected
  sets; this acceptance does not authorize it.

### Bypass review

- Host forwarding must already equal `1`; the controller refuses rather than
  modifying it. Both worker namespaces force IPv4/IPv6 forwarding off, disable
  RA, and use separate default-drop input/forward/output chains.
- The owned host forward chain has terminal drops scoped to the owned veth.
  Accepts in an earlier foreign base chain do not bypass this chain, and accepts
  here do not override a later foreign drop. A foreign default-drop forward
  policy requires an attributable family-specific approval after that owner
  admits the exact path.
- Return traffic is limited to conntrack `established,related`, the configured
  egress/veth direction, and the worker source address. New outbound flows must
  still pass the exact diagnostic tuple or research DNS/deny/443 rules before
  NAT. NAT is veth-, egress-, family-, and source-scoped.
- A compromised namespace policy plus an added default route remained contained
  by the host table. Loaded namespace drift is reported. Workers do not have
  host `CAP_NET_ADMIN`; host-root replacement of an egress interface or nft
  table is outside the worker threat boundary and must be treated as a live
  stop condition. The controller verifies the owned veth type, marker and lack
  of bridge master; production activation must also compare the approved egress
  interface and global firewall to the captured baseline before and after each
  operation.

These results establish enforcement in disposable namespaces, not live campus
or Containerlab containment.

## Reversibility, recovery and audit

- Diagnostic and research have separate locks, state files, namespace/veth
  names, nft tables, activation IDs and configuration digests. Rollback of one
  preserved the other's byte-identical snapshot and validation.
- Failure after every applicable creation step removed only positively owned
  resources. Changed markers, activation IDs, config digests, resolver content,
  foreign pre-existing objects and the corrected pending-step races fail closed.
- The controller never changes existing host addresses, default routes, policy
  rules, forwarding sysctls, SSH, Docker tables/networks, or Containerlab
  interfaces. During activation it adds only its owned veth/address/connected
  route and owned nft table; rollback removes those objects by exact ownership.
- Root-only configuration/state, atomic mode-0600 journals, approval IDs,
  configuration/policy digests, structured command results and the application
  audit trail provide attribution. Operators must retain the exact config and
  system journal/change record because SNAT alone is not per-worker attribution.
- Cleanup failure records `activation-failed-cleanup-required`; ambiguous
  ownership is now preserved for manual reconciliation rather than broadly
  deleted. Management/firewall/route drift is a stop-and-rollback condition,
  using OOB/console recovery approved before activation.

## Verification performed

| Check | Result |
| --- | --- |
| Submitted, prior and corrected identities/checksums/payload audit | PASS |
| Corrected production preconditions | PASS, 210/210 |
| Python and launcher syntax | PASS |
| Packaged disposable namespace suite | PASS, 19 groups |
| Original foreign-resolver race reproducer on submitted package | FAIL as expected: foreign objects deleted |
| Same reproducer on corrected package | PASS: foreign objects preserved |
| Diagnostic exact-target IPv4/IPv6, SNAT and negative matrix | PASS in disposable namespaces |
| Research DNS/HTTPS/NAT and protected/non-443/mapped-IP negative matrix | PASS in disposable namespaces |
| Namespace compromise, forwarding, foreign-chain and rollback isolation tests | PASS in disposable namespaces |
| Every-step failure cleanup and three repeat cycles | PASS |
| Focused worker/target/research/model/artifact tests from corrected staged tree | PASS, 44/44 |
| Corrected disposable apply/post-verify | PASS, 210/210; 201 added, 9 saved |
| Disposable migration 0035→0039 | PASS; integrity `ok`, zero FK violations |
| Disposable reverse migration 0039→0035 | PASS; schema digest restored to `d0c55100…a39` |
| Corrected package rollback/pre-verify | PASS; 201 removed, 9 restored, 210/210 |
| Real-host baseline inside both namespace suites | PASS; unchanged before/after |

Disposable evidence is under `/tmp/nmas-veth-acceptance-SVZl39`. It contains
copies, synthetic topology objects and test data only.

## Production preservation

Final read-only checks found no production drift:

- source HEAD remains `129d3f090f8b94b982178b1e8f3ec51047278068` with the same pre-existing
  13 modified and 3 untracked paths;
- database remains at core 0035 with integrity `ok`, zero FK violations, 88
  tables and schema digest `d0c55100…a39`;
- the starting normalized address, route and rule digests are unchanged;
- SSH still listens on IPv4 and IPv6 port 22, and no `nmas-ts-*` namespace exists;
- `nmas-web` and all four existing timers are active; localhost health and
  login return 200;
- all 15 `clab-srlceos01-*` containers remain `Up`.

No live firewall digest comparison is claimed from an unprivileged command;
the two root disposable suites independently captured and compared the complete
real-host nft ruleset before and after and reported no change.

## Exact remaining configuration and authorization requirements

1. Gate A application authorization naming corrected entries identity
   `b6c636…aa39`, manifest `9dfc9a…5570`, production root/window, operator,
   reviewer, DB/source/rollback owners, quiescence, root-only backup path,
   restore record, install owners/modes and tested OOB recovery.
2. Gate B infrastructure-owner confirmation of VM1's assigned `ens33` and
   `nmas-mgmt` boundaries, all protected university/public IPv4 and IPv6
   ranges, VLAN-200/Containerlab ownership, permitted veth/nft/cgroup/systemd
   mechanisms, audit/retention requirements and named approver.
3. Separate Gate C records for diagnostic and research: non-overlapping VM-local
   link prefixes, exact existing egress interface, NAT source/mode, policy
   digest, host-policy digest, all approval IDs, named operator/reviewer and
   one-namespace rollback. Diagnostic additionally needs exact approved
   `TARGETS`; it currently has none. Diagnostic IPv6 additionally needs the
   owner of the foreign IPv6 forward chain to admit/approve the exact path.
4. Research requires approved literal recursive resolvers and UDP+TCP transport,
   complete `EXTRA_DENY_CIDRS` including institutional public space, direct
   HTTPS versus mandatory-proxy decision, exact hostname/purpose allowlist,
   privacy/logging/retention approval, public-egress approval, and
   `IPV6_MODE=disabled` with no IPv6 values.
5. Gate D needs a current per-device approved `ManagementPath`: verified owned
   non-R5 device, topology/lifecycle/admission state, exact IP/port/source
   binding, host-key pin, credential reference, health/revision, read-only
   operation family, expiry, owners and approvers. No production path is
   currently approved.
6. Gate F still needs approved dedicated UIDs/GIDs/ownership, three IPC-key
   lifecycles, model-broker/provider/TLS/privacy controls, and authorized live
   read-only evidence. Live dual-stack containment and campus-side filtering
   must be tested only in an approved window; simulated results must not be
   represented as that proof.

Gate B remains NO-GO until its owner signs it. Approval for one namespace or
gate does not authorize another.

## Final disposition

**TECHNICALLY_ACCEPTED — LIVE_APPROVAL_PENDING**
