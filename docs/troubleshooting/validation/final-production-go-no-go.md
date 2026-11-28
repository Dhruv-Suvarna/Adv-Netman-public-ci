# NMAS V2 minimum production go/no-go gate

Candidate entries SHA-256:
`5dab9de7e6af5d29fcfb23bb194ae65bde944c276f72cb8b3afe2c6bc0bd520f`

Candidate manifest SHA-256:
`47c98c1a0952bf0cd52e2271685dfa1d2e3891409d1e3989072702efa8da6242`

Technical acceptance does not clear any gate below. **Gate B is not
automatically authorized.** Each gate needs its own attributable record; an
approval for one gate is not authority for another.

## Gate A — application deployment authorization

Current state: **NO-GO — authorization missing**.

- [ ] Change manager names the exact candidate identities above, production root,
  approved window, user impact, named operator, independent reviewer, DB owner,
  rollback owner, and OOB recovery operator.
- [ ] Application owner approves quiescing only `nmas-web` and the four named
  package-importing timers/oneshots; unrelated collectors and Containerlab stay
  running.
- [ ] DB owner approves the root-only backup location, retention/encryption,
  consistent backup and restore test, migration 0035→0039, reverse migration,
  data-export decision, and loss point for last-resort restore.
- [ ] Source owner approves preservation of the dirty production tree through
  the package journal and source archive; no Git reset/checkout is permitted.
- [ ] Entry checks show exact hashes, 210/210 preconditions, production head
  `129d3f...068`, DB head 0035, healthy web/timers, and 15 running topology
  containers.

Missing inputs: `@APPROVED_APPLICATION_CHANGE_ID@`, window, people/roles,
`@APPROVED_ROOT_ONLY_BACKUP_DIRECTORY@`, backup retention/encryption/restore
record, install root/venv/file ownership confirmation, downtime notice, and OOB
method.

GO authorizes only source application, migrations, and restart of existing
application units. It does not authorize worker identities, namespaces,
firewall, device access, research, or model activation.

## Gate B — university infrastructure authorization

Current state: **NO-GO — external authorization missing**.

- [ ] An authorized university/infrastructure owner confirms VM1's assigned
  management interface/address/prefix/default route and identifies all protected
  IPv4/IPv6 assets and ranges without NMAS probing them.
- [ ] The owner confirms whether VLAN-200 and Containerlab management prefixes
  are wholly project-local, shared, or bridged, and that existing VM1/SSH,
  Docker, and Containerlab networking must remain unchanged.
- [ ] The owner records whether dedicated namespaces, a VM-local veth pair with
  an owned veth-scoped host nftables table (forward filter and source NAT behind
  VM1's existing address), cgroup-BPF, namespace-local nftables, resolver files,
  and dedicated service identities are permitted on VM1. No additional
  university-facing address is requested (`vm-local-veth-networking.md`).
- [ ] Console/OOB recovery, monitoring/audit requirements, escalation, and any
  two-person rule are approved and tested without altering production.

Missing inputs: authoritative boundary/protected-range list, subnet ownership,
allowed host mechanisms, recovery channel, monitoring/retention requirements,
and named infrastructure approver. Route visibility, sudo, DNS, ARP/ND, or a
successful connection is not a substitute.

## Gate C — namespace and firewall activation authorization

Current state: **NO-GO — values and separate activation approvals missing**.

Complete separately for diagnostic and research:

- [ ] Exact existing egress interface, VM-local point-to-point link prefix for
  each enabled family (overlapping nothing on VM1), NAT source, and protected
  set are approved. Diagnostic and research links differ from each other.
- [ ] The root-owned namespace config contains attributable activation,
  authorization, host-networking, firewall-policy, and per-family NAT IDs; its
  exact namespace nft digest and the `preflight` host-policy digest are recorded.
- [ ] Diagnostic IPv6 is either disabled or the owner of the Docker-managed
  `ip6 filter FORWARD` chain has admitted the exact path
  (`IPV6_FOREIGN_FORWARD_APPROVAL_ID`). Research IPv6 is disabled: VM1 has no
  public IPv6 path.
- [ ] Rendered policy and negative fixtures are reviewed; no R5, protected,
  unverified, private research, mapped-address, or wrong-port path is allowed.
- [ ] VM1 SSH, addresses, routes/rules, global firewall, Docker networks,
  Containerlab, services, and the other namespace have captured baselines.
- [ ] Named operator/reviewer authorize exactly one namespace activation in the
  approved window and accept the matching one-namespace rollback.

Additional research inputs: literal resolver IPs, UDP+TCP transport approval,
public-route/HTTPS decision, and `@RESEARCH_EGRESS_APPROVAL_ID@`.

Missing values: host-networking, firewall-policy and per-family NAT approval
IDs and named approvers for both; diagnostic `TARGETS` (zero approved paths
today); research resolvers, `EXTRA_DENY_CIDRS` protected set and egress
approval. No external source address, gateway, return route or upstream ACL is
required any longer.

GO for one namespace does not authorize the other. Stop on management change,
link-prefix collision, route leak, global firewall change, cross-namespace effect,
or unauthorized reachability.

## Gate D — device ManagementPath approval

Current state: **NO-GO — production has no approved ManagementPath**.

Repeat this gate for one device and one path at a time:

- [ ] Project owner confirms topology `srlceos01` and the named device is owned,
  verified, in service, admitted, and not R5 or an infrastructure/other-student
  asset.
- [ ] The record contains exact SSH IP/port, diagnostic namespace source binding,
  current host-key pin provenance, credential reference, health state,
  inventory/path revision, allowed fixed read-only operation family, expiry,
  requester, owners, and named approver(s).
- [ ] The tuple is rendered from current authoritative records and independently
  compared with the change record; no discovery, DNS, alternate endpoint,
  legacy/direct provider, or raw command fallback exists.
- [ ] Diagnostic worker activation is separately authorized and negative fixtures
  pass before the single approved read-only operation.

Missing inputs: all per-device records above, credential/pin custodians,
approvers, expiry, and operation family. Unverified devices remain denied and R5
remains excluded.

## Gate E — research egress authorization

Current state: **NO-GO — egress and privacy approvals missing**.

- [ ] Infrastructure owner approves exact recursive resolver IPs/transports and
  direct public TCP/443, or states that a proxy is mandatory. A mandatory proxy
  requires a new reviewed pinned-proxy design; proxy environment variables are
  intentionally ignored.
- [ ] Project owner and privacy/security reviewer approve each exact hostname,
  retrieval purpose, content class, logging/retention, and data-handling terms.
- [ ] Research namespace is independently active/valid while device credentials,
  production DB/inventory, diagnostic/model sockets, private/protected space,
  non-443 egress, uploads, executable content, and proxy inheritance remain
  inaccessible.
- [ ] One approved public textual retrieval passes DNS stability, IP pinning,
  TLS hostname, redirect reauthorization, method/media/size/time, and sanitized
  audit checks before another hostname is added.

Missing inputs: exact resolver IPs, proxy/no-proxy decision, public HTTPS
approval, exact hostname allowlist, privacy/security reviewer, retention terms,
and research change record. Until then the hostname allowlist stays empty and
the research worker stays stopped.

## Gate F — final read-only Troubleshooter acceptance

Current state: **NO-GO — requires authorized deployment and live evidence**.

- [ ] Application health/login, monitoring, timers, topology inventory, traffic,
  Change Engine, DB integrity/FKs, and all 15 topology containers match baseline.
- [ ] Dedicated runtime/diagnostic/research/model identities, UIDs/GIDs,
  directories, unit ownership, socket modes, and three distinct IPC-key
  generation/storage/rotation records are approved.
- [ ] Completion-only model broker has exact owner, provider/model/version,
  destination/TLS/privacy controls, bounded responses, and no shell, Docker,
  device, research, or arbitrary RPC authority.
- [ ] Runtime is AF_UNIX-only; workers cannot cross sockets or access capabilities
  outside their accepted role; signed IPC, expiry, replay refusal, bounded output,
  durable audit, and post-use authorization revalidation pass live.
- [ ] Troubleshooter exposes read-only/terminal tools only. `APPLY_CHANGE` remains
  handed off or refused; no AI remediation or alternate writer is enabled.
- [ ] Security, application, infrastructure, and device/research approvers accept
  the evidence and residual risks. Final baseline comparison shows only the
  explicitly authorized changes.

Missing inputs: service UID/GID assignments, secret lifecycle, model broker and
provider approvals, live containment evidence, named final reviewers, and the
final acceptance record.

GO here authorizes the accepted read-only scope only. Remediation still requires
a new per-change authorization through the existing NMAS Change Engine.

## Operator decision

Proceed only when every gate required by the intended stage is checked and
signed. Any unresolved placeholder, hash mismatch, baseline drift, missing
approver, or failed stop condition is **NO-GO**.

Current decision: **TECHNICALLY_ACCEPTED — EXTERNAL_AUTHORIZATION_PENDING**.
