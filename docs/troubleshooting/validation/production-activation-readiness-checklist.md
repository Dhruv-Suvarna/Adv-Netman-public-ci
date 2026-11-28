# NMAS V2 production activation readiness checklist

Prepared: 2026-11-14 (America/Denver)

Status: **NOT APPROVED FOR EXECUTION**. This checklist is approval material,
not an instruction to activate the candidate in the current session.

## Global entry gate

- [ ] The change record names the candidate entries identity
      `514f49bafd8aa38d178c4c36e275f85211867fc3f00ae600b59284800dd63ddc`
      and manifest SHA-256
      `dfbe2f5e8b589c63853ee8f823b6adf08a682da3126d923b3091f856b2330352`.
- [ ] A reviewer independently verifies `SHA256SUMS`, canonical entries identity,
      all payload hashes, `problems: []`, and production preconditions 205/205.
- [ ] Every pre-existing dirty production path is reviewed; no user work is
      discarded or overwritten outside an exact reviewed overlay operation.
- [ ] Stage A through F decisions are recorded separately. No approval is
      interpreted transitively.
- [ ] Named operator and independent reviewer are present in the approved
      maintenance window with a working VM1 console/OOB recovery path.
- [ ] Baselines are captured for VM1 SSH, interfaces/addresses, routes/rules,
      normalized nftables, Docker networks, topology containers, NMAS units and
      timers, localhost health/login, DB integrity/migration head, and disk space.
- [ ] Stop conditions and rollback ownership are read aloud and accepted.

**Automatic stop:** any identity/hash/precondition mismatch, unknown dirty-file
overlap, absent approver/reviewer, unavailable console, baseline collection
failure, or unexplained pre-existing degradation.

## A. Application code and database migrations

- [ ] Stage A has its own application deployment authorization.
- [ ] All package-importing units are quiesced exactly as the existing overlay
      runbook requires; unrelated services, timers and collectors are preserved.
- [ ] A consistent database backup and source archive are created, hashed,
      access-controlled, and restore-tested before any production write.
- [ ] The exact overlay diff is reviewed and applied only to the approved
      production root.
- [ ] Migration plan is exactly core 0036 through 0039; no other migration runs.
- [ ] DB integrity, foreign keys, migration head, NMAS health/login, monitoring,
      topology inventory, existing timers and Change Engine workflows pass.
- [ ] Troubleshooter transports, workers, research hosts and model provider
      remain unavailable after Stage A.

**Automatic stop/rollback:** package drift, backup/restore failure, unexpected
migration, integrity/foreign-key failure, service/timer/monitoring/topology
regression, unexpected listener/transport, or credential discovery.

## B. Inactive worker service artifacts

- [ ] Stage B has separate host-owner authorization; Stage A approval is not used.
- [ ] Install root, venv, production bind paths, allocated UIDs/GIDs, directory
      owners/modes and secret mechanism match the approved record.
- [ ] Dedicated identities have no shell, sudo, Docker/containerd group,
      capabilities, broad supplementary group, or access to each other's state.
- [ ] Diagnostic, research and model IPC keys are independent high-entropy
      values installed outside source with reviewed mode/owner and rotation plan.
- [ ] Units, environment files and policies are installed but not enabled or
      started; sockets and namespaces remain absent.
- [ ] Rendered units pass syntax/security review on the target; code and unit
      files are not worker-writable.
- [ ] Model-broker ownership and completion-only contract are separately reviewed.

**Automatic stop/rollback:** privileged group inheritance, identity collision,
wrong UID/GID, shared/reused key, secret exposure, writable code/unit, unexpected
socket/process, or broader filesystem/network access than reviewed.

## C. Host and namespace network restrictions

- [ ] Stage C has an attributable infrastructure authorization containing exact
      source CIDRs, parent interfaces/VLANs, gateways, protected destinations,
      DNS resolvers, return routes/upstream ACLs and recovery plan.
- [ ] The two sources are unique, not assigned elsewhere, not VM1 management
      addresses, and not equal to each other.
- [ ] Existing `ens33`, `nmas-mgmt`, host default routes/rules, VM-wide firewall,
      Docker networks and Containerlab interfaces will not be modified.
- [ ] Rendered diagnostic policy contains only currently approved exact
      destination IP+TCP-port tuples and no R5/protected/unverified endpoint.
- [ ] Rendered research policy contains only approved resolver IPs and the
      reviewed public-HTTPS policy, with all required IPv4/IPv6 protected sets.
- [ ] Diagnostic and research namespace creation and rollback can be invoked and
      validated **independently**.
- [ ] Before the production window, the successor per-namespace artifact passes
      disposable tests proving idempotent check/rollback, cleanup after an
      injected failure at every creation step, and zero change to the other
      namespace and the host baseline. Test evidence is independently reviewed.
- [ ] Negative fixtures and namespace-local policy are validated before any
      allowed destination; validation never probes a real unauthorized endpoint.

**Implementation status:** the frozen helper remains prohibited and the frozen
205-entry package is unchanged. Development source now has per-namespace
`preflight/activate/validate/deactivate/rollback`, ownership journals and passing
disposable failure/cross-rollback tests. Stage C remains blocked until a new
candidate identity containing that implementation is independently reviewed.
The unapproved candidate is the 210-operation package with entries identity
`5dab9de7e6af5d29fcfb23bb194ae65bde944c276f72cb8b3afe2c6bc0bd520f` and
manifest SHA-256 `47c98c1a0952bf0cd52e2271685dfa1d2e3891409d1e3989072702efa8da6242`.
The exact external inputs above and the change window remain unapproved.

**Automatic stop/rollback:** management/SSH change, source collision, ambiguous
ownership, missing protected range, route leak, VM-wide firewall delta,
Containerlab/Docker delta, cross-namespace effect, DNS/proxy surprise, or any
private/protected/unauthorized reachability.

## D. Public research egress

- [ ] Stage D has separate public-egress, exact-hostname, resolver and privacy
      approvals; an empty allowlist is not replaced by guessed values.
- [ ] Research namespace is active and validated while diagnostic worker remains
      stopped or independently unchanged.
- [ ] Start only the research worker.
- [ ] Prove production DB, inventory, credentials, diagnostic/model sockets,
      private/protected destinations and non-443 egress are unavailable.
- [ ] Validate exact-host allow, public textual HTTPS, DNS answer stability,
      TLS hostname verification, redirect reauthorization, proxy non-inheritance,
      method/media/size/time limits and sanitized audit.

**Automatic stop/rollback:** private/protected access, resolver/hostname bypass,
proxy inheritance, unsafe redirect, credential-bearing URL, upload, executable
content, unexpected egress, cross-worker access, or missing audit evidence.

## E. Individually approved Containerlab diagnostics

- [ ] Stage E approval exists for one named device and one current
      `ManagementPath`; approval does not cover another device.
- [ ] Identity, topology, tenant, lifecycle/admission, endpoint/port, diagnostic
      namespace source binding, host-key pin, credential reference, path health,
      permitted operation family, approvers and expiry are all current.
- [ ] Device is not R5, VM1, university infrastructure, another student's asset,
      or an unregistered/discovered endpoint.
- [ ] Policy is re-rendered and reviewed from authoritative records; there is no
      legacy/direct fallback.
- [ ] Start only the diagnostic worker and prove public Internet, research/model
      sockets, Docker/containerd and all non-approved destinations unavailable.
- [ ] Run only an approved read-only operation against the named device and
      verify source address, pinned identity, bounded output, signed audit,
      replay refusal, revalidation and expiry.
- [ ] Repeat this gate independently for each additional device.

**Automatic stop/rollback:** stale/revoked/path-changed authorization accepted,
wrong source, host-key mismatch, credential leakage, raw/unlisted command,
unauthorized endpoint, replay acceptance, or any device/topology configuration
change.

## F. Governed remediation

- [ ] Stage F has separate Change Engine authorization under the existing NMAS
      change process; diagnostic or research approval is not remediation approval.
- [ ] Troubleshooter model tools remain read-only/terminal; `APPLY_CHANGE` is
      handed off or refused and no alternate executor/writer is configured.
- [ ] Each proposed change receives existing human approval, eligibility,
      locks, precheck, execution, postcheck and rollback treatment.
- [ ] No worker receives shell, Docker, sudo, raw credential, direct device-write,
      host-policy-write, or service-management authority.

**Automatic stop/rollback:** direct write outside Change Engine, approval bypass,
alternate executor, self-policy modification, raw command/destination surface,
or missing existing governance/audit control.

## Final operational gate

- [ ] Independent security and infrastructure reviewers accept live evidence for
      each activated stage and all residual risks, including SQLite directory
      write semantics for the runtime alias.
- [ ] All initial baselines are recaptured and compared; expected changes are
      limited to the specifically authorized stage.
- [ ] Production is not called operational until the explicit final decision is
      recorded. Offline tests and inactive staging are not live-containment proof.

