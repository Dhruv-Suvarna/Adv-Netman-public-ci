# NMAS V2 staged production rollout and rollback procedure

Prepared: 2026-11-14 (America/Denver)

Status: **PREPARED, NOT AUTHORIZED, NOT EXECUTED**

## Safety model

Every stage is independently approved, validated and reversible before the
next stage. The operator stops automatically on a failed precondition or stop
condition; schedule pressure is never a reason to continue. This procedure
does not modify vSphere, ESXi, vCenter, VM hardware, host default routes,
VM-wide firewall tables, Docker networks, Containerlab topology, or device
configuration.

The frozen 205-entry package remains immutable and its combined namespace helper
is prohibited. The development successor now provides independent per-namespace
preflight/activate/validate/deactivate/rollback with ownership journals. Its
disposable test evidence does not authorize production; the successor package
identity and independent review must be recorded before this procedure is used.

Successor awaiting independent review: 210 operations at
`/home/student/Scripts/nmas-independent-namespaces-release-20261115T050919Z/package`,
entries identity `5dab9de7e6af5d29fcfb23bb194ae65bde944c276f72cb8b3afe2c6bc0bd520f`,
manifest SHA-256 `47c98c1a0952bf0cd52e2271685dfa1d2e3891409d1e3989072702efa8da6242`.
This records identity only; it is not approval or activation authorization.

## 0. Authorization and change-window preparation

1. Obtain separate recorded decisions for stages A through F and populate only
   owner-approved values from the missing-input matrix.
2. Assign a primary operator, independent reviewer, application owner,
   infrastructure owner, database rollback owner and OOB recovery operator.
3. Verify console/OOB access without changing VM state. Keep the original SSH
   session open and establish the separately approved recovery channel.
4. Recompute package identities and run the 205/205 production pre-verifier.
5. Capture the complete read-only baseline listed in the readiness checklist.
6. Review the exact forward and rollback actions and define the maximum elapsed
   time for each validation. A timeout is a failure, not an inconclusive pass.

Exit: authorization, identities, baseline and recovery are complete. Otherwise
stop before production writes.

## 1. Stage A — application and migrations

1. Quiesce only the package-importing writers named by the existing application
   rollout runbook.
2. Create and restore-test the approved database backup and source archive.
3. Apply the exact reviewed overlay and verify all 205 postconditions.
4. Confirm the migration plan, migrate only core 0036 through 0039, and run DB
   integrity/foreign-key checks.
5. Start only the existing application service(s). Verify health, login,
   monitoring, topology inventory, timers and existing change workflows.
6. Confirm workers, namespaces, sockets, research hosts, device transports and
   model provider remain absent/inactive.

Rollback A: stop only package-importing processes; restore the pre-migration DB
backup first if migrations ran; use the candidate rollback journal for overlay
paths; restore the source archive only if needed; verify 205/205 preconditions,
DB head 0035, health, timers, monitoring and topology. Never use destructive Git
reset/checkout against the dirty production tree.

## 2. Stage B — inactive worker identities and files

1. Create only approved no-login identities/groups and exact runtime/state/log
   directories.
2. Generate and install distinct IPC keys through the approved secret mechanism.
3. Render units and environment/policy files from approved values, install them
   root-owned, and perform target-host syntax/security review.
4. Do not enable or start units. Confirm namespaces, sockets and processes are
   absent and existing unit states are unchanged.

Rollback B: preserve sanitized validation evidence, remove only new inactive
unit/config/directory/account artifacts in the reverse reviewed order, and
rotate any key that may have been exposed. Do not touch existing NMAS identities.

## 3. Governance data before diagnostic activation

1. Reconcile only explicitly owned Containerlab devices through existing NMAS
   workflows; do not discover or auto-approve endpoints.
2. Register the approved diagnostic namespace attachment/source.
3. Create one approved `ManagementPath` at a time with exact endpoint/port,
   source, host-key pin, credential reference, owners, two-person approval where
   required, health, expiry and revision.
4. Keep the diagnostic worker stopped. Render policy only from current records
   and independently compare every tuple to the change record.

Rollback governance data: revoke the new paths through existing governance and
regenerate policy. Do not delete history or fall back to a legacy/direct path.

## 4. Stage C-Diagnostic — diagnostic containment only

Precondition: the successor candidate containing the controller documented in
`../namespace-activation.md` is independently reviewed. Disposable tests must
remain passing for idempotent rollback, every injected creation-step failure,
research preservation and the host baseline. Do not use the frozen helper.

1. Reconfirm the egress interface, VM-local link prefix, NAT source, host
   networking approval, exact target tuples, protected sets, SSH/OOB recovery
   and baseline. Review the `host-policy` output against the change record.
2. Run `namespace-activate.sh preflight diagnostic
   /etc/nmas/diagnostic-namespace.env`; confirm `mutations: 0` and review the
   activation/config identities in its output.
3. Run the diagnostic-only `activate`, then `validate`; create only
   `nmas-ts-diagnostic` and its namespace-local policy.
4. Before any allowed device test, verify local negative fixtures for wrong
   ports and protected/unauthorized destinations. Never probe a real forbidden
   asset.
5. Compare VM1 SSH, host routes/rules/firewall, Docker/Containerlab networks,
   topology containers and NMAS services to baseline.
6. Start the diagnostic worker only after containment passes. Complete Stage E
   for one approved device at a time.

Rollback C-Diagnostic: stop only the diagnostic worker, confirm process exit,
run `namespace-activate.sh rollback diagnostic` with the exact retained config,
remove only diagnostic cgroup policy and owned namespace resources, revoke affected
paths if required, rotate the diagnostic IPC key if exposed, and compare the
host baseline. The research namespace/service, if later present, must be
untouched.

## 5. Stage E — one diagnostic device at a time

1. Revalidate the exact `ManagementPath`, grant digest/revision/expiry, source,
   host-key pin and credential reference immediately before use.
2. Execute one approved fixed read-only operation and capture sanitized audit.
3. Verify destination IP/port and source binding, bounded output, signed IPC,
   replay refusal and post-use revalidation.
4. Confirm no device configuration, routing adjacency, interface, topology, VM1
   service or management behavior changed.
5. Obtain independent acceptance before adding another device tuple.

Rollback E: stop the diagnostic worker, revoke the affected path/grant, remove
its exact tuple from policy through a newly reviewed render, rotate affected
credentials/IPC key, and preserve audit. If containment is suspect, execute
Rollback C-Diagnostic.

## 6. Stage C-Research — research containment only

Precondition: the same independently reviewed successor supports research-only
lifecycle and its disposable every-step, diagnostic-preservation and host
baseline tests remain passing.

1. Reconfirm research egress interface, VM-local link prefix, NAT decision,
   approved resolvers/transports, `EXTRA_DENY_CIDRS` protected sets,
   public-HTTPS decision and recovery baseline. Review the `host-policy` output.
2. Keep research hostname allowlist empty and the research worker stopped.
3. Run `namespace-activate.sh preflight research
   /etc/nmas/research-namespace.env`; confirm `mutations: 0`, then run the
   research-only `activate` and `validate`. Create only `nmas-ts-research`, its
   resolver file and namespace-local nft policy.
4. Validate local dual-stack denial fixtures, DNS only to approved resolvers,
   and public-shaped TCP/443 without contacting an unauthorized real endpoint.
5. Compare all host and topology baselines; verify diagnostic behavior is
   unchanged.

Rollback C-Research: stop only the research worker, confirm exit, run
`namespace-activate.sh rollback research` with the exact retained config, remove
only ownership-verified research resolver/policy/namespace resources, rotate the research IPC key if
exposed, and compare baseline. Diagnostic state must be untouched.

## 7. Stage D — approved public research

1. Install only the exact separately approved hostname list and start only the
   research worker.
2. Prove cross-worker, DB, inventory, credential, model-socket, private/protected
   and non-443 denial before the allowed test.
3. Retrieve one approved non-sensitive public textual document with sanitized
   purpose/audit and validate DNS/TLS/pinning/redirect/content limits.
4. Independently accept evidence before adding another hostname.

Rollback D: empty the hostname allowlist through reviewed configuration, stop
the research worker, preserve audit and execute Rollback C-Research if network
containment is suspect. Existing Slack/model paths are not changed.

## 8. Completion-only model broker and governed runtime

1. Separately validate broker UID/GID, socket ownership/mode, distinct key,
   exact provider/model/version, response bounds, provider destination/TLS and
   privacy controls, and absence of shell/Docker/device authority.
2. Start one reviewed runtime instance with AF_UNIX-only networking.
3. Prove it cannot reach IP networks, Docker/containerd, credentials, arbitrary
   Unix sockets or direct device/research transports.
4. Confirm only read-only evidence tools and Change Engine handoff are exposed.
5. Inspect the runtime DB alias for only expected SQLite DB/journal artifacts.

Rollback runtime/model: stop the runtime instance and broker, remove model
socket access, rotate the model key, preserve audit, and leave diagnostic and
research workers stopped unless their own stages remain independently approved.

## 9. Stage F — governed remediation

1. Treat each proposal as a new existing-NMAS Change Engine request.
2. Require the normal human approval, eligibility, lock, precheck, execution,
   postcheck and rollback plan. Troubleshooter never writes directly.
3. If governance or containment differs from the accepted evidence, refuse the
   change and return to read-only operation.

Rollback F is the existing Change Engine's change-specific rollback. A
Troubleshooter containment rollback does not substitute for a device-change
rollback, and device-write authorization does not authorize host/network work.

## Out-of-band recovery and automatic abort

If SSH or management behavior changes, the operator immediately stops forward
work. The OOB operator uses the pre-approved console, stops only newly started
`nmas-*troubleshooter*`/research units, and invokes the reviewed per-namespace
rollback for the last changed namespace. They do not flush host nftables, alter
the host default route, restart Docker, destroy/redeploy Containerlab, reboot
network containers, or change devices. Baselines are recaptured before deciding
whether application rollback is necessary.

If the exact changed object cannot be identified, production activation remains
NO-GO and the incident is escalated; broad cleanup is not an acceptable recovery.

