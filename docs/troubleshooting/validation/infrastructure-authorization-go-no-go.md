# NMAS V2 infrastructure authorization and GO/NO-GO matrix

Prepared: 2026-11-14 (America/Denver)

## Decision matrix

| Decision point | Evidence required | Current evidence | Decision |
|---|---|---|---|
| Preserve frozen candidate | Exact entries/manifest/tool/payload identities | Recomputed and matched; all 13 `deploy/sandbox/` artifacts match package payload | GO to request/review only |
| Production remains pre-deployment | 205/205 preconditions, DB at 0035, old routes/services/topology, no sandbox activation | Observed: 205/205; DB integrity OK/0 FK violations/head 0035; health 200; 15 containers Up; no sandbox namespace/unit | GO to continue preparation only |
| A. Application and migrations | Independent package/security review, backups/restore test, app window, exact migration/rollback approval | Technical candidate is conditionally accepted for inactive staging; no production deployment authorization/window/backup record | **NO-GO** |
| B. Inactive worker artifacts | Host-owner approval, exact install paths/UIDs/GIDs/modes, secret lifecycle, inactive-unit verification | Templates reviewed; owner values and approval absent | **NO-GO** |
| C. Diagnostic host containment | Owner-approved source/parent/VLAN/gateway/return route/protected set/upstream ACL/OOB; independent activation/rollback | Successor mechanism passes disposable independent tests; external values, authorization and independent candidate review remain absent | **NO-GO** |
| C. Research host containment | Owner-approved source/parent/VLAN/gateway/resolvers/protected set/public route/OOB; independent activation/rollback | Successor mechanism passes disposable independent tests; external values, authorization and independent candidate review remain absent | **NO-GO** |
| D. Public research egress | Public-443 decision, exact resolvers and hostnames, privacy review, live containment evidence | Empty-by-default allowlist; no owner approval or live proof | **NO-GO** |
| E. One-device diagnostics | Verified/admitted/in-service device, exact active approved `ManagementPath`, source binding, pin, credential reference, operation, expiry/approvers | Production `ManagementPath` count is zero; R5 excluded | **NO-GO** |
| E. Additional devices | Independent path approval and policy review for each device | No approved paths | **NO-GO** |
| Completion-only model/runtime | Broker identity/socket/key/provider/model/privacy approval and live AF_UNIX-only proof | Protocol/tests staged; external broker/ownership not approved or activated | **NO-GO** |
| F. Governed remediation | Existing Change Engine per-change authorization, locks, pre/postchecks and rollback; no alternate writer | Separation is implemented/tested; no production activation or particular change approval | **NO-GO** for execution; handoff design acceptable |
| Full operational service | All prior stages independently accepted and live containment evidence signed by authorized owners | External authorization and live evidence absent | **NO-GO** |

## Exact missing information and approvals

1. Authoritative VM1 management interfaces/addresses/routes/source rules and SSH
   recovery endpoint.
2. Permission for two dedicated namespaces and two unique additional source
   address/CIDRs.
3. Approved parent interface, VLAN/attachment, gateway, return route and upstream
   ACL for each namespace and each enabled address family.
4. Complete protected IPv4/IPv6 networks and assets, including shared lab,
   other-student, university, metadata and vSphere/ESXi/vCenter scopes.
5. Exact recursive resolver IPs/transports and institutional proxy decision.
6. Public TCP/443 decision, exact research hostnames and privacy/data-handling
   approval.
7. Authorization for dedicated service identities, systemd/cgroup-BPF,
   network namespaces, namespace-local nftables and resolver files.
8. Maintenance window, named operator/reviewer, two-person requirement, working
   console/OOB recovery and escalation procedure.
9. Install root/venv/UID/GID/modes, IPC secret lifecycle and completion-only
   model-broker ownership/provider controls.
10. Database backup/quiescence/restore and source rollback approval.
11. Individually approved current `ManagementPath` records with exact target,
    source, host-key pin, credential reference, lifecycle/identity/admission,
    operation, expiry and named approvers.
12. A separately reviewed activation artifact that can check/apply/rollback the
    diagnostic and research namespaces independently without editing the frozen
    205-entry package.

## What can be prepared now

- Submit the infrastructure-owner request and collect attributable answers.
- Review the immutable package, exact overlay diff, unit templates, renderer,
  namespace policies, service identities and secret-handling design offline.
- Allocate change roles and draft separate Stage A–F change records.
- Prepare empty, unrendered configuration forms and backup/restore test plans.
- Independently review the successor candidate's per-namespace controller,
  disposable evidence and package identity; do not alter or relabel the frozen
  package.
- Reconcile project inventory and prepare proposed `ManagementPath` records for
  human review without approving, activating or contacting devices.
- Select candidate public documentation hostnames for privacy/infrastructure
  review while leaving the production allowlist empty.

## Actions that remain blocked

- Applying the production overlay or running migrations.
- Installing, enabling, starting or stopping production worker/runtime services.
- Creating namespaces, assigning addresses, adding routes, loading nftables or
  cgroup policy, or altering interfaces/Docker/Containerlab networking.
- Enabling public research, model-provider access or live diagnostics.
- Creating or approving a path from reachability/discovery evidence.
- Contacting unauthorized university, vSphere/ESXi/vCenter, other-student or
  private/reserved destinations.
- Any device configuration change or direct Troubleshooter remediation.
- Claiming university authorization or live containment.

## Required subsequent order

1. Obtain infrastructure facts/authorization and separate Stage A–F decisions.
2. Independently review and accept the implemented successor namespace
   controller/package without changing the frozen candidate.
3. Execute Stage A application/DB deployment in its own approved window.
4. Execute Stage B inactive identity/unit/secret installation; start nothing.
5. Create and approve governance records for the diagnostic namespace attachment
   and one device `ManagementPath`; keep workers stopped.
6. Activate and validate diagnostic containment only.
7. Enable and accept diagnostics for one approved device at a time.
8. Activate and validate research containment only, with an empty host allowlist.
9. Enable and accept exact research hostnames one at a time.
10. Activate and validate the completion-only model broker and one governed
    AF_UNIX-only runtime instance.
11. Permit only existing Change Engine handoff; authorize each remediation as a
    separate governed change.
12. Recapture baselines and obtain independent final operational acceptance.

## Current conclusion

The technical candidate remains a conditional GO for review and inactive
staging only. Production deployment, host containment, research, diagnostics,
model access and remediation are not authorized. The exact external questions
and internal stop conditions are now ready for formal submission.

**READY_TO_REQUEST_INFRASTRUCTURE_AUTHORIZATION**
