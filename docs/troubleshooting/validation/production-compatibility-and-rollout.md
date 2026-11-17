# Production compatibility and rollout

## Decision

A new deployment candidate is required. The immutable package identity `8a4111f7...8f70` predates the sandbox guardrails and must not be edited, relabelled or deployed as if it contained them.

An explicitly **unreviewed, non-deployable candidate** was built to validate overlay mechanics at `/home/student/Scripts/nmas-sandbox-release-20261114T145500Z/package`:

- 181 ADD, 8 REPLACE, 1 MERGE (190 operations);
- candidate entries identity `955faa118060c3b7694fdd3d3453976eafdb9b5b4f5f7b3be5ac663d0e1df97a`;
- manifest SHA-256 `acca183adca00a39a4067cadb17f11f39e302a55eddef825c69172f2c26ba82d`;
- zero builder problems; production preconditions and staged-copy postconditions both verified for all 190 paths;
- fresh staged database migrated through 0039; focused staged-copy suite 102/102 PASS.

This candidate is evidence/preparation only. The dedicated device/research worker commands and externally approved activation manifest are not complete, so the candidate is **not ready for review or deployment** and receives no approval identity.

Production source, database, services, topology, routes, firewall and Docker state were not modified. The reviewed package `manifest.json` SHA-256 remained `5d30929d1d197eca9dabeb449d198455b74683b18e641a37a4c35d958b2de252` after implementation.

## Separate release tracks

### Track A — NMAS project code

Future candidate must be rebuilt from the authoritative public worktree and include the prior reviewed 179 operations plus these guardrails. It needs a new content/manifest identity and fresh independent review. Required gates:

1. Start from or rebuild the unreviewed candidate against production HEAD `129d3f...068`; exclude unrelated worktree artifacts.
2. Verify every add/replace/merge and all generated hashes.
3. Repeat migration inspection and copy-based install/rollback tests. Migrations remain 0036-0039 unless separately changed.
4. Complete and test actual standalone worker management commands/Unix protocols; no fallback to Gunicorn, gateway root or Docker-group identities.
5. Repeat full Troubleshooter, core/regression, deployment, commissioning, ZTP, isolation, DHCP, identity, maintenance, credential, traffic and orchestration suites.
6. Obtain compatibility/security/QA approval for the new identity. Prior approval does not transfer.
7. Deploy code only during an NMAS application change window. Keep transports, model provider and research host list disabled.
8. Verify health/login/existing timers/collectors/traffic/topology and migration state before proceeding.

### Track B — host/process/network containment

This is a separate privileged change and must not be bundled into an ordinary source-copy step:

1. University approval identifies protected boundaries, DNS resolvers and recovery method.
2. Operator reconciles/adopts/verifies devices and creates approved management paths through existing workflows; no auto-approval.
3. Generate a reviewed manifest from exact authoritative endpoints. Renderer must reject R5, unverified/ineligible devices and VM1 protected addresses.
4. In a disposable namespace, validate the rendered systemd and nft syntax and all dual-stack denial fixtures.
5. Pre-stage dedicated `nmas-ts-worker` and `nmas-research` users without shell, sudo or Docker group; root-own units/env/policy.
6. Record current SSH/default-route/interface/firewall/systemd state and an out-of-band recovery path.
7. In the approved window, create only the new namespaces/cgroups/units. Do not change global VM input/output/default route, Docker daemon or active Containerlab networks.
8. Validate exact authorized device access; deny simulated private/shared/metadata/IPv6/mapped/redirect/DNS-rebind cases locally. Never probe a real unauthorized endpoint.
9. Enable reviewed research hosts, then the model provider and Troubleshooter worker identity. Do not give it raw gateway shell, Docker, systemd or credential access.
10. Keep Gate B held until post-activation evidence is independently accepted.

## Readiness gates

| Gate | Required evidence | Current state |
|---|---|---|
| Immutable package preservation | old manifest hash and production status unchanged | PASS |
| New source candidate complete | worker commands, Unix APIs and exact grant enforcement included | PARTIAL: unreviewed 190-path candidate built; worker commands incomplete |
| Application tests | focused, AI, deployment and broad Troubleshooter regression | See test report; development-only |
| Inventory/identity reconciliation | every target verified/admitted; R5 exclusion | BLOCKED: R2/R4 unverified, other originals unresolved |
| Approved management paths | exact active path per target | BLOCKED: production count zero |
| University boundary approval | owned/protected scopes and DNS/proxy policy | BLOCKED_EXTERNAL |
| Kernel isolation dry run | disposable namespace/cgroup/nft evidence | PARTIAL: templates/renderer tests only |
| Dedicated runtime privilege | no root, Docker, shell, service-policy writes | BLOCKED: accounts/services not activated |
| Management recovery | tested SSH/out-of-band rollback | BLOCKED/change window |
| Independent new-package review | new hash/signoff | NOT STARTED |

## Rollback

### Application rollback

- Before deployment: copy-based compatibility validation must produce an exact rollback manifest for every add/replace/merge.
- During deployment: stop on hash mismatch, migration error, health failure, unexpected transport activation or topology/service regression.
- Restore only from the candidate's independently reviewed rollback payload; do not use destructive Git reset/checkout against the dirty production tree.
- Database rollback follows the existing Troubleshooter rollback runbook. Back up and verify the live DB first. Do not fake a migration or delete audit/history records.
- Revalidate `/healthz`, login, timers, telemetry, traffic and topology after rollback.

### Worker/network rollback

- Keep the original SSH session and a separately verified recovery channel open.
- Disable only the new worker/research units; remove only their cgroup/namespace policy and namespace after confirming process exit.
- Never flush or replace global nftables/iptables tables. Namespace policy has its own table `inet nmas_research`.
- Do not alter `ens33`, `nmas-mgmt`, default routes, Docker networks or topology containers.
- Clear research/device activation environment only after preserving sanitized audit evidence.

## Activation-stop conditions

Stop and roll back if management connectivity changes, any existing health check/timer/collector/traffic flow regresses, any target lacks exact identity/path evidence, R5 is rendered, a worker gains Docker/root/shell access, public research can reach private/metadata fixtures, IPv4 and IPv6 policy differ, or direct provider settings are enabled.

## Approvals still required

- University/infrastructure containment and resolver/egress approval.
- Project owner approval of exact research hostname list.
- Human inventory reconciliation, identity verification and management-path approvals.
- Root/operator change window for dedicated users, systemd/cgroup/network namespace/nft activation.
- New compatibility, security and QA review for the new package identity.
- Separate deployment authorization; no automatic Gate B clearance.

## New candidate and separated activation stages

The completed source requires a new review: 203 entries, identity `cab1ac29d8be78b11dc9ecfa130843634a754049afe6c7dd012fef3e25d091d1`, manifest `75010e99e83b49a9a562caa8305cf363214490bd298251f473913f6492b7d596`, at `/home/student/Scripts/nmas-sandbox-workers-release-20261114T212024Z/package`. This is unapproved and does not inherit any older package approval. All earlier 203-path intermediate builds are superseded.

### A. Application package

Preconditions: independent diff/security review, production pre-hash verification, DB/source backup, approved application window, all package-importing units stopped per the existing overlay runbook. Apply only the 203-entry package and migrate 0035→0039. Expected: package post-hashes, migration head 0039, health/login/timers/topology regressions pass, Troubleshooter remains unable to contact devices because workers are absent. Stop on any hash/migration/health mismatch. Roll back application/migrations with the candidate journal and verified DB backup; do not touch worker/network state.

### B. Worker identities and files

Preconditions: Stage A healthy; reviewed `/opt/nmas` immutable release; exact production DB/inventory/credential-store binds; separately generated diagnostic/research IPC keys; approved runtime UID recorded in both worker env files. Install sysusers, units and root-owned mode-0600 environments, but do not start units. Expected: users have no sudo/Docker groups, sockets absent, service verification clean except inactive namespace conditions. Stop if any identity inherits privileged groups or can read the other worker's state. Roll back by removing only new inactive unit/config/account artifacts after evidence capture.

### C. Kernel/network activation

Preconditions: separate university/network approval, console recovery, approved VM-local veth/forward/NAT host change (no external source address), exact egress interfaces/link prefixes/resolvers, rendered nft and cgroup allowsets reviewed, existing SSH held open. Run `namespace-activate.sh preflight <kind> <config>`, then `activate` and `validate`, one namespace at a time; start workers only after namespace tests pass. Expected: diagnostic exact address+port only, research DNS+public 443 only, v4/v6 denials, VM1 SSH/default route/topology unchanged. Stop on any management/service/routing/container change or bypass. Rollback stops only the three new units, runs the exact namespace rollback and verifies existing network state; never flush host firewall tables.

### D. Management paths

Preconditions: reconciled/verified devices, university ownership, approved namespace attachment, pinned host key, broker credential and two-person path approval. Register the paths (devices see the existing NMAS management source; no new source address is registered) through existing management workflows; do not auto-approve. Expected: only healthy active paths render; R5/unknown/unverified endpoints refuse. Stop on address/path/revision mismatch. Rollback revokes the new paths through governance and regenerates policy; no legacy/direct fallback.

### E. Research destinations

Preconditions: exact operator-approved hostname and resolver list, privacy review, namespace policy active. Render/install the allowlist and start only the research worker. Expected: approved textual HTTPS succeeds; redirects/private/mapped/proxy/attachment/executable tests refuse; Slack/model paths remain unchanged. Stop on any private reachability or credential-bearing request. Rollback stops research worker and removes its namespace/allowlist without changing control-plane services.

### F. Troubleshooter AI

Preconditions: A–E pass, completion-only Unix model-provider factory reviewed, no role on the root execution gateway, runtime unit has `PrivateNetwork`, AF_UNIX-only and no Docker/credentials. Start one reviewed `nmas-troubleshooter-runtime@<handoff>` instance. Expected: signed worker IPC, governed evidence and proposals only; Change Engine remains sole writer. Stop on raw command/destination surface, direct fallback, unexpected DB/network access or self-policy modification. Rollback stops the instance and revokes/rotates IPC keys; device/research workers may remain inactive pending review.

Approval of any one stage does not authorize another. In particular, application approval is not host-network approval, path registration is not research approval, and successful tests do not clear the university containment NO-GO.
