# NMAS V2 final operational acceptance record

Evidence time: 2026-11-15 18:46 MST. This is one consolidated operational
record. It does not supersede the immutable release acceptance or authorize a
live change.

## Release and production baseline

- Technically accepted frozen package: entries
  `b6c636301d3cfa48429a373662d748738b07e5daba58c7bf76db62c1d383aa39`,
  manifest `9dfc9ae4c0c213b454f639a88dd0fc1a714cdf8d90c028c946b7ca5fe29d5570`,
  tool `46db050bd863183498203b796a21bb563026b97a829d1cdbe4678f0e5dd99a0e`.
- Package checksum and 210/210 production preconditions: PASS.
- Production HEAD `129d3f090f8b94b982178b1e8f3ec51047278068` with the reviewed 13 modified and
  three untracked paths: matched.
- Database: core 0035, integrity `ok`, zero foreign-key violations.
- HTTP: health 200, login 200, Troubleshooter 404 (not deployed).
- Existing web plus four timers: active. All 15 original containers: `Up`.

## VM2 recovery

- VM2 identity: `csci5840-vm2-dhsu9160`, Ubuntu 24.04, authenticated using the
  already configured SSH key and pinned host keys; no TOFU.
- Preliminary online recovery set:
  `/home/student/nmas-backups/PRE-STAGE-A-20261116T013308Z` on VM1 and the same
  restricted path on VM2. Directory 0700; 12 files mode 0600.
- Recovery-set `SHA256SUMS` digest:
  `6ba0d10c1bffd8b2e3984c6c408e19c461f4022fc1ddbb4caab18e999bf53c7e`.
- SQLite backup and sidecar, source archive and sidecar, release metadata,
  checksum manifest, and restore/rollback instructions are present.
- Disposable restore passed on VM1 and independently on VM2: integrity `ok`,
  zero FK violations, core head 0035. Archive inclusion/exclusion checks passed.
- Encryption: NONE. This is explicitly a preliminary online recovery set, not
  the authoritative stopped-service Stage A backup. Retain until stability and
  explicit deletion approval.

## Engineering added after the frozen package

- Separate successor candidate (not deployed, not yet independently accepted):
  `/home/student/Scripts/nmas-failover-fault-release-20261116T020000Z/package`;
  218 operations (209 ADD, eight REPLACE, one MERGE); entries
  `e808337b913006a2443d48b280dc79781e2e367840411f3098e52f66184e8bea`;
  manifest `2c1924eee55105f30391f073b7eab9b9c6f2f9d2ed7a09c6818653e5e3e04525`;
  tool `3de30cf640d4840b0a294be8ec105f5c142945d6fb16db4959637f0da12965f3`.
- Global singleton agent lease, monotonic fencing, capacity selection,
  watchdog, atomic transfer/pause, checkpoint digest, and stale provider/tool
  rejection are implemented inside the new Troubleshooter schema while the
  migration head remains 0039.
- Codex, ClaudeA, and ClaudeB have distinct completion-only fixed-socket
  adapters. No live provider broker or credential was activated.
- `break.py` implements an exact allowlist, authorization/digest binding,
  dual-stack flow guard, deadline, hidden ground truth, and independent
  rollback. The live driver is deliberately unconfigured.
- The existing Change Engine single-caller contract is preserved. The
  Troubleshooter can propose and hand off an approved Change but cannot call
  the mutating engine directly.

## Verification

- Combined agent, model-adapter, existing AI gateway/runtime, remediation
  governance, sandbox-artifact, and Change Engine contract suites: 143/143 PASS.
- Fault-policy/unit/mock tests: 12/12 PASS.
- Compatibility overlay tool tests: 18/18 PASS.
- Fixture CLI campaign: `ARMED → ACTIVE → RESTORED`; state 0600, directory 0700;
  disposable artifacts removed.
- `makemigrations --check --dry-run`: no changes detected; the plan remains
  exactly core 0036–0039.
- Successor disposable apply and 218/218 postconditions: PASS. Migration
  0035→0039 and reverse 0039→0035: PASS; integrity `ok`, zero FK violations;
  lease table present at 0039 and removed at 0035. Package rollback restored
  218/218 preconditions; disposable artifacts removed.
- These are isolated tests. No live namespace, nftables/NAT, model, device
  write, Containerlab fault, or autonomous remediation was activated.

## Operational disposition

| Milestone | State | Evidence / blocker |
| --- | --- | --- |
| VM2 preliminary recovery | COMPLETED_AND_VERIFIED | Independent hashes and restore passed; unencrypted and online |
| Stage A application deployment | DEPLOYED_AND_VERIFIED | Exact 218-operation package applied; all postconditions and production verification passed in the amended window |
| Database migration 0035→0039 | ACTIVATED_AND_VERIFIED | Production head is 0039; integrity `ok`; zero foreign-key violations |
| Diagnostic/research containment | RESEARCH_READY_FOR_FINAL_AUTHORIZATION (LIVE ROLLED BACK) | Complete 18-file release `c58264ef…144a2c` binds overlay, controller, historical receipt, generated/reviewed policy, service and rollback dependencies and passed three complete cycles. A new exact approval/window is required. Diagnostic remains disabled because no endpoint is admitted |
| Three-agent capacity/failover | IMPLEMENTED_NOT_ACTIVATED | Provider-double tests pass; live brokers/keys/usage approval absent |
| Governed remediation | BLOCKED_APPROVAL | Existing Change page is the sole mutating caller; no autonomous approval exists |
| `break.py` fixture campaign | COMPLETED_AND_VERIFIED | Mock/fixture only |
| Live fault-recovery campaign | BLOCKED_APPROVAL | Requires exact target/fault and live safety approval after activation |

Overall: **STAGE_A_DEPLOYED_AND_VERIFIED — STAGE_B RESEARCH ENGINEERING READY; LATER LIVE STAGES NOT ACTIVATED**.

## Stage B corrected research activation attempt and rollback

The owner authorized change `CHG-NMAS-20261115-STAGE-B-001`, overlay SHA-256
`45a3f5a2c084367d0d8d229580a055e7356265d62742875d72e157d45ebcfc36`,
an immediate 60-minute window beginning at the system-observed authorization
receipt `2026-11-16T12:22:48-07:00`, and personally attested current VM1
vSphere Client Web Console access.

The exact worker runtime, resolver root/receipt, resolver file, IPv4-only
research namespace/veth, two NMAS-owned nftables tables and scoped masquerade
were installed and validated. Root-only service preflight verified the exact
resolver bind, namespace, disabled IPv6 state and reviewed nft policy. At
`2026-11-16T12:24:59.103295-07:00`, the service main process then failed before
execution with `226/NAMESPACE` because the research unit's mandatory
`InaccessiblePaths=` entry named the intentionally absent
`/etc/nmas/troubleshooter-device-worker.env` path.

The authorized stop condition triggered ownership-scoped rollback. Cleanup
completed at `2026-11-16T12:25:33-07:00`. Post-rollback validation found no
research namespace/veth, Stage B nftables table, resolver root, runtime, unit,
policy or environment. Original routes/rules, ens33, nmas-mgmt, SSH, host
forwarding, all eight checked services and all 15 frozen lab containers were
preserved. NMAS `/healthz` and login returned 200, and unauthenticated
Troubleshooter returned the expected login redirect. The complete record is
`stage-b-research-activation-attempt-20261116-dns-integration.md`.

Stage B research is not active. Retry requires a corrected, tested,
content-addressed overlay and a new explicit owner authorization/current
maintenance window. Diagnostic activation, live AI, autonomous device writes
and `break.py` remain disabled.

Disposition: **STAGE_B_RESEARCH_ROLLED_BACK**.

## Stage A 218-operation owner authorization received

Change record: `CHG-NMAS-20261115-STAGE-A-001`.

The NMAS project owner explicitly authorized Stage A in the execution
instruction received for this change record. This authorization is bound only
to the following successor release identity:

- operations: 218 (209 ADD, eight REPLACE, one MERGE);
- entries SHA-256:
  `e808337b913006a2443d48b280dc79781e2e367840411f3098e52f66184e8bea`;
- manifest SHA-256:
  `2c1924eee55105f30391f073b7eab9b9c6f2f9d2ed7a09c6818653e5e3e04525`;
- tool SHA-256:
  `3de30cf640d4840b0a294be8ec105f5c142945d6fb16db4959637f0da12965f3`;
- effective maintenance window: 2026-11-15 22:00–23:00 MST; and
- maximum website interruption: 30 minutes.

The authorized scope is the exact source overlay, the documented database
migration from core 0035 through 0039, the named existing web service and four
importing timers, the authoritative stopped-service database/source recovery
set, transfer to VM2 at `10.224.77.199`, independent disposable restore and
hash/integrity/foreign-key/migration-head verification, and documented rollback
if required. The owner accepts the package-specific sole-owner review exception,
the documented QA/database risks, and temporary unencrypted VM2 recovery
arrangement within the owner's authority. This authorization does not waive an
applicable mandatory external requirement and does not authorize Stage B or
later work, workers, namespaces, firewall/NAT changes, research, live models,
device writes, or fault injection.

Owner-provided signature: **NOT PROVIDED**. Owner-provided authorization
timestamp: **NOT PROVIDED**. No signature or owner timestamp is inferred from
the execution instruction. At the time this entry was added, the approved
window had not begun; this entry records authorization only and is not evidence
that production execution occurred.

### External-requirement applicability finding

The repository's production gates separate Stage A application/database work
from the university/infrastructure approvals required for later service
identities, namespaces, veths, host firewall/NAT, research egress, device
paths, and live runtimes. This Stage A changes none of those externally governed
objects. The existing change record identifies the approver as the authorized
application/database owner for assigned VM1 and records `NONE — authorized
application-owner attestation` for an additional Stage A external approval.
No documented mandatory external approval applicable to this application-only
Stage A remains unresolved. This finding does not satisfy, waive, or alter any
external requirement for Stage B or later stages.

## Immediate Stage A window amendment

The authoritative VM1/NMAS owner amended the previously recorded maintenance
window by explicit execution instruction. The former 2026-11-15 22:00–23:00
MST window is superseded. The system-observed receipt and execution start time
is **2026-11-15 19:43:30 MST (-0700)** and the amended 60-minute window ends at
**2026-11-15 20:43:30 MST (-0700)**. These are operator-observed system times,
not an owner-supplied signature timestamp. Owner-provided signature remains
**NOT PROVIDED** and no signature is inferred.

This amendment changes only the execution time. The exact 218-operation release
identity, 30-minute maximum website interruption, Stage A-only scope, stopped-
service recovery requirements, VM2 target, accepted temporary unencrypted
recovery arrangement, automatic stop/rollback conditions, and all later-stage
exclusions remain unchanged.

## Stage A execution and closeout evidence

System-observed execution completed at **2026-11-15 19:51:17 MST (-0700)**,
inside the amended 19:43:30–20:43:30 MST window.

- Immediate preflight reconfirmed the authorized manifest and tool hashes,
  canonical entries identity, all 218 production preconditions, production
  HEAD `129d3f090f8b94b982178b1e8f3ec51047278068`, the reviewed 13 modified
  and three untracked production paths, DB head 0035, clean integrity/FKs,
  healthy services, VM2 SSH, sufficient capacity, and 15 running containers.
- The four importing timers were stopped and all four one-shots were inactive
  before `nmas-web.service` was stopped. Website interruption ran from
  **19:44:47** through **19:47:34 MST**, **2 minutes 47 seconds**.
- Authoritative stopped-service DB backup:
  `f6e7d9429f30aae6956701908bcd5b74f5b64fbb059712c259881fca2d81e8d8`;
  source archive:
  `f011839c20afe890577fbf20cce75d5de924b3edfaf1b4f213b591c07d9b6a8b`.
  The complete VM1/VM2 recovery-set `SHA256SUMS` digest, including the apply
  journal manifest, is
  `1cb7b2dc8d8ac5228d1f78c48baa10c97d4c3122bbd54f96fb0cbcb2f69cc332`.
- VM2 verified every transfer hash. Its independent disposable database restore
  reproduced the exact DB hash, integrity `ok`, zero foreign-key violations,
  and head 0035. Its independent source restore extracted 1,747 files and
  passed expected inclusion/exclusion checks. Disposable artifacts were removed.
- The package applied exactly 218 operations and the tool verified all 218
  postconditions. The apply journal and nine preserved shared files are
  mode 0600 beneath mode-0700 recovery directories on VM1 and VM2.
- `manage.py check` reported no issues; `makemigrations --check --dry-run`
  reported no changes. The plan contained only core 0036, 0037, 0038 and 0039;
  all four applied successfully. Final head is
  `0039_observation_authorizations`, integrity is `ok`, foreign-key violations
  are zero, and the expected Troubleshooter tables are present.
- Final HTTP: health 200; login 200; unauthenticated Troubleshooter 302 to the
  login page. A nonpersistent in-process authenticated, MFA-marked,
  permission-authorized smoke session rendered the Troubleshooter page with
  status 200. No production role or binding was added; real accounts remain
  fail-closed until separately authorized.
- `nmas-web.service` and all four existing timers are active. Maintenance and
  telemetry one-shots logged successful results; unrelated gNMI, syslog,
  topology and traffic services remained active.
- Containerlab inspection reported all 15 original containers running.
- Non-activation audit found zero Troubleshooter/research/model unit files,
  namespaces, processes, sockets or nftables tables. Readiness admitted zero
  devices and showed all live transport bindings absent. No live model, device
  write, fault injection, host firewall/NAT change, or later-stage activation
  occurred.

The authoritative VM2 recovery set must be preserved until the owner explicitly
authorizes deletion.

## Stage B read-only baseline and disposition

Baseline captured: **2026-11-15 21:04:54 MST (-0700)**. No namespace, veth,
nftables rule, route, address, account, unit, key, service, device session or
database row was created or changed during this review.

- VM1 is `csci5840-vm1-dhsu9160`; the operator is `student` and the existing
  SSH session still terminates on `10.224.77.0:22`. The previously documented
  vSphere Client Web Console check remains the recovery evidence; it was not
  re-exercised and no vSphere, ESXi, vCenter or VM2 endpoint was contacted.
- `ens33` is up at `10.224.77.0/22` with the unchanged IPv4 default via
  `10.224.76.1`. `nmas-mgmt` is up at `192.168.200.100/24` and
  `2001:db8:200::100/64` (plus its existing RA-derived addresses). Host IPv4
  and IPv6 forwarding are already `1`; Stage B proposes no host sysctl change.
- Address, route, rule and link baseline SHA-256 values are respectively
  `2ed8fc68dced4553b276dafa994516ce14aba8b6731685bb3b406620abf160ec`,
  `8e3d422a4dc3efc0fe3a261d2d48751793c4c4ae03acaac6af03becf191813b2`,
  `e16dc40a841f7a7df9d2d4676dfc6ce49976b4290fcae20affe8699ab75a1192`
  and `45df4486e3d267c8bada96e3ac91f905bab2baf88245bb349543a5be7f612ec0`.
  The nftables structural baseline (handles and counters removed) is
  `93a93a5ebc63b952a21186bd08900e95df466ba85e053a8e2c22870e062c70bb`.
  Existing IPv4 `FORWARD` policy is accept; existing IPv6 `FORWARD` policy is
  Docker-managed drop. No `nmas_diagnostic`, `nmas_research`,
  `nmas_host_diagnostic` or `nmas_host_research` table exists.
- Twenty-one existing network namespaces are Containerlab or capability-test
  owned. None is named `nmas-ts-diagnostic` or `nmas-ts-research`; neither
  NMAS worker veth exists. These foreign namespaces and veths are not NMAS
  resources and must not be adopted or removed.
- `nmas-web`, gNMI collection, syslog ingestion, topology, traffic socket and
  the four existing timers are active. Health and login return 200,
  unauthenticated Troubleshooter returns the expected login redirect, and the
  previously accepted nonpersistent authenticated Troubleshooter smoke remains
  the Stage A evidence. All 15 `clab-srlceos01-*` containers are running.
- Production remains at `core.0039_observation_authorizations`; SQLite
  integrity is `ok` and the foreign-key violation count is zero. There are zero
  `ManagementPath`, `ManagementPathProbe`, `ObservationAuthorization`,
  `TsCase` and `TsAiHandoff` rows. Readiness admits no device and has no live
  transport binding.
- The deployed namespace controller and launcher exactly match both the
  development source and the 218-operation payload. The supported commands are
  the documented independent `preflight`, `activate`, `validate` and
  namespace-specific `rollback` actions; the retired combined helper remains
  prohibited.

Stage B is **BLOCKED BEFORE OWNER ACTIVATION APPROVAL**. An exact approvable
activation plan cannot yet be rendered because there is no approved diagnostic
`ManagementPath`; no approved research resolver, hostname set, institutional
public protected-range set or research NAT/egress approval; and no rendered
root-owned policies/configuration. In addition, the reviewed worker units use
`/opt/nmas/current` and `/opt/nmas/venv`, both absent on VM1, while no reviewed
installer or binding command for those paths exists in the deployed release.
The worker users/groups, IPC keys, units and runtime directories are also
absent. Do not improvise symlinks, rewrite units in production, or activate a
namespace until this deployment-path discrepancy is resolved in development,
the missing governance inputs exist, and the owner is shown one exact forward
and rollback plan for consolidated confirmation.

Disposition: **STAGE_B_BLOCKED — no approved diagnostic target or research
policy inputs, and the deployed release has no reviewed install path for its
worker runtime locations.**

## Stage B research DNS correction and current disposition

Correction evidence date: **2026-11-16 MST**. This section supersedes the
technical blockers in the earlier Stage B baseline while preserving that
baseline as historical evidence. It does not record or authorize a live change.

- The worker runtime plan is valid for 1,964 base files, four content-addressed
  overlay files, 12 distributions and 5,234 dependency files. The corrected
  overlay manifest SHA-256 is
  `c037e81a17e0f31981dd72270f0fd200a48cf8a11612ffe687f490031d39349a`.
  The superseded `45a3f5a2…cfc36` overlay is not reusable. The corrected unit
  SHA-256 is
  `f4aea87ff4cd12fe47e6efa40dc84e579dafecd9a22d213b0ebe3a20682aea89`.
- `/etc/netns` remains absent on the live host. The tested
  `resolver_root.py` installer is the only approved way to create it and its
  root-only ownership receipt; generic directory creation remains prohibited.
- The corrected unit explicitly read-only binds the lifecycle-owned
  `/etc/netns/nmas-ts-research/resolv.conf` over the worker's
  `/etc/resolv.conf`. A root-only startup check verifies the ownership receipt,
  resolver and policy identities/content, actual mount, network namespace and
  IPv6-disabled state before the unprivileged broker starts.
- The systemd 255 mount-namespace correction prefixes all six legitimately
  absent protected targets with `-` in `InaccessiblePaths=`. A real transient
  systemd fixture proved missing-path startup, existing-path inaccessibility,
  network-namespace and read-only resolver-bind coexistence, unrelated-path
  isolation and mandatory-missing-path `226/NAMESPACE` fail-closed behavior.
  Container-runtime sockets, inventory and monitoring remain mandatory
  inaccessible targets. `systemd-analyze security --offline` remains 1.5 OK.
- The namespace controller can prepare and verify the resolver before network
  activation, records its inode/content ownership, and removes it only through
  exact independent rollback.
- The disposable containment suite passed 22 groups, including real
  `getaddrinfo()` over restricted UDP/TCP DNS, hostname-verified TLS/HTTPS,
  missing/wrong/symlink/drift failures, exact TCP/UDP denials, IPv6 containment,
  independent rollback and an unchanged real-host baseline. Focused Django
  research/sandbox/worker tests passed 29/29.
- A disposable install of the exact 1,964-file production source manifest and
  corrected four-file overlay passed full-tree verification, byte comparison
  of every overlay destination and independent uninstall.
- All three current ens33 resolvers returned exactly the five reviewed A
  addresses for the three approved hostnames. Direct hostname-verified TLS
  succeeded to all five literal addresses. No allowlist expansion was made.
- Diagnostic remains unactivated and unactivatable because there are no
  approved `TARGETS`. Live models, autonomous writes and `break.py` remain off.
- Engineering closeout at `2026-11-16T13:04:28-07:00` found no research
  service/process, namespace, veth, nftables table, resolver root, runtime or
  transient fixture object. NMAS health/login returned 200, the established
  SSH session remained present, all eight checked services were active and all
  15 frozen Containerlab containers were running.

The previous maintenance window is expired. The owner must make one new
consolidated decision covering the exact overlay, resolver-root receipt,
systemd bind, worker identities, research DNS/HTTPS/nft/NAT policy and
independent rollback, while supplying a current window and confirmed console
recovery. No privileged Stage B filesystem, network or service mutation was
performed during this correction.

Disposition: **STAGE_B_RESEARCH_READY_FOR_FINAL_AUTHORIZATION**. The reviewed
generation-aware correction now starts a new resolver-before-network cycle
only after proving the prior generation is terminal and resource-free. Exact
historical receipt bytes are archived, never rewritten as the new generation.

## Four-workstream master execution update — 2026-11-16 14:50 MST

This update records development and read-only production evidence. It does not
reuse either expired Stage B maintenance window and does not authorize a live
host-network, device-admission, provider-broker or Change Engine execution.

### Research lifecycle correction

- New overlay manifest:
  `worker-overlay-manifest.json.generation-review`, SHA-256
  `f56dfc5c2ed067fc071522a6755e269cbe6f969f452369a3e8ae10294a37f21b`.
  Both `45a3f5a2…cfc36` and `c037e81a…39349a` are obsolete.
- Updated controller SHA-256:
  `0a87da4cfa65bbeb6073dec52d34ecdaa62e694fd7512046ba1aa0029f90d5a7`.
  The reviewed service, research broker and worker hashes are unchanged.
- Each attempt receives a random 128-bit generation. A new attempt requires a
  terminal receipt with no pending/owned state and no residual resolver,
  namespace, veth or nftables object. The old root-only receipt is archived by
  exact bytes before a clean receipt is created; generation markers and
  recorded inode/device identities prevent old cleanup authority from matching
  current resources.
- Atomic fsync/rename receipt writes, no-follow checks, per-kind `flock`,
  idempotent rollback and partial-cleanup refusal are enforced.
- The namespace suite passed 32 groups. Three consecutive generations each
  completed restricted network activation, real transient-systemd startup,
  actual `getaddrinfo()`, hostname-verified TLS, denials and rollback. Fault
  cases covered stale flags, partial rollback, foreign collisions, concurrent
  attempts, interrupted receipt writes, resolver inode/symlink replacement,
  mismatched generations and host drift. The exact live schema-v2 rollback
  receipt shape also completed a schema-v3 retry and remained byte-preserved
  in history. The real-host network/SSH/namespace baseline was unchanged.
- The exact 1,964-file Stage A source plus four-file overlay installed into a
  disposable runtime, verified 5,234 dependency files, returned
  `already-installed` on repeat, matched every overlay destination byte for
  byte, and uninstalled twice without residue.
- Resolver-root, real systemd optional/mandatory `InaccessiblePaths`, proposal,
  inventory and installer suites passed. Combined focused Django research,
  worker, admission, orchestration, deterministic-engine, governance and
  Change Engine suites passed 321/321.

### Diagnostic admission state

The read-only production audit still reports migration
`0039_observation_authorizations`, zero NMAS management attachments, zero
device MANAGEMENT attachments, zero ManagementPaths and zero observation
authorizations. R2 is `IN_SERVICE/UNVERIFIED/LEGACY_PREEXISTING` with no pin;
R1 and S1–S4 are not adopted. The six reviewed SSH endpoints therefore remain
candidates, not approved `TARGETS`. The deployed Stage A inventory also lacks
the development-only management attachment provenance fields. No identity,
attachment, host key, path or target was manufactured, and diagnostic remains
inactive.

### Three-agent orchestration state

Codex and Claude command-line logins are currently authenticated, but that is
not a production worker boundary. The repository contains the three fixed
completion-only client adapters and the globally fenced orchestration logic,
but deliberately contains no separately owned provider-broker implementation,
service, IPC keys or sockets. Production has zero global lease and case rows.
Bounded developer-only connectivity probes succeeded for Codex in an empty
read-only ephemeral sandbox and for Claude in restricted, safe, no-tools,
nonpersistent mode. No NMAS or device evidence was supplied. These probes
establish account/provider reachability only; they do not establish the
Codex/ClaudeA/ClaudeB production identities or broker containment.
Provider-double tests prove monotonic fencing, checkpoints, Codex→ClaudeA→
ClaudeB transfer, stale-owner rejection, in-flight safety, safe pause and
cooldown recovery; live provider connectivity and broker containment are not
claimed.

### Governed remediation state

The Troubleshooter remains proposal-only. The existing public Change Engine
execution POST view is its sole mutating caller; `ChangeEngineExecutor.apply`
refuses `EXECUTION_VIA_CHANGE_WORKFLOW`, and model self-approval is rejected.
Fixture tests cover approval, eligibility, device locks, idempotency,
pre/postchecks, rollback/compensation, traffic guard and sustained verification.
No live plan can be authorized or executed without an eligible admitted
ManagementPath and an independent human Change approval. Production has zero
cases and remediation plans, and no device write occurred.

Master disposition: **NMAS_V2_PARTIALLY_COMPLETE**. Research engineering is
ready for one new exact activation decision. Diagnostic activation is blocked
by legitimate admission records and separated human decisions; live
three-agent activation is blocked by the absent separately owned completion
broker/keys; governed live remediation is blocked by both diagnostic admission
and an actual human-approved Change. Production Stage A remains unchanged.

Read-only closeout at `2026-11-16T14:51:58-07:00` found `ens33` and
`nmas-mgmt` up with their existing addresses/routes, an established SSH
session, no research/diagnostic namespace or worker runtime, and both worker
units inactive. The preserved live receipt is root-owned mode 0600, schema v2,
`status=rollback`, with no ownership flags. NMAS `/healthz` and login returned
200 on its actual Gunicorn loopback endpoint; unauthenticated Troubleshooter
returned the expected 302 login redirect. Database migration remained 0039,
integrity was `ok` and foreign-key violations were zero. The checked NMAS and
monitoring services were active and all 15 original `clab-srlceos01-*`
containers remained `Up`. No `nmas_research`, `nmas_host_research`,
`nmas_diagnostic` or `nmas_host_diagnostic` nftables table existed.

All three reviewed resolver candidates still returned exactly the five
approved IPv4 addresses. Direct TLS hostname verification succeeded for every
address (HTTP 302/301/200 according to the site); no DNS or HTTPS destination
was added.

## Stage B generation-overlay activation attempt — 2026-11-16 17:32 MST

The owner approved overlay `f56dfc5c2ed067fc071522a6755e269cbe6f969f452369a3e8ae10294a37f21b`
and controller `0a87da4cfa65bbeb6073dec52d34ecdaa62e694fd7512046ba1aa0029f90d5a7`
for a 60-minute research-only window and attested current vSphere console
access. Preflight matched both hashes, the reviewed DNS/HTTPS policy and the
host baseline. NMAS returned health/login HTTP 200, SSH was established, and
all 15 original Containerlab containers were `Up`.

The exact runtime installed and verified idempotently. The resolver root,
locked identities, root-only configuration, nft policy, systemd unit and
installation receipt were installed. Before resolver or network creation,
`prepare-resolver` refused with `state ownership mismatch for config_digest`.
The schema-v3 controller had compared its schema-inclusive digest directly to
the authentic preserved schema-v2 rollback receipt. The earlier synthetic
legacy regression had relabelled a v3 receipt without recomputing its v2
digest and therefore did not reproduce production bytes.

The attempt stopped immediately and ran ownership-scoped rollback. No resolver
file, namespace, veth or nftables table had been created. The resolver root,
five installed files and runtime were removed only after their receipts,
hashes, modes and inode identities matched. The historical schema-v2 receipt
remains root-owned mode 0600, byte-unchanged, terminal and ownership-free.
At 17:36 MST every captured address/link/route/rule/nftables/SSH baseline hash
matched preflight. NMAS health/login, checked services, SSH and all 15
containers remained healthy. Disposition: **STAGE_B_RESEARCH_ROLLED_BACK**.

The lifecycle now computes the exact digest for every explicitly supported
legacy receipt schema while retaining exact comparison of namespace,
activation ID, policy, approvals, resolver and destination fields. The live
receipt digest `d0ce9ede30c97bc8b2f98e57005d5b86eb32a56157773b62b50e5c353f420290`
matched the independently recomputed v2 digest and differs from the v3 digest
`fd0198911915325ec997ea18ae6fac7642f24a054cba7bbabc4a3fa80049a86a`.

Replacement release identity:

- overlay `worker-overlay-manifest.json.legacy-receipt-review`, SHA-256
  `ecbfc3687bbe0c1ac7565fc6489a577f3517b5598fb9ae286306d1fa40b40430`;
- controller SHA-256
  `fd375d3cc4b86cca7a8d888745122a682999ab369d501a98b543d67009a992b8`;
- the service, research broker, worker, resolver-root and network policy bytes
  are unchanged; overlay `f56dfc5c…37f21b` is obsolete.

Validation completed at 17:44 MST: all 32 disposable lifecycle groups passed,
including real systemd, actual `getaddrinfo()`, hostname-verified TLS, three
distinct generations, exact v2-to-v3 retry, concurrency, partial rollback,
interrupted writes, inode/symlink/foreign-object drift, denials and real-host
baseline preservation. Resolver-root, runtime, proposal, inventory and real
systemd mount suites passed; 46 focused Django research/deployment/sandbox
tests passed. The exact 1,964-source/four-overlay/5,234-dependency runtime
installed, verified, returned `already-installed`, matched all four installed
files byte-for-byte, and uninstalled without an owned runtime residue.

Current disposition: **STAGE_B_RESEARCH_READY_FOR_FINAL_AUTHORIZATION** for
the replacement hash only. It is not live, and the expired approval for the
changed controller is not reused.

## Stage B corrected-controller retry — 2026-11-16 17:54 MST

The owner authorized overlay `ecbfc3687bbe0c1ac7565fc6489a577f3517b5598fb9ae286306d1fa40b40430`
and controller `fd375d3cc4b86cca7a8d888745122a682999ab369d501a98b543d67009a992b8`
for a research-only 60-minute window and attested current vSphere console
access. Both hashes, the Stage A source manifest, lock, resolver-root tool and
research nft policy matched. All nine approved resolver/name combinations
returned exactly the five reviewed IPv4 addresses, and hostname-verified TLS
succeeded directly to all five.

The mandatory read-only compatibility preflight ran the exact new controller
against `/var/lib/nmas-ts-namespaces/research.json`. It authenticated the real
v2 digest `d0ce9ede…f420290`, proved terminal resource absence, and left the
receipt's inode, mtime and SHA-256 `ed105dee…b1302e` unchanged. Runtime and
resolver-root installation, locked identities, systemd verification and the
five-file root-only installation receipt then passed. Resolver generation
`7dd17cca64aa7dec84025e964bf2e61c` prepared successfully with the exact three
nameserver lines; controller preflight passed with zero mutations.

The required reviewed-host-policy diff then stopped the activation. All
network rules and destination sets matched, but the review artifact's comment
still used obsolete v2 marker `d0ce9ede30c97bc8`; the authorized controller
correctly generated v3 marker `fd0198911915325e`. No namespace, veth, nftables
table, NAT rule or service process had been created.

Ownership-scoped rollback completed at `2026-11-16T17:57:36-07:00`. It removed
the prepared resolver generation, resolver root, five receipt-matched files
and exact runtime. The current v3 receipt is root-owned mode 0600,
`status=rollback`, with no ownership flags. At 17:58 MST every normalized
address, link, IPv4/IPv6 route, rule, nftables, forwarding, SSH and foreign
namespace baseline hash matched preflight. NMAS health/login returned 200,
Troubleshooter returned its expected 302, SSH remained established, checked
services were active, and all 15 original containers remained `Up`.

The development-only review artifact is corrected to marker
`fd0198911915325e`, SHA-256
`7a1ba4249d09b896ddaedd9b3d111992925338230bdee7655ca0924d8382d0e4`,
and now byte-matches the controller's generated policy. It was not used for a
second live attempt. Disposition: **STAGE_B_RESEARCH_ROLLED_BACK**.

## Five-workstream integration closeout — 2026-11-16 18:11 MST

### Research release

Complete activation release
`deploy/sandbox/stage-b/research-activation-release.json`, SHA-256
`c58264ef3f0493d9f2009a8d864f78dd85749417a1da7cf62f6db1bfdb144a2c`,
binds 18 exact files: source/overlay manifests, lock, controller, lifecycle
wrapper, resolver-root tool, service/sysusers/environment templates, namespace
configuration, namespace and host nftables policies, destination map, broker
implementation, validator and the exact observed schema-v2 rollback receipt.
Its validator recomputes the production v3 digest with the actual controller,
authenticates the exact v2 digest, generates the host policy and requires a
byte-for-byte match. An internally rehashed stale v2-marker artifact is now a
regression test and fails closed.

The complete release validator and installer/resolver/systemd suites passed.
The 32-group disposable containment suite then passed all three activation and
rollback generations with real transient systemd, actual DNS/getaddrinfo(),
hostname-verified TLS, unauthorized TCP/UDP/private/IPv6 denial, resolver bind,
credential/Docker isolation, historical receipt migration, concurrency, crash,
inode/symlink/foreign-object faults and unchanged real-host baseline. Research
is not installed or active; live activation requires approval of the complete
release hash and a current window.

### Diagnostic admission

The current immutable production database still has zero ManagementPaths,
zero approved/verified NMAS attachments and zero ObservationAuthorizations.
The eligibility report returns no approved endpoint. R2 remains unverified
with no enrolled host key; R1 and S1-S4 remain unadopted. The six exact
candidate endpoints responded to read-only SSH key exchange and their current
Ed25519 fingerprints match the recorded candidate batch, but discovery is not
trust enrollment. Production inventory also lacks the authoritative upstream
attachment fields required to construct truthful paths. Registration/path
requesters must differ from attachment/path approvers, an ObservationAuthorization
approver must differ from its requester, and the authenticated-session evidence
collector must differ from the identity verifier. No actor was fabricated and
diagnostic `TARGETS` remains empty.

### Orchestration, remediation and fault injection

Production source byte-matches the implemented global lease/fencing,
completion-only model adapters, Change Engine governance and fault controller.
There are zero production cases, handoffs, global leases and remediation plans.
There is no production Codex/Claude broker unit, fixed model socket, separately
owned credential or provider egress configuration. User-session Codex/Claude
sockets were observed but are explicitly not production credentials and were
not accessed or repurposed.

A combined 338-test Django run passed research, typed workers, admission,
observation evidence, three-agent capacity/fencing/checkpoint/failover,
completion-only adapters, deterministic runbooks, AI containment, Change
Engine governance, rollback/verification and fault-injection controls. Django
system checks and migration drift checks passed. The fixture-only `break.py`
campaign independently completed `ARMED -> ACTIVE -> RESTORED`, used mode-0600
state, and removed all fixture artifacts. No live model, device write, fault or
remediation was activated.

One final serial regression of every `test_troubleshooting_*.py` module then
ran 805 tests in 277.774 seconds: **OK**, with a clean Django system check and
test database teardown. This includes the full case/runtime/reporting surface
in addition to the focused security and governance set above.

### Production closeout

Database migration remains `0039_observation_authorizations`, integrity is
`ok`, and foreign-key violations are zero. NMAS health/login returned 200,
Troubleshooter returned its expected unauthenticated 302, SSH remained
established, monitored services and Docker were active, and all 15 original
containers remained `Up`. No research/diagnostic namespace, resolver root,
runtime or NMAS-owned nftables table exists.

Overall disposition: **NMAS_V2_PARTIALLY_COMPLETE**. Research is the only
independently executable live activation and awaits approval of release
`c58264ef…144a2c`. Diagnostic requires separated governed admission records;
live orchestration requires separately provisioned production provider
credentials/brokers; remediation requires an admitted path and independent
Change approval; a live fault campaign requires an exact separately approved
target/fault/rollback/protected-flow bundle.

## Operator website integration and final source successor — 2026-11-16 18:55 MST

The production website now exposes the real evidence-first Troubleshooter at
`http://localhost:8001/troubleshooting/`. Automation lists Troubleshooting as
an implemented section and the legacy `/automation/troubleshooting/` path
redirects once to that page. The stale disabled placeholder is no longer the
operator path.

The supported role-grant command assigned `dhruv` exactly `ts-admin` and
`ts-tenant:default`; it did not make the account a superuser and did not grant
an NMAS action permission. The account remains active/staff/non-superuser,
website MFA remains required and has a confirmed authenticator, and the
default principal resolver returns role `admin` in tenant `default`. Existing
NMAS Approver/Executor/Security Admin groups predated this grant and were not
manufactured or re-labelled. An audited console role-grant event was recorded.

The live dashboard shows the actual diagnostic/research worker sockets, exact
ManagementPath eligibility count, Codex/ClaudeA/ClaudeB fixed socket state and
global lease owner/fence. Case detail exposes the evidence timeline,
deterministic results, hypotheses, AI handoffs/checkpoints, remediation and
Change status, verification, report/export and historical case state. Its
read-only diagnostic button calls the same admitted runtime as the API and
returns the real refusal instead of claiming a run when the backend is absent.

Intake now presents authoritative device choices from NMAS's shared resolver,
labels each lifecycle/path prerequisite, and presents the tracked inter-device
links. Arbitrary posted device/link values are refused; selecting a link adds
both endpoints to the persisted scope. Live production currently shows 14
managed-device choices and 18 tracked links, with zero marked diagnostic-ready
because there is still no ACTIVE, HEALTHY, approved ManagementPath.

Production view/API tests passed 21/21. The complete serial production
`test_troubleshooting_*.py` regression then passed **806/806** in 285.974
seconds with no system-check issue. `/healthz` returned 200, the login page
returned 200, anonymous Troubleshooter access redirected to login, and a
credential-free POST was rejected 403 by CSRF. Session HttpOnly and SameSite
Lax remain enabled. No password, MFA secret, cookie or session token was read.
Consequently, the final human browser step (password login, normal MFA and
visual click-through as `dhruv`) remains an operator action and is not falsely
claimed as executed by this record.

Recovery points are
`/home/student/nmas-backups/CHG-NMAS-20261116-FINAL-WEB-001` (stopped-service
database/source) and `CHG-NMAS-20261116-FINAL-WEB-002` (incremental intake
source). Database migration remains 0039, integrity is `ok`, foreign-key
violations are zero, `nmas-web.service` and the real NMAS timers/services are
active, and all 15 original topology containers remain running.

The exact post-website production tree is now bound by source manifest
`1d5e4934a6ddaca72dfc1a98f0b054c1b21d5f66ad7c85c4a629e9265ecefba9`
(1,957 files). Final research release COMPLETE-09 is
`05ce9cc1675fd6c8f1e3cc10add910c891ffe0e3d6dd696f6f36f692df696bad`:
18 files, overlay `ecbfc368…b40430`, controller `fd375d3…92b8`, host policy
`7a1ba424…2d0e4`, four overlay files and 5,234 dependency files. Release,
installer, resolver and systemd tests passed, and the install plan reports zero
source mutations. It supersedes `c58264ef…144a2c` and `abcdcb92…d2aa`.

Research remains inactive pending a current operator attestation that VM1's
vSphere/web console is usable and explicit acceptance of COMPLETE-09 in the
current window. Diagnostic remains governance-blocked by separated identity,
attachment, ManagementPath and ObservationAuthorization decisions. Live
Codex/ClaudeA/ClaudeB calls remain credential-blocked because there is no
separately owned completion broker/key; developer CLI sessions were not used.
The Change Engine remains the only writer, and the fixture-only `break.py`
campaign remains the only authorized fault test.

Current disposition: **NMAS_V2_PARTIALLY_COMPLETE**.

### Managed port-8001 cutover — 2026-11-16 19:09 MST

Final listener inspection found that the owner-facing port 8001 was still an
unmanaged Django `runserver` process group started on 2026-09-28, bound to
`0.0.0.0` with `DJANGO_DEBUG=true`. The hardened `nmas-web.service` Gunicorn
instance was correctly running on loopback port 8002 behind Apache, but the
documented 8001 URL bypassed it.

The four root-owned Apache/Gunicorn/unit files were backed up mode 0600 under
`CHG-NMAS-20261116-FINAL-WEB-002`. Only the resolved runserver process group
was terminated. The established idempotent `install_web_stack.sh` mechanism
then rendered the local Apache vhost with
`--local-listen 127.0.0.1:8001 --skip-apt`; no package or secret was changed.
The cutover completed in nine seconds.

Final listeners are Apache `127.0.0.1:8001`, Apache tunnel origin
`127.0.0.1:8081`, and Gunicorn backend `127.0.0.1:8002`. There is no
`runserver` or wildcard port-8001 listener. Health is 200 through all three
paths, login is 200 through 8001, anonymous Troubleshooter access redirects to
login, Apache configtest passes, and both Apache and `nmas-web.service` are
active. The former port-80 local listener was intentionally replaced by the
owner-specified port 8001; the reviewed design has one local vhost and one
tunnel vhost, not an extra compatibility listener. The source/release manifest
remained exact after `collectstatic`.


## Remaining-deployment execution — 2026-11-16 19:29–20:00 MST

This section records what was built, tested and deployed in this window, and what is still inactive. Fixture and
provider-double results are labelled as such and are not live evidence.

### Defects found and corrected

| Defect | Evidence | Correction and regression |
| --- | --- | --- |
| No server existed behind the three fixed model sockets | `model_provider` had client adapters only | `model_broker.py` plus `model_backend_anthropic.py` / `model_backend_openai.py`; `test_troubleshooting_model_broker` |
| The global lease was never bound to a continuation; a leased handoff would have been refused `STALE_EXECUTION_LEASE` because `continue_handoff` built `ai.Runtime` without the fence | `agent_orchestrator` had no caller outside tests | `agent_dispatch.py`, `continue_handoff(fencing_token=, lease_validator=)`, `agent_orchestrator.release`, `troubleshooting_ai dispatch|agents`; `test_troubleshooting_agent_dispatch` |
| Provider usage stored as `input_tokens` / `output_tokens` was rejected by the stored-secret policy, so every completion that reported usage failed its checkpoint write | Reproduced through the real socket path: `TsAIHandoff.checkpoint key 'input_tokens' looks like a secret` | Broker reports `input_units` / `output_units`; asserted against `secret_policy` |
| The operator page had no escalation action and printed an always-empty authorization column (`it.authorization`) | Template and view inspection | `POST /troubleshooting/<case>/ai/escalate/`, `access_decision`, lease/model facts per handoff, lease history and campaign panel; view tests |
| Readiness told operators that no identity-observation producer exists for adopted devices, although `device_observe` is deployed | `troubleshooting_readiness --with-nmas-providers` for R2 | `IDENTITY_NO_PRODUCER` now names the deployed workflow and is owned by the operator; `test_RDY04` |
| The dispatch unit would have failed `226/NAMESPACE` on legitimately absent worker paths, the same class as the 12:24 MST research failure | Unit review | Optional (`-`) protected paths in `nmas-troubleshooter-dispatch@.service.in`; `ModelBrokerArtifactTests` |

### Verification

- Development regression: every `test_troubleshooting_*` module plus architecture, contract, identity-access,
  deploy-binding and management-entrypoint suites, **921/921** in 353 s. Migration drift check: no changes.
- Three-agent failover over three real authenticated broker sockets (provider behind each broker is a scripted double):
  Codex quota exhaustion mid-task → ClaudeA rate limit → ClaudeB completion with exactly one diagnostic execution;
  context exhaustion; provider refusal; broker crash before and during a task; all agents unavailable → `PAUSED` with
  the handoff OPEN and no tool authority, then recovery after a dispatcher/broker restart from the durable checkpoint;
  busy lease; watchdog stall transfer with the stale owner's completion discarded and tool request refused; invalid
  model output spending retry budget without failover; wrong IPC key. Fences are strictly monotonic.
- Provider SDK surface checked against the real packages (`anthropic` 2.9.0, `openai` 3.52.0) in a scratch environment;
  an unroutable endpoint maps to `PROVIDER_UNREACHABLE`. The hash-pinned lock installs with `--require-hashes`.
  **No live provider completion was made**: no production provider credential exists.
- Broker containment on real systemd (transient unit, exact address policy): lab device, loopback service,
  Containerlab gateway and host management address unreachable; Docker socket and web environment unreadable; IPv6
  socket refused; hostname-verified TLS to both provider API hosts established. `systemd-analyze security`: 1.8 OK.
- Research lifecycle suite re-run against the unchanged controller `fd375d3…92b8`: all groups passed, including three
  consecutive generations with real transient systemd, `getaddrinfo()`, hostname-verified TLS, denials, the exact
  schema-v2 receipt migration and an unchanged real-host baseline. (A first invocation as root failed one negative case;
  the suite is documented to run as the unprivileged operator, where the "unsafe resolver root" fixture is meaningful.)
- All nine resolver/hostname combinations still return exactly the five approved IPv4 addresses.

### Production change `CHG-NMAS-20261116-FINAL-WEB-003`

Source-only, additive, no migration, no worker, namespace, firewall or credential change. Fourteen files added and
fourteen changed; recovery point `/home/student/nmas-backups/CHG-NMAS-20261116-FINAL-WEB-003` (replaced sources, online
database backup with integrity `ok`, list of added files, previous manifests). In the production tree: system check
clean, no migration drift, 215/217 of the affected suites pass; the two failures are the existing
`ExecutionBoundaryContractTests` findings for `frr_isolation`, a module this change does not touch. `nmas-web` was
reloaded; `/healthz` 200, login 200, anonymous Troubleshooter 302, unauthenticated escalation POST 403. A non-persistent
in-process render as `dhruv` returned the dashboard with the real state: zero eligible paths, three broker sockets
absent, "AI escalation is blocked" with its prerequisite, an empty lease history and no fault campaign. An anonymous
caller and `nmas-demo-operator` (no `ts-*` role) received 403. Database integrity `ok`, zero foreign-key violations,
migration 0039, all 15 original containers `Up`, no NMAS worker namespace or nftables table.

Research release after this change: `research-activation-release.json` COMPLETE-10, SHA-256
`bbb0da54a5bbc0196ebd3db809dbb11e7820b5e5285ac23359e3bf85e9c56057`; source manifest
`5093674fec9064d4e287c103a9acfdc81d1e7df2288bbe2549581827f74e818b` (1,971 files); overlay `ecbfc368…b40430`, controller
`fd375d3…92b8` and host policy `7a1ba424…2d0e4` unchanged. Validator, installer, proposal and inventory suites pass and
the install plan reports zero mutations. `05ce9cc1…696bad` and `c58264ef…144a2c` are superseded.

### Diagnostic admission evidence

R2's device-side Ed25519 host key was read through the container-host administrator channel
(`show management ssh hostkey ed25519 public`, read-only) and stored mode 0600 at
`/home/student/nmas-evidence/host-keys/R2-hostkey.json` (SHA-256 `d92ec3d9…8e28e1`, collector
`claude-code-automation`, ticket `CHG-NMAS-20261116-DIAG-R2-001`). Its computed pin
`SHA256:OyuxmXszJ9liLZjlWuKOvoKhGCxuryrmLDf0GIB4dtk` equals the key the device presents on 192.168.200.2. This is
evidence for an enroller who is not the collector; no pin was enrolled, no path registered, no identity verified and no
observation authorized. Production still has zero ManagementPaths and `TARGETS` remains empty.

### Component state

| Component | State | Proof / blocker |
| --- | --- | --- |
| Website | DEPLOYED, operator login not exercised | Real pages rendered in-process as `dhruv`; password + MFA login is an operator action |
| Case management | DEPLOYED, zero production cases | Create/history paths covered by production view tests; no case fabricated |
| Research | DEPLOYED_INACTIVE → BLOCKED_APPROVAL | COMPLETE-10 validated; needs the exact owner decision, window and console attestation |
| Diagnostics | BLOCKED_APPROVAL | R2 evidence captured; separated enrollment, attachment, path, observation and identity decisions outstanding |
| Codex / ClaudeA / ClaudeB | BLOCKED_CREDENTIALS | Brokers, units and lock deployed in source and FIXTURE_VERIFIED; no provider credential exists |
| Failover | FIXTURE_VERIFIED | Real sockets, scripted providers; no live handoff has run |
| Remediation | FIXTURE_VERIFIED, BLOCKED_APPROVAL | Change Engine remains the only writer; needs an admitted path and a human-approved Change |
| `break.py` | FIXTURE_VERIFIED | Live campaign not authorized; none listed on the website |
| Infrastructure | LIVE_AND_VERIFIED | NMAS, SSH, Docker, database and all 15 containers healthy at 19:58 MST |

Disposition: **NMAS_V2_PARTIALLY_COMPLETE**.

## Research activation and follow-on work — 2026-11-16 20:09–20:30 MST

The owner approved, interactively in this session, live activation of release COMPLETE-10
(`bbb0da54a5bbc0196ebd3db809dbb11e7820b5e5285ac23359e3bf85e9c56057`) for a 60-minute window from 20:09 MST and
confirmed working VM1 vSphere console access. No owner signature or timestamp beyond that answer is inferred. All
privileged research steps ran between 20:10:16 and 20:12:50, inside the window. Evidence and rollback authority:
`/home/student/nmas-backups/CHG-NMAS-20261115-STAGE-B-001-ACTIVATION-20261116T201043`.

### Research: LIVE_AND_VERIFIED

- Release graph valid; runtime installed and verified (1,971 source files, four overlay files); resolver root created
  with its 0600 receipt; four configuration files installed with foreign-object stop gates and a 0600 installation
  receipt (`/var/lib/nmas-stage-b-install-receipt.json`); resolver generation `9280c342e9fbf89bca12ccf2191097f7` prepared
  with exactly the three approved nameservers; controller preflight zero mutations; generated host policy byte-identical
  to the reviewed artifact; `activate` and `validate` succeeded.
- **Deviation, recorded:** the installer left the owned runtime root `/opt/nmas` at mode 0700 (it renames a `mkdtemp`
  staging directory), so `User=nmas-research` could not traverse to its interpreter. Found before any network change.
  Corrected with `chmod 0755 /opt/nmas`; no approved artifact changed and runtime `verify` still passes. The installer is
  fixed for future installs with a regression in `test_worker_runtime.py`; the development release file is rebound as
  COMPLETE-11 (`7cb1fade…fd489`, only `worker_runtime.py` differs). COMPLETE-10 remains the live rollback authority and its
  exact manifests are preserved under `rollback-authority/` in the evidence directory.
- `nmas-research-broker.service` started at 20:12:50; `ExecStartPre` and the main process succeeded, zero restarts.
  Main process: UID/GID 973, groups 973 and 976 only, all five capability sets empty, `NoNewPrivs` 1, seccomp filter.
  Its network namespace is the named `nmas-ts-research` namespace and differs from the host's. Inside the unit,
  `/etc/resolv.conf` resolves to the lifecycle resolver inode with the expected SHA-256. Docker and containerd sockets,
  inventory and the monitoring tree are inaccessible. The namespace has one IPv4 `/30`, a single default route, no IPv6
  route and IPv6 disabled.
- Through the running worker, authenticated as `nmas-ts-runtime`: `docs.frrouting.org` 200 (12,368 bytes),
  `www.arista.com` 200, `www.rfc-editor.org` 200 (`robots.txt`, and RFC 5880 at 110,279 bytes); a 450 KB RFC is refused
  `RESPONSE_TOO_LARGE` by the 262,144-byte cap. Refused: unapproved host, plain HTTP, alternate port, lab device, VM2,
  loopback, IPv6 literal, veth gateway, `file:` and a userinfo-smuggled URL. Each decision is in the worker audit log.
- Raw sockets from inside the worker namespace as the unprivileged worker UID: approved HTTPS and approved resolver
  UDP/TCP 53 connect; wrong ports on approved addresses, an unapproved public address, an unapproved resolver, the
  resolver on 443, R2, the NMAS management address, the Containerlab gateway, VM1 `ens33`, VM2, the campus gateway, the
  veth gateway on 22 and 8001, and IPv6 all fail.
- Host baseline after activation: rules, forwarding sysctls, sshd configuration, service states and all 15 containers
  unchanged; address, link, route, nftables and namespace lists differ only by added NMAS-owned objects
  (`nmas-ts-resh0`, its `/30`, `nmas_host_research`, `nmas-ts-research`); no line was removed. SSH stayed established;
  `/healthz` and login 200; R2 and the campus gateway still answer ping from VM1.
- The unit is disabled and the namespace is not persistent, so a reboot leaves research inactive until re-activated.

### Website

The unprivileged web process cannot see into the workers' private socket directories and would have shown the running
worker as `STATUS_UNAVAILABLE`. The dashboard now reports systemd's unit state for the fixed worker and broker units
(`CHG-NMAS-20261116-FINAL-WEB-004`); in production it reports research `ACTIVE`, diagnostic and the three brokers
`INACTIVE`. `CHG-NMAS-20261116-FINAL-WEB-005` synced the broker entry-point fix and `break.py` live mode.

### Model brokers: DEPLOYED_INACTIVE, BLOCKED_CREDENTIALS

Installed: three locked nologin accounts, `/run/nmas-ts-model` (1770 root:nmas-ts-model-ipc), a hash-pinned SDK
environment and an eight-file broker code tree under `/opt/nmas-model` (receipt
`/var/lib/nmas-model-install-receipt.json`), the unit, and three `root:<broker> 0640` environment files with distinct
IPC keys and an empty credential slot. The ClaudeA broker was started without a credential on the real unit: health over
the authenticated socket reported `credential_configured: false`, `authenticated: false`, `restricted_interface: true`;
a completion returned `AUTHENTICATION_UNAVAILABLE`. As the broker UID inside the unit, the worker runtime, `/home`, every
other NMAS environment file (including its own) and the Docker socket were unreadable. It was stopped again.
**Defect found by this live start:** run as `python -m`, the broker module loaded twice, so backend errors did not
match the handler and surfaced as `WORKER_INTERNAL_ERROR`; fixed, with `EntryPointTests`. No provider call has been made.
Not yet done: the runtime-side client environment and dispatch unit installation, and write access for
`nmas-ts-runtime` to the production database, which the dispatch unit needs and which has not been exercised live.

### R2 admission: requester side complete, BLOCKED_APPROVAL

NMAS has no sole-owner exception: every approval path refuses the requester. That restriction was preserved. As `dhruv`,
on the owner's instruction: host-key evidence validated (`host_key_pin_check`, enroller `dhruv`, pin
`SHA256:OyuxmXszJ9liLZjlWuKOvoKhGCxuryrmLDf0GIB4dtk`, no registered conflict); `mgmt_swt` adopted as an unverified
legacy device because an attachment's upstream switch must be adopted (this grants no diagnostic access to it); NMAS
attachment `NMA-000001` (`nmas-mgmt` → `mgmt_swt` Ethernet9) registered and observed `VERIFIED`; R2 MANAGEMENT attachment
(Ethernet3 → `mgmt_swt` Ethernet2, access VLAN 200) registered. Both are `PENDING`. Facts were checked against the
topology file, LLDP on `mgmt_swt` and switchport state. A self-approval attempt as `dhruv` was refused
`MGMT_PATH_SELF_APPROVAL` and audited. No path exists, identity is unverified and `TARGETS` is empty.

### break.py

`break.py run|rollback|status` drives the existing controller with a live Containerlab cEOS driver: one interface
administrative shutdown in the running configuration only, original state saved, dual-stack protected-flow guard,
deadline watchdog and verified restore; ground truth stays in the 0600 state file. Covered by scripted-runner tests. No
live fault was injected: the controller requires a verified, write-eligible target with an approved ManagementPath, R2
has neither yet, and no exact interface has been authorized. The Troubleshooter has no automatic trigger; a case is
opened by an operator or by a caller of the cases API.

Disposition: **NMAS_V2_PARTIALLY_COMPLETE** — research live; diagnostics, live AI, governed repair and the live fault
test each wait on the specific owner action listed in the session report.

## Codex-only takeover completion — 2026-11-16 21:01–21:20 MST

### Recovered interrupted state

Claude had completed the source-only production sync and Gunicorn HUP at 21:00:47, created the verified recovery point
`CHG-NMAS-20261116-CODEX-ONLY-006`, installed and started the restricted Codex broker, copied the production source into
`/opt/nmas-dispatch`, and created `/etc/nmas/troubleshooter-ipc-client.env`.  It stopped before installing the dispatch
unit.  The copied critical sources matched development and production.  The research namespace and policy were not
changed.

### Codex completion path: LIVE VERIFIED

The dispatcher unit is installed as `nmas-troubleshooter-dispatch@.service` under `nmas-ts-runtime`, with
`PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, no capabilities, strict filesystem protection, and a bind of
only the live SQLite file.  The runtime has the Codex IPC key but cannot read the broker credential file.  The source
tree is release `CHG-NMAS-20261116-DISPATCH-007-FINAL`: 1,971 files, zero verification mismatches.  A copied
`netbox/.env` was found in the interrupted runtime copy and removed; future worker manifests exclude every `.env`.

Case `TS-20261117-B721557A`, handoff `AIH-0ebe78350202`, ran through the real production unit and completion broker.
Codex `gpt-5.3-codex` made three bounded exchanges: `get_case_summary`, then two governed terminal decisions.  All model
request/response digests and usage units were checkpointed; the reasoning log has three entries.  The handoff ended
`BLOCKED` because no approved R2 diagnostic path or evidence exists.  That is the correct authorization result: allowed
targets remained empty and no device operation or write occurred.  The singleton lease advanced monotonically through
fences 1–4 and returned to `IDLE`.  The dispatcher oneshot exited 0.  ClaudeA and ClaudeB remain masked, inactive and
outside the configured provider pool.

Defects found during activation and corrected with focused regressions: the template referenced the older runtime,
bound the whole production web directory, used systemd `%I` (which unescaped the handoff hyphen to `/`), and the client
environment lacked the complete import surface.  The corrected unit uses `/opt/nmas-dispatch`, `%i`, an exact DB-file
bind, and the minimum additional import dependencies required by Django checks.  Recovery point
`CHG-NMAS-20261116-DISPATCH-007` contains a consistent mode-0600 SQLite backup (`integrity_check=ok`) and root-only
environment backups.

### Final live state

- Website health and login: 200; anonymous Troubleshooter: expected 302.  Django checks and migration drift checks pass;
  migration remains `0039`, database integrity is `ok`, foreign-key violations are zero.
- Website runtime state: admission binding configured; provider pool `[Codex]`; Codex active; both Claude providers
  “Disabled by owner”; diagnostic unavailable because eligible ManagementPaths = 0; lease `IDLE`, fence 4.
- Research: service active with zero restarts; named namespace, `/30`, single default route, IPv6 disabled and the
  existing `nmas_host_research` allowlist intact.
- Frozen `srlceos01` topology: all 15 containers remain running.  No topology lifecycle command or device mutation ran.
- Focused dispatch/broker/sandbox regression: 37 tests OK before activation; final artifact regression: 9 tests OK.
  The previously recorded Codex-only outage/quota/crash/restart suite remains fixture-verified; no paid outage was
  deliberately induced.

Disposition: **NMAS_V2_CODEX_ONLY_OPERATIONAL_AND_VALIDATED** for the Codex production path.  Diagnostic collection,
Change Engine remediation and a live `break.py` campaign remain **BLOCKED_APPROVAL**, not failed: an independent human
must approve the pending R2 attachment/path and observation authorization before those steps can legally proceed.
