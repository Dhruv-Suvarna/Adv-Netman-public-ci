# NMAS V2 bulk topology admission and topology-wide troubleshooting: acceptance report (2026-11-17/18)

Change record: `CHG-NMAS-20261117-BULK-ADMISSION-019`. Evidence: `~/nmas-evidence/bulk-admission-019/` (checkpoint
`state.json`, host-key evidence, attachment edge records, the exception documents, `ceos-escalation-proof.json`,
`admission-matrix.txt`). The backups and pre-change copies are in `~/nmas-backups/CHG-NMAS-20261117-BULK-ADMISSION-019/`.
Secrets are never stored in either location.

Classifications: **LIVE_VERIFIED**, **REPLAY_VERIFIED**, **FIXTURE_VERIFIED**, **DEPLOYED_BUT_UNVERIFIED**,
**BLOCKED_BY_AUTHORIZATION**, **BLOCKED_BY_SAFETY**, **FAILED**.

## 1. Nine-device admission matrix: LIVE_VERIFIED (9/9)

| Device | Platform | Identity (verified host key) | ManagementPath | Attachment | Diagnostic identity | RBAC proof | Worker read |
|---|---|---|---|---|---|---|---|
| R1 | cEOS 4.36.2F | VERIFIED `SHA256:y8B6G1mN…` | MPATH-000004 ACTIVE/HEALTHY | mgmt_swt:Ethernet1 VERIFIED | nmas-diag network-operator/priv 1 | configure denied (also after `enable`) | code=OK cli:interfaces |
| R2 | cEOS | VERIFIED (pre-existing) | MPATH-000001 ACTIVE/HEALTHY | mgmt_swt:Ethernet2 | nmas-diag (new; worker no longer uses `nmas-automation`) | as R1 | OK |
| R3 | Ubuntu 24.04 / FRR 8.4.4 | VERIFIED `SHA256:/M98uBiD…` | MPATH-000008 ACTIVE/HEALTHY (Linux L2/L6 probe) | mgmt_swt:Ethernet3 | nmas-diag forced-command broker (key only) | `configure`, `id`, `ip link set` refused (126) | code=OK cli:addr |
| R4 | Ubuntu / FRR | VERIFIED `SHA256:Q8t+/BDy…` | MPATH-000009 ACTIVE/HEALTHY | mgmt_swt:Ethernet4 | broker | as R3 | OK |
| S1 | cEOS | VERIFIED `SHA256:xXEM3ufw…` | MPATH-000005 | mgmt_swt:Ethernet5 | nmas-diag | as R1 | OK |
| S2 | cEOS | VERIFIED (pre-existing) | MPATH-000002 | mgmt_swt:Ethernet6 | nmas-diag (pre-existing) | as R1 | OK |
| S3 | cEOS | VERIFIED `SHA256:KQy/cTH2…` | MPATH-000006 | mgmt_swt:Ethernet7 | nmas-diag | as R1 | OK |
| S4 | cEOS | VERIFIED `SHA256:zkq3EvkJ…` | MPATH-000007 | mgmt_swt:Ethernet8 | nmas-diag | as R1 | OK |
| mgmt_swt | cEOS | VERIFIED `SHA256:XGWv42ld…` | MPATH-000003 DIRECT_OOB, NMAS-switch self path | self (provenance: NMA-000001 Ethernet9) | nmas-diag | as R1 | OK |

How each column was established:
- **Host keys**: every pin was captured through an independent device-side channel (cEOS console
  `show management ssh hostkey ed25519 public`; Linux: the container host reading `/etc/ssh/ssh_host_ed25519_key.pub`). Each
  was cross-checked against the key the device presents on the network, and validated by `host_key_pins.validate_evidence`
  with `dhruv` as enroller and the labelled automated collector `nmas-bulk-admission-console`.
- **Identity**: AUTHENTICATED_SESSION observations by the signed observer source under observation authorizations, then
  verified by `dhruv`.
- **Worker reads**: these came from acceptance cases TS-20261117-0A0F9944 and -28D9E04D (and -84ED42B7 for R3/R4) through
  the production dispatcher: peer uid 972, the live handoff authorized each target, and 100+ observations were persisted
  per device.

## 2. Single-admin exception windows (authorization and revocation)

Each window is one owner-authorized, exact-target document. Every window was installed root-owned, activated once and
consumed per target with `separation_of_duties_satisfied=false`. Each was revoked, and the file was removed afterwards (the
mechanism is disabled by default again).

| Window | Targets | Uses | Outcome |
|---|---|---|---|
| A (019-A) | 6 attachments + observation grant + MPATH-000003 | 1 | After R4's attachment, SQLite `database is locked` rolled back the next approval; revoked |
| A2 | 5 attachments + grant (R1,R3,R4,S1,S3,S4,mgmt_swt) + MPATH-000003 | 7/7 | revoked |
| B | MPATH-000004…000009 | 6/6 | revoked |
| C | grant (S4, mgmt_swt): the first grant's budget was spent by two refused FRR sessions | 1/1 | revoked |

The approvals ran in more than one window for these reasons:
- the 30-minute / 16-use limit;
- a path can only be registered after its attachment is approved;
- an FRR path can only be registered after its legacy-route identity observation.

No second human was claimed. No user was created. No row was edited directly.

## 3. Credential and worker isolation: LIVE_VERIFIED

**Credentials**
- Nine unique secrets live in the protected runtime store: 7 cEOS passwords and 2 FRR ed25519 keys.
- The worker sees only `/etc/nmas/troubleshooter-worker-store.managed.json`, which holds exactly the nine `nmas-diag` entries.
  `r2-nmas-automation` was removed from it. Sync is fail-closed.

**Worker network scope**
- Exactly 9 tcp/22 tuples, configured three ways: host nft, namespace nft + 9 /32 routes, and systemd `IPAddressAllow` with 9 /32.
- Proven from inside the namespace: each host presents its pinned key; 192.168.200.20:22 and 192.168.200.1:443 are dropped.

**FRR broker**
- Exact-string allowlist of 13 read-only commands, generated from the Troubleshooter catalogue.
- `shlex.split` then exec: no shell, no sudo, 20 s timeout, 512 KiB output cap.
- sshd admits `nmas-diag` only from 192.168.200.100, by public key, with no TTY or forwarding.

**cEOS**
- `enable` succeeds (there is no enable secret on these lab devices), but command authorization still denies
  `configure terminal`. Verified on all seven.

**Persistence**
- `write memory` was run on S1, S3, S4 and mgmt_swt, whose running-vs-startup diff was exactly the new account.
- **Not on R1/R2**: their running configuration holds pre-existing unsaved changes (R1 loopbacks; R2 Lab 9 Ethernet4/5 and
  the DHCP relay option) that a save would silently persist. Their `nmas-diag` is running-config only and re-creatable by
  the IaC module. **Owner decision.**

## 4. cEOS and FRR diagnostic support

- cEOS: `show … | json` catalogue through the worker. LIVE_VERIFIED for `interfaces` on all seven devices. Route summaries
  were added to the catalogue (FIXTURE_VERIFIED).
- FRR: broker transport (`diagnostic_worker.broker_command`). LIVE_VERIFIED for `addr` on R3/R4. The OSPFv2/OSPFv3/BGP/RIB
  queries are in the allowlist; the broker answered `vtysh … ospf neighbor json` and `show version` live through the
  credential verifier and the identity observer.
- FRR identity observations use the dedicated broker account. `nmas-automation` holds no sudo on the Phase 26B hosts, and
  NMAS deliberately did not grant it any.

## 5. Topology-wide incident intake: DEPLOYED, LIVE read-only, REPLAY_VERIFIED

- Interfaces on all nine managed devices plus R5:
  - cEOS via `show interfaces`
  - R3/R4 via `ip -j -s link`, cabled ports only
  - FRR link ends keep their kernel names, so the R3/R4 ↔ S3/S4/R5/mgmt_swt cables correlate as one incident each
- Routing reads on R1, R2, R3, R4, R5, S1, S2:
  - OSPFv2/OSPFv3/BGP-v4/BGP-v6 adjacencies (cEOS JSON; FRR `vtysh … json`)
  - per-protocol route counts (cEOS summaries; FRR selected RIB entries)
- On the healthy lab, intake ran with no false incident and no error.
- Each new monitoring case now records the topology-wide forwarding paths (`TsTopologyPath`, CORRELATE stage) and a
  `TOPOLOGY_PATHS` audit naming the affected flows.
- REPLAY_VERIFIED by TS-20261118-C82A083C, a replayed S1–R1 carrier loss:
  - one correlated `LINK:R1:Ethernet2|S1:Ethernet1` incident, `OPERATIONAL_LINK_DOWN`, `DIAGNOSE_AND_ESCALATE`
  - live RIB paths for 4 flows / 6 branches
  - H1→WebServer v4/v6 marked as traversing the incident; H1→H2 not

## 6–8. Routing, correlation, IPv4/IPv6 paths

These are covered by `routing.py` (`SUPPORT_MATRIX.md`):
- OSPFv2/v3 and BGP v4/v6: REPLAY_VERIFIED; live read-only monitoring DEPLOYED.
- RIP: route-count based, because cEOS 4.36.2F has no JSON neighbor form.
- Missing route, wrong next hop, redistribution mismatch, source collapse: REPLAY_VERIFIED.
- Redistribution fault-domain correlation: REPLAY_VERIFIED.
- Path-aware multi-device correlation and ECMP-aware IPv4/IPv6 path reconstruction: REPLAY_VERIFIED; live RIB collection
  verified in the REPLAY case above.
- No routing fault was injected live. That would break adjacencies, which the safety rules forbid without a specific
  bounded campaign authorization.

## 9–10. Remediation

- Autonomous recovery is unchanged: `interface_enable` on R2 Ethernet1 under ARP-R2-E1-002 is the only standing policy.
  Admission added no write authority. Every new category decides `DIAGNOSE_AND_ESCALATE`.
- Safe non-remediation: LIVE_VERIFIED (013, 017) and REPLAY_VERIFIED (C82A083C).

## 11. Website

The case page has a new "Topology-aware investigation" section:
- affected devices and interfaces
- the deterministic fault domain
- remediation eligibility
- admission resolution
- correlated symptoms
- every forwarding-path branch with its incident traversal
- verification

The existing report also lists the stored paths. FIXTURE_VERIFIED (TSACC-031) and LIVE rendering of the REPLAY case
(HTTP 200). Login, MFA and authorization are unchanged.

## 12. Defects found and fixed during the bulk admission
1. A single-admin exception could bind only one attachment observation → it now uses a per-target evidence map, and
   borrowing another device's evidence is refused.
2. The NMAS management switch could not have a path (model + DB constraint) → narrow DIRECT_OOB self path and migration
   0040; the L1/L2 checks use the NMAS-facing port.
3. Linux/FRR paths were refused (`L2_PLATFORM_NOT_IMPLEMENTED`) → Linux probe through the broker.
4. The worker refused Linux (`PLATFORM_TRANSPORT_NOT_SUPPORTED`) → broker transport, with no fallback to automation accounts.
5. The FRR identity observation needed sudo for `nmas-automation` → it now uses the broker account.
6. HC04 raised `IndexError` on a scope with no path link → it is now an honest INCONCLUSIVE.
7. Dispatcher pre-model calls failed on SQLite lock contention → bounded retry under a distinct nonce.
8. **Stalled dispatch never retried** (found live, see §14): a dispatcher unit that started but exited `GLOBAL_LEASE_BUSY`
   was recorded `started=True` and left its handoff OPEN forever. Intake now re-dispatches an OPEN handoff that made no
   progress once its unit is no longer running (bounded, audited). LIVE_VERIFIED: TS-20261117-52FAF2F8 was retried and
   closed `EXHAUSTED`, with no write.
9. Identity observations over a management path stay cEOS-only (explicit early refusal for FRR paths).

## 13. Remaining limitations
- **SQLite write contention** under concurrent intake, web and dispatcher writers. It appeared six times during this work,
  each time safely rolled back. Recommended: `"OPTIONS": {"transaction_mode": "IMMEDIATE"}` (Django 5.1) or PostgreSQL.
  WAL is not safe here, because the sandboxed units bind-mount the database file alone.
- R1/R2 `nmas-diag` persistence needs your decision (see §3).
- `nmas-diag` rotation is supported by the IaC module (`ensure_password(rotate=True)` + promote) and by worker sync, but no
  timer schedules it (`rotation_enabled=False`, as for S2).
- Live routing-fault campaigns: **BLOCKED_BY_SAFETY**, pending a specific bounded authorization. The peer-carrier harness
  refuses H4 while it holds a DHCPv6 lease (campaign 017 fix).

## 14. Concurrent unauthorized-ID fault campaign observed during this work

At 22:35:01Z a concurrent Codex session (separate process, started 22:32:47Z) ran
`NMAS-R2-E1-20261117-PRESENTATION-001`, an `admin_shutdown` of R2 Ethernet1, with **no authorization_id** recorded. The
harness restored it at 22:40:11Z. Two agents operating on this lab at the same time contradicts `AGENTS.md`
("Only one coding agent should edit this working tree at a time").

NMAS behaviour:
- Intake detected it within the confirmation window: TS-20261117-52FAF2F8, `ADMIN_STATE_MISMATCH`, `AUTO_REMEDIATE` under
  ARP-R2-E1-002.
- The dispatch lost the single global AI lease to an acceptance dispatch, which exposed defect 8. No recovery executed;
  the harness restored the link.
- R1's OSPF route count collapse (8 → 4) during the outage opened a separate case, TS-20261117-59531120
  (`RSRC:R1:ipv4:ospf`). This is a **correlation gap**: the route symptom lies downstream of R2's link, not on R1's own
  link, so the same-device secondary rule did not apply. Path-aware correlation (`routing.correlate_with_paths`) covers this
  shape but is not yet wired into intake's admission step. The case remains open for an engineer (route-source cases never
  auto-close); the fault has cleared.
