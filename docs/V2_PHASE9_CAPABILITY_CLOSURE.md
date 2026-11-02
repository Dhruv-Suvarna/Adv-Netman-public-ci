# NMAS V2 Phase 9: platform × feature capability closure

Status: one lifecycle-linked capability (DHCP relay option 82 on Arista EOS) is implemented and live-verified at the device level. It stays **PARTIAL** because it does not run through the governed execution engine. No matrix cell was promoted, so the matrix total is still **46 SUPPORTED out of 396**. A generated ten-stage ledger replaces the binary view.

## 1. Method: the ten stages

A platform × feature cell is **SUPPORTED** only when all ten stages exist for that platform:

| # | Stage | Ledger probes behind it (all must PASS) |
|---|---|---|
| 1 | intent / model | semantic_model, device_builder_ui, field_validation |
| 2 | renderer | renderer, candidate_generation |
| 3 | syntax / semantic validation | config_validation |
| 4 | execution | executor, live_write (LIVE) |
| 5 | device read-back / import | live_read (LIVE), parser_import |
| 6 | postcheck | live_post_write_validation (LIVE) |
| 7 | compensation | compensation (LIVE) |
| 8 | restoration of prior state | compensation (LIVE; the isolated verifier requires the running-config / section to match the pre-apply capture) |
| 9 | positive + negative regression tests | automated_tests |
| 10 | live platform verification | runtime_validation (LIVE) |

Stages 7 and 8 come from the same stored probe, because the Phase 4 harness records one compensation result and that result already requires the digest or section to match. Mocks and fixtures satisfy stages 1–3 and 9 only. cEOS evidence is never counted for another NOS.

Classification vocabulary: `capabilities.vocabulary.ClosureClass`. It refines the existing four-value `CapabilityStatus` and never replaces it, and `CLOSURE_TO_STATUS` maps every class back to that four-value set. The first matching rule wins:

1. **OUT_OF_SCOPE**: a scope decision is recorded.
2. **UNSUPPORTED**: unsupported by the platform. A completed assessment recorded a platform reason. This keeps the existing value and meaning.
3. **SUPPORTED**: all ten stages exist. The ledger's binary `final_status` must agree, otherwise generation raises an error.
4. **BLOCKED_BY_ENVIRONMENT**: stages 1–3 and the executor exist, but a live probe is BLOCKED by `RUNTIME_IMAGE_UNAVAILABLE` or `RUNTIME_BOOT_FAILED`.
5. **LIVE_EVIDENCE_MISSING**: stages 1–4 and 9 exist, but a live stage is unproven.
6. **PARTIAL**: stages 1–3 exist, plus at least one later stage but not all of them.
7. **RENDER_VALIDATE_ONLY**: stages 1–3 exist and nothing later.
8. **NOT_IMPLEMENTED**: intent, renderer or validation is missing.

Regenerate the ledger with `DJANGO_DEBUG=1 python manage.py nmas_phase9_ledger` (run from `web/`). Code: `core/services/capabilities/phase9_ledger.py`. Outputs: `docs/evidence/v2-phase7-9/phase9/capability-ledger.json` and `capability-summary.md`. Do not edit the outputs by hand. A test checks that regeneration produces the committed files byte for byte.

## 2. Totals (generated)

Before Phase 9 the binary ledger showed 396 cells: 46 SUPPORTED and 350 UNSUPPORTED (cEOS 21, FRR 15, SR Linux 5, IOS XE 5, IOS XR 0, SONiC 0 supported).

After Phase 9 the matrix still has **396 cells and 46 SUPPORTED**, the same cells. The 350 non-supported cells are now split by class:

| Platform | Total | SUPPORTED | PARTIAL | NOT_IMPLEMENTED | UNSUPPORTED | LIVE_EVIDENCE_MISSING | RENDER_VALIDATE_ONLY | BLOCKED_BY_ENVIRONMENT | OUT_OF_SCOPE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| arista_ceos | 66 | 21 | 0 | 42 | 3 | 0 | 0 | 0 | 0 |
| cisco_c8000v_iosxe | 66 | 5 | 5 | 56 | 0 | 0 | 0 | 0 | 0 |
| cisco_iosxr | 66 | 0 | 18 | 48 | 0 | 0 | 0 | 0 | 0 |
| nokia_srlinux | 66 | 5 | 13 | 48 | 0 | 0 | 0 | 0 | 0 |
| sonic | 66 | 0 | 15 | 51 | 0 | 0 | 0 | 0 | 0 |
| ubuntu_frr | 66 | 15 | 0 | 51 | 0 | 0 | 0 | 0 | 0 |
| **all** | **396** | **46** | **51** | **296** | **3** | 0 | 0 | 0 | 0 |

The three UNSUPPORTED cells are cEOS EIGRP_IPV4, EIGRP_IPV6 and RIPNG. Each has a recorded platform reason.

The 296 NOT_IMPLEMENTED cells are made up of:
- 290 that miss the intent stage itself, mostly because the feature is not selectable or field-validated for that platform;
- 5 that miss renderer and validation;
- 1 that misses validation only.

Lifecycle-linked rows sit outside the matrix and are not added to the 396. There is one: `arista_ceos lifecycle.DHCP_RELAY_OPTION82`, now classed **SUPPORTED**. All ten stages are derived from the governed live evidence (see §3).

**Closure outlook (generated, `closure_outlook` in the ledger).** The closure class records which stages exist. Separately, each
cell's `environment_blocker` lists the host-environment reasons (`RUNTIME_IMAGE_UNAVAILABLE`, `RUNTIME_BOOT_FAILED`) that block
its live probes. Such a cell cannot reach SUPPORTED on this host even after its software stages are written, because stage 10
needs a live run.

| Outlook | Cells | Basis |
|---|---:|---|
| SUPPORTED | 46 | all ten stages with live evidence |
| UNSUPPORTED (recorded platform decision) | 3 | cEOS EIGRP_IPV4, EIGRP_IPV6, RIPNG |
| Environment-blocked | 66 | every `cisco_iosxr` cell: `live_read` and `runtime_validation` BLOCKED by `RUNTIME_IMAGE_UNAVAILABLE`. No IOS XR image is on the host. The IOS XR executor is also absent (`EXECUTOR_ABSENT`), which is software work, but live closure needs the image first. |
| Technically feasible remaining | 281 | everything else. No environment reason applies. |

The 281 technically feasible cells, by platform and first missing stage:

| Platform | Cells | First missing stage | Notes |
|---|---:|---|---|
| sonic | 66 | intent 49, renderer 2, execution 15 | The SONiC VS image is on the host (`sonic-vs.img.gz`, used by the Phase 4 QEMU probe), so these cells are **not** environment-blocked. The live stages need a SONiC executor (`EXECUTOR_ABSENT`). |
| cisco_c8000v_iosxe | 61 | intent 56, execution 5 | The executor refuses live writes in the capability lab (`EXECUTOR_REFUSED`). The image is present (vrnetlab 17.06.01a). |
| nokia_srlinux | 61 | intent 47, renderer 1, execution 13 | Same as IOS XE; srlinux:24.10 is present. |
| ubuntu_frr | 51 | intent 51 | The feature is not selectable or field-validated for FRR. |
| arista_ceos | 42 | intent 41, renderer 1 | The feature is not selectable or field-validated for cEOS. |

Promoting a matrix cell needs the Phase 4 capability verifier (`nmas_capabilities verify-matrix --isolated-live`) against the
containerlab capability lab. Containerlab deploy and destroy are out of scope for this repository's agents (CLAUDE.md), so no
matrix cell was promoted in Phase 9. The lifecycle work in Phase 9 (§3, FRR isolation, disabled RIP, IPv6 admission) was proven
live on the disposable namespace fixtures instead.

No new matrix feature axis was added for option 82. Adding one would grow the matrix to 402 cells and would need a full re-assessment of the 6 new cells on every platform. That is a decision for the integration owner.

## 3. DHCP relay option 82 (P1)

**Implementation:** `web/core/services/dhcp_relay_option82.py`, plus Device Builder and ZTP integration.

| Stage | Where | Evidence |
|---|---|---|
| intent | `service_policy_intent_service.set_dhcp_relay_option82`: stored as `relay["option82"]` on an IPv4 relay; non-EOS and IPv6 are refused | tests |
| renderer | `platform_drivers._option82_global_lines` (global `ip dhcp relay information option`), `_ceos_option82_interface_lines` (per-port circuit-id / remote-id), wired into `_render_services` and `_dhcp_interface_contributions` | candidate_renderer test |
| validation | `dhcp_relay_option82.validate_intent` (platform, interface name, safe 1–63-character ids, boolean); render-time refusal | tests |
| execution | `ztp.relay_option82.plan` / `approve` / `execute`: a governed `DHCP_RELAY_OPTION82` Change through the single-device transaction and CeosExecutor over SSH. The first Phase 9 run used the Docker CLI transport and is superseded. | live `o82-30-governed-apply.json` |
| read-back / import | `parse_eos` (global flag, per-port circuit-id / remote-id / helpers / addresses) | live JSON `post.readback` |
| postcheck | `postcheck` (EOS stores no line for a circuit-id equal to its default; this was live-verified) | live: `post.postcheck == []` |
| compensation | `compensation_eos(prior, intent)`: the exact inverse from the pre-change read-back | live: `compensation.rc == 0` |
| restoration | `config_digest`: the full running-config digest returned exactly to the pre-change value | live: `restored.equals_pre == true` |
| tests | `core.tests.test_phase9_option82` (34) and `core.tests.test_relay_option82` (governed change, read-back, trust, ledger row), positive and negative for every function | |
| live | ISC dhcpd leases only through the relay with option 82 | see below |

**Platform syntax**, verified on disposable cEOS 4.36.2F:
- `ip dhcp relay information option` is global and off by default.
- Per interface: `ip dhcp relay information option circuit-id <id>` (default is the interface name) and `... remote-id <id>`.
- Each `no` form restores the default exactly.

**Live run.** Fixture: `labs/phase9-option82-isolated/fixture.sh`, with alpine udhcpc → cEOS relay Et1 → Et2 → `nmas-ztp-svc:p3` ISC dhcpd. Harness: `run_live.py`. Evidence: `docs/evidence/v2-phase7-9/phase9/option82-ceos-live.json`, secret-free. The NMAS-rendered ISC policy matches `packet(24,4)=giaddr AND option agent.circuit-id`.

| Scenario | Lease? | Wire (tcpdump on the server link) |
|---|---|---|
| relay without option 82 (prior state) | no | Gateway-IP 10.254.90.1, no option 82 |
| after NMAS apply (option 82 on) | **yes**, 10.254.90.10 | `Agent-Information (82)`, `Circuit-ID SubOption 1: Ethernet1` |
| after compensation | no | no option 82; running-config digest equals the pre-change digest |

**Security findings, live-proven on cEOS 4.36.2F:**

1. **The relay forwards a client-supplied option 82 unchanged**, whether `ip dhcp relay information option` is on or off. The client sent circuit `Ethernet1` and remote `FORGE`, and both reached the server untouched. This release has no `information policy replace|drop` knob; every variant tried was rejected by the CLI.
2. **Shared-giaddr attack.** A reservation was bound to circuit `Ethernet7` behind the same giaddr. A client on Ethernet1 that forged circuit `Ethernet7` **obtained the lease** (10.254.90.17). The same client without the forgery got nothing.
3. **Conclusion:** the circuit id alone is not attachment proof. Only giaddr is unforgeable, because the relay sets it from the interface that received the request.
4. **Fix, implemented:** `relay_trust_problems` and `ztp.dependencies.evaluate(..., relay_readback=...)` (check `bootstrap_path_option82`) trust a relay only when all of the following hold:
   - it is a listed trusted relay;
   - the attachment is approved and not mismatched;
   - option 82 is enabled;
   - the port exists and has a helper to the bootstrap service;
   - **giaddr identifies exactly one routed Ethernet port**, so SVI / VLAN relay ports are refused (`RELAY_UNTRUSTED`);
   - the effective circuit id equals the attachment port, which is the value the reservation matches.

   The live gate refuses a shared-giaddr SVI (`ztp_gate_refuses_shared_giaddr_port`).
5. A configured **remote-id was not inserted on the wire** by cEOS 4.36.2F: option 82 length 11 means circuit only. The remote-id is rendered, read back and compensated, but NMAS never relies on it.

Existing protections unchanged: discovery (`ztp.discovery.fold`) already records a lease without a trusted giaddr, or without a circuit id, as `UNTRUSTED_RELAY`. A client-supplied option 82 that arrives without a relay therefore has no giaddr and is never trusted. An unknown circuit id finds no session and is recorded as `UNAUTHORIZED`.

**Closure (governed path, this release).** Both items that the first Phase 9 run left open are now done:

- **Execution through the governed engine.** `web/core/services/ztp/relay_option82.py` turns a Device Builder relay revision
  (`intent_from_revision`) into a `DHCP_RELAY_OPTION82` Change in the single-device governed transaction
  (`isolation/transaction.py`, the same one isolation uses). The Change goes through:
  - validate → plan (plan hash) → precheck → approval by someone other than the requester, bound to the plan hash;
  - execute: lock, preflight, apply, final postcheck;
  - on a failure, compensation newest first, with digest verification and reconnection after a lost session.

  Each operation is a CeosExecutor declared-inverse config block (`dhcp_relay_option82`) over the authorized SSH transport
  (pinned host key, key-only service account). There is no Docker console in the path.
- **Persistent trusted read-back.** `DhcpRelayReadback` (migration 0036, immutable rows) stores NMAS's own read of the relay,
  written by `refresh` (READ) or by a successful execution (POSTCHECK). `ztp.dependencies.evaluate` now loads the fresh stored
  read-back by itself for every upstream whose platform needs option 82 (`RELAY_READBACK_MISSING` without one, maximum age
  `NMAS_OPTION82_READBACK_MAX_AGE_SECONDS`, default 86400). `ztp.discovery` refuses a lease whose circuit id does not
  equal the effective circuit id of the one routed port that owns the giaddr (`OPTION82_CIRCUIT_FORGED`), recorded as
  `UNTRUSTED_RELAY`.

Live proof (`core.tests.live_option82_ztp_fixture` on `labs/isolation-commissioning-isolated`, UP1 started without option 82;
evidence `docs/evidence/v2-phase9-closure/option82/`):

| File | What it shows |
|---|---|
| `o82-10-gate.json` | Before any change, the ZTP dependency gate refuses UP1: `RELAY_READBACK_MISSING` with no stored read-back, then `RELAY_UNTRUSTED` after a READ read-back shows option 82 off. UP1's digest is unchanged by the read. |
| `o82-20-fault-compensated.json` | A governed apply whose session is cut after the device accepted the change (`SESSION_LOST`). Compensation runs on a fresh session, the outcome is `FAILED_ROLLED_BACK`, UP1's running-config digest equals the pre-change digest, and no read-back is recorded. |
| `o82-30-governed-apply.json` | Self-approval and a wrong plan hash are refused. The approved Change is `SUCCEEDED` / `DEPLOYED`, `ip dhcp relay information option` is in UP1's running config, the POSTCHECK read-back is stored against the Change, and the gate now passes (`UP1:Ethernet1 inserts its circuit id`). |
| `o82-40-forged-option82.json` | Wire capture on the service link: requests relayed with UP1's own circuit `Ethernet1` pass NMAS's discovery gate, and requests carrying a client-forged circuit `Ethernet9` are flagged `OPTION82_CIRCUIT_FORGED`. cEOS forwards the forged option unchanged. |
| `o82-50-native-ztp.json` | Native ZTP of a factory-default cEOS behind UP1: every relayed request from NEW1's DHCP hardware address carries circuit `Ethernet1` and giaddr 10.254.60.1. The only message NEW1 sends the server directly is its DHCPRELEASE (giaddr 0, no option 82), which the run checks by message type. The lease is `CORRELATED` from a trusted relay, and the session reaches `BOOTSTRAPPED` (configuration delivered and applied). |

The ledger row (`phase9_ledger.governed_option82_row`) derives every one of the ten stages from these files.

## 4. P3: additional cells

No additional matrix cell was closed in Phase 9. The time budget went to P1 and P2, and no cell was promoted without full ten-stage proof.
- cEOS OSPFV2, RIPV2 and OSPFV3, and FRR RIPV2 and OSPFV2, were already SUPPORTED in the stored ledger.
- Non-zero OSPF area (10 / 20) on cEOS was not re-verified live in Phase 9. It remains covered only by the existing OSPFV2 cell evidence, which used area 0.
- SR Linux features beyond the 5 SUPPORTED cells remain open.
- IPv6 routing admission (OSPFv3 isolation on a cEOS upstream, dual-stack admission, `ipv6 unicast-routing` for a ZTP-onboarded cEOS) is implemented and live-verified: `docs/V2_IPV6_ADMISSION.md`.

## 5. P4: non-cEOS trusted isolation

**Ubuntu/FRR: implemented and live-verified** (`docs/V2_FRR_TRUSTED_ISOLATION.md`, evidence `docs/evidence/v2-phase9-closure/frr-isolation/`):
- one NMAS-owned nftables `inet` table on the forward / input / output hooks of the bootstrap port, IPv4 and IPv6;
- exact read-back, drift detection, digest-verified compensation and restoration;
- lifecycle integration (planning, admission, release);
- an authorized SSH transport with a pinned host key and least-privilege `sudo` (no Docker console).

Production R3/R4 stay refused (`NOT_CONFIGURED`) until an operator pins their host keys and grants the automation account
`nft` / `vtysh`.

The `ISOLATION_PLATFORM_NOT_IMPLEMENTED` refusal is kept for the other platforms:

| Platform | Missing for a complete safety contract | Class |
|---|---|---|
| nokia_srlinux | ACL filter renderer for isolation, attachment, management-plane ACL, gNMI read-back and compensation, live proof on srlinux:24.10 | NOT_IMPLEMENTED |
| cisco_c8000v_iosxe | isolation ACL renderer, executor and compensation; live proof needs the ~7-minute vrnetlab boot | NOT_IMPLEMENTED |
| sonic | isolation renderer, an executor (none exists yet), read-back and compensation; the SONiC VS image is on the host | NOT_IMPLEMENTED (technically feasible) |
| cisco_iosxr | executor and renderer; no IOS XR image on the host, so no live proof is possible here | environment-blocked (`RUNTIME_IMAGE_UNAVAILABLE`) |

## 6. Live-verified versus contract-only

- **Live in Phase 9, besides option 82 (below):**
  - Ubuntu/FRR trusted isolation over SSH (`docs/V2_FRR_TRUSTED_ISOLATION.md`);
  - a RIP instance disabled in intent, rendered as `router rip` / `shutdown` on cEOS, with RIP routes learned while enabled,
    withdrawn while disabled, and both compensations digest-exact (`docs/V2_DISABLED_RIP.md`);
  - OSPFv3 isolation and dual-stack admission behind a cEOS upstream (`docs/V2_IPV6_ADMISSION.md`).
- **Live in Phase 9, option 82:** cEOS 4.36.2F option 82 render, apply (first through the Docker CLI transport, then as a governed `DHCP_RELAY_OPTION82` Change through CeosExecutor over SSH), stored read-back, postcheck, DHCP lease through ISC, forged-option attacks, compensation after a lost session, exact digest restoration, and native ZTP of a factory-default cEOS gated by the stored read-back.
- **Contract-only (unit tests):**
  - the Device Builder intent and candidate rendering of option 82;
  - the ZTP dependency check with a supplied read-back;
  - the ledger classifier;
  - refusals for non-EOS platforms.

## 7. Files

- New:
  - `web/core/services/dhcp_relay_option82.py`
  - `web/core/services/capabilities/phase9_ledger.py`
  - `web/core/management/commands/nmas_phase9_ledger.py`
  - `web/core/tests/test_phase9_option82.py`
  - `web/core/tests/test_tg_phase9_closure.py`
  - `labs/phase9-option82-isolated/{fixture.sh,run_live.py}`
  - evidence under `docs/evidence/v2-phase7-9/phase9/`
- Modified:
  - `web/core/services/service_policy_intent_service.py` (`set_dhcp_relay_option82`)
  - `web/core/services/platform_drivers.py` (`_render_services`, `_dhcp_interface_contributions`, plus two new helpers)
  - `web/core/services/ztp/dependencies.py` (`evaluate`)
  - `web/core/services/capabilities/vocabulary.py` (`ClosureClass`, `CLOSURE_TO_STATUS`)
  - `.gitignore` (fixture runtime)
