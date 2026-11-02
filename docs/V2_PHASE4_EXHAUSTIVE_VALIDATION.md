# Version 2 Phase 4 exhaustive validation

Every one of the 396 capability cells has a completed, evidence-backed assessment. The final state is in the next section; the per-prompt checkpoints below it are the history of how the matrix got there and are kept as written. The authoritative machine-readable ledgers are [`offline-ledger.json`](evidence/v2-phase4-exhaustive/offline-ledger.json) (396 non-destructive, fixture-only probes) and [`progress-ledger.json`](evidence/v2-phase4-exhaustive/progress-ledger.json) (latest persisted assessment per cell). PR #39 is not merged; merging is a human decision.

## Final Phase 4 state (Prompt 6)

Code-complete head: `8f4b1d7`. The commits after it change only this document, `tier3-local.json` and nothing executable.

| Measure | Count |
| --- | ---: |
| Total cells | 396 |
| Assessed | 396 |
| Unassessed | 0 |
| Supported | 46 |
| Unsupported | 350 |

| Platform | Supported | Unsupported |
| --- | ---: | ---: |
| Arista cEOS | 21 | 45 |
| Ubuntu/FRR | 15 | 51 |
| Nokia SR Linux | 5 | 61 |
| Cisco IOS XE (Catalyst 8000V) | 5 | 61 |
| Cisco IOS XR | 0 | 66 |
| SONiC | 0 | 66 |

**What "unsupported" means.** It is a statement about NMAS at the recorded head, not about the vendor platform. Of the 350 unsupported cells, 277 stopped at the prerequisite gate: NMAS has no renderer, candidate path or registered executor for that feature on that platform, and the cell names the missing layer. The other 73 were investigated against a runtime: either NMAS lacks a later layer (parser, postcheck, compensation), or a specific probe failed, or no runtime image exists (all 66 IOS XR cells; no IOS XR image was available, and nothing is inferred from IOS XE). Only three cells record `PLATFORM_DOES_NOT_SUPPORT`, where the native cEOS 4.36.2F CLI itself rejected the command form.

**Evidence model.** A supported cell has all fourteen probes passing and a `live:` reference to an isolated-lab run that applied the NMAS-rendered Configlet through the registered executor, ran the operator postcheck, imported the result, and restored the exact pre-change state through NMAS compensation. An unsupported cell has classified reason codes and a `gate:` or runtime reference. The ledger holds no pending, unknown or default-red cell: 396 complete assessments, 46 supported cells each with every stage `PASS` and a live reference, 350 unsupported cells each with at least one reason code and one evidence reference. Each cell keeps the head and timestamp of its own assessment; these were not rewritten.

**Regressions closed in Prompt 6.**

| Failure | Classification | Fix |
| --- | --- | --- |
| `test_contracts`: 5 process spawns in the engine instead of 1 | Regression. The four Phase 4 state readers in `executors/linux.py` each called `subprocess.run`. | All reads and writes go through one `docker_exec()`; argv shape, timeout and capture are decided there. The contract is unchanged. |
| `test_contracts`: `vtysh` in `execution/codes.py` | Regression. The generic reason catalogue described FRR behaviour. | Two messages reworded platform-neutrally; FRR detail stays in the Linux executor. The contract is unchanged. |
| `test_config_workflows`: `bgp_neighbor` mode | Stale expectation. Prompt 2 proved exact running-config restoration for cEOS BGP live, so Complete mode is correctly offered. `COMPLETE_OR_PARTIAL`, `PARTIAL_UAT_ONLY` and `NOT_EXECUTABLE` are one three-value vocabulary, not two competing ones. | Expectation updated; a new test pins each mode to the capability model. |
| Bootstrap: 91 failures, 1 error, `BASELINE_UNHEALTHY` | Regression in the health engine, one root cause. The routing-binding configuration check added in Prompt 2 recognised only a per-interface `ip ospf area` line, so a healthy device that enables OSPFv2 with a covering `network … area` statement was reported unhealthy. | The check also accepts a covering `network` statement, most specific statement deciding the area. A wrong area, a passive expectation and an uncovered interface still fail. No bootstrap test or health gate was changed. |
| `test_tier3_selection`: `srlinux_model.py` unclassified | Regression found by the full run (not on the Prompt 5 list). | Classified under `platform_drivers`, with its health and execution consumers declared. |

Because the Linux executor's transport changed, `ubuntu_frr` `routing.BGP_IPV4` and `routing.OSPFV2` were reassessed live at `de24e71` on the disposable lab: apply, operator postcheck, compensation and exact restoration passed. The SR Linux and IOS XE executors were not modified, so their evidence stands.

**Local validation at `8f4b1d7`.**

- Complete Django suite, serial (`manage.py test core.tests`): 1,923 tests, 0 failures, 0 errors, 0 skipped.
- Full local Tier-3 (`python tier3.py --base origin/main --mode full`, [`tier3-local.json`](evidence/v2-phase4-exhaustive/tier3-local.json)): `PASS_WITH_WARNINGS`, exit 0. Syntax (607 files), Django system check, migration drift, 1,923 Django tests, 476 monitoring tests and Grafana drift all pass: 2,399 tests. The same result came from a run with no base.
- The one warning: the hygiene scan stops at 50,000 added lines and this branch adds 122,257, most of them the two ledgers. The project's scanner was run once more over the whole diff with the bound lifted in-process: 122,257 lines, no credential format, conflict marker or credential-store file.
- No pending migration; no image or disk artifact is tracked.

**Hosted Tier-3.** GitHub Actions runs Tier-3 on every push to PR #39, so the run that covers the final head cannot be named inside that head. The run for the commit before this line was last edited is recorded below; the run for the final head is recorded in the PR #39 description.

- Run `37324194008` (`pull_request`) on `aed0d65`: conclusion **success**. Targeted mode against `4adec06`: `PASS_WITH_WARNINGS`, with syntax, Django system check, migration drift and all 1,923 Django tests passing. The warning is the same hygiene line bound described above; the monitoring tests were not selected because no monitoring file changed, and they pass in the local full run.

**Labs.** `nmas-cap-validation` and `nmas-cap-iosxe` were destroyed through their own topology files with `--cleanup`; no capability container, network or VM remains. Production `srlceos01` is 15/15 running and was only read. No production configuration, VLAN 200 addressing, or R5 / WebServer / H1–H4 was changed.

**Remaining limitations.**

- SR Linux and IOS XE cover loopback, routed physical, subinterface and IPv4/IPv6 static routes only. Management-interface changes are refused on both. Neither is part of the production lab.
- IOS XR and SONiC have no executor. IOS XR was never run; SONiC was observed natively once.
- cEOS RIPng and EIGRP are rejected by the 4.36.2F CLI. IS-IS works natively on cEOS but NMAS lacks the layers for it.
- FRR daemon lifecycle is not managed by NMAS; a missing daemon is refused at preflight.
- The OSPF `network`-statement form confirms a binding but carries no passive flag in the normalized model.
- Tier-3's lab-backed verifiers were not run (they are optional and need `--lab`).

Regenerate the progress ledger with:

```text
DJANGO_DEBUG=1 python web/manage.py nmas_capabilities report-matrix --allow-incomplete --report docs/evidence/v2-phase4-exhaustive/progress-ledger.json --summary docs/evidence/v2-phase4-exhaustive/matrix-summary.md
```

The normal `report-matrix` command fails if even one cell is unassessed; `--allow-incomplete` is visibly marked as in-progress. Offline verification alone cannot satisfy the assessment gate. All 14 named probes must have deliberate non-pending outcomes, runtime/HEAD/timestamp metadata, and concrete classified reasons for failure. A live pass requires live evidence; a blocked live stage requires a referenced runtime investigation. The report lists every remaining cell and its unfinished probes.

## Batch harness

`verify-matrix` assesses a whole platform, family or the entire matrix in one run and records one deliberate assessment per cell:

```text
DJANGO_DEBUG=1 python web/manage.py nmas_capabilities verify-matrix --platform arista_ceos --remaining \
    --isolated-live --allow-write --allow-incomplete
DJANGO_DEBUG=1 python web/manage.py nmas_capabilities verify-matrix --platform all --family service_policy --match NAT_ --allow-incomplete
DJANGO_DEBUG=1 python web/manage.py nmas_capabilities report-matrix --allow-incomplete \
    --report docs/evidence/v2-phase4-exhaustive/progress-ledger.json --summary docs/evidence/v2-phase4-exhaustive/matrix-summary.md
```

Selection: `--platform`, `--feature`, `--family interface|routing|service_policy`, `--match <key substring>`. Completed assessments are kept (`--remaining`, the default) unless `--reassess` is given, so a batch never replaces live evidence with a weaker record. Without `--allow-incomplete` both commands exit non-zero while any selected cell is unassessed.

Per cell the harness runs the real offline probes, then applies the **prerequisite gate**: if the semantic model, renderer, candidate generation or registered executor probe failed, the five live stages are recorded `BLOCKED` with that exact reason and a per-cell `gate:<platform>/<feature>@<head>#<digest>` reference to the cell's own offline evidence. No runtime is started merely to re-prove an absent renderer or executor, and `runtime_version` says the device was not contacted. A cell whose prerequisites all pass can only be completed by a registered isolated live probe (`--isolated-live --allow-write`, `core/services/capabilities/batch_live.py`); a gate reference on such a cell is rejected. `progress-ledger.json` (schema 2) remains the single authoritative ledger; each cell now also carries flat layer fields (`semantic`, `renderer`, `parser`, `validator`, `executor`, `live_read`, `live_write`, `postcheck`, `compensation`, `runtime_test`), `assessment_basis` (`RUNTIME_INVESTIGATION` or `PREREQUISITE_GATE`) and `evidence_references`. [`matrix-summary.md`](evidence/v2-phase4-exhaustive/matrix-summary.md) is generated from it and must not be edited by hand.

A prerequisite-gated cell is an honest statement about NMAS at the recorded HEAD, not about the vendor platform. The gate records the exact missing renderer, candidate or executor layer for each affected cell. New implementations require selective reassessment of cells whose prerequisites change.

## Prompt 2 checkpoint (local worktree, not merged)

| Measure | Count |
| --- | ---: |
| Total cells | 396 |
| Assessed | 396 |
| Unassessed | 0 |
| Supported | 23 |
| Unsupported | 373 |

The generated ledger now enforces a complete assessment for every cell. Its `remaining_cells` list is empty. The four formerly open Ubuntu/FRR interface cells have live assessments: `SUBINTERFACE` and `SVI` are supported after registered LinuxExecutor application, semantic/kernel-route readback and exact restoration. `MANAGEMENT` remains unsupported because the FRR parser cannot import its intent; `ROUTED_PHYSICAL` remains unsupported because the existing eth1 MTU differs from rendered intent and the executor cannot safely change and restore that pre-existing physical-port setting.

Five cEOS routing cells became supported: OSPFv2 and OSPFv3 reached FULL; BGP IPv4 and IPv6 reached ESTABLISHED and exchanged prefixes both ways; RIPv2 exchanged routes. Their NMAS process/interface postchecks now use normalized routing facts. The registered cEOS executor derived bounded inverses from captured pre-change running configuration, preserved unrelated configuration, and verified full configuration restoration after compensation. Broad process deletion is accepted only when the process did not exist before the test.

Ubuntu/FRR OSPFv2 and OSPFv3 also became supported. Each was rendered, applied incrementally through bounded vtysh commands, reached FULL with the disposable cEOS peer, passed semantic postcheck, and was compensated through an inverse derived from pre-change FRR configuration. The exact FRR running configuration and both peers' link/config baselines were restored. OSPFv3 needed native `ipv6 ospf6 cost` and `ipv6 ospf6 network point-to-point` interface commands to match the peer's point-to-point network type.

Other FRR RIP/BGP and NAT cells remain unsupported; there is no claimed routing/NAT executor support for them. The batch prerequisite gate assessed the other 300+ cells deliberately, so they require reassessment only if an implementation changes their prerequisites. The ledger remains an in-progress Phase 4 artifact: 396/396 assessment does not establish Phase 4 completion.

## Prompt 3 checkpoint (local worktree, not merged)

| Measure | Count |
| --- | ---: |
| Total cells | 396 |
| Assessed | 396 |
| Unassessed | 0 |
| Supported | 28 |
| Unsupported | 368 |

Ubuntu/FRR `routing.BGP_IPV4`, `routing.BGP_IPV6`, `routing.RIPV2`, `routing.RIPNG` and `service_policy.NAT_NAT44_PAT` became supported. `service_policy.NAT_NAT44_STATEFUL` passed every live stage but stays unsupported on `parser_import`. Only these six cells, the two FRR OSPF cells that share the changed executor code and the four other FRR `NAT_NAT44_*` cells the selection matched (re-gated with unchanged outcomes) were reassessed.

**Shared executor.** `core/services/execution/executors/frr_routing.py` holds the routing-operation primitives every FRR protocol uses: one strict per-context grammar (process, interface, BGP address-family), the ordered `vtysh -c` command sequence (process enter/create, leaves, address-family enter/exit), a reader that turns `show running-config` into captured semantic state, and one inverse generator. A process that did not exist before apply is removed as a whole; under an existing process only provably additive leaves are removed, each by its own `no` form, address-family leaves before the neighbor they reference. A leaf that would replace an existing value (router-id, a neighbor's remote AS) or change how unrelated neighbors behave (the process-wide `no bgp default ipv4-unicast` / `no bgp ebgp-requires-policy` settings) has no safe inverse and fails closed, as does a second BGP autonomous system (`BGP_PROCESS_CONFLICT`). Nothing rewrites `frr.conf`.

**Preflight.** vtysh silently accepts configuration for a daemon it cannot reach, so preflight reads `show daemons` and refuses with `ROUTING_DAEMON_UNAVAILABLE` when the needed daemon is not running. NMAS does not manage FRR daemon lifecycle. The engine preflights every Configlet before the first apply, so the executor derives each exact inverse again immediately before that Configlet is applied and compares compensation against the configuration captured at that moment; a multi-Configlet plan (process, neighbor, address-family activation, network) therefore compensates in reverse order to the exact pre-change configuration.

**Renderer and parser.** The FRR BGP template now renders `no bgp default ipv4-unicast` and `no bgp ebgp-requires-policy`, as the tracked R3/R4 configurations do. Without the second line FRR 8.4.4 establishes an eBGP session but exchanges no prefixes; without the first, an IPv6-only neighbor is also activated for IPv4. The FRR import parser now models FRR's default IPv4 activation and no longer loses one family of a dual-activated neighbor.

**Postcheck.** The live probes run the operator postcheck itself (`evaluate_requirements` over a fresh live read): process ASN/router-id, neighbor and remote AS, address-family activation, network, RIP process and interface binding. The FRR BGP facts now carry received/sent prefix counters per family, and a new `rip` fact group reads `show ip rip` / `show ipv6 ripng`. A protocol daemon that is not running now reads as "no state" instead of failing the whole fact group.

**Live behaviour (FRR 8.4.4 DUT eth3 to FRR 8.4.4 peer eth1, lab `nmas-cap-validation`).** Each BGP family ran twice: against a DUT with no BGP process, and against a DUT whose native process already held an unrelated neighbor and network. In all four runs the session reached ESTABLISHED, the DUT installed the peer's prefix as a BGP kernel route, the peer's BGP table held the DUT's network, the postcheck passed, compensation reported `COMPENSATED` for every Configlet, the FRR running configuration was identical to the pre-change capture (unrelated objects intact), and the peer lost the session and prefix. RIPv2 and RIPng ran the same two scenarios: the DUT learned the peer's prefix into the RIP table and kernel, the peer listed the DUT as a routing information source, and after compensation the configuration was identical and the learned route disappeared. When NMAS removes only its binding from a process that stays, the learned route leaves by RIP's own timeout and garbage timers (about two minutes observed), not immediately; the probe waits for that and records the elapsed time.

**Limits of this evidence.** Addresses, the originating dummy interface, daemon start/stop and the entire peer configuration are lab prerequisites applied natively. RIP redistribution is not rendered by the FRR driver and was not tested. The grammar also accepts the additive neighbor attributes the renderer can emit (`update-source`, `ebgp-multihop`, `shutdown`, `next-hop-self`, `route-reflector-client`, RIP `passive-interface`); their inverses are unit-tested but were not exercised live.

**NAT44.** The FRR NAT renderer emits one dedicated nftables table (`table ip DEVICE_BUILDER_PAT`, a source-NAT postrouting chain of `masquerade` rules). The Linux executor accepts exactly that shape, creates the table as a single atomic `nft` transaction and compensates by deleting that table, then requires the whole ruleset digest (packet/byte counter values excluded) to equal the pre-apply capture. Adding rules to a table that already exists has no proven inverse and is refused before any write, so a second NAT rule on a device that already carries the NMAS table still cannot run in Complete mode.

The disposable flow was inside client (FRR peer) to DUT `eth3`, DUT `nmasout0` to an outside endpoint in a namespace of the DUT container. A UDP echo server at the outside endpoint reported the source address it saw: the client's own address before apply, the DUT's outside address with the table applied, and the client's own address again after compensation. With the table applied the client received the return datagram, which proves connection state (the conntrack table itself is not readable in that container), and a client source outside the translated prefix arrived untranslated. The container's own Docker DNS `table ip nat` was present throughout and unchanged. The operator postcheck (`NAT_RULE_PRESENT` over the live `nat` fact group) passed.

The disposable FRR image ships no `nft` binary (production R3/R4 do). The probe installs the `nftables` package as a lab prerequisite and purges it afterwards; package set, apt lists, namespace, addresses, routes and ruleset are compared with the captured baseline.

`NAT_NAT44_STATEFUL` renders the identical table, so it passed the same live stages. It remains unsupported because the import parser cannot distinguish it from PAT (`parser_import` fails with `PARSER_ABSENT`); the model would need a rendered difference before that cell can turn green.

## Prompt 4 checkpoint (local worktree, not merged)

| Measure | Count |
| --- | ---: |
| Total cells | 396 |
| Assessed | 396 |
| Unassessed | 0 |
| Supported | 36 |
| Unsupported | 360 |

Eight cells became supported: Ubuntu/FRR `service_policy.NAT_NAT44_STATEFUL`, `interface.MANAGEMENT`, `interface.ROUTED_PHYSICAL`, and cEOS `interface.ROUTED_PHYSICAL`, `ACCESS`, `TRUNK`, `SUBINTERFACE`, `SVI`. Only those cells and the FRR cells sharing changed probe/executor code (`NAT_NAT44_PAT`, `interface.SUBINTERFACE`, `interface.SVI`) were reassessed.

**FRR stateful NAT44.** On nftables PAT and stateful NAT44 are the same conntrack-based `masquerade`; there is no behavioural difference to render. A stateful rule now carries the NMAS-owned rule comment `nmas-nat44-stateful`, which the kernel stores with the rule and `nft list ruleset` prints back. The renderer emits it, the import parser maps it to mode `STATEFUL` (a rule with any other comment is not imported as an NMAS rule), and the executor accepts only that exact comment. The live probe additionally parses the live ruleset and requires the intent mode to be recovered. A PAT table already on the device does not satisfy a stateful Configlet.

**FRR management import.** Linux has no management interface type, so the parser now takes the addresses the device is managed through (inventory `address` / `address_v6`) and classifies the plain physical port that holds one as `MANAGEMENT`, keeping its addresses, MTU and admin state. An SVI, subinterface, bridge, bond or loopback holding that address keeps its kind, so the in-band `Vlan200` model of production R3/R4 imports exactly as before. No DHCP conversion is involved. Live: `eth0` of the disposable FRR node (docker management address) imported as `MANAGEMENT`, `eth1` as `ROUTED_PHYSICAL`.

**FRR existing links.** The Linux executor captures an existing link (`ip -j addr show`: MTU, admin state, master, addresses) before changing it, sends only the rendered fields that differ, and compensates by restoring the captured MTU and comparing the whole captured link. The renderer already omits the MTU line when intent carries no MTU, so an omitted MTU is never overwritten. An admin-state change of an existing interface, an MTU below 1280 on an interface with IPv6, lowering the MTU under a child interface, and an enslaved interface fail closed. Live: `eth1` went 9500 to 1500 and back to 9500 with every other link property identical.

**cEOS interfaces.** One captured-section inverse (`interface_snapshot_inverse`) serves all five kinds. For an interface block that already exists it never uses `default interface`: each new line that introduces a setting the captured section did not hold is undone on its own (`no <line>` for coexisting lines, `default <setting>` for single-valued ones), then every captured child line is re-sent verbatim. Re-sending restores replaced values and anything EOS dropped as a side effect of a routed/switched mode change, and leaves unmodelled lines untouched. A captured section with a redacted value fails closed. New SVIs, subinterfaces and VLANs are removed as created objects. The inverse is derived again right before each apply and compensation is verified against the full running-configuration digest captured at that moment, so a plan's Configlets (parent, interface, addresses) compensate in reverse order.

Live, each kind ran on pre-existing `Ethernet2` against the Linux peer, with a negative control before apply and after compensation: routed IPv4/IPv6 pings; access VLAN44 reachable while VLAN45 stayed isolated; trunk native VLAN44 and tagged VLAN45 both reachable; tagged subinterface IPv4/IPv6; SVI IPv4/IPv6 through a member port. All but SVI ran twice, on a pristine port and on a port already carrying a description, an unmodelled `load-interval 30`, and either an access VLAN (for kinds that make it routed) or routed addresses (for kinds that make it switched). In every run the running configuration and the `Ethernet2` section were identical to the pre-apply capture.

That second scenario exposed an import defect: EOS keeps `switchport access vlan` on a port made routed, and the cEOS parser classified such a port as `ACCESS`. `no switchport` now decides the kind.

**Limits.** VLANs, SVIs used as ping endpoints, `ip routing` / `ipv6 unicast-routing` and all peer state are lab prerequisites. cEOS `interface.LOOPBACK` and `interface.MANAGEMENT` were not re-run live; their Configlets still take the unchanged state-based path. The legacy per-feature cEOS interface probes in `isolated_live.py` are superseded by `batch_ceos_interfaces.py` but were left in place. SR Linux execution was not started: 18 SR Linux cells render but have no executor, and 17 of them also fail `parser_import`.

**NAT rule merging.** When the device already holds `table ip DEVICE_BUILDER_PAT` in exactly the NMAS shape, a further rule is appended with `nft add rule` and compensation puts the chain back to the captured rule list in one atomic `flush chain` + `add rule` transaction, verified by the whole-ruleset digest. A table of that name holding anything else, or a rule that would duplicate an existing match under the other intent mode, is refused before any write. Whether to create or append is decided right before apply, so two NAT rules of one plan create then append and compensate in reverse. Both FRR NAT cells were re-proven live with a second scenario: a pre-existing NMAS rule for another prefix kept translating its own traffic before, during and after, while the appended rule translated the client and was removed again. nft lists a host prefix without `/32`; rules are compared in one canonical form.

Tests: the focused executor/parser modules and the affected 905-test subsystem run passed. Full local and hosted Tier-3 remain for Prompt 6. The disposable lab is running 4/4 at its baseline; production `srlceos01` was not contacted.

## Prompt 5 checkpoint (local worktree, not merged)

| Measure | Count |
| --- | ---: |
| Total cells | 396 |
| Assessed | 396 |
| Unassessed | 0 |
| Supported | 46 |
| Unsupported | 350 |

Ten cells became supported, five on each of Nokia SR Linux and Cisco IOS XE: `interface.LOOPBACK`, `interface.ROUTED_PHYSICAL`, `interface.SUBINTERFACE`, `routing.STATIC_IPV4` and `routing.STATIC_IPV6`. `interface.MANAGEMENT` was assessed live on both platforms and stays unsupported. Supported cells per platform are now cEOS 21, Ubuntu/FRR 15, SR Linux 5, IOS XE 5, IOS XR 0 and SONiC 0.

**SR Linux executor.** `SrLinuxExecutor` is registered in the execution registry. It sends each Configlet as one atomic gNMI CLI-origin Set, derives the inverse from a gNMI Get of the running configuration taken right before apply, and accepts compensation only when the configuration tree is identical to that capture. One shared module (`core/services/srlinux_model.py`) converts rendered set paths, gNMI JSON_IETF and the import tree into each other, so the renderer, `parser_srlinux` and the executor use the same list-key model. Statements outside that verified model (OSPF, BGP, ACL, DHCP relay) are refused, which is why the remaining renderable SR Linux cells record `EXECUTOR_REFUSED`. `health.live` reads interface, address and route state over allowlisted gNMI Get, so the operator postcheck evaluators run unchanged.

**SR Linux renderer corrections.** The isolated 24.10.7 node rejected or ignored four things the fixtures had accepted: an address family needs an explicit `ipv4|ipv6 admin-state enable`; the next-hop list is `nexthop`; the port `mtu` is a layer-2 value, so intent MTU renders as the subinterface `ip-mtu`; and a `vlan-tagging true` port cannot hold an untagged routed subinterface 0.

**SR Linux live behaviour (lab `nmas-cap-validation`, `e1-1` to FRR `eth2`).** Each supported cell ran on a pristine node and on a node already holding related configuration: operator postcheck over gNMI state, live import through `parser_srlinux`, traffic from the node's own network-instance, then exact restoration. `MANAGEMENT` stays red because `mgmt0` is DHCP-addressed and SR Linux refuses a static address while the DHCP client exists.

**IOS XE executor.** `IosXeExecutor` is registered for `cisco_c8000v_iosxe` only; IOS XR inherits nothing from it. It applies each Configlet in Netmiko configuration mode, derives the inverse from the running configuration captured right before that Configlet, and accepts compensation only when the running configuration is identical to the capture. A Configlet that would replace the primary address of, shut down or re-home the interface carrying the executor's own SSH session is refused at preflight with `MANAGEMENT_SESSION_AT_RISK`. `health.live` reads interface, address and route state from allowlisted `show` commands. OSPF, BGP and RIP have no IOS XE executor path.

**IOS XE live behaviour (lab `nmas-cap-iosxe`, `Gi2` to the Linux peer).** Each supported cell ran on a pristine router and on one already holding related configuration, including a replaced primary address: operator postcheck, live import through `parser_iosxe`, pings from the router, exact restoration. `MANAGEMENT` stays red by design, through the session guard above. Two device behaviours affect comparisons: IOS XE rewrites the `crypto pki trustpoint SLA-TrustPoint` enrollment by itself after boot, and a deleted subinterface lingers as "deleted" in `show ip interface brief` until reload.

**Limits.** Both platforms cover interfaces, addresses and static routes only. Nothing here applies to IOS XR or SONiC.

**Tests.** The boundary contracts now name every module allowed to import a device library and cover the IOS XE show allowlist and the SR Linux gNMI state queries. The `core.tests` modules outside Tier-3 passed at `a82ca03` except for the following, which fail identically at the Prompt 4 head `e00b228` and are owed to Prompt 6:

- `core.tests.test_bootstrap` and `test_bootstrap_views`: 91 failures and 1 error (`BASELINE_UNHEALTHY`).
- `test_contracts`: "exactly one process spawn in the whole engine" finds 5, and the forbidden token `vtysh` appears in `execution/codes.py`.
- `test_config_workflows`: the widget catalogue `bgp_neighbor` mode assertion fails (`'COMPLETE_OR_PARTIAL' != 'PARTIAL_UAT_ONLY'`).

Full local and hosted Tier-3 remain for Prompt 6. Both disposable labs are still running; production `srlceos01` was not written to.

## Disposable labs and actual observations

- `/home/student/clab-quickstart/capability-validation/capability-validation.clab.yml`, lab `nmas-cap-validation`, management network `172.31.248.0/24`: cEOS `4.36.2F`, Ubuntu/FRR `8.4.4`, SR Linux image `24.10` (running `24.10.7-191`) and a Linux peer. cEOS/FRR loopbacks were added, read back through NMAS, compensated and proved absent. cEOS and FRR IPv4/IPv6 static routes were applied by the registered NMAS executors, found in normalized readback, then compensated and proved absent. FRR kernel route selection matched the isolated peer. The first IPv6 FRR readback raced convergence and failed closed; a bounded retry was added and the repeat passed with restoration. cEOS OSPFv2 and OSPFv3 reached FULL with the FRR peer and were read/imported, then manually removed. cEOS BGPv4 and BGPv6 reached ESTABLISHED and exchanged a prefix in each direction; NMAS rendered/applied the cEOS process, neighbor, remote AS and network, then a native inverse restored both peers. FRR's default eBGP policy gate required an explicit disposable peer setting. The cEOS OSPFv3 renderer's cost/network syntax was corrected after the live device rejected the old syntax; the import parser was updated accordingly. Disposable cEOS routing prerequisites and peer MTU/RA settings were reverted. These runtime findings do not claim NMAS renders or compensates the prerequisites.
- The isolated lab was deployed again for cEOS RIPv2, RIPng, IS-IS and EIGRP. RIPv2 was enabled by the NMAS renderer/executor and both peers learned the other's loopback prefix. The cEOS RIP renderer was corrected to include `no shutdown`; unsupported passive-interface intent now fails closed. Native IS-IS reached an UP adjacency and exchanged prefixes both ways, while the offline NMAS probes confirmed multiple missing implementation layers. RIPng and EIGRP IPv4/IPv6 process command forms were rejected by native cEOS 4.36.2F CLI; each grammar probe proved exact running-config restoration. This lab was reused for the cEOS interface assessments below.
- On the same disposable lab, NMAS rendered and applied routed Ethernet2; IPv4 and IPv6 peer traffic passed and normalized addresses/import matched. NMAS rendered/applied ACCESS VLAN44 and TRUNK native VLAN44/tagged VLAN45; EOS-to-peer pings passed on both paths and live import matched. EOS suppressed the default ACCESS mode in running config, so the cEOS importer now infers ACCESS from its access VLAN. Each probe restored the original Ethernet2, VLAN/SVI and peer state. The branch lacks NMAS compensation for modifying an existing physical port, so all three remain unsupported.
- NMAS rendered/applied a tagged Ethernet2.44 child above Ethernet2; IPv4 and IPv6 tagged peer traffic passed, normalized read/import matched, and NMAS compensated the child. Its physical parent needed a manual inverse. The fixture's duplicate parent/child addresses were corrected, and cEOS subinterface MTU now fails closed because the live image rejected that command. NMAS also rendered/applied VLAN44/Vlan44; untagged IPv4/IPv6 traffic and read/import passed, and a native inverse restored the SVI, VLAN and parent. Full NMAS compensation remains unproven for both cells.
- The disposable Management0 retained its primary IPv4 and IPv6 while NMAS applied an additive secondary IPv4 address through the address executor path. A peer ping, normalized live read, native import, NMAS compensation and exact interface-config restoration passed. The management cell is supported for this tested secondary-address operation.
- After this checkpoint, Containerlab destroyed only `nmas-cap-validation` using its exact topology and `--cleanup`. `containerlab inspect --all` showed only production `srlceos01`, and its exact topology inspection showed all 15 nodes running.
- `/home/student/clab-quickstart/capability-validation/cap-iosxe.clab.yml`, lab `nmas-cap-iosxe`, management network `172.31.249.0/24`: a disposable vrnetlab Catalyst 8000V booted and became healthy; authenticated SSH reports IOS XE `17.06.01a`. A rendered loopback was applied, imported from live running configuration, found in the route table, removed and proved absent. This is device-side evidence only, not an NMAS IOS XE executor.
- SONiC boots from a `-snapshot` QEMU VM with loopback-only SSH forwarding on `127.0.0.1:2233`. The running build reports `SONiC.master.1236848-ad5af6706`. A loopback/address were added with the native configuration CLI, read through ConfigDB JSON and the NMAS parser, deleted and proved absent. This is device-side evidence only, not an NMAS SONiC executor.
- No IOS XR qcow2/container image was found in the canonical image tree or local Docker inventory. Each IOS XR cell was still exercised through its available offline paths and has a referenced runtime-unavailable finding. No IOS XR live support is inferred from IOS XE.

Both named Containerlab labs and the SONiC snapshot VM were stopped after the first checkpoint. The temporary decompressed SONiC disk and copied C8000V qcow2 were removed; canonical image artifacts were preserved. The small `nmas-cap-validation` lab was subsequently redeployed for cEOS IPv6/OSPF tests and destroyed again, then redeployed for this BGP/OSPFv3 checkpoint and destroyed through its exact topology path after baseline restoration. Its generated lab directory was removed with Containerlab's `--cleanup`. No production device, VLAN200 address, or unmanaged R5/WebServer/H1–H4 was changed. Image build products remain outside the Git worktree; none is committed.

## Implementation and test state

This branch adds the append-only `CapabilityAssessment` model/migration, real offline probe harness, an explicit evidence-completeness gate, detail-page assessment metadata, isolated live probes, SR Linux live-JSON parser/quoting fixes, and a strict incremental FRR static-route executor with inverse. The public CLI never pushes through `verify-matrix`; isolated write actions require `--allow-write` and hard-pin the lab target. Credentials are provided at invocation time and are not stored in the repository or ledger.

Focused tests: 48 capability/SR Linux tests passed; 27 executor/exhaustive/eligibility tests passed after FRR static support. The relevant 380-test subsystem suite passes. Its first run exposed a historical expectation that FRR static routes were unsupported; that test now uses still-unsupported FRR OSPF and the entire suite was rerun successfully. The first full local Tier-3 run exposed two more stale FRR-static assumptions; after narrowing those contracts, the second full local Tier-3 run **passed**, including all 1,820 Django tests (see [`tier3-local.json`](evidence/v2-phase4-exhaustive/tier3-local.json)). The current interface checkpoint passed focused suites of 59, 65 and 78 tests. Full local Tier-3 has not run on current HEAD.

The first checkpoint was pushed as `5dabc24` and draft PR #39 passed its hosted Tier-3 run. The subsequent cEOS IPv6/OSPF and parser-strengthening edits are **not yet covered by that result**; their focused tests pass, but full local and hosted Tier-3 must be rerun before Phase-4 acceptance. PR #39 remains draft and is not ready for human merge.

The follow-up focused capability/executor/SR Linux suite passed (66 tests), and the OSPFv2 isolated live probe passed twice with full baseline restoration. The first three OSPF attempts did not form an adjacency: the peer MTU was initially mismatched, and the disposable cEOS had `no ip routing`. Both causes were investigated and the harness now supplies/reverts those prerequisites explicitly. Do not represent those initial attempts as successful sessions.

Prompt 2 added semantic cEOS/FRR routing postchecks, bounded routing inverses, incremental FRR OSPF executor commands and disposable OSPF pair probes. The 396/396 assertion in `test_capability_batch_harness.py` is a continuing gate for later prompts. The affected 401-test subsystem suite passed after the implementation changes and stale eligibility fixtures were updated. A focused 55-test routing/executor/health run also passed. Full local and hosted Tier-3 remain for Prompt 6.

After the last Prompt 2 OSPF probe, FRR eth1 had only its link-local IPv6 address and original MTU 9500; the FRR routing daemons were stopped as at the lab baseline; cEOS had no OSPF/BGP/RIP process and retained `no ip routing`. Production `srlceos01` remained 15/15 running. No production routing configuration was touched.

After Prompt 3 the disposable `nmas-cap-validation` lab is still running with four nodes at its tested baseline: no global addresses on the FRR/peer data links, no `nmascap0`/`nmasout0` interface or probe namespace, no `nft` package or NMAS table, no running FRR daemon on either FRR container, and cEOS without OSPF/BGP/RIP and with `no ip routing`. Production `srlceos01` remained 15/15 running and was not written to. The 14 focused FRR routing/NAT executor and semantics tests and the affected 867-test subsystem run (routing, FRR, health, execution, capability, parser, planning, renderer, template, import and precheck modules) passed after the change. That run also corrected one assertion in `test_change_precheck.py` that had been failing since the Prompt 2 commit, which gave the routing requirements real evaluators. Full local and hosted Tier-3 remain for Prompt 6.
