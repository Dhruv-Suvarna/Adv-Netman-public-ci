# V2 Phase 9 — a RIP instance disabled in intent

## The defect

Every platform renderer emitted only the comment `! RIP instance disabled in intent; not rendered` for a RIP instance whose
intent says `enabled: false`. Planning drops comment lines, so the Configlet was comment-only (`NO_DEPLOYABLE_CONFIG`):
nothing was sent and a running RIP process kept advertising. On cEOS the importer already reads `router rip` + `shutdown` as
`enabled: false`, so an imported disabled instance could not be rendered back to the device.

## The fix (`web/core/services/platform_drivers.py`)

| Platform | Enabled instance (unchanged) | Disabled instance |
|---|---|---|
| Arista cEOS | `router rip` / `no shutdown` / networks | `router rip` / `shutdown` / networks — the process stays configured, administratively down |
| Ubuntu/FRR | `router rip` / `version 2` / networks | refused: `UNSUPPORTED_OBJECT` (ripd has no shutdown; remove the instance to remove the process) |
| Cisco IOS XE | unchanged | refused: `UNSUPPORTED_OBJECT` (no verified IOS XE form) |
| Cisco IOS XR | unchanged | refused: `UNSUPPORTED_OBJECT` (no verified IOS XR form) |

A refusal is explicit: planning raises `PlanGenerationError(UNSUPPORTED_OBJECT)` instead of silently producing nothing. No
vendor syntax was added for a platform where it was not verified.

## Live proof (cEOS 4.36.2F, `docs/evidence/v2-phase9-closure/disabled-rip/`)

Run with `NMAS_LIVE_MODULE=core.tests.live_disabled_rip_fixture labs/decommission-isolated/run-harness.sh` on the isolated
decommission fixture. STUB (Et1 10.254.86.1/31) is the device under test; E2 (Et4 10.254.86.0/31) is the RIP peer. Every STUB
change is NMAS's own rendering, applied and compensated by `CeosExecutor` over SSH as the key-only `nmas-svc`; the fixture
console is used only for the scaffolding NMAS does not own (two loopbacks, the peer's RIP process) and its removal.

| Stage | Result |
|---|---|
| baseline | no RIP on either side; neither RIP-only prefix routed |
| enable (`no shutdown`) | E2 learns 203.0.113.0/24 and STUB learns 198.51.100.0/24 as `R … [120/2]` within 7.6 s |
| disable (`shutdown`) | both RIP routes withdrawn within 0.6 s; the running section holds `shutdown` |
| compensate disable | `COMPENSATED`; configuration digest equals the enabled digest; both routes relearned within 7.6 s |
| compensate enable | `COMPENSATED`; configuration digest equals the baseline digest; no RIP route remains |

Live finding: on a heavily loaded host cEOS answers the CLI minutes before it offers RIP — `router rip` is refused with
`% Unavailable command (not supported on this hardware platform)` until then. A clean cEOS with no other configuration showed the
same, and later accepted it. The harness waits for availability with a configuration session that it aborts, so the readiness
probe never commits configuration. The same finding exposed that `CeosExecutor` treated `% Unavailable command` as success
(its rejection markers were copied from `master.py push_eos`); the marker is now a rejection (`COMMAND_REJECTED`), with a
regression row in `test_execution_executors`. `master.py` is unchanged.
