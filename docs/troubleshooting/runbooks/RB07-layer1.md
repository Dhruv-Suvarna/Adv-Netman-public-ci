# RB07 v1.0.0 -- Layer 1 physical and framing degradation

Separate optics, cable, FEC/negotiation and platform causes of framing errors; never act on counters that were reset.

> Stage 1 is deterministic and read-only. Unavailable evidence is UNKNOWN. Results in this document come from SIMULATED replay fixtures unless stated otherwise (see `deterministic-engine.md`).

## Symptoms
CRC/FCS/framing errors, FEC uncorrected codewords, flapping optics, one-directional loss.

## Triggering signals
Error-rate alarms, DOM alarms, link degradation.

## Production contracts
The link, its NetBox cable record and the services on it.

## Worked before / what changed
Counter-reset events, approved optic/cable work, learned error rates.

## Scope
One interface and its peer.

## Collectors and permissions
Read-only counters, DOM, FEC, speed/duplex, L1 events, component alarms; counters are never cleared.

## Baselines
Intent = NetBox cable type/length; historical = per-interface error rates; golden = speed/FEC settings.

## Hypothesis tree and tests
The tables below are generated from the executable DAG (`python -m core.services.troubleshooting.runbooks write`); edit the code, not the table.

## Hypothesis tree
Each hypothesis lists the tests that confirm or eliminate it; counter-evidence from passing tests is kept in the report.

<!-- DAG:BEGIN -->
Runbook-Id: RB07
Runbook-Version: 1.0.0
Strategies: bottom-up, divide-and-conquer

| Step | Test | Title | Layer | Hypothesis | Class | Hard prerequisite | Expected (healthy) |
|---|---|---|---|---|---|---|---|
| 1 | PH02 v1 | Counter reset / wrap detection | L1 | H-counters | CONTEXT | - | counters monotonic, no reset |
| 2 | PH01 v1 | CRC/FCS/align/runt/giant/LOS/LOF vs baseline | L1 | H-signature | CONTEXT | - | framing counters at baseline |
| 3 | PH03 v1 | Both ends' transceiver identity and compatibility | L1 | H-optics | DISCRIMINATING | - | supported, matched transceivers |
| 4 | PH04 v1 | DOM thresholds (Rx/Tx power, temperature) | L1 | H-optics | DISCRIMINATING | - | DOM within thresholds |
| 5 | PH05 v1 | Cable type/length vs optic reach | L1 | H-cable | DISCRIMINATING | - | media within limits |
| 6 | PH06 v1 | Speed / FEC / duplex negotiation (both ends) | L1 | H-neg | DISCRIMINATING | - | FEC, speed, duplex agree |
| 7 | PH07 v1 | Errdisable, driver, power and thermal alarms | L1 | H-platform | DISCRIMINATING | - | no platform alarm |
| 8 | PH09 v1 | Direction localisation: peer receive errors and Tx power | L1 | H-optics | DISCRIMINATING | - | no one-directional fault |
| 9 | PH08 v1 | Port-channel member health and blast radius | CTRL | H-blast | SAFETY | - | blast radius evaluated (read-only) |

| Hypothesis | Statement | Domain | Tests |
|---|---|---|---|
| H-counters | Counters were reset or wrapped, so the trend cannot be trusted | L1 | PH02 |
| H-signature | A framing/signal error signature exists | L1 | PH01 |
| H-neg | FEC/speed/duplex negotiation mismatch | L1 | PH06 |
| H-optics | Optics fault or incompatibility (transceiver, DOM, direction) | L1 | PH03, PH04, PH09 |
| H-cable | Cable/media beyond design | L1 | PH05 |
| H-platform | Platform, driver, power or thermal alarm | system | PH07 |
| H-blast | Blast radius of an intervention | ctrl | PH08 |

<!-- DAG:END -->

## Tests and expected outcomes
Every test states its healthy expectation before execution, records the actual output with evidence ids, interpretation and next action. PASS = expectation held; FAIL = fault condition present; INCONCLUSIVE/UNAVAILABLE carry a specific reason; SKIPPED rows carry NOT_APPLICABLE / UNSAFE_TO_EXECUTE / SKIPPED_AFTER_CONFIRMED_ISOLATION with the exact reason.

## Platform adaptations
Virtual platforms may expose no DOM or FEC: UNAVAILABLE, not PASS.

## Causal isolation
Error signature, counter-reset validity, transceiver identity, DOM, cable, FEC/speed/duplex, platform alarms, blast radius, direction.

## Alternative explanations
Incompatible optics, DOM out of range, cable class/reach, FEC mismatch, platform alarm, one-directional fibre fault.

## Safe stopping criteria
Stop after a proven L1 cause; a counter reset makes the error trend inconclusive rather than healthy.

## AI handoff gate
Only when physical evidence is contradictory or unavailable.

## Proposed remediations
Proposals only; nothing here is executed. Each is Tier 2 or higher unless it is explicitly 'none', requires operator approval and is subject to NMAS governance.

* **F-direction** (tier 2): replace the transmitter/fibre strand of the faulty direction. Approvals: operator acknowledgement. Never: blind port bounce.
* **F-dom** (tier 2): clean connectors, then replace optic/fibre. Approvals: operator acknowledgement, maintenance window. Never: blind port bounce.
* **F-fec** (tier 2): align FEC (or speed) with the golden/intent value. Approvals: operator approval, traffic-safety proof: the port flaps on renegotiation. Never: port bounce as a fix.
* **F-reach** (tier 2): move to a longer-reach optic or shorter run. Approvals: operator acknowledgement. Never: n/a.
* **F-transceiver** (tier 2): replace with a compatible transceiver pair. Approvals: operator acknowledgement of physical intervention, maintenance window or proof of alternate path. Never: blind port bounce, clear counters to hide errors.

## Pre- and post-tests
* F-direction: before PH09, PH08; after PH01, PH09.
* F-dom: before PH04, PH09, PH08; after PH01, PH04.
* F-fec: before PH06, PH08; after PH01, PH06.
* F-reach: before PH05; after PH01, PH04.
* F-transceiver: before PH03, PH08; after PH01, PH04, PH06.

## Rollback
Reinstall the original optic/cable; restore FEC/speed settings.

## Soak
Optic or FEC changes in the soak window are correlated, not blamed.

## Documentation example
FEC rs vs none with 900 uncorrected codewords and CRC on both ends while DOM is healthy -> F-fec; low Rx power with errors on one side -> F-dom.
