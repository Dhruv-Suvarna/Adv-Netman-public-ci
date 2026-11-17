# RB01 v1.0.0 -- Link flapping

Establish whether an interface is unstable, why (planned action vs physical/protection/system cause), and what a safe response is.

> Stage 1 is deterministic and read-only. Unavailable evidence is UNKNOWN. Results in this document come from SIMULATED replay fixtures unless stated otherwise (see `deterministic-engine.md`).

> **Unattended intake (2026-11-17):** live monitoring classifies this fault deterministically before any model call, and records a remediation decision (`faults.decide`). See `../MULTI_FAULT_CLASSIFICATION.md`. Operational-down, flapping, degradation, routing and reachability faults are `DIAGNOSE_AND_ESCALATE`: no automatic bounce, shutdown, counter clear, routing or process change. An administrative enable is valid only for an interface observed administratively down.

## Symptoms
An interface or link goes down/up repeatedly, a LAG member churns, or monitoring reports `LINK_FLAP`/`INTERFACE_DOWN` bursts.

## Triggering signals
Syslog link up/down, SNMP linkUp/linkDown traps, gNMI `oper-status` on-change events, alert-storm group whose primary is a physical alarm.

## Production contracts
The interfaces/flows that ride the link (NetBox cable and service intent) and any redundancy that is *already* configured. Redundancy is never invented.

## Worked before / what changed
Compare transitions per hour with the learned normal (baseline 2), look for approved changes/maintenance windows on either end and an active golden soak window.

## Scope
One interface and its NetBox-recorded peer; both ends are read. LAG members and downstream devices are added from intent.

## Collectors and permissions
Read-only: interface link events, transceiver DOM, error rate samples, errdisable state, LACP member state, system events. No bounce, no counter clear.

## Baselines
Intended design = NetBox cable + golden bundle; historical normal = per-interface transition and CRC rate per hour; production contract = flow SLO.

## Hypothesis tree and tests
The tables below are generated from the executable DAG (`python -m core.services.troubleshooting.runbooks write`); edit the code, not the table.

## Hypothesis tree
Each hypothesis lists the tests that confirm or eliminate it; counter-evidence from passing tests is kept in the report.

<!-- DAG:BEGIN -->
Runbook-Id: RB01
Runbook-Version: 1.0.0
Strategies: bottom-up, divide-and-conquer

| Step | Test | Title | Layer | Hypothesis | Class | Hard prerequisite | Expected (healthy) |
|---|---|---|---|---|---|---|---|
| 1 | LF01 v1 | Transition history and rate vs baseline | L1 | H-phy | CONTEXT | - | fewer than 3 down transitions per window; at baseline |
| 2 | LF02 v1 | Administrative shutdown / planned maintenance | CTRL | H-admin | CONTEXT | - | no administrative cause |
| 3 | LF07 v1 | Port security, errdisable, link-flap detection | L2 | H-admin | DISCRIMINATING | - | no protection event |
| 4 | LF03 v1 | Optics DOM, transceiver support, speed/autoneg (both ends) | L1 | H-phy | DISCRIMINATING | - | optics healthy and compatible |
| 5 | LF04 v1 | Error bursts vs transitions (CRC/FCS), counter-reset aware | L1 | H-phy | DISCRIMINATING | - | no bursts near drops |
| 6 | LF05 v1 | Peer-side interface health (both ends) | L1 | H-phy | DISCRIMINATING | - | peer shows no matching drops |
| 7 | LF06 v1 | LACP / port-channel member churn | L2 | H-lag | DISCRIMINATING | - | member bundled and stable |
| 8 | LF08 v1 | Power, controller, system logs | CTRL | H-sys | DISCRIMINATING | - | no platform event |
| 9 | LF09 v1 | Topology/path change, service impact, existing alternate (read-only) | CTRL | H-impact | SAFETY | - | alternate evaluated, never assumed lossless |

| Hypothesis | Statement | Domain | Tests |
|---|---|---|---|
| H-admin | Planned administrative action, maintenance or port protection | ops | LF02, LF07 |
| H-phy | Physical-layer cause: optics, cable, signal errors, medium | L1 | LF01, LF03, LF04, LF05 |
| H-lag | LACP/port-channel member churn | L2 | LF06 |
| H-sys | Power/controller/system event | system | LF08 |
| H-impact | Service impact and containment options | ctrl | LF09 |

<!-- DAG:END -->

## Tests and expected outcomes
Every test states its healthy expectation before execution, records the actual output with evidence ids, interpretation and next action. PASS = expectation held; FAIL = fault condition present; INCONCLUSIVE/UNAVAILABLE carry a specific reason; SKIPPED rows carry NOT_APPLICABLE / UNSAFE_TO_EXECUTE / SKIPPED_AFTER_CONFIRMED_ISOLATION with the exact reason.

## Platform adaptations
Platforms that cannot report DOM (virtual cEOS/IOS XE/FRR) yield UNAVAILABLE for the optics test; no value is invented.

## Causal isolation
Planned administrative action is separated from physical instability first (admin reason + maintenance/approved change), then both ends are compared, then optics and error bursts relative to the transitions.

## Alternative explanations
Planned maintenance, port-protection (errdisable/link-flap-detection), LACP churn, power/controller events, one-sided local port fault.

## Safe stopping criteria
Stop after a causal finding with confidence >= 0.85 that is not contradicted by impact tests. Context and safety tests are always executed; skipped tests keep an applicability row.

## AI handoff gate
Allowed only when the deterministic outcome is INCONCLUSIVE_ESCALATED and every applicable safe test was examined; a single flap observation never justifies handoff.

## Proposed remediations
Proposals only; nothing here is executed. Each is Tier 2 or higher unless it is explicitly 'none', requires operator approval and is subject to NMAS governance.

* **F-errdisable** (tier 2): correct the policy or port-protection setting. Approvals: change approval. Never: n/a.
* **F-medium** (tier 2): swap optic/cable one end at a time. Approvals: operator acknowledgement, alternate path proof from LF09. Never: blind port bounce.
* **F-optics** (tier 2): replace or clean transceiver/cable (physical, external work). Approvals: operator acknowledgement of physical intervention, maintenance window. Never: blind shut/no shut, counter clear to hide errors.
* **F-planned** (tier 1): none: expected behaviour; keep observing until the planned work ends. Approvals: none. Never: reverting the planned change.

## Pre- and post-tests
* F-errdisable: before LF07; after LF01.
* F-medium: before LF05, LF09; after LF01, LF05.
* F-optics: before LF03, LF05, LF09; after LF01, LF04.
* F-planned: before LF02; after LF01.

## Rollback
Physical work is restored by reinstalling the original optic/cable; no software rollback is implied. Configuration drift alone never triggers rollback.

## Soak
If an active golden soak overlaps the first flap the correlation is recorded (blame=false); the candidate is not rolled back without a causal test.

## Documentation example
Fault: 6 down transitions in 50 minutes on r1:Eth2 and r2:Eth1, CRC bursts within 120 s of each drop, Rx power near the low alarm -> F-medium/F-optics. Recovery: stable link -> expected behaviour.
