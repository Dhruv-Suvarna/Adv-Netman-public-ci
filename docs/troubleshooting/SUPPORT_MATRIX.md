# NMAS V2 Troubleshooter support matrix (2026-11-17)

**Legend**
- **LIVE** = proven on the lab with a real fault.
- **CAT** = implemented in the diagnostic catalogue or a runbook, with unit tests, but not live-validated.
- **—** = not implemented.
- **AUTH** = autonomous execution exists only under an explicit standing owner policy for that exact device, interface and operation.

| Fault class | Detection (unattended) | Diagnosis | Proposal (typed op) | Autonomous execution |
|---|---|---|---|---|
| Interface admin-down vs intent (R2 Ethernet1) | **LIVE**: intake, campaigns 010 and 011 | **LIVE**: HC29 | **LIVE**: `interface_enable` | **LIVE + AUTH**: ARP-R2-E1-002 |
| Interface admin-down, other managed interfaces | LIVE-capable (same intake on R1, R2, R5, S1–S4) | CAT (HC29 is generic) | CAT: `interface_enable` | **No**: no policy, so the case stays with a human |
| Interface flapping / link-state (oper down, admin up) | Intake opens the case after a 30 s persistent down. A flap shorter than 30 s is suppressed, with no flap counter yet | CAT: RB01, HC03/04/05, RB07 | CAT: `interface_bounce`, `debounce_config` (HIGH/MEDIUM) | No |
| Routing adjacency failure (OSPF/IS-IS/BGP) | — (no adjacency monitor in the intake) | CAT: RB03, HC14 | CAT: `neighbor_reset`, `config_rollback` (HIGH) | No |
| Missing or incorrect route | — | CAT: HC15 (RIB), HC16 (FIB), HC17 (path) | CAT: `config_rollback`, `routing_metric_change` (HIGH) | No |
| Host-to-host reachability | — (protected-flow probes exist only inside the recovery gates) | CAT: HC27, HC17, HC10, HC06 | depends on cause | No |
| Interface errors / discards | — (gNMI collects counters, the intake does not use them) | CAT: HC05, HC20, RB07 | CAT: `counter_clear` (LOW, not traffic-affecting) | No |

## What blocks the next step, per class

1. **Deterministic observations.** In every run, the case runtime had no normalized interface admin/oper observations; diagnosis depended on Codex running live tests through the diagnostic worker. Binding the device-observation source (`NMAS_OBSERVATION_*`) to the runtime would make the deterministic stage conclusive on its own.
2. **Detection beyond interface state** needs new intake readers:
   - OSPF/BGP neighbor state (`show ip ospf neighbor | json`), compared with intended adjacencies from the templates
   - route presence for intended prefixes
   - error and discard rate from gNMI counters, against a baseline

   Each uses the same fingerprint, debounce, dedup and budget rules.
3. **Execution.** Each new class needs:
   - a typed operation with an exact Change Engine mapping (like `interface_enable` → Remove Configuration `shutdown`)
   - a scope check
   - Change Engine compensation
   - an explicit owner policy per device, interface and operation

   No broader policy exists, and none is created automatically.

## Recommended next fault type

**Interface flapping / oper-down with admin-up on R2 Ethernet1**, diagnosis-only first. It reuses:
- the live intake (already detecting it)
- the link correlation (already pairing R2 Ethernet1 with S4 Ethernet3)
- HC29, RB01 and RB07
- the same recovery scope

The gap is small: a flap counter in the intake, plus a check that Codex concludes "physical/peer" rather than proposing `interface_enable` when the interface is admin-up. That conclusion should keep `ARP-R2-E1-002` from authorizing anything: its intent gate passes, but the observed-state no-op gate should refuse. The next live campaign should prove this. Autonomous `interface_bounce` would need its own owner policy.
