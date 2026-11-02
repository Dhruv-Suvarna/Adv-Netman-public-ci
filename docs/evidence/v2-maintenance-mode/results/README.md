# Maintenance Mode: real cEOS / FRR sandbox evidence (2026-10-17, pre-merge review of PR #58)

Disposable sandbox `isisbx` only (labels `nmas-sandbox=isisbx`); no production device, NetBox or deployed database was
involved. Harness: `../sandbox/run.py`; scratch settings `../sandbox/maintenance_sandbox_settings.py`. Each `results.json`
holds one entry per scenario (`ok` and the facts it was judged on); `events.log` is the run's timeline, every NMAS
operation event included.

| Directory | Scenarios | Notes |
|---|---|---|
| `migration/` | the sandbox's static-to-IS-IS migration (`nmas_lifecycle.py forward`) | brings the sandbox to production's post-migration state: 48 operations, 0 of 858,898 probes lost, 0 covers left |
| `A_readonly_refusals/` | 1, 3, 12, 11, 9, 2, 10 | all PASS. Its 4-6 entries FAILED on a harness defect (the sandbox transport refused the shield gate's `ping`); superseded by B |
| `B_writes/` | 4, 5, 6, 7, 8, 14, 13 | all PASS. Its 11b entry FAILED on the probe-file defect it found (route-shield probes); superseded by C / D |
| `C_southbound/` | 5b, 11b | 5b PASS (both directions, no core cover, workload running: 0 of 147,916 lost). Its 11b used the earlier recovery (the restore wrote, failed a gate and compensated); superseded by D |
| `D_crash_recovery/` | 11b | the final recovery: killed at a step boundary -> `ENTRY_ABORTED_RESTORED`; killed inside the northbound stage -> escalated with nothing written |

Code between batches: A and B ran before the probe-file fix and the recovery's mid-stage refusal; those changes affect
only probe file names, probe deadlines, a dead worker's probes and the restore precheck of an interrupted stage. C ran
with the probe fixes; D with the final code.
