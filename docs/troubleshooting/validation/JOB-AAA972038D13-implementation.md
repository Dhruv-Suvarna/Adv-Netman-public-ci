# JOB-AAA972038D13 — validated public reconciliation implementation

claude_b delivered the additive read-only service, command and initial 10 tests. claude_a delivered the inventory evidence matrix at `/home/student/Scripts/JOB-AAA972038D13-inventory-evidence.md`. The master validator corrected both deliverables following checkpoint #29 and added six regressions. Existing dirty overlay, production, legacy repository, lab assets and checkpoints were preserved. No identities, approvals, host keys, configuration or production database were changed; no migration or remote write was performed.

## Corrected evidence semantics

`nmas_reconcile_inventory [--json] [--fail-on-gap]` reads configured local inventory/registry sources only. Output is LOCAL, never automatically LIVE, GATEWAY_ATTESTED or verified production evidence. The report defines SUPPLIED, HISTORICAL, LOCAL, GATEWAY_ATTESTED and LIVE explicitly. A gateway-attested unit test verifies source behavior only. Recorded lifecycle states remain recorded claims; current management status and provenance remain UNKNOWN. Historical linked records and old code comments do not establish current identity or authority.

Registry-only identities are REGISTRY_ONLY with CURRENT_AUTHORITY_NOT_ESTABLISHED, preserved rather than inferred authoritative. Source conflicts cannot be REGISTERED. A missing registry or a failure during the second registry read invalidates the snapshot rather than reporting absent devices. A NetBox ID is not a comparison: NETBOX_NOT_CHECKED always remains. Recorded path approvals, broker-reference presence, pins and verifier/registrant inequality are reported as local indicators only: current identity and approval provenance remain unchecked. No secrets or broker contents are read. `--fail-on-gap` fails for evidence-only gaps as well as absent rows, conflicts, unknowns and source discrepancies.

## Focused verification

Gateway command: `python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting core.tests.test_reconcile_inventory`

- Run: `pt49049d99287a`; evidence sequence `6221`.
- Outcome: **16 tests passed**, Django system check clean; no fixtures started.
- Evidence hash: `438b9b6e7e30e1a40fa89f04481d44b760586dac02b25d0a301d213ec83e02e8`.
- Exact source: HEAD `4f950b36f97188f4d7b2c879006c472d9607bace`, branch `troubleshooting/job-9aa10b4e7ca7-port`, dirty source tree SHA256 `47fce735b3b1a9251b7db242afb122ab28759b85ac4a2b842a1258bc228a26e2`, unchanged during execution. Documentation was updated afterward; tested Python files unchanged.
- Coverage includes preservation/idempotence, exclusion, platform/name/source conflicts, unavailable registries including mid-read failure, historical-only evidence, unknown provenance, NetBox-reference negative case, CLI and evidence-only fail-on-gap behavior.
- Earlier worker run `pt35935bf85a53`: 85 reconciliation/resolver/lifecycle tests passed, evidence hash `acdf45b4ac8a62bdf37aa20f2b9f074c8f14fba1124ab1fa13b4be5d49def2b1`. Reconciliation changed afterward and was rechecked above; unchanged resolver/lifecycle suites were not repeated.

These are GATEWAY_ATTESTED unit tests against a disposable test DB through migration 0038, not production registry, NetBox or live-device observations. Production migration-0035 compatibility has not been demonstrated. No deployed compatibility is claimed.

## Pending operator evidence and implementation plan

Use the corrected inventory report sections 3, 7, 8 and 10 for the device matrix, exact workflow calls, ordered approval gates and minimum safe exports. No migration is introduced by these additive files, but public dirty-overlay deployment must be reviewed separately for production 0035 compatibility before use. First obtain timestamped production registry/admission/history/path/attachment exports and live NetBox comparison, plus authoritative later-lab inventory linking R6/R7/R8/S5 to stable identities. Never infer their provenance from Lab 8 comments.

After evidence review and separate authorization, use existing-device adoption only for R1,R3,S1,S2,S3,S4,mgmt_swt with individually approved roles and approver. Preserve R2/R4 and R6/R7/R8/S5 IDs and admission records. Keep R5 and hosts excluded. Design and approve exact management paths/attachments, dedicated broker reference names and independently sourced public host-key pins before observation collection. Independent identity approval requires authenticated observations and distinct principals under existing policy. Existing operational originals remain LEGACY_PREEXISTING; no new commissioning is proposed.

Production and NetBox exports remain unavailable. Exact approved paths, trusted pin evidence, broker ownership and R6/R7/R8/S5 current authority/status cannot be supplied by source inspection or unit tests. No claim that all devices are admitted or operational is justified. Task remains incomplete on external evidence gates.
