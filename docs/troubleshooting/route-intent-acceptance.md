# Versioned per-prefix routing acceptance

`web/core/tests/fixtures/troubleshooting_routing/acceptance-intent-v1.json` is the reviewed acceptance intent for the frozen `srlceos01` H1-to-WebServer path. Its topology revision is pinned to `adf5fb5ac3c8bc0cbbc058595ee1207075b9cb30`, and its provenance names the topology, device templates, and captured baseline timestamp used to qualify the expectations.

The source declares IPv4 and IPv6 forward and return targets. Every device expectation names the route prefix that must cover the target, normalized route source, and acceptable next-hop set. A surviving declared ECMP member is accepted. Missing routes, wrong next hops, and unexpected route sources remain distinct classifications. An unreadable RIB is `INDETERMINATE`, never treated as a missing route.

`core.services.troubleshooting.route_intent` loads the source with a strict schema and rejects unknown fields, duplicate targets/expectations, invalid address families, non-covering routes, and next-hop family mismatches. It never derives intent from the RIB being evaluated.

The focused acceptance test performs a reversible replay campaign: it verifies the healthy dual-stack baseline, removes the R1 WebServer IPv4 route from an isolated in-memory copy, observes one `MISSING_ROUTE`, restores from the untouched baseline, proves exact equality, and obtains a clean post-check. This is restoration-safe replay evidence; it does not alter a live route or qualify as a live fault campaign. A future governed end-to-end campaign must use a disposable gateway fixture and record pre-change, fault, diagnosis/correlation, website, action/escalation, restoration, and forward/return post-check evidence.

## Unattended intake binding

`core.services.troubleshooting.intake` now evaluates this reviewed source on each configured routing pass. The deployment binds `NMAS_TS_ROUTE_INTENT_FILE`, the independently supplied `NMAS_TS_TOPOLOGY_REVISION`, and a 60-second maximum RIB age. A missing or mismatched revision refuses evaluation before any RIB read. The collector uses the intake's existing read-only console channel, timestamps every device, and treats missing, stale, future or unreadable observations as `INDETERMINATE`, never as a missing route.

Confirmed `MISSING_ROUTE`, `WRONG_NEXT_HOP`, and `UNEXPECTED_SOURCE` results use the normal intake debounce, deduplication, maintenance, cooldown and hourly-budget gates. A case stores the intent revision, active topology revision, per-device collection time, exact expected/observed route classification and evidence hash before Codex dispatch. The deterministic decision is `DIAGNOSE_AND_ESCALATE`; this integration registers no route-writing correction and creates no remediation plan.

The source-pinned local regression now covers healthy evaluation, topology mismatch, stale and unreadable RIBs, confirmation/debounce, case evidence and denial of remediation. This is runtime code qualification, not deployment or gateway-recorded fixture acceptance. The disposable-fixture campaign described above remains the release gate.
