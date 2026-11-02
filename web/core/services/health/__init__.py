"""Phase-15 operational health, prechecks and the reusable postcheck engine.

Layout (each module has ONE job; nothing here deploys, edits a Configlet, writes NetBox/Git, or
advances a Change lifecycle):

    codes.py         vocabularies, the stable check-code catalogue, the blocking policy table
    thresholds.py    freshness / CPU / memory thresholds -- read from the EXISTING monitoring config
    results.py       CheckResult (structured evidence), bounded serialization, aggregation rules
    evidence.py      normalized per-device fact groups with source + timestamp, evidence precedence
    inventory.py     the managed-device list and live targets (inventory.yml only, never the browser)
    telemetry.py     Fleet-Quick adapter over the EXISTING topology / monitoring services (no InfluxDB client)
    live.py          Deep-Health read-only adapters: fixed per-platform command allowlists + parsers
    fleet.py         Fleet Quick health
    device.py        per-device Deep Health
    requirements.py  Phase-14 verification descriptors -> executable requirements (table driven)
    evaluators.py    requirement evaluators + ``evaluate_plan_requirements`` (the postcheck engine)
    scope.py         plan-derived affected-device scope
    prechecks.py     change-aware precheck
    persistence.py   ONE append-only run model, audit, bounded report
    connectivity.py  Phase-22 IP connectivity (ping) check; reuses OperationalCheckRun / live.py sessions
"""
