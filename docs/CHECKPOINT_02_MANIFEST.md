# Checkpoint 02 Manifest — Phases 6 through 10

Prepared: 2026-09-20

This is a review and staging manifest only. Nothing was staged or committed
while preparing it.

## 1. Baseline and scope

Baseline commit:

```text
62be82f Phase 1-5 checkpoint: baseline, monitoring, Django, notifications and topology
```

Branch: `main`.

Checkpoint 02 contains the intentional, currently uncommitted work from
Phases 6–10. It excludes the two known tracked runtime-log deltas and every
ignored database, generated, cache, or secret path.

## 2. Phase summaries

### Phase 6 — Django Monitoring integration

- Read-only Django wrappers for the three canonical Grafana dashboards.
- Validated bookmarkable filters/time ranges and credential-free bounded
  health checks.
- Safe link-only behavior for the current authenticated, frame-denying Grafana
  deployment; no duplicate dashboards, datasource, collector, or database.
- Monitoring templates, service tests, settings, shared CSS, URL/view/context
  wiring, and `docs/DJANGO_MONITORING_INTEGRATION.md`.

### Phase 7 — Read-only NSOT

- Multi-source read-only NetBox/Git/live-cEOS/topology aggregation.
- Explicit, bounded, redacted live configuration fetch; Ubuntu/FRR correctly
  marked unsupported for this live-read path.
- NSOT subpages, templates, provenance badges, tests, and
  `docs/DJANGO_NSOT_INTEGRATION.md`.
- NetBox remains passive; no NSOT write route exists.

### Phase 8 — Device Intent / Change / Configlet model

- Stable Changes/Configlets, targets, versioned DeviceIntent revisions,
  per-field draft/accepted state, dependencies, append-only lifecycle/audit
  rows, secret-policy enforcement, and admin/read-only inspection surfaces.
- One intentional migration:
  `web/core/migrations/0002_phase8_device_intent_change_model.py`.
- Structure only: no deployment, Golden, Probation, UAT execution, NetBox
  write, or candidate renderer.
- Full design in `docs/DEVICE_INTENT_CHANGE_MODEL.md`.

### Phase 9 — Device Builder foundation

- Basic/Advanced split-screen editor over the same Phase-8 records.
- Browser-local typing, explicit Enter/Commit, one-field rollback, fixed field
  allowlist, Tier-1 syntax validation, and Python-authoritative platform
  rendering.
- Copy, accepted candidate Download, accepted-vs-draft Diff, five platform
  driver identities, and no device/NetBox/Git/GitHub side effects.
- Full design in `docs/DEVICE_BUILDER_FOUNDATION.md`.

### Phase 10 — Interfaces, addressing, and WAN

- Stable `if_*`/`addr_*` structured collections with explicit sequence,
  candidate-local ownership, 64-interface/16-address bounds, and confirmed
  DRAFT-only POST mutation.
- Four-state evidence-backed platform capability matrix. cEOS has the broadest
  support; Ubuntu/FRR has selected iproute2 support; SR Linux, IOS 8000v, and
  SONiC remain truthfully unimplemented.
- Routed/access/trunk/subinterface/SVI/management/loopback where supported;
  deterministic trunk normalization; IPv4/IPv6/dual-stack MANUAL; read-only,
  unresolved/unreserved AUTO; strict VLAN-200 static-management enforcement;
  WAN metadata without routing generation.
- Additive cEOS/Ubuntu feature templates and deterministic one-Python-renderer
  output.
- 138 focused tests and full documentation in
  `docs/DEVICE_BUILDER_INTERFACES_ADDRESSING_WAN.md`.

## 3. Included paths by phase

Some shared files span more than one phase. Their classification below names
the phase that first introduced the checkpoint delta; later-phase additions in
the same file remain intentional.

### INCLUDE — PHASE 6

```text
docs/DJANGO_MONITORING_INTEGRATION.md
web/config/settings.py
web/core/services/monitoring_service.py
web/core/templates/core/monitoring/dashboard_wrapper.html
web/core/templates/core/monitoring/landing.html
web/core/templates/core/monitoring/link_events.html
web/core/templates/core/monitoring/link_state_traffic.html
web/core/templates/core/monitoring/resources.html
web/core/tests/test_monitoring_integration.py
```

### INCLUDE — PHASE 7

```text
docs/DJANGO_NSOT_INTEGRATION.md
web/core/services/nsot_git.py
web/core/services/nsot_live.py
web/core/services/nsot_netbox.py
web/core/services/nsot_service.py
web/core/templates/core/nsot/                      (directory)
web/core/templates/core/nsot.html                  (intentional deletion)
web/core/templatetags/nsot_extras.py
web/core/tests/test_nsot.py
```

### INCLUDE — PHASE 8

```text
docs/DEVICE_INTENT_CHANGE_MODEL.md
web/core/admin.py
web/core/models.py
web/core/migrations/0002_phase8_device_intent_change_model.py
web/core/services/change_service.py
web/core/services/configlet_service.py
web/core/services/intent_service.py
web/core/services/lifecycle_service.py
web/core/services/secret_policy.py
web/core/services/notification_service.py
web/core/tests/test_phase8_models.py
web/core/tests/test_phase8_services.py
web/core/tests/test_phase8_views.py
web/core/tests/test_secret_policy.py
```

### INCLUDE — PHASE 9

```text
docs/DEVICE_BUILDER_FOUNDATION.md
web/core/services/candidate_renderer.py
web/core/services/device_builder_service.py
web/core/services/field_commit_service.py
web/core/services/field_registry.py
web/core/services/field_validators.py
web/core/services/platform_drivers.py
web/core/static/core/js/device_builder.js
web/core/templates/core/device_builder/            (directory)
web/core/templates/core/device_builder.html
web/core/tests/test_phase9_architecture.py
web/core/tests/test_phase9_candidate_renderer.py
web/core/tests/test_phase9_field_commit_service.py
web/core/tests/test_phase9_field_validators.py
web/core/tests/test_phase9_js_contract.py
web/core/tests/test_phase9_views.py
```

### INCLUDE — PHASE 10

```text
docs/DEVICE_BUILDER_INTERFACES_ADDRESSING_WAN.md
templates/features/                               (directory)
web/core/services/device_builder_ipam_service.py
web/core/services/feature_template_renderer.py
web/core/services/interface_intent_service.py
web/core/tests/phase10_helpers.py
web/core/tests/test_phase10_architecture.py
web/core/tests/test_phase10_capabilities.py
web/core/tests/test_phase10_field_validation.py
web/core/tests/test_phase10_interface_service.py
web/core/tests/test_phase10_ipam.py
web/core/tests/test_phase10_js_contract.py
web/core/tests/test_phase10_renderer.py
web/core/tests/test_phase10_views.py
```

### INCLUDE — SHARED PHASE 6–10 WIRING / STATE

```text
docs/CURRENT_STATE.md
docs/CHECKPOINT_02_MANIFEST.md
web/core/context_processors.py
web/core/static/core/css/base.css
web/core/tests/test_services.py
web/core/urls.py
web/core/views.py
```

## 4. Excluded paths

| Path/pattern | Classification | Reason |
|---|---|---|
| `Run_Logs.log` | EXCLUDE — RUNTIME | Known tracked runtime execution-log delta; full diff has its pre-existing blank-line warning. |
| `logs/R2.log` | EXCLUDE — RUNTIME | Known tracked Netmiko/session runtime delta. |
| `web/db.sqlite3` | EXCLUDE — RUNTIME | Ignored local Django database; the synthetic Phase-10 Change was deleted. |
| `web/staticfiles/` | EXCLUDE — GENERATED | Ignored collectstatic output. |
| `netbox/.env` | EXCLUDE — SECRET | Ignored live NetBox/PostgreSQL/Redis/Django/API credentials. |
| `netbox/runtime/` | EXCLUDE — GENERATED | Ignored shadow/candidate artifacts. |
| `monitoring/runtime/` except `.gitkeep` | EXCLUDE — RUNTIME/SECRET | Ignored monitoring data and credentials. |
| `__pycache__/`, `*.pyc`, `*.pyo` | EXCLUDE — GENERATED | Ignored interpreter caches produced by checks/tests. |
| temporary browser/export/syntax files | EXCLUDE — TEMPORARY | None remain. |

## 5. Validation results

All results below were observed in this continuation session.

| Gate | Result |
|---|---|
| Phase-10 focused Django tests | PASS — 138 tests |
| Full Django `manage.py test core` | PASS — 541 tests |
| Django `manage.py check` | PASS — 0 issues |
| `makemigrations --check --dry-run` | PASS — no changes detected |
| Phase-10 Python compile | PASS |
| Feature-template parse | PASS — 12/12 Jinja templates |
| Browser JavaScript | PASS — static contract suite plus real headless Firefox execution; Node.js unavailable for `node --check` |
| Monitoring unit discovery | PASS — 446 tests |
| Grafana verifier | PASS — 7 dashboards, 62 panels, 23 variables, 79 queries, datasource OK, secrets PASS |
| Topology verifier | PASS — 19/19, 15 nodes, 23 edges, real/demo modes and secrets PASS |
| NetBox model verifier | PASS — 392/392 |
| NetBox population dry run | PASS — `UNCHANGED=318` |
| Reservation verifier | PASS — 35 rows, 0 reservation targets, READY with zero blocked/fail issues |
| DHCP server verifier | PASS — NMAS and R2 IPv4/IPv6 active |
| NMAS infrastructure | PASS — 20/20 |
| SNMP verifier | PASS — all 10 devices plus R1 trap ingestion |
| Syslog verifier | PASS — all 10 devices, config/critical/raw/storage |
| Telemetry verifier | PASS — all 10 devices across gNMI/stream/InfluxDB/NETCONF/NC-GET |
| cEOS syntax evidence | PASS — isolated uncommitted session, no running markers, session deleted |
| Ubuntu/iproute2 evidence | PASS — disposable routed/VLAN/bridge links and IPv4/IPv6, all removed |
| Django live browser workflow | PASS — typing/commit/rollback/sync/platform/VLAN200/IPAM/Copy/Download/Diff/themes |
| Candidate-scope `git diff --check` | PASS |
| Full-worktree `git diff --check` | WARNING only — excluded `Run_Logs.log:893` blank line at EOF |

## 6. Secret scan

- Changed and untracked Phase 6–10 text paths were scanned for Slack webhook
  values, NetBox v2 token values, private-key markers, AWS access keys, and
  literal NetBox/Slack credential assignments without printing candidate
  values. No high-risk value was found.
- The only repository-wide webhook-pattern hit is the already-committed,
  explicitly redacted placeholder example in
  `docs/NOTIFICATION_AND_SLACK_ARCHITECTURE.md`; it is not a Phase 6–10 delta
  and is not a usable secret.
- Secret-shaped assignments in tests are deliberate rejection fixtures, not
  credentials.
- The pre-existing plaintext device credentials documented by Phase 7 remain
  outside this checkpoint's new data. Phases 6–10 did not duplicate them into
  docs, fixtures, DeviceIntent data, candidates, or new configuration.

## 7. Runtime/generated scan

- `.gitignore` covers `monitoring/runtime/*`, `netbox/.env`,
  `netbox/runtime/`, `web/db.sqlite3`, `web/staticfiles/`, `__pycache__/`, and
  `*.py[cod]`.
- Python caches created by testing exist only under ignored paths.
- No synthetic export file or temporary feature-template render exists.
- The one live synthetic Change was selected by its exact unique title,
  deleted with 116 cascaded child rows (117 rows total), and independently
  confirmed absent afterward.
- The EOS configuration session was not committed, marker lines were absent
  from running config, and the session record was explicitly deleted.
- Disposable Ubuntu links were removed by a cleanup trap and confirmed absent.

## 8. Known limitations

- AUTO is prefix-assisted intent only; host selection, reservation, collision,
  and availability checks wait for Phase 13.
- cEOS has the strongest interface support. Ubuntu/FRR supports selected
  iproute2 behavior only. SR Linux, IOS 8000v, and SONiC have no Phase-10
  interface renderer.
- No routing, static-route, FHRP, NAT, GRE, IPsec, deployment, Golden,
  Probation, soak, or rollback behavior is generated.
- cEOS live syntax evidence produced one expected semantic warning for a native
  VLAN absent from the chosen R1 test context; Tier-1 parser acceptance was
  otherwise observed, and no session was committed.
- Node.js is not installed, so `node --check` was unavailable; Django static
  JavaScript contract tests and Firefox execution passed.

## 9. Operator decisions

No inclusion decision remains for the Phase 6–10 source set. The operator
must still decide separately what to do with the two tracked runtime-log
deltas (`Run_Logs.log`, `logs/R2.log`); they must not be included in this
checkpoint.

## 10. Exact recommended staging commands

Run from `/home/student/Scripts/clab_dualstack_lab` after review:

```bash
git add docs/CURRENT_STATE.md docs/DJANGO_MONITORING_INTEGRATION.md
git add docs/DJANGO_NSOT_INTEGRATION.md docs/DEVICE_INTENT_CHANGE_MODEL.md
git add docs/DEVICE_BUILDER_FOUNDATION.md
git add docs/DEVICE_BUILDER_INTERFACES_ADDRESSING_WAN.md
git add docs/CHECKPOINT_02_MANIFEST.md

git add templates/features/

git add web/config/settings.py
git add web/core/admin.py web/core/context_processors.py web/core/models.py
git add web/core/urls.py web/core/views.py
git add web/core/migrations/0002_phase8_device_intent_change_model.py

git add web/core/services/candidate_renderer.py
git add web/core/services/change_service.py web/core/services/configlet_service.py
git add web/core/services/device_builder_ipam_service.py
git add web/core/services/device_builder_service.py
git add web/core/services/feature_template_renderer.py
git add web/core/services/field_commit_service.py web/core/services/field_registry.py
git add web/core/services/field_validators.py web/core/services/intent_service.py
git add web/core/services/interface_intent_service.py
git add web/core/services/lifecycle_service.py
git add web/core/services/monitoring_service.py web/core/services/notification_service.py
git add web/core/services/nsot_git.py web/core/services/nsot_live.py
git add web/core/services/nsot_netbox.py web/core/services/nsot_service.py
git add web/core/services/platform_drivers.py web/core/services/secret_policy.py

git add web/core/static/core/css/base.css web/core/static/core/js/device_builder.js
git add web/core/templates/core/device_builder.html
git add web/core/templates/core/device_builder/
git add web/core/templates/core/monitoring/
git add web/core/templates/core/nsot/
git add -u web/core/templates/core/nsot.html
git add web/core/templatetags/nsot_extras.py

git add web/core/tests/phase10_helpers.py
git add web/core/tests/test_monitoring_integration.py web/core/tests/test_nsot.py
git add web/core/tests/test_phase8_models.py web/core/tests/test_phase8_services.py
git add web/core/tests/test_phase8_views.py
git add web/core/tests/test_phase9_architecture.py
git add web/core/tests/test_phase9_candidate_renderer.py
git add web/core/tests/test_phase9_field_commit_service.py
git add web/core/tests/test_phase9_field_validators.py
git add web/core/tests/test_phase9_js_contract.py web/core/tests/test_phase9_views.py
git add web/core/tests/test_phase10_architecture.py
git add web/core/tests/test_phase10_capabilities.py
git add web/core/tests/test_phase10_field_validation.py
git add web/core/tests/test_phase10_interface_service.py
git add web/core/tests/test_phase10_ipam.py web/core/tests/test_phase10_js_contract.py
git add web/core/tests/test_phase10_renderer.py web/core/tests/test_phase10_views.py
git add web/core/tests/test_secret_policy.py web/core/tests/test_services.py

git diff --cached --check
git status --short
git diff --cached --stat
```

These commands deliberately omit `Run_Logs.log` and `logs/R2.log`. They do
not use `git add .`, `git add -A`, or `git commit -a`.

## 11. Expected commit command

After human review of the staged manifest and diff:

```bash
git commit -m "Phase 6-10 checkpoint: monitoring, NSOT and Device Builder foundations"
```

Do not run this commit until the staged content has been reviewed.

## 12. Phase-11 handoff

Proceed to Device Builder routing modules: static routing, RIP, OSPF, IS-IS,
EIGRP, and BGP foundations. Reuse the Phase-10 structured object/stable-ID,
capability, field-commit, additive-template, and deterministic Python-renderer
patterns. Keep WAN metadata non-generative unless an explicit routing-intent
relationship is modeled and validated in Phase 11.
