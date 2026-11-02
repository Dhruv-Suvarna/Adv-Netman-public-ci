# Checkpoint 01 Manifest — Phases 1 through 5

Prepared: 2026-09-20

This is a review/staging manifest only. Nothing was staged or committed while
preparing it.

## 1. Checkpoint scope

Checkpoint 01 captures the intentional project state from the verified
pre-Phase-1 NetBox/IPAM/DHCP migration through Phase 5:

1. authoritative current-state reconstruction;
2. canonical Grafana monitoring taxonomy;
3. Django human-control-plane and theme foundation;
4. the ten operator-provided artwork assets;
5. notification/event and Slack-adapter foundation;
6. read-only Django Home integration of the existing NetworkX topology.

The checkpoint does not include runtime databases, generated files, logs,
caches, credentials, tokens, webhook values, or synthetic database rows.

## 2. Included features

### NetBox / IPAM / DHCP

- independent loopback-only NetBox stack and bootstrap tooling;
- repository-owned recovery/seed manifest and model verifiers;
- normalized NetBox read abstraction and fail-closed DHCP context;
- NetBox-driven NMAS primary and R2 secondary DHCP rendering;
- static VLAN 200 management policy and zero reservation targets;
- render, pool-safety, idempotency, and dual-server verification tests.

### Monitoring

- the existing NMAS monitoring implementation remains unchanged by Phase 5;
- full 446-test monitoring regression and all documented-safe live verifiers
  pass at checkpoint time.

### Grafana taxonomy

- three canonical dashboards (`nmas-resources`, `nmas-link-events`,
  `nmas-link-state-traffic`) alongside the four retained legacy dashboards;
- stable UIDs/variables/panel contract for future Django Monitoring work;
- explicit event-optional panel semantics and live query verification.

### Django foundation

- five-item sidebar, top-right Notification/Profile controls, and service
  boundaries;
- Basic Minimal, Dark Mode, Dark Angels, and Adeptus Mechanicus themes;
- route shells for Monitoring, Device Builder, NSOT, and Automation.

### Theme artwork

- all ten operator-supplied PNG watermark assets at their documented static
  paths, unchanged;
- resolver correction for brand/minimal/dark slots and resolution tests.

### Notifications / Slack

- normalized `Notification` model and migration;
- publisher/dedup/read-state services;
- Notification Center, detail, dropdown max-four behavior, synthetic test
  tooling, and bounded Slack webhook adapter;
- no webhook or runtime secret stored in the repository.

### Topology Home integration

- validated adapter to the existing schema-version-1 topology service;
- same-origin GET-only Django endpoint;
- 15-node/23-edge live SVG with pan, zoom, presentation-only drag/reset,
  address visibility, real node/link details, auto-refresh, and explicit
  degraded state;
- no second graph/discovery backend and no topology mutation behavior.

## 3. Files recommended for staging

### Repository policy / ignored runtime paths

- `.gitignore`

### NetBox/IPAM/DHCP implementation

- `dhcp/dhcpd.conf.j2`
- `dhcp/dhcpd6.conf.j2`
- `master.py`
- `modules/eos_render.py`
- `modules/ipam_context.py`
- `modules/netbox_ipam.py`
- `monitoring/requirements.txt`
- `monitoring/scripts/install_python_dependencies.sh`
- `monitoring/tests/test_eos_render.py`
- `monitoring/tests/test_ipam_context.py`
- `monitoring/tests/test_master_r2_integration.py`
- `monitoring/tests/test_netbox_ipam.py`
- `monitoring/tests/test_populate_netbox.py`
- `monitoring/tests/test_render_nmas_dhcp.py`
- `monitoring/tests/test_render_r2_dhcp.py`
- `monitoring/tests/test_verify_dhcp_servers.py`
- `netbox/` (the real `netbox/.env` and generated `netbox/runtime/` are
  ignored; `.env.example` is intentionally included)
- `templates/R2.cfg.j2`
- `templates/R2_dhcp_server.cfg.j2`

### Phase 1 documentation

- `docs/CURRENT_STATE.md`
- `docs/NETBOX_IPAM.md`

### Phase 2 Grafana taxonomy

- `docs/GRAFANA_DASHBOARDS.md`
- `docs/GRAFANA_MONITORING_TAXONOMY.md`
- `modules/grafana.py`
- `monitoring/scripts/build_grafana_dashboards.py`
- `monitoring/tests/test_grafana.py`
- all seven JSON files under
  `monitoring/grafana/provisioning/dashboards/json/`

### Phases 3-5 Django, artwork, notifications, topology

- `web/` (with `web/db.sqlite3` and `web/staticfiles/` ignored)
- `docs/DJANGO_UI_FOUNDATION.md`
- `docs/NOTIFICATION_AND_SLACK_ARCHITECTURE.md`
- `docs/DJANGO_TOPOLOGY_INTEGRATION.md`
- `docs/CHECKPOINT_01_MANIFEST.md`

## 4. Files explicitly excluded

| Path/pattern | Classification | Reason |
|---|---|---|
| `Run_Logs.log` | EXCLUDE RUNTIME | Tracked historical execution log with a large pre-existing runtime delta; not source or checkpoint evidence. |
| `logs/R2.log` | EXCLUDE RUNTIME | Tracked Netmiko/session output changed by prior live work; not desired state. |
| other `logs/*.log` | EXCLUDE RUNTIME | Runtime session output; currently unchanged but must not be deliberately added to this checkpoint. |
| `monitoring/runtime/` except `.gitkeep` | EXCLUDE RUNTIME/SECRET | Live monitoring environment, credentials, database, and service state; ignored. |
| `netbox/.env` | EXCLUDE SECRET | Real NetBox/PostgreSQL/Redis/Django/API credentials; ignored. |
| `netbox/runtime/` | EXCLUDE GENERATED | Shadow-rendered candidates; ignored. |
| `web/db.sqlite3` | EXCLUDE RUNTIME | Local Django data, including synthetic notification rows; ignored. |
| `web/staticfiles/` | EXCLUDE GENERATED | `collectstatic` output; ignored. |
| `__pycache__/`, `*.pyc`, `*.pyo` | EXCLUDE GENERATED | Interpreter cache; ignored. |

## 5. Files requiring operator decision

No path needs an inclusion decision for the checkpoint itself. The two
tracked runtime-log deltas (`Run_Logs.log`, `logs/R2.log`) are deliberately
left unstaged. After the checkpoint, the operator should separately decide
whether to restore, archive, or retain those working-tree deltas; that choice
must not be bundled into this commit.

## 6. Validation results

| Gate | Result observed 2026-09-20 |
|---|---|
| Django `manage.py test core` | PASS — 140 tests |
| Django `manage.py check` | PASS — 0 issues |
| Monitoring unit discovery | PASS — 446 tests |
| Grafana verifier | PASS — 7 dashboards, 62 panels, 23 variables, 79 queries, datasource OK, secrets PASS |
| Topology verifier | PASS — 19/19, 15 nodes, 23 edges, real/demo/secrets PASS |
| NetBox model verifier | PASS — 392/392 |
| `populate_netbox.py --check` | PASS — `UNCHANGED=318` |
| Reservation verifier | PASS — 35 rows, 0 reservation targets, READY=0 BLOCKED=0 FAIL=0 |
| DHCP server verifier | PASS — NMAS and R2 IPv4/IPv6 active |
| NMAS infrastructure | PASS — 20/20 |
| SNMP verifier | PASS — all 10 devices plus trap ingestion |
| Syslog verifier | PASS — all 10 devices |
| Telemetry verifier | PASS — all 10 devices across gNMI/stream/InfluxDB/NETCONF/NC-GET |
| Python compile / shell syntax | PASS |
| Dashboard JSON parse | PASS — 7 files |
| Phase-5 live Home/API | PASS — HTTP 200, schema 1, 15 nodes, 23 edges, backend OK |
| Headless Firefox interactions | PASS — details, address toggle, zoom, pan, drag, reset, refresh preservation |
| Drag network activity | PASS — zero fetches during drag; refresh issued one same-origin GET |
| Backend unchanged after interaction | PASS — 15/23 and source SHA-256 unchanged |
| Degraded-state live check | PASS — Home 200, proxy 503, generic message, capability cards usable |
| Full `git diff --check` | WARNING — pre-existing excluded `Run_Logs.log:893` blank line at EOF |
| Candidate-scope `git diff --check` excluding both runtime logs | PASS |

The full-worktree whitespace warning belongs only to an explicitly excluded
runtime log. Run `git diff --cached --check` after the path-based staging
commands below; the candidate source/documentation set has no whitespace
errors.

## 7. Secret and generated-file audit

- 251 versionable tracked/untracked paths were enumerated; 241 text files were
  pattern-scanned without printing candidate values and the remaining ten
  files were the intended binary PNG artwork.
- No Slack webhook URL, NetBox v2 token, private-key marker, or AWS access key
  pattern was found.
- Secret-named assignments were reviewed as environment-variable references,
  generated-token code, placeholders, or test fixtures; no runtime secret was
  identified in a recommended path.
- `monitoring/runtime/`, `netbox/.env`, `netbox/runtime/`, `web/db.sqlite3`,
  `web/staticfiles/`, and Python caches are confirmed ignored.
- The ten PNG artwork files are intentional version-controlled inputs, not
  generated output.

## 8. Known limitations

- `Run_Logs.log` and `logs/R2.log` remain modified but unstaged.
- Node positions are browser-memory presentation state only and disappear on
  page reload by design.
- Home does not display traffic rate/utilization; the real Grafana monitoring
  integration belongs to Phase 6.
- Slack was not given a real webhook during Phase 4; delivery behavior is
  covered by mocked tests and the documented `NOT_CONFIGURED` path.
- The historical H1-to-WebServer inconsistency remains documented in the
  current-state material and is not part of this checkpoint's changes.

## 9. Expected commit message

```text
Phase 1-5 checkpoint: baseline, monitoring, Django, notifications and topology
```

This matches the operator-specified checkpoint convention and accurately
covers the deliberately combined five-phase scope.

## 10. Exact safe staging commands

Run from `/home/student/Scripts/clab_dualstack_lab` after reviewing this
manifest:

```bash
git add .gitignore

git add dhcp/dhcpd.conf.j2 dhcp/dhcpd6.conf.j2
git add master.py modules/eos_render.py modules/ipam_context.py modules/netbox_ipam.py
git add templates/R2.cfg.j2 templates/R2_dhcp_server.cfg.j2
git add netbox/

git add monitoring/requirements.txt monitoring/scripts/install_python_dependencies.sh
git add monitoring/tests/test_eos_render.py monitoring/tests/test_ipam_context.py
git add monitoring/tests/test_master_r2_integration.py monitoring/tests/test_netbox_ipam.py
git add monitoring/tests/test_populate_netbox.py monitoring/tests/test_render_nmas_dhcp.py
git add monitoring/tests/test_render_r2_dhcp.py monitoring/tests/test_verify_dhcp_servers.py

git add docs/GRAFANA_DASHBOARDS.md docs/GRAFANA_MONITORING_TAXONOMY.md
git add modules/grafana.py monitoring/scripts/build_grafana_dashboards.py
git add monitoring/tests/test_grafana.py
git add monitoring/grafana/provisioning/dashboards/json/

git add web/
git add docs/CURRENT_STATE.md docs/NETBOX_IPAM.md docs/DJANGO_UI_FOUNDATION.md
git add docs/NOTIFICATION_AND_SLACK_ARCHITECTURE.md
git add docs/DJANGO_TOPOLOGY_INTEGRATION.md docs/CHECKPOINT_01_MANIFEST.md

git diff --cached --check
git status --short
git diff --cached --stat
```

These commands intentionally do not stage `Run_Logs.log` or `logs/R2.log`.
They do not use `git add .` or `git add -A`.

After reviewing the staged diff, the operator may commit with:

```bash
git commit -m "Phase 1-5 checkpoint: baseline, monitoring, Django, notifications and topology"
```

Do not run that commit until the staged manifest and diff have been reviewed.
