# JOB-E78CED9B29DE (s2) — device discovery, bindings and qualification

Worktree HEAD 4f950b3 + uncommitted overlay. Nothing deployed, admitted, approved, staged or committed.

## Evidence classes
| class | status |
|---|---|
| local tests (simulated, no device) | `core.tests.test_troubleshooting_{qualification,readiness,nmas_providers,deployment}`: 60 tests OK (`DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python web/manage.py test ... --noinput`) |
| fixture qualification | NOT PERFORMED — gateway `help` returns `grants: []`; fixture_start/exec were not attempted, no fixture started |
| production evidence | NONE — no gateway-recorded device session; Docker daemon not reachable from this worker; live state UNKNOWN |

## Discovered (tracked sources only)
Sources: `inventory.yml` (network_devices, hosts), tracked `srlceos01.clab.yml` (15 nodes, 24 links), `devices.resolver` (authority/scope), `management.paths` (failover order), lifecycle registry, `AGENTS.md` baseline. `/home/student/clab-quickstart/srlceos01.clab.yml` differs from the tracked copy only in comments/header (runtime copy is not the source of truth; not re-diffed beyond header).

| device | class | platform (declared) | topology image | admission gates (matrix run against the local dev DB) |
|---|---|---|---|---|
| R1 R2 S1 S2 S3 S4 mgmt_swt | MANAGED | ceos | ceos:4.36.2F | lifecycle registration/identity, observed version, production admission — all unproven |
| R3 R4 | MANAGED | linux (Ubuntu 24.04 + FRR 8.4.4) | ubuntu:24.04 | same; Linux argv-only collector |
| R5 | EXCLUDED | ceos | ceos:4.36.2F | exclusion preserved: edge, `address: auto`, no machine identity; never admitted/written |
| H1 H2 H3 H4 WebServer | HOST | linux | ubuntu:24.04 | outside network-device management scope |
| external peers | none | — | — | none declared in topology/inventory; none invented |

Management: declared VLAN200 addresses 192.168.200.{1,2,3,4,10..14} (+ 2001:db8:200::/64); approved failover order DIRECT_OOB > VLAN_ADJACENT_SWITCH > ROUTED_VRF; Containerlab management (172.20.20.0/24, 3fff:172:20:20::/64), `auto`, docker-exec prohibited for production. Registered ManagementPath rows: unknown here (local dev DB has no lifecycle tables/rows → `LIFECYCLE_UNKNOWN`; this is not production state).

## Operational / approval blockers (every MANAGED device)
1. `lifecycle_provider`/`version_provider`/`inventory` not yet bound in settings (`RECOMMENDED_BINDING`; reviewed deploy — settings.py outside s2 scope).
2. Lifecycle registration (Adopt Existing Device) → identity VERIFIED from an AUTHENTICATED_SESSION observation (s1 mechanism) → production ADMITTED/IN_SERVICE: human actions, not granted.
3. `observations.observed_version` (s1) must return a persisted observed version; until then `VERSION_UNKNOWN` (fail closed). Module is now present; no provisioned observation source or live observations are available.
4. Transport/source providers (CLI, SNMP, syslog, gNMI, contexts) are site-owned and unbound; credentials come from the broker, never read here.
5. Production reachability and live NOS versions: UNKNOWN; require gateway-recorded read-only sessions (no grants available).

## Gateway
`aiorch_gw.py help` ⇒ ops listed (python_test, fixture_*, evidence_*, sandbox_*, github_*) but `grants: []`; no operation was attempted. Unavailable: any approved fixture/device operation.

## Changed files
`services/troubleshooting/qualification.py` (new), `services/troubleshooting/adapters/nmas_providers.py` (+`version`, `RECOMMENDED_BINDING`), `services/troubleshooting/readiness.py` (actions), `management/commands/troubleshooting_readiness.py` (`--matrix`, full binding), `tests/test_troubleshooting_qualification.py` (new), `deployment-bindings.md`, this file.

## Master validation (attempt 4)
Inspected both worker implementations and their integration. Corrected raw-digest uniqueness: a fresh signed session with a new nonce may legitimately return identical NOS output; source nonce uniqueness and timestamp ordering still refuse replay. Updated the unapplied 0038 migration consistently. Added a real ingest -> independent verify -> NMAS version provider -> matrix integration test.

Focused checks after changes: `core.tests.test_device_observations` 25/25 OK; `makemigrations --check --dry-run` no changes; `git diff --check` passed. Existing worker results retained without rerunning unchanged suites: s1 126 local tests and s2 60 local tests. No gateway-attested tests claimed. Gateway help rechecked: `grants: []`.

Saved full local matrix as `JOB-E78CED9B29DE-device-readiness.json`: 9 MANAGED, 1 EXCLUDED (R5), 5 HOST, 0 EXTERNAL_PEER. All managed observed versions remain unknown, all managed admission results false. This is development database state, not production evidence.

Remaining engineering: connect authorized read-only, host-key-pinned sessions to signed observation ingest with retained evidence provenance; the ingest API alone does not collect evidence. Implement and locally test this bridge before requesting deployment. Remaining operational prerequisites: gateway grants, site provisioned trusted observation source, authoritative management/credential/session bindings, reviewed migration/binding deployment, independent device verification and lifecycle approval, per-device source collection and gateway-attested regression. No production mutation or external Git write performed.

## Master validation (attempt 7 / cycle 4)

Inspected f3's `observation_connections.py`, its factory/provider/collector tests, the session/collector interfaces, and the
`linux_ssh.py` diff. The factory re-resolves the endpoint, compares the registered pin, and reads the actually presented transport
key before exposing pinned provenance. Existing `connect()` retains its non-observation behavior. Reused f3's reported
153 passing local mocked tests on unchanged files; did not repeat them or treat them as live evidence.

Fresh checks: Django `check` reports no issues; `makemigrations --check --dry-run` reports no changes; `git diff --check` passes.
Gateway `help` again reports `grants: []`. No fixtures, device sessions, deployment, admission, credential reads or remote Git
writes were performed. The historical 837 gateway-attested regressions do not attest this new overlay.

The concrete connection factory is now delivered (f3); the older remaining-engineering paragraph above is superseded on that
point. A concrete durable evidence sink and a reviewed caller that composes source registration, factory, provider and collector
are still missing: current examples require an injected sink/caller. This can be implemented and tested locally without keys,
live access, settings edits or approval. Production source/pin provisioning, reviewed deployment, independent per-device identity
verification/admission, real source collection and gateway-attested regression remain unmet external prerequisites. The existing
matrix is development evidence only; it does not prove production readiness for the nine eligible devices.

## Master validation (attempt 8 / cycle 5)

Reviewed f4's durable sink, command, tests and documentation against the existing collector, session provider,
connection factory and 0038 migration. The durable sink and concrete caller are delivered; the preceding
attempt's missing-engineering statement is superseded. Reused f4's 15 passing local tests on unchanged Python
files rather than rerunning them. Corrected the runner documentation's migration prerequisite from 0037 to
0038_device_observations. Fresh command-discovery check (`device_observe --help`) succeeds and exposes all
four required arguments; `git diff --check` passes. Gateway help still returns `grants: []`.

No live evidence, deployment, device admission, credential access or remote Git write was performed. Worker
ownership: claude_a delivered s1 and f1/f3/f4; claude_b delivered s2 and f2; Codex performed master review and
the documentation correction. Prior local test results remain local, and the historical 837 attested tests
do not cover this overlay. No additional unblocked engineering gap was identified in this review.

Unfinished external prerequisites: operator-provisioned trusted source/key, approved authorization reference
and evidence directory; authoritative broker credentials and host-key pins (including R3/R4); approved deployment
of migration 0038 and NMAS_TS_DEPLOYMENT/source bindings; gateway grants for actual collection and regression;
independent identity verification and established lifecycle admission for R1/R2/R3/R4/S1/S2/S3/S4/mgmt_swt;
then per-device source collection and a refreshed production readiness matrix. R5 remains excluded and the
five hosts remain outside network-device admission. Operational qualification remains UNKNOWN until these
prerequisites and live checks are satisfied. The task is incomplete.
