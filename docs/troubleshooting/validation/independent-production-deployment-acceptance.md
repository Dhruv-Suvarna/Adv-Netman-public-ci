# NMAS V2 independent production deployment acceptance

Review date: 2026-11-14 America/Denver

Decision: **READY_FOR_PRODUCTION_APPROVAL**

This is not a deployment record. No production source was replaced, no live database was migrated, no service was restarted, no
credential or host key was accepted, no device was contacted, and no Git remote was changed. Consequently this report does not and
must not claim **PRODUCTION_DEPLOYED_AND_ACCEPTED**.

## 1. Reviewed identity and scope

| Item | Independently verified value |
|---|---|
| Authoritative public repository | `Dhruv-Suvarna/Adv-Netman-public-ci` |
| Public source revision | `4f950b36f97188f4d7b2c879006c472d9607bace` plus the preserved uncommitted troubleshooting overlay |
| Production source revision | `129d3f090f8b94b982178b1e8f3ec51047278068` plus the same preserved 13 modified tracked and three untracked paths |
| Final package review identity (`entries_sha256`) | `8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70` |
| Rebuilt package manifest SHA-256 | `5d30929d1d197eca9dabeb449d198455b74683b18e641a37a4c35d958b2de252` |
| Superseded identity | `e579455831f60a5f6556e29b10832dfdb45011d1ed140c6be34daf45a503606d` — obsolete after the authorization-reference correction in §4.1; it must not be approved or applied |
| Reviewed manifest file SHA-256 | `f32ff8af9eacfaf05eea8f4e7a91188d710e8483c14cc7655e43324ec41170dd` |
| Reviewed deployment-diff SHA-256 | `dbd852545c47e8ce216fe0dd2ad07503de177e18fb9a0dac54bac7e1c5cd933e` |
| Deployment tool SHA-256 | `897c7923146e45c3988a1f8aac7d6194c5d79fe3447d688b84efe8faee29e8c1` |
| Stable test-identity appendix SHA-256 | `a394929b198c64d5c4b3b65bf70ac861782e69a66c96405ade53310cdf91e67c` |

The complete 179-entry affected-file manifest, including action, path, mode, pre-hash and post-hash, is
[`deploy/compat/reviewed-manifest.json`](../../../deploy/compat/reviewed-manifest.json). The exact production summary plus the eight
shared-file patches is [`deploy/compat/production-deployment.diff`](../../../deploy/compat/production-deployment.diff). The generated
complete diff is 45,500 lines and is reproducible with `nmas_compat_overlay.py diff` from the final package.

Manifest accounting is exactly:

| Action | Count | Result |
|---|---:|---|
| ADD | 171 | Every target is absent in production and payload hash verified. |
| REPLACE | 7 | Every production pre-hash and resulting post-hash verified. |
| MERGE | 1 | Only the reviewed `ci/rules.py` hunks are transplanted; production-only adjacent rules remain. |
| Total | 179 | Rebuilt entries are byte-for-byte equal to the reviewed manifest. |

The actual package includes migrations `0036`, `0037`, `0038` **and `0039`**. References that describe only `0036–0038` are historical
and incomplete: `0039_observation_authorizations` is required by the final observation-authorization implementation.

## 2. Acceptance gates

| Gate | Status | Evidence / boundary |
|---|---|---|
| Repository policy, frozen topology and production safety boundary | PASS | Policies read; no topology lifecycle, device write, production edit, service restart, remote Git write or job/checkpoint change. |
| Full manifest and package reproducibility | PASS | 179/179 entries reproduce the final identity; production pre-verification is 179/179. |
| Differential production QA | PASS | 7,005 baseline versus 7,880 final candidate; no missing baseline ID and no status change. |
| 875 added tests | PASS | Exactly 875 added stable IDs; every event is `OK`. |
| Focused workflow regression | PASS | 255 focused tests across all requested domains, all passed. |
| Public-worktree accounting | PASS | 8,901 tests; four dependency-environment failures, zero errors, 44 skips; the affected 227-test subset passes with the correct interpreter. |
| Package security review | PASS | One defect found and fixed; final critical paths and secret scan pass. |
| Production-copy database forward migration | PASS | `0035 → 0036 → 0037 → 0038 → 0039`, integrity and FK clean at every step. |
| Database reverse/failure recovery | PASS | Reverse schema equals `0035`; injected atomic failure recovered; destructive risks recorded. |
| Apply/rerun/partial-apply/rollback simulation | PASS | Exact 179-path apply; rerun refusal; injected partial apply detected; full tree restored byte-identically. |
| Production-specific compatibility | PASS | No path outside the manifest changed; all production-only and dirty paths preserved. |
| Current pre-deployment NMAS health | PASS | Relevant units active; `/healthz` 200; troubleshooting 404 as expected before deployment; frozen lab containers remain running. |
| Gateway-attested observation of production devices | BLOCKED_EXTERNAL | Existing gateway operations address fixtures only; no production-device read operation or grant exists. Local observation must remain labelled unattested. |
| Per-device pin and credential enrollment | BLOCKED_EXTERNAL | Requires independent human enrollment/approval and broker state; none was inferred or changed. |
| Live production deployment and post-deployment B5–B13 | NOT_TESTED | Explicitly outside the autonomous safety boundary. |
| Live production-flow soak and in-production acceptance | NOT_TESTED | Requires an authorized deployment and observation window; local/simulated tests are not substituted. |

## 3. Independent QA evidence

### 3.1 Four-shard strategy

Each tree used sorted `core/tests/test_*.py` modules, assigned round-robin to four shards. Shards ran concurrently but each shard used
`--parallel 1`, so there was no intra-shard test concurrency. The module sets were disjoint and their unions were complete:

| Tree | Modules | Tests | Failures | Errors | Skips |
|---|---:|---:|---:|---:|---:|
| Production baseline copy | 253 | 7,005 | 260 | 6 | 45 |
| Final production-overlay candidate | 297 (253 common + 44 added) | 7,880 | 260 | 6 | 45 |
| Public worktree, production venv | 317 | 8,901 | 4 | 0 | 44 |

Discovery was not weakened: no baseline module or test ID disappeared. All 7,005 baseline cases and all 7,880 candidate cases had a
parsed verbose status. The canonical identity evidence is
[`independent-acceptance-test-identities.json`](independent-acceptance-test-identities.json); it contains every baseline non-PASS ID,
all 875 added IDs and the empty missing/change sets, without test payloads.

Stable-identity comparison:

- baseline status events: 6,697 OK, 260 FAIL, six ERROR, 45 SKIP;
- final candidate status events: 7,572 OK, 260 FAIL, six ERROR, 45 SKIP;
- missing baseline IDs: zero;
- common IDs with any status-multiset change: zero;
- baseline PASS changing to FAIL, ERROR or SKIP: zero;
- added IDs: exactly 875, all OK.

### 3.2 The 263-versus-266 discrepancy

Both numbers described different units. There are 266 failure/error **events** (260 failures + six errors) across 263 parent test IDs.
`core.tests.test_execution_executors.CeosExecutorTests.test_assess_and_compensate_follow_the_captured_state_and_verify_by_read_back`
contains four failing subtests, producing three more failure events than parent IDs. The consistent wording is therefore “260 failure
events and six error events across 263 distinct failing/error parent IDs.”

### 3.3 Baseline failure judgment

The baseline is not a green release suite. Every event is enumerated in the identity appendix. Review of all 266 failure/error blocks
found:

- 235 events contain `RELAY_UNTRUSTED`. These are stale tests expecting a ZTP/bootstrap path to proceed; deployed production now refuses
  earlier at the trusted-relay gate. That is fail-closed security behavior, not a reason to loosen the gate.
- Four public governance failures are caused by `coverage.py` being absent from `/home/student/Scripts/.venv`; the same tests pass with
  `/opt/ai-orchestrator/nmas-env` (coverage 7.16.2).
- Several copied-tree failures require Git metadata that the secret-free staging operation intentionally excludes.
- The remainder is legacy production-lineage test debt in isolation/executor inverse tests, old fakes, catalog expectations and
  production-specific behavior. It predates this package and is exactly unchanged in the candidate.

Some remaining debt concerns safety-sensitive legacy executors. It is acceptable **for this additive deployment only** because the
package does not change those executor paths, every affected test identity is unchanged, all paths outside the manifest are unchanged,
and manual review confirms troubleshooting adds no second device-configuration executor. This is not a declaration that the legacy
suite is healthy; the debt remains a separate remediation obligation and must not be hidden or excluded.

### 3.4 Focused regressions

A separate 255-test run passed using these all-green modules:

- commissioning: `test_commissioning_dependencies`;
- ZTP/bootstrap: `test_ztp_adapters`;
- device identity/lifecycle: `test_lifecycle_identity`;
- isolation: `test_isolation_admission_ospf_release`;
- maintenance: `test_maintenance_mode`;
- provisioning: `test_provisioning_views`;
- credentials: `test_credential_rotation`;
- traffic: `test_traffic`;
- DNS dependencies: `test_troubleshooting_dns_rules`, `test_troubleshooting_dns_source`;
- troubleshooting/observation: `test_observation_authorizations`, `test_deploy_bindings`.

The overlay tool's CO01–CO18 suite also passed. Final payload Python compilation succeeded, `manage.py check` reported no issues and
`makemigrations --check --dry-run` reported no changes.

### 3.5 Public environment reproduction

With `/home/student/Scripts/.venv`, the full public worktree produced the four claimed failures and no others. The exact IDs are the
three coverage-dependent tests in `test_test_governance` and one in `test_tg_governance_units`. With
`/opt/ai-orchestrator/nmas-env`, those modules plus `test_contracts` ran 227 tests successfully. Assertions and discovery were not
changed in either run.

## 4. Security review

### 4.1 Defect found and corrected

Observation execution accepted a bare `OBSAUTH-NNNNNN` ID although the operator contract required
`OBSAUTH-NNNNNN#sha256=<scope_digest>`. Stored-row tamper detection still existed, but the omission weakened reference binding and
contradicted the documented contract.

The correction requires the complete digest-bearing reference in `observation_authorizations.admit`; bare IDs remain valid only for
administrative show/revoke operations. The command help and runbook now state that boundary, and the authorization tests prove bare-ID
execution is refused with `AUTHORIZATION_REF_MISMATCH`. This changed four ADD payloads and caused the new `8a411…` package identity.

### 4.2 Final security findings

| Area | Result |
|---|---|
| Credential-broker isolation | PASS — the observation factory handles references only; resolution stays inside existing helpers. Fleet fallback and `LEGACY_SHARED` credentials are refused. |
| SSH pinning | PASS — Paramiko missing-host-key policies compare the registered pin during SSH key exchange, before authentication; the presented key is read back and compared again. No TOFU or `known_hosts` fallback. |
| Authenticated observation | PASS — one fixed version command, read-only session interface, HMAC source key from a named environment variable, nonce/replay/staleness checks and digest-bound evidence. |
| Independent approval/identity | PASS — authorization approver differs from requester and executor; an observation records evidence but cannot verify identity or admit a device. |
| Lifecycle/admission | PASS — authoritative resolver, identity and version providers fail closed; binding is explicit. |
| Management failover | PASS — endpoint and path are re-resolved before connect; changed/blocked paths refuse with no legacy, Docker or Containerlab fallback. |
| R5 exclusion | PASS — R5 is outside writable scope and is refused before authorization or connection. |
| Access control | PASS — authenticated role, tenant/device scope and NMAS action permission are checked server-side; cross-tenant IDs do not create an existence oracle. |
| Commissioning/isolation/ZTP | PASS for package compatibility — relevant production-specific files remain byte-identical; relay and isolation gates remain fail closed. |
| Change Engine boundary | PASS — troubleshooting's `ChangeEngineExecutor.supports()` is always false and `apply()` refuses; execution remains available only through the existing Change page. |
| Troubleshooting AI | PASS — registered tools are read-only or proposal-only, raw command/privilege keys and write verbs are refused, scopes/budgets/nonces are enforced. |
| Production-flow safety | PASS in code/tests; live soak NOT_TESTED — missing samples never become zero loss, degraded/interrupted states are sticky and passing requires elapsed window plus coverage. |
| Secret handling | PASS — final payload has no private-key header, GitHub/AWS token signature, PEM blob, `.env`, database or runtime-state path. Runtime key values were never printed. |

`HealthLiveTransport` retains a lab-capable Docker branch in source, but the shipped production binding configures no CLI transport and
the admission/session path prohibits Docker/Containerlab endpoints. Enabling a site transport is a separate reviewed deployment action;
it is not enabled by this package.

## 5. Production-copy database preflight

An access-restricted 0600 SQLite backup was made through the read-only SQLite backup API. Snapshot SHA-256 was
`6af0ef521de87c4bd597b48036dac2e95d45c06bdf055c9a37ceca3cd86cae14`; no sensitive row values are included here.

Pre-state:

- integrity `ok`, foreign-key violations zero, core head `0035_v2_phase7_9_decommission_dynamic`;
- 87 application tables and 35,070 rows;
- six managed devices, 24 `DeviceObservation` rows and zero `ManagementPath` rows;
- R2/R4 remained `LEGACY_ADOPTION / IN_SERVICE / UNVERIFIED / LEGACY_PREEXISTING`;
- R6/R7/R8/S5 remained `REGISTERED_NEW / IN_SERVICE / VERIFIED / ADMITTED`.

Forward result:

- plan was exactly core `0036`, `0037`, `0038`, `0039`, with no other app migration;
- integrity remained `ok` and `foreign_key_check` remained empty after every step;
- 84 existing tables were row-for-row identical;
- only Django metadata appended: `django_migrations` +4, `django_content_type` +22, `auth_permission` +72; all previous rows remained an
  unchanged prefix;
- 22 new tables were created and all were empty;
- no managed-device, observation, lifecycle, configuration or change-history row changed or disappeared.

Reverse/failure result:

- reversing `0039 → 0038 → 0037 → 0036 → 0035` restored a byte-identical `sqlite_master` schema and clean integrity/FKs;
- Django leaves 22 stale content types and 72 stale permissions after reverse migration;
- an injected collision on the second table of atomic migration `0039` caused the first table creation to roll back, did not record
  `0039`, retained clean integrity/FKs, and succeeded after removal of the disposable collision.

Schema rollback is destructive to data created after deployment: reversing `0039`, `0038`, `0037` or `0036` drops the corresponding
new tables. Export required records first. A full DB restore also loses all writes after the pre-change backup; it is the last-resort
operator action documented in the runbook.

## 6. Deployment-tool and production compatibility review

The final package was applied to a disposable production-tree copy and verified at all 179 post-hashes. A second apply refused because
the preconditions no longer held. Rollback removed 171 additions, restored all eight shared files, removed created directories and
returned the complete content/mode/directory snapshot to exact equality.

An injected failure after one atomic file write produced journal status `FAILED_NEEDS_ROLLBACK`; post verification found 178 missing
postconditions, pre verification found the single partial write, and rollback returned all 179 entries to their pre-state. The journal
is written before overlay writes. Per-file replacement uses `fsync` plus atomic rename.

The tool additionally enforces:

- approval-hash prefix and change ID;
- exact payload/tool hashes at load time;
- exact production pre-hashes and absence of all ADD paths;
- stopped import-owning units for real apply/restore;
- 0700 apply backup directory, 0600 database/source backups;
- refusal to roll source back while any overlay migration is recorded;
- refusal to restore a corrupt DB backup, a DB with WAL/journal sidecars or while importing units are active;
- preservation of the replaced DB as a timestamped 0600 file during last-resort restore.

The candidate changed no path outside the manifest. Therefore the 47 production-unique paths, all 13 tracked production edits, all three
untracked files, `settings_demo.py`, inventory authority, environment files, credential references, gateway configuration and installed
production services remain untouched.

Read-only pre-deployment health evidence at review close:

- `nmas-web`, maintenance, soak, credential rotation, demo telemetry, gNMI collector, syslog ingest, topology and traffic runner units
  were active;
- `/healthz` returned 200, `/accounts/login/` returned 200 and `/troubleshooting/` returned the expected pre-deploy 404;
- all 15 frozen `srlceos01` lab containers were running (21 Containerlab-labelled containers total, including disposable capability
  fixtures); topology file SHA-256 was `44fa83569c1952f488b195194751103a993a700facd0a2b219b5615c9e8e3884`.

## 7. Remaining external approvals and blockers

The package is technically ready for an authorized production decision, but these organizational/live gates remain:

1. P2 and P3 are signed. Ordinary P1 remains unavailable because no separate non-author reviewer exists. A sole-owner exception is
   prepared as a transparent package-specific governance amendment, not an independent-review claim, and remains ineffective until
   explicitly signed with an external-authority declaration.
2. Change manager and production operator entered a Gate B authorization, but it remains held until the P1 exception and final Gate B
   decision record are complete and the maintenance window is current.
3. NMAS owner separately approves C1 (`NMAS_TS_BINDING=nmas-v1`).
4. For each device, an enroller and independent cEOS path approver complete C2. No key may be accepted from first contact; R5 remains
   excluded.
5. C3 authorization approver and C4 observation operator must be different people; the complete digest-bearing authorization reference
   is mandatory.
6. Gateway owner action is required only if production-device observations must be gateway-attested. No such operation exists today;
   local evidence must remain labelled `local-unattested`.
7. The operator must execute and record B5–B13, post-deployment service health, reconciliation, read-only UI smoke tests and the live soak.

The exact approval form is
[`production-p1-p3-signoff-packet.md`](production-p1-p3-signoff-packet.md). The future operator record is
[`gate-b-change-window-checklist.md`](gate-b-change-window-checklist.md). The separate owner-deviation decision is
[`sole-owner-p1-exception-and-gate-b-approval.md`](sole-owner-p1-exception-and-gate-b-approval.md). Preparing those documents does not
satisfy a human gate.

## 8. Final recommendation and exact next authorized step

Recommendation: **READY_FOR_PRODUCTION_APPROVAL** for package
`8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70`, subject to the external approvals above.

Phase A/A1–A5 are now complete: the protected rebuild has `problems: []`, manifest SHA-256 `5d3092…e252`, the required
`entries_sha256`, clean package checksums and a 179/179 production pre-verification; production still has the exact reviewed Git and
migration baseline; the pre-deploy endpoints are healthy. A6 was deliberately not performed because it belongs to separately
authorized Phase C.

The exact next approval action is to obtain P1, P2 and P3 signatures, then explicit Gate B authorization from the change manager and
production operator. After those approvals—and only after repeating the checklist's drift checks at the window boundary—the first
production command is Phase B step B1: stop the four import-owning timers and wait until their one-shot services are neither `active`
nor `activating`. No service stop, source apply, production backup, live migration or Phase C action is authorized by this report.
