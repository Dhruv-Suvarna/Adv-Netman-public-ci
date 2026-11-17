# NMAS V2 P1/P2/P3 production sign-off packet

Prepared: 2026-11-14 America/Denver  
State: **PARTIALLY SIGNED — P2/P3 APPROVED — P1 EXCEPTION PENDING**  
Technical recommendation: **READY_FOR_PRODUCTION_APPROVAL**  
Deployment state: **NOT DEPLOYED**

This packet binds every approval to one immutable deployment review identity. Signing it authorizes neither Phase B nor Phase C.
Phase B still requires an explicit change-manager and production-operator authorization. Phase C remains separately controlled.

## 1. Approval identity

| Item | Required value |
|---|---|
| Package review identity (`entries_sha256`) | `8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70` |
| Rebuilt package manifest SHA-256 | `5d30929d1d197eca9dabeb449d198455b74683b18e641a37a4c35d958b2de252` |
| Rebuilt package location | `/home/student/Scripts/nmas-compat-release-20261114T072224Z/package` |
| Reviewed manifest SHA-256 | `f32ff8af9eacfaf05eea8f4e7a91188d710e8483c14cc7655e43324ec41170dd` |
| Production deployment diff SHA-256 | `dbd852545c47e8ce216fe0dd2ad07503de177e18fb9a0dac54bac7e1c5cd933e` |
| Deployment tool SHA-256 | `897c7923146e45c3988a1f8aac7d6194c5d79fe3447d688b84efe8faee29e8c1` |
| Stable test-identity appendix SHA-256 | `a394929b198c64d5c4b3b65bf70ac861782e69a66c96405ade53310cdf91e67c` |
| Public source revision | `4f950b36f97188f4d7b2c879006c472d9607bace` plus the reviewed uncommitted troubleshooting overlay |
| Production source revision | `129d3f090f8b94b982178b1e8f3ec51047278068` plus the preserved 13 modified tracked and three untracked paths |
| Migration sequence | `0036_v2_phase9_relay_option82_readback` → `0037_troubleshooting` → `0038_device_observations` → `0039_observation_authorizations` |

The superseded package identity `e579455831f60a5f6556e29b10832dfdb45011d1ed140c6be34daf45a503606d` is not
approvable. Any change to the required `entries_sha256`, any nonempty package `problems` list, or any pre-verification mismatch voids
all signatures in this packet.

The full 179-path manifest is
[`deploy/compat/reviewed-manifest.json`](../../../deploy/compat/reviewed-manifest.json). It contains 171 additions, seven replacements
and one merge. The rebuilt package's entries are exactly equal to that reviewed manifest.

## 2. Completed non-production preflight

These observations are technical evidence, not human sign-offs.

| Check | Status | Evidence observed on 2026-11-14 |
|---|---|---|
| A1 package rebuild | PASS | Manifest SHA-256 is `5d309…e252`; `entries_sha256` is `8a411…8f70`; 179 entries; `problems: []`; package `SHA256SUMS` verifies both manifest and tool. |
| A2 production pre-verification | PASS | Package tool reported `VERIFIED (pre): all 179 entries match`. |
| A3 production source baseline | PASS | HEAD remains `129d3f…78068`; the exact reviewed 13 `M` and three `??` paths remain; no overlay path has been applied. |
| A4 migration baseline | PASS | Service-environment `showmigrations core` ends at applied `0035_v2_phase7_9_decommission_dynamic`; `0036`–`0039` are absent. |
| A5 application baseline | PASS | `http://127.0.0.1:8002/healthz` returned 200; `/troubleshooting/` returned the expected pre-deploy 404; `/accounts/login/` returned 200. |
| Current live DB read-only check | PASS | SQLite `integrity_check` is `ok`; `foreign_key_check` returns zero rows; core head is 0035. This does not replace the stopped-service B3 backup validation. |
| Capacity and protection | PASS | 26,993,072 KiB was free on the target filesystem; the release parent is mode 0700. The change-specific backup directory must also be 0700. |
| Current service/topology baseline | PASS | Web, four timers, collectors, topology and traffic runner are active; one-shots complete normally. All 15 frozen `srlceos01` containers are running. No topology action was performed. |
| A6 observation credential | NOT_TESTED | Deliberately not performed. It is a separately authorized Phase C action and is not a Gate B prerequisite. |

The accepted independent evidence is
[`independent-production-deployment-acceptance.md`](independent-production-deployment-acceptance.md). The stable per-test accounting is
[`independent-acceptance-test-identities.json`](independent-acceptance-test-identities.json).

## 3. P1 — independent package review

Approver: code reviewer who is not the package author.

Evidence to review:

- the complete 179-entry reviewed manifest and rebuilt package identity above;
- all eight shared-file patches in `deploy/compat/production-deployment.diff`;
- 171 ADD, seven REPLACE and one MERGE actions, with only the reviewed two widened lines in `removed_text`;
- preservation of all 47 production-unique paths, the 13 modified tracked paths and the three untracked paths;
- package security findings, including the corrected requirement for a complete digest-bearing observation authorization reference;
- the absence of a second independent device-configuration executor.

P1 attestation:

> I independently reviewed the exact package identified by
> `8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70`. I confirm that its 179 operations match the reviewed
> manifest, preserve production-specific behavior as documented, and are suitable to advance to a separately authorized Gate B
> window. I did not author the package. This signature does not authorize Phase B or Phase C.

| Field | Completion |
|---|---|
| Decision | **PENDING — select APPROVE or REJECT** |
| Reviewer name | ______________________________ |
| Role / organization | ______________________________ |
| Independent of package author | ______________________________ |
| Signature | ______________________________ |
| Date/time and timezone | ______________________________ |
| Comments / conditions | ______________________________ |

## 4. P2 — QA and accepted baseline failures

Approver: QA owner or independent engineering reviewer.

| Test population | Tests | Failures | Errors | Skips | Decision evidence |
|---|---:|---:|---:|---:|---|
| Production baseline copy | 7,005 | 260 | 6 | 45 | Stable identities captured. |
| Production copy plus final overlay | 7,880 | 260 | 6 | 45 | No baseline identity missing or changed; 875 added identities all passed. |
| Public worktree in production venv | 8,901 | 4 | 0 | 44 | Four environment-only `coverage.py` failures reproduced. |
| Correct-environment affected subset | 227 | 0 | 0 | 0 | Passed under `/opt/ai-orchestrator/nmas-env`. |
| Focused safety/workflow regressions | 255 | 0 | 0 | 0 | Commissioning, ZTP, identity, isolation, maintenance, provisioning, credentials, traffic, DNS and troubleshooting. |

The baseline has 266 failure/error events: 260 failures plus six errors, across 263 parent test IDs. One cEOS executor parent has four
failing subtests, which explains the three-event difference. Of the 266 events, 235 contain the expected fail-closed
`RELAY_UNTRUSTED` result. The remaining events are unchanged legacy/environment/Git-metadata test debt. Safety-sensitive legacy
executor debt is accepted only for this additive overlay because no affected identity or out-of-manifest path changed; it is not
waived, hidden, excluded or declared healthy.

P2 attestation:

> I reviewed the stable-identity comparison and accept the documented non-green production baseline for this additive deployment
> only. The candidate introduces 875 passing tests, introduces no new failure, error or skip, changes no existing test status, and
> does not change discovery. I understand that the 260 failures and six errors remain remediation debt. This signature does not
> authorize Phase B or Phase C.

| Field | Completion |
|---|---|
| Decision | **APPROVE** |
| QA reviewer name | Dhruv Ramesh Suvarna |
| Role / organization | NMAS lab QA owner (if authorized) |
| Signature | Dhruv Ramesh Suvarna |
| Date/time and timezone | 2026-11-14 00:52:03 MST |
| Accepted conditions / defect reference | ______________________________ |

## 5. P3 — database migration and recovery review

Approver: production database owner.

Evidence to review:

- an access-restricted production-copy backup started at core migration 0035 with integrity `ok` and no FK violations;
- the exact forward plan was `0036 → 0037 → 0038 → 0039`, with integrity and FK checks clean after every step;
- 84 existing tables were row-for-row identical; existing device, observation, lifecycle, configuration and change-history records
  did not change or disappear;
- R2/R4 remained `UNVERIFIED / LEGACY_PREEXISTING`; R6/R7/R8/S5 remained `VERIFIED / ADMITTED`;
- 22 new tables were empty; only expected Django migration/content-type/permission metadata was appended;
- reverse migration to 0035 restored the schema byte-for-byte; injected atomic failure and recovery passed;
- reverse migration drops all data written to the new 0036–0039 tables and leaves stale content types/permissions; a full B3 database
  restore loses every database write made after that backup.

P3 attestation:

> I reviewed the production-copy migration, failure-recovery and reverse-migration evidence for 0036 through 0039. I accept the
> recorded rollback risks. I require a stopped-service, integrity-checked B3 backup with its SHA-256 recorded before source apply,
> and an export of any required post-deployment records before schema rollback. This signature does not authorize Phase B or Phase C.

| Field | Completion |
|---|---|
| Decision | **APPROVE** |
| Database owner name | Dhruv Ramesh Suvarna |
| Role / organization | NMAS lab database owner (if authorized) |
| Signature | Dhruv Ramesh Suvarna |
| Date/time and timezone | 2026-11-14 00:52:03 MST |
| Backup / recovery conditions | ______________________________ |

## 6. Approval disposition

| Gate | Current state | Required before Gate B execution |
|---|---|---|
| P1 package review | **PENDING — INDEPENDENT REVIEW UNAVAILABLE** | The original attestation remains unsigned. A separate sole-owner policy exception is prepared but is not effective until explicitly signed. |
| P2 QA review | **APPROVED** | Signed by Dhruv Ramesh Suvarna at 2026-11-14 00:52:03 MST, including explicit baseline-debt acceptance. |
| P3 DB review | **APPROVED** | Signed by Dhruv Ramesh Suvarna at 2026-11-14 00:52:03 MST, including backup and destructive-rollback acknowledgment. |
| Gate B authorization | **RECORDED BUT HELD** | The 2026-11-14 00:53:42 MST authorization is preserved; it is not operable until the separate exception/external-authority record and final Gate B decision are complete. |
| Phase C | **OUT OF SCOPE / NOT AUTHORIZED** | Separate owner, per-device and credential/observation approvals. |

The original P1 attestation is deliberately unchanged and unsigned; no independent human review is claimed. The proposed package-only
exception and final Gate B decision are recorded separately in
[`sole-owner-p1-exception-and-gate-b-approval.md`](sole-owner-p1-exception-and-gate-b-approval.md). Until that record is explicitly
completed, no production command is authorized.
