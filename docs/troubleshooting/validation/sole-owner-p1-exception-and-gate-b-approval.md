# NMAS V2 sole-owner P1 exception and final Gate B approval record

Prepared: 2026-11-14 America/Denver  
State: **PENDING EXPLICIT OWNER DECISION — GATE B HELD**  
Package review identity: `8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70`  
Package manifest SHA-256: `5d30929d1d197eca9dabeb449d198455b74683b18e641a37a4c35d958b2de252`

This record is separate from the original P1 independent-review attestation. It does not state or imply that an independent human
review occurred, and it does not reproduce, replace or forge an independent reviewer's signature.

## 1. Policy determination

The ordinary P1 path is not available to the sole owner/package author:

- `docs/troubleshooting/compat-deployment.md` defines P1's approver as a **code reviewer (not the author)**;
- `docs/troubleshooting/validation/production-p1-p3-signoff-packet.md` repeats that requirement and its original P1 attestation says
  the signer did not author the package;
- `AGENTS.md` includes human review in the development workflow;
- none of the reviewed project policies defines an owner waiver, sole-owner substitute or emergency exception for P1.

Therefore a sole-owner signature must not be entered in the original P1 attestation. Under the currently written ordinary process,
P1 remains unsatisfied. The only transparent project-level alternative is a formal, one-time owner amendment to governance for this
exact package. Section 4 prepares that amendment for an explicit decision; it is not effective while unsigned.

This exception cannot waive technical preconditions, P2, P3, Gate B execution checks, rollback controls, Phase C separation of duties,
or any rule imposed by a university, VM/infrastructure owner or other authority above the project owner.

## 2. Evidence and approvals preserved

No technical evidence or signed approval is replaced by this record.

| Item | Preserved state |
|---|---|
| Independent technical review | Complete as recorded in `independent-production-deployment-acceptance.md`; this was agent-generated technical evidence, not an independent human P1 signature. |
| Package operations | 179 total: 171 ADD, seven REPLACE, one MERGE; production pre-verification 179/179. |
| Production baseline | Legacy revision `129d3f090f8b94b982178b1e8f3ec51047278068` plus the reviewed 13 modified tracked and three untracked paths. |
| Test comparison | 7,005 baseline versus 7,880 candidate; unchanged 260 failures, six errors and 45 skips; 875 added stable identities all passed. |
| P2 | **APPROVE**, signed by Dhruv Ramesh Suvarna as NMAS lab QA owner at 2026-11-14 00:52:03 MST. |
| P3 | **APPROVE**, signed by Dhruv Ramesh Suvarna as NMAS lab database owner at 2026-11-14 00:52:03 MST. |
| Migration sequence | `0036 → 0037 → 0038 → 0039`; production remains at 0035. |
| Existing Gate B entry | Change manager `AUTHORIZE` and operator acceptance were entered by Dhruv Ramesh Suvarna at 2026-11-14 00:53:42 MST for `CHG-NMAS-20261114-001`. They are preserved, but are conditionally held because P1 was not satisfied when entered. |
| Deployment execution | Not started; B1–B13 remain unchecked. |

The signed P2/P3 fields remain in
[`production-p1-p3-signoff-packet.md`](production-p1-p3-signoff-packet.md). The existing Gate B entry remains in
[`gate-b-change-window-checklist.md`](gate-b-change-window-checklist.md).

## 3. University and infrastructure authority review

The checked repository contains no university, course, instructor, infrastructure-owner or VM-owner approval rule for this specific
source/database deployment. It identifies the environment as CSCI 5840 and requires phase/operator approval, but it does not name an
external approver for Gate B.

Read-only host inspection shows:

- the `student` account owns the production checkout;
- the `student` account has `NOPASSWD: ALL` sudo capability on `csci5840-vm1-dhsu9160`;
- the service unit and `/etc/nmas` are root-owned;
- Gate B stops/starts a root-managed service but does not modify the unit, `/etc/nmas`, network topology or gateway policy.

These facts establish technical administrative capability, not institutional authorization. No local repository or host control can
prove that a university or infrastructure-owner policy does not exist outside the project. The owner must make one of the explicit
declarations below. If external approval is required, Gate B is **BLOCKED_EXTERNAL** until its reference is recorded.

| External-authority declaration | Owner selection |
|---|---|
| I am authorized to administer this VM and no separate university/infrastructure-owner approval applies to this Gate B source/database change. | [ ] |
| A separate approval applies and has been obtained; reference: ______________________________ | [ ] |
| Authority is uncertain or approval is outstanding; Gate B remains `BLOCKED_EXTERNAL`. | [ ] |

## 4. Proposed one-time sole-owner P1 governance amendment

This amendment is intentionally narrower than the original P1 rule. It applies only to the exact immutable package identity above and
does not create an independent-review claim or a general precedent.

Owner attestation for explicit decision:

> I am the sole owner and administrator of the NMAS project. No separate independent human reviewer is available. For package
> `8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70` only, I knowingly accept a one-time project-governance
> exception to the ordinary P1 requirement that the code reviewer be someone other than the author. I acknowledge that this is an
> owner risk acceptance and policy amendment, not an independent human review. I rely on the preserved manifest, security, QA,
> migration, rollback and disposable-copy evidence, and I accept the reduced separation-of-duties assurance. I do not waive P2, P3,
> Gate B preconditions, automatic stop conditions, production backup requirements, Phase C controls or any higher-level external
> policy.

| Field | Explicit owner completion |
|---|---|
| Exception decision | **PENDING — select APPROVE EXCEPTION or REJECT EXCEPTION** |
| Owner name | Dhruv Ramesh Suvarna (from the existing P2/P3 approval record) |
| Authority to amend project governance | **PENDING — confirm YES or NO** |
| Signature | ______________________________ |
| Date/time and timezone | ______________________________ |
| Conditions / expiry | Package-specific; expires on any package hash, manifest hash, production-baseline or migration-plan change. Additional conditions: ______________________________ |

If `REJECT EXCEPTION` or `NO` is selected, the original independent P1 requirement remains a blocker. Do not execute Gate B.

## 5. Final Gate B decision after the exception

The existing 2026-11-14 00:53:42 MST Gate B entry is preserved as a preliminary authorization. It becomes operable only if all of the
following are true immediately before B1:

- the owner explicitly approves and signs the exception in §4;
- the owner selects one non-blocking external-authority declaration in §3;
- P2 and P3 remain approved;
- the change window is current or is explicitly rescheduled and re-announced;
- every Phase A drift check in the Gate B checklist is repeated successfully;
- the package identity remains exactly `8a4111…8f70`, manifest SHA-256 remains `5d3092…e252`, and production remains at the reviewed
  source and migration baseline;
- production backup B3 and source archive B4 are completed before source apply;
- no Phase C action is included.

Final Gate B owner decision:

> I have reviewed the sole-owner exception, external-authority declaration, P2/P3 approvals, expected outage, B3 database backup,
> B4 source archive, 0036–0039 migration sequence, rollback data-loss risks and all automatic stop conditions. I make the decision
> below for `CHG-NMAS-20261114-001` and the exact package identity recorded above. This decision does not claim that deployment has
> occurred and does not authorize Phase C.

| Field | Explicit owner completion |
|---|---|
| Final Gate B decision | **PENDING — select AUTHORIZE, REJECT or DEFER** |
| Effective maintenance window | ______________________________ |
| Owner/change-manager signature | ______________________________ |
| Production-operator acceptance | ______________________________ |
| Date/time and timezone | ______________________________ |
| External approval reference, or `NONE — owner attestation §3` | ______________________________ |

Until this section and §§3–4 are explicitly completed, status remains **GATE B HELD**. No service may be stopped and no production
backup, source apply or migration may begin.

## 6. Resulting status vocabulary

- Before signed exception and final decision: **READY_FOR_PRODUCTION_APPROVAL — GATE B HELD**.
- After valid signed exception, non-blocking external declaration and final `AUTHORIZE`: **GATE B AUTHORIZED — NOT DEPLOYED**.
- Only after B1–B13 and required live acceptance/soak evidence: **PRODUCTION_DEPLOYED_AND_ACCEPTED**.

None of those states authorizes credential provisioning, host-key acceptance, device approval/adoption, gateway changes or any other
Phase C action.
