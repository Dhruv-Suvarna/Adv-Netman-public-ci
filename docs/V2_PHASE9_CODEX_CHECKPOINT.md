# NMAS V2 Phase 9 Codex takeover checkpoint — 2026-10-28

## Active work

- Worktree: `/home/student/Scripts/clab_dualstack_lab-v2-phase9-ceos-isis`.
- Branch: `v2-phase9-ceos-isis` at `5e40d28`, with uncommitted IS-IS probe, transport, tests and evidence. No implementation changes were staged or committed.
- The committed 396-cell ledger still reports **46 SUPPORTED**. The new cEOS `routing.ISIS` assessment is complete and **SUPPORTED in reviewable, uncommitted evidence** at `docs/evidence/v2-phase9-closure/ceos-isis/assessment.json`. The artifact includes the exact hashes of the uncommitted source used for the live run; the authoritative ledger has not yet been promoted.

## cEOS IS-IS result

- Existing implementation already supplied intent, cEOS rendering and validation, the native parser, the `CeosExecutor` process/binding path and operator IS-IS evaluators. The unfinished part was an isolated, end-to-end proof over normal management transport.
- The disposable `clab-nmas-cap-validation-ceos` cEOS 4.36.2F and `clab-nmas-cap-validation-peer` FRR 8.4.4 pair were used on Ethernet2 ↔ eth2. The cEOS management route was pinned to the fixture bridge and source address; SSH authenticated with a runtime-only password and verified the public host key read out of band from the isolated fixture console. Every cEOS configuration and read-back command in this proof used that SSH connection.
- NMAS rendered and applied one IS-IS process and two bindings through `CeosExecutor`. The cEOS adjacency reached UP. NMAS read the learned `198.51.100.0/24` route and passed its routing-process, binding, adjacency and route postchecks; FRR installed `203.0.113.0/24`. The cEOS parser imported the NET, level, address family, interface metric and passive loopback binding.
- Three executor compensations returned `COMPENSATED`; the pre-apply configuration digest and full fixture baseline matched. Negative control before apply and absence after compensation passed. `negative-transport.json` records wrong-host-key and wrong-management-route refusals without a device write.
- One earlier scenario run failed because the probe supplied evaluator check names in place of requirement kinds; it still restored the fixture. A retry exposed FRR zombie processes and an interrupted cleanup path. That disposable residue was restored, daemon detection and cleanup were fixed, and the final live assessment passed. The failed attempts are not counted as positive evidence.
- Focused Django tests: `core.tests.test_ceos_isis_phase9` plus `core.tests.test_isis_ceos`, 18/18 passed. Python compilation and `git diff --check` passed. The full Tier-3 suite is reserved for the release boundary.

## Other recovered work

- cEOS ACL branch/worktree: `/home/student/Scripts/clab_dualstack_lab-v2-phase9-ceos`, branch `v2-phase9-ceos-acl6`, has uncommitted IPv6 ACL renderer, parser, live harness and tests. Preserve those changes; focused verification is the next subsystem action.
- IOS XE branch/worktree: `/home/student/Scripts/clab_dualstack_lab-v2-phase9-iosxe`, branch `v2-phase9-iosxe-routing`, has two uncommitted fixes. Its completed full Django suite command was `xvfb-run -a env DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python manage.py test core`, piped through filters into `/tmp/claude-1001/-home-student/52e860a2-d529-4df7-8dd4-ed3a47592e8e/scratchpad/xe_full2.log`. The wrapper exited 0 because the pipeline ended with `cat`; the actual suite ran 7,430 tests and **FAILED with 10 failures** (7 IOS XE routing render tests and 3 stale 46-cell ledger/governance expectations). Reuse that log and run focused corrections before another full suite.
- SR Linux branch/worktree: `/home/student/Scripts/clab_dualstack_lab-v2-phase9-srlinux`, branch `v2-phase9-srlinux`, has uncommitted harness and test edits. Preserve them.

## Next action

Run the cEOS ACL branch's focused tests, diagnose any failure, and complete its isolated live proof. Then address the IOS XE suite failures and SR Linux partial work in their existing worktrees. Promote each cell in the generated 396-cell ledger only with matching reviewable live evidence; do not stage, commit or merge before the requested human review.
