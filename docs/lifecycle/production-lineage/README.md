# Deployed ZTP lineage: how this branch's lease handling reaches production

The production NMAS web tree (`clab_dualstack_lab-deploy/web`) is **not** a checkout of this branch. It was built up by
earlier releases. Its ZTP, isolation and commissioning modules form a sibling lineage, the one the live Lab 8/9 onboarding
ran on (R6, R7, R8, S5). The main difference in ZTP:

| | This branch (`99282bc` lineage) | Deployed lineage |
|---|---|---|
| Option 82 trust of a cEOS relay | NMAS's stored read-back (`ztp/relay_option82.py`) | Live read of the relay's running-config in `workflow` (`_upstream_running_config` → `dhcp_relay_option82.parse_eos`) |

CHG-NMAS-20261127-ZTP-LEASE-023 therefore does **not** copy branch files over production's ZTP modules. It applies this
branch's changes as hunks onto the deployed files. Every hunk applied unchanged except one:

- `workflow.bootstrap_path_checks(device, attachment, network)` is the single path gate shared by session open and the
  controlled re-discovery window (`lease.expect_renewal`).
  - **Branch:** it is `dependencies.evaluate(...)`.
  - **Deployed lineage:** it is production's existing live relay read, moved out of `open_problems` unchanged (an unreadable
    relay is still `RELAY_UNTRUSTED`), followed by `dependencies.evaluate(..., relay_readback=...)`.

  So an R7 re-discovery passes exactly the gates its session was opened under, in both lineages.
- **Deployed test helper** `core/tests/helpers/ztp.py`: the live relay transport (`workflow._upstream_running_config`) is
  stubbed with S1's running-config as S1 relays the test network.
  - The parse and the option 82 checks stay real.
  - Before this, 157 of the deployed tree's ZTP / commissioning tests failed closed with `RELAY_UNTRUSTED`, because the tests
    had no relay to read.
  - The branch helper records a stored read-back instead and is unchanged.

`ztp/policy.py`, `ztp/artifacts.py`, `ztp/lease.py` (new), `management/commands/nmas_ztp.py` and
`tests/test_single_admin_lab_exception.py` are byte-identical in both lineages. The other files carry identical hunks on
lineage-specific context, with one exception: on the branch, `identity/single_admin_exception.py` also drops two unused imports
(`os`, `timedelta`) that the deployed variant never had.

`chg-023/` holds the exact per-file diffs from the deployed pre-change content to the deployed release. Their hashes are
recorded in the change record and the release `PROVENANCE.json`.

## CHG-NMAS-20261127-PROD-TEST-REMEDIATION-024: the 23 inherited admission/isolation test failures

Before this change, 23 tests in the deployed tree failed on production's own code, with or without CHG-023. Each one was
classified against production's admission and isolation code. **None is a defect in production code.** Every failure is a
deployed test that predates legitimate production behavior from the Lab 9 lineage. So the change is five test files, taken
byte-for-byte from this branch (commit `ea4f65f`). No application module changed, and every admission and isolation gate the
tests assert is still asserted.

| Failures | Classification | Cause in the deployed tests | Correction |
|---|---|---|---|
| 6 in `test_commissioning.AdmissionTests`, 13 in `test_tg_commissioning_closure` (admission, model, outbox, gate closure) | Outdated fixture | `admission.plan()` reads the upstream at plan time. With no `access`, it falls back to `default_access(policy.upstream_platform)`, a live transport. The tests passed their fake access to `precheck`/`execute` only, so `plan` failed closed. | Pass the test's fake `access` to `plan` as well. The same refusals (self-approval, stale/unapproved execution, a second plan) are still asserted. |
| Same tests, via the EOS double (`helpers/isolation.py`) | Test double | Production reads `show ipv6 ospf neighbor \| json` (OSPFv3) and treats the DHCP relay option 82 circuit-id/remote-id as single-valued, as cEOS 4.36.2F does. The double returned nothing for the first and kept duplicates for the second. | The double returns cEOS's empty OSPFv3 answer and models the two single-valued relay settings. |
| `test_tg_isolation_closure` ×2 (`upstream_device` of another policy; `release_helpers` drift) | Test double | `isolation.service.upstream_device()` branches on `policy.upstream_platform` (FRR vs cEOS). The `SimpleNamespace` policy doubles omitted a field every real `IsolationPolicy` row has. | The doubles carry `upstream_platform`. The drift refusal and the other-policy assertion are unchanged. |
| `test_isolation_eos.RenderTests.test_render_release_refuses_an_uncovered_operation` | Outdated fixture | It dropped the last `RELEASE_ORDER` key, assuming that was `acl-v4`. Production appended the control-plane ACL keys after it. | It removes exactly `acl-v4`, so an uncovered operation is still refused. |
| `test_isolation_eos.IntentProblemTests.test_management_plane_exposed_by_other_services_or_nmas_lockout` | Production-specific divergence (legitimate) | Production closes eAPI, gNMI, NETCONF and SNMP to the isolated device by installing an NMAS control-plane ACL (`attach-cp-v4/v6`, released exactly). It no longer refuses those services outright. | `ISOLATION_MGMT_PLANE_EXPOSED` is still asserted where exposure remains: an operator's custom control-plane ACL, or NMAS lockout. New tests check the NMAS control-plane ACL entries, the attach/release lines and their order, and the IPv6 link-local denies. |

`chg-024/` holds the exact per-file diffs from the deployed pre-change content to the release.
