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
lineage-specific context.

`chg-023/` holds the exact per-file diffs from the deployed pre-change content to the deployed release. Their hashes are
recorded in the change record and the release `PROVENANCE.json`.
