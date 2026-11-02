# NMAS V2 Phase 4 — management multihoming: live evidence

Revalidated on 2026-10-26 (UTC) in the disposable, isolated fixture `labs/mgmt-multihoming-isolated/`. Nothing here was run
against the production lab, its VLAN 200, NetBox, DHCP, routing, monitoring or any deployed database. The fixture was torn
down afterwards: the host link count was 37 before, while up and after, and no `nmas-mgmt-p4-*` containers remain.

## Fixture (what is real, what stands in)

| Element | Real | Stand-in / limitation |
|---|---|---|
| DUT1, MSW1 (management switch, STP root), SW1 (adjacent switch) | cEOS `4.36.2F`, real EOS CLI, SSH, STP (MSTP), LLDP | Software forwarding (ETBA); fixture-local VLAN 200, not the production one |
| NMAS | NMAS code (Django test runner) inside its own network namespace with two real interfaces: `eth1` 10.254.40.10/24 → MSW1, `eth2` 10.254.42.2/30 → DUT1 Ethernet3 | The namespace is an alpine holder; `run-harness.sh` adds a private mount namespace with that namespace's sysfs so NMAS-side observation reads the fixture interfaces, not the host's |
| Links | veth pairs created by `fixture.sh`; every container uses Docker network `none` | No Containerlab management bridge, no docker0, no route to the lab or the host |
| Failures | `oob`: MSW1 Ethernet2 shut. `via-sw1`: SW1 Ethernet2 shut. `msw`: MSW1 frozen (`docker pause`): links up, nothing forwarded | Injected on fixture switches only, never on DUT1. cEOS re-enables a kernel-downed veth, so switch ports are shut instead |
| Credentials | ed25519 keys generated into `runtime/` (git-ignored, removed by `down`); NMAS read them through a `FileSecretProvider` store | Throwaway fixture keys only. Accounts carry random `openssl passwd -6` secrets that nobody knows |
| Host-key confirmation | `fixture.sh hostkey dut` reads the key via `docker exec … Cli` | Stands in for reading the key on a physical console. NMAS never uses this path |
| ZTP enrollment account | `fixture-admin` installs `nmas-enroll` with the session's enrollment public key | Stands in for the Phase 3 delivered bootstrap artifact; live ZTP is Phase 3's evidence |

Run: `fixture.sh up`, then `run-harness.sh <evidence dir> LiveManagementFixture` and `… LiveBootstrapRetirement`
(module `core/tests/live_management_fixture.py`, skipped unless `NMAS_MGMT_LIVE_FIXTURE=1`), then `fixture.sh down`.

## Files

### `live/vrf-execution.json` (+ `vrf-running-before.txt`, `vrf-running-applied.txt`, secrets redacted)
- A six-Configlet management-VRF plan, built by the real intent → validate → `build_change_plan` path. It covers VRF MGMT,
  the Ethernet3 binding, a static route, and SSH, eAPI and gNMI in the VRF.
- The plan was applied by the real `CeosExecutor` through the production resolver and interface/source-bound, pinned
  Netmiko connector. `binding` records the actual socket interface, source and peer. `show vrf` shows MGMT routing on Et3, and an SSH
  login *inside the VRF* (10.254.42.1) returned hostname `DUT1`.
- Compensation ran in reverse and every Configlet ended COMPENSATED. The running-config digest after compensation equals the
  digest before the plan. Re-applying produced the same applied digest (complete digests are in the JSON).
- A client-side lost-response injection after an accepted real VRF write produced `TRANSPORT_ERROR` with partial effects.
  The write was sent once, without replay; compensation restored the original digest. This is a response-loss injection,
  not a claim that a physical link was disconnected during that write.
- Not exercised live: SYSLOG, NTP and SNMP in the VRF. Their execution stays refused, because the service gate is now
  per service (`arista_ceos:execute:mgmt_vrf_service:<SERVICE>`).

### `live/failover.json`
Three approved paths to DUT1:

| Path | Class | Type | Route |
|---|---|---|---|
| MPATH-000001 | 1 | DIRECT_OOB | Vlan200 via MSW1 |
| MPATH-000002 | 2 | VLAN_ADJACENT_SWITCH | via SW1 |
| MPATH-000003 | 3 | ROUTED_VRF | 10.254.42.1 in VRF MGMT, over the independent `fx-direct` NMAS attachment |

- Attachments were observed from live LLDP on MSW1 and SW1. Both NMAS attachments were observed from the NMAS namespace
  (sysfs + iproute2).
- Transitions:
  - ACTIVATE 1
  - `fail oob` → FAILOVER 1→2 (`L1_LINK_DOWN`), after two hysteresis evaluations
  - `fail via-sw1` → FAILOVER 2→3 (`L3_UNREACHABLE`)
  - `fail msw` (MSW1 frozen) → stays on 3, and the device is still managed
  - restore all → restoration threshold, then FAILBACK 3→1 (`PREFERRED_PATH_RESTORED`) after the 30 s hold-down
- Each successful evaluation records `consumer_reached` and `consumer_binding`: the production cEOS connector performs
  authenticated `show hostname`; the actual socket's `SO_BINDTODEVICE`, local address and peer must match the selected path.
  Health and NSOT running-config reads also succeed after each activation, failover and failback. During degraded hysteresis,
  new consumers are BLOCKED rather than silently using the other L2 link. Failback occurred 38.702 seconds after VRF failover,
  exceeding the configured 30-second hold-down.
- During the MSW1 failure, `spof_report` reports `management_switch_failure_tolerant: true`. That holds only because the
  fixture has two verified NMAS attachments in separate failure domains. DUT1 itself is `fully_redundant: false`.
- Live negatives:
  - duplicate path → `MGMT_PATH_DUPLICATE`
  - wrong pinned host key → `L5_HOST_KEY_MISMATCH`; no credential is offered, and `highest_layer` is 1 because L2 is read
    over the authenticated session
  - revoked path → `PROBE_TARGET_FORBIDDEN`; it is never contacted
  - Containerlab network as an NMAS attachment → `MGMT_ENDPOINT_FORBIDDEN`
  - nonexistent interface, unavailable source, and route through the wrong bound interface → `BOUND_CONNECT_FAILED`
  - revoking the active path blocks the production connector (`NOT_CONFIGURED`); revoking every remaining approved path
    still refuses the connector (`negative_all_paths_revoked_no_legacy_fallback: NOT_CONFIGURED`) and never restores inventory access

### `live/bootstrap-retirement.json`
- Sequence: preflight over the bootstrap session → install `nmas-ops` (key-only) in a configure session → verify over an
  independent pinned session → `no username nmas-enroll` with `commit timer 00:10:00` → prove that the account is absent
  **and** that the device rejects the bootstrap key → confirm the commit → retire the provider secret → COMPLETE.
- Independent re-proof afterwards: `nmas-enroll` is absent, the bootstrap key gets `AUTH_FAILED`, and `nmas-ops` logs in.
- The revalidation uses a socket bound to fixture `eth1` / `10.254.40.10`; the production enrollment address and key are
  substituted by the disposable DUT's address and console-confirmed key, as stated in the harness.

### `live/isolation-cleanup.json`
- Before/after checks show 37 host interfaces, unchanged addresses/flags and IPv4/IPv6 routes, unchanged existing container
  IDs and named namespaces, no remaining fixture containers, and no fixture runtime credentials. Address lease/RA lifetime
  countdowns are excluded from equality; address values and interface properties are retained.

## Live findings (defects found by this fixture and fixed, each with a regression test)

1. **Multi-Configlet compensation digest (cEOS executor).** The engine assesses every Configlet before applying any, so a
   management config-block Configlet captured its inverse and digest from the *pre-plan* state. GNMI compensation then
   failed with `STATE_NOT_RESTORED`. Fix: `CeosExecutor.apply` re-captures the inverse and digest at apply time for
   management block types. Regression: `MultiConfigletCompensationTests` (it fails without the fix).
   *Not verified:* whether other pre-existing CONFIG_BLOCK types share this pattern. They fail safe (COMPENSATION_FAILED).
2. **Silence treated as completion (`ssh.PinnedCli.configure`).** One live retirement run left the EOS revoke session
   `pending` with `no username nmas-enroll` staged and uncommitted. The proof step correctly refused completion, and the
   bootstrap account stayed intact. The cause: a line counted as finished after 0.4 s of quiet, so the channel could close
   before EOS had processed `commit timer`. Fix: every line now waits for the CLI prompt, and no prompt before the timeout
   is `TRANSPORT_ERROR` (UNCERTAIN, `sent: true`). Regression:
   `test_pinned_cli_configure_without_a_returning_prompt_fails_and_sends_nothing_more` (fails without the fix).
3. **Half-run revocation left on the device.** When the proof finds the bootstrap account still present, the uncommitted
   revoke session is now aborted (`uncommitted_session: ABORTED`), so nobody can commit it later.
4. **Session-name reuse.** EOS refuses to re-enter a completed session (`% Cannot enter session … (already completed)`,
   observed live). Session names now carry the transition's binding-digest prefix
   (`nmas-bcred-<id>-<digest8>-<kind>`), so a reset NMAS database cannot collide with a session already on the device.
5. **SPOF report named the managed device as its own switch** (`switch:DUT1` for the direct attachment). Fixed in
   `nmas_side.path_dependencies`.

6. **Concurrent credential retirement.** A bounded, network-free reproducer let a competing retirement enter device I/O,
   close the transition and strand the first worker after a configuration write. Retirement now holds a nonblocking kernel
   file lock, shared with Change and maintenance device-lock acquisition. An execution-start journal prevents concurrent
   cancellation or selector movement; uncertainty is recorded before install, undo and revocation writes. Interrupted
   credential state blocks other writers until explicit reconciliation. The current Linux/local-SQLite deployment shares
   locks by canonical database path; no database transaction spans network I/O. `ConcurrentRetirementTests` proves zero
   competing device calls, Change/maintenance exclusion, cancellation refusal and accepted-write recovery with one install.
   `DeviceMutexTests` also proves exclusion across processes, release on exit and failure, and refusal of unsafe lock paths.
   The selector additionally rechecks for a newly arrived writer inside its selection transaction before committing a
   switch; a deterministic late-claim regression proves deferral instead of activation.

7. **Last-path revocation restored legacy access.** The resolver previously treated a revoked-only path set like a
   device that had never registered any paths. It now retains fail-closed path management after registration, including
   pending and revoked-only sets. The selector reports NO_PATH in that state. Active-path acknowledgement is also rechecked
   under the revocation transaction lock, so a stale browser/model instance cannot revoke a newly activated path without
   acknowledgement. Regressions cover pending registration, the last revoked path, zero consumer connection attempts and
   stale active-path revocation. The isolated live negative revokes all remaining approved paths and proves NOT_CONFIGURED.

Observed but not defects:
- On the first live run, EOS refused SSH inside the VRF immediately after the commit; the per-VRF sshd starts
  asynchronously. The harness waits for the port. On later runs it was open at 0.0 s.
- DUT1 Ethernet2 is STP alternate (discarding) until Ethernet1 fails.

## Limitations of this evidence

- **Classes 1 and 2 share one endpoint** (DUT1 Vlan200 10.254.40.21). The selector tells them apart by the path's local
  interface status and the probe outcome. The probe does not read the adjacent switch's configuration or STP state, so when
  the active L2 path degrades, STP may still carry an already established connection over the other link. New connections
  are refused while the selected path is degraded. Socket binding enforces NMAS egress and source; it does not pin an
  intermediate L2 switch port. The fixture's verified LLDP links and injected port failures establish the tested alternatives.
- The supported routed-VRF path is currently an on-link NMAS-to-device neighbor in the attachment's prefix, as in this
  fixture. A routed path through a switch or several hops is refused until NMAS can verify the upstream route and physical
  neighbor chain; source-bound SSH alone cannot authorize those intermediate networks.
- Telemetry does not follow failover (Phase 8). It was neither tested nor claimed.
- Only Arista cEOS has live evidence. The other platforms are render and validate only.
- In production, NMAS has one attachment (mgmt_swt). Management-switch failure tolerance is proven only for the fixture
  topology and is not claimed for production (`NMAS_SINGLE_ATTACHMENT`).

## Full-trace deadline recovery measurements

- The earlier bounded, verbose full-scope diagnostic completed 1,624 tests in 1,500 seconds without a blocked test.
  That measured diagnostic suite contained 6,328 tests. A subsequent complete-scope attempt reached the old 2,700-second limit
  while CPU active; its trace was incomplete and its governance report was not accepted as a pass.
- Tier-3 bounds each report line to 300 characters, so a clipped line of progress dots cannot establish a completed-test
  count. Full traced Django now uses verbosity 2 so a timeout tail retains actual test names.
- Ten-second samples at different points observed completed-test writes. The process stayed near one CPU with one thread;
  a five-second profile showed Python execution and coverage tracing. No leaked SSH fixture or accidentally discovered live
  harness was demonstrated.
- A bounded comparison with the entire suite imported ran the same two import-preservation cases in both monitoring modes:
  per-method event toggling took 0.418 seconds of test execution; stable global monitoring took 0.210 seconds. Direct-call
  evidence was identical. The tracer retains stable global monitoring, identity-based code caches and its original
  method-extent/fixture exclusion rules. A nested-runner regression proves return and exception evidence remain collected.
- Scaling the early diagnostic suggested a conservative 5,845-second estimate, so a temporary 7,200-second diagnostic
  ceiling allowed the actual full run to finish. It completed all 6,328 tests in 2,754.096 process seconds (2,724.985 test
  execution seconds): 6,326 passed, one documentation-catalogue contract failed, and one opt-in runtime smoke test skipped.
  Monitoring's 851 tests and the complete governance report passed. The documentation defect was corrected separately.
- The completed run proves the old 2,700-second limit was 54.096 seconds short. The final suite limit is 3,600 seconds,
  matching the standalone collector's existing one-hour budget, with a 90-minute hosted job bound for setup/reporting.
  Test scope, polarity, coverage collection, case requirements, debt baseline and capability closure remain unchanged.
