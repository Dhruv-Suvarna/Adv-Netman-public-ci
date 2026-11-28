# L2 runtime evidence source (HC08 VLAN/port mode, HC09 MAC movement)

Subtask f4-f4_l2 of JOB-9AA10B4E7CA7, attempt 1. Source HEAD cbb9c96 plus existing uncommitted work. Changed only the six assigned files. No production, gateway policy, topology, compatibility ledger, remote repository or credentials were touched; no device was contacted.

## Path (no new collector or database)

`CliCollector` catalogue (cEOS, read-only) -> parser -> `runtime.map_observations` -> engine keys -> `runbooks/hc.py`.

| Catalogue key | Command | Parser | Engine key | Consumer |
|---|---|---|---|---|
| `switchport` (new) | `show interfaces switchport \| json` | `l2.port` / `eos-json-1.0` | `l2.port@<interface>` = `{mode, access_vlan, allowed_vlans, native_vlan, uncertain}` | HC08 |
| `mac_table` (was evidence-only) | `show mac address-table \| json` | `mac.table` / `eos-json-1.0` | `mac.table@<vlan>` = `{moves_per_min, flapping_macs, move_count_window, mac_count, dynamic_count, interfaces, uncertain}` | HC09 |

`adapters/l2.py` provides `L2Context` (caller-owned MAC history, injected as `RuntimeDeps.l2_context`, in memory only) and `describe_source()` labelling SIMULATED / RECORDED / LIVE_GATEWAY_PINNED (live only for `gateway.live is True`; a label, not an attestation verifier). IOS XE stays evidence-only (no parser).

## Safety rules implemented

- **Version gate:** both parsers cEOS EOS >= 4.28 and < 5.0 (a simulated envelope, not live qualification). The collector refuses before contacting the device (`PARSER_UNAVAILABLE`); unknown/empty versions refuse.
- **Raw hash, source and scope preserved:** observations carry `raw_hash`, command, transport, parser id/version; VLAN (`target.vlan`) and interface scope are kept; gateway dict is carried verbatim.
- **MAC movement needs history:** moves are derived only from differences between two consecutive complete samples (dynamic entries only; static ignored). First sample, gap > 900 s, span < 60 s or non-monotonic sample -> `moves_per_min = None` with `uncertain` notes, never zero. Window 600 s; `flapping_macs` = MACs with >= 2 moves in the window.
- **Partial parse never advances history.** Dropped rows, duplicate (VLAN, MAC), or fewer entries than announced `totalMacAddresses` -> PARTIAL.
- **Empty/incomplete tables do not prove absence:** empty MAC table or `switchports` -> `EMPTY` gap; a VLAN missing from the table yields no observation (gap).
- **HC08/HC09 only read headline fields**, so `runtime.map_observations` stores any `mac.table`/`l2.port` value with `uncertain` notes as `UNTRUSTED` (retained for audit, blocked from PASS and FAULT). Any parse error makes every port of that document PARTIAL; unsupported modes (e.g. dot1q-tunnel) and malformed VLAN lists are `UNTRUSTED_PARSE`. `ALL` expands to 1-4094, `NONE` to `[]`; malformed/out-of-range lists are never guessed.
- Consequence: HC09 cannot report a fault on the first poll; it requires >= 60 s of sample history.

## Validation (SIMULATED inputs only)

All documents are hand-written to the EOS JSON shape inside `web/core/tests/test_troubleshooting_l2_source.py`; fixture time 2026-11-09T12:00:00Z. Stable IDs L2SRC-001..016: switchport contract, malformed/partial/unsupported mode, version gates, first-sample unknown, history movement/flapping, short span/gap/non-monotonic, wrong-VLAN isolation, static entries, empty/malformed/partial/truncated tables, catalogue read-only + source labels + no-contact refusal, collector raw hash/gateway/history, runtime->RB02 HC08 PASS / wrong access VLAN / trunk disallow FAIL, HC09 PASS / flap FAIL / other-VLAN flap PASS, unknown/partial/empty never PASS, unsupported version no contact + evidence provenance (gateway live=false).

Commands (from `web/`, `DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python manage.py test ...`):

- `core.tests.test_troubleshooting_l2_source`: **16 tests PASS**.
- `core.tests.test_troubleshooting_l2_source core.tests.test_troubleshooting_stp_source core.tests.test_troubleshooting_runbooks core.tests.test_troubleshooting_collectors core.tests.test_troubleshooting_runtime core.tests.test_troubleshooting_forwarding_source`: 194 tests, **193 PASS, 1 FAIL**: `test_troubleshooting_runtime.MappingTests.test_RT003...` line 133 still expects `mac.table` gap `PARSER_UNAVAILABLE` for `{}`; it is now `PARSE_FAILED` (parser exists). Test is outside this write scope: **INCOMPLETE_WORK** for the integration owner (change the assertion to `PARSE_FAILED`).
- `python3 -m py_compile` on the four changed modules: PASS.

## INCOMPLETE_WORK / live prerequisites

- No gateway-recorded cEOS 4.36.2F `show interfaces switchport | json` / `show mac address-table | json` is pinned; the real field names (`switchportInfo`, `accessVlanId`, `trunkAllowedVlans`, `unicastTable.tableEntries`, `entryType`) are from the EOS schema as understood, unverified live. Gateway live run (disposable `ceos_pair`) is required before claiming live evidence.
- `deployment.py` has no `l2_context_provider` yet (out of scope); until wired, `RuntimeDeps.l2_context` is None and HC09 stays INCONCLUSIVE. A scheduler/poll cadence retaining context across polls is a deployment prerequisite; history is not restart-persistent.
- MAC flooding/unknown-unicast, EVPN/VXLAN MAC mobility and the EOS per-entry `moves` counter are not used. Interface naming in intent must match the canonical long names (`Ethernet1`).

## Source pins (SHA-256)

```text
3d248aaec0e2961a1f0c0d09df34c02d151a128ade6d822cd513d9de3c863693  web/core/services/troubleshooting/normalization.py
96612e04db7a7d271ca6b7e92a149aa5425fedf168f32665edd793ac855dd318  web/core/services/troubleshooting/collectors.py
f74a7830812b9bc57a7b9ec75ec99f186c1d8f9641d3dd82809d841c473940db  web/core/services/troubleshooting/runtime.py
045dbab37cd5c05dfae9391f2ca6b6e13fd193c5a78f58230064926ed8aef59d  web/core/services/troubleshooting/adapters/l2.py
ee8021967d2506a2b6651ab5f8930dc0792b0b37102ac469d1e1685d74254073  web/core/tests/test_troubleshooting_l2_source.py
```
