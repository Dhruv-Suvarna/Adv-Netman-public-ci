# Exact cEOS compensation — live proof

Run on 2026-10-27 against `NEW1`, a disposable cEOSLab 4.36.2F that the isolated commissioning fixture
(`labs/isolation-commissioning-isolated`) had taken from factory default through ZTP, commissioning and admission. NMAS
reached it the normal way: `CeosExecutor` over SSH (pinned host key, the `nmas-svc` key), with `live.read_device` as the
reader. No production device, database or service was touched.

`NEW1` has no link behind `Ethernet9`. EOS accepts and keeps configuration for that port, but interface telemetry never reports it.

`80-ceos-exact-compensation.json` (digests only, no configuration text):

| Scenario | Result |
|---|---|
| A — port + address on `Ethernet9`, then reverse compensation | Defect reproduced: after apply, the running configuration holds `interface Ethernet9`, yet the read groups alone report both Configlets restored (`[true, true]`), which was the old `NONE_NEEDED` verdict. The fixed executor sent both inverses (`INVERSE_APPLIED`, `exact_configuration: true`), and the configured-state digest equals the original. |
| B — the second Configlet reaches the device but its CLI response is lost | Apply reports `TIMEOUT` with partial effects (the address is on the device); compensation is exact. |
| C — the inverse never reaches the device (staged state left behind) | `COMPENSATION_FAILED / STATE_NOT_RESTORED` (`exact_configuration: false`), never COMPENSATED; a retry then compensates exactly. |
| D — repeated compensation once exact | `NONE_NEEDED`, no command sent. |

After every scenario the session was not in configuration mode, and the device's configured-state digest equals the digest before the run (`final_exact: true`).

Reproduce (after `run-harness.sh ... admit` of the commissioning fixture), inside the fixture's NMAS namespace with
`DJANGO_SETTINGS_MODULE=settings_fixture`:
`python manage.py shell -c "from core.tests.live_ceos_compensation_fixture import main; main()"`.
