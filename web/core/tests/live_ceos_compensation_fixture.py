"""LIVE proof of exact cEOS compensation on a disposable cEOSLab 4.36.2F (``NEW1`` of labs/isolation-commissioning-isolated).

NOT part of any automated suite (the module name does not match ``test*.py``).  Run inside the fixture's NMAS namespace with the
fixture settings, after the commissioning fixture admitted NEW1 (``run-harness.sh ... admit``):

    sudo -n nsenter -t "$(labs/isolation-commissioning-isolated/fixture.sh svc-pid)" -n sudo -n -u "$USER" env ... \
        DJANGO_SETTINGS_MODULE=settings_fixture python manage.py shell -c \
        "from core.tests.live_ceos_compensation_fixture import main; main()"

Everything goes through NMAS's own path to the device: ``CeosExecutor`` over SSH (pinned host key, the nmas-svc key) and the
health reader ``live.read_device``.  NEW1 has no link behind ``Ethernet9`` -- exactly the port the defect concerned: EOS keeps its
configuration, interface telemetry never reports it.

Scenarios (each starts and must end at NEW1's original configured state, proven by digest):
  A  two Configlets (port + address on Ethernet9), then reverse compensation: INVERSE_APPLIED twice, exact state again;
     the read groups alone would have called it NONE_NEEDED (recorded)
  B  a lost CLI response: the second Configlet reaches the device but its response is lost -> TIMEOUT; compensation exact
  C  staged configuration left behind: the inverse is swallowed (never reaches the device) -> STATE_NOT_RESTORED, never
     COMPENSATED; a retry then compensates exactly
  D  repeated compensation once exact: NONE_NEEDED, nothing sent
Every scenario also checks that the session is not left in configuration mode.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.services.execution.executors import ceos, state
from core.services.execution.executors.base import ConfigletSpec

DEVICE = "NEW1"
INTERFACE = ConfigletSpec("CFG-L1", 1, DEVICE, "arista_ceos", "interface", "CREATE_DEFINE",
                          ("interface Ethernet9", "   description NMAS live compensation probe (unbacked port)"),
                          {"interface": "Ethernet9"})
ADDRESS = ConfigletSpec("CFG-L2", 2, DEVICE, "arista_ceos", "address", "CREATE_DEFINE",
                        ("interface Ethernet9", "   ip address 192.0.2.9/31"), {"interface": "Ethernet9", "address": "192.0.2.9/31"})


class Lossy:
    """Wraps the real Netmiko session.  ``lose_response``: the next config set reaches the device, its response is lost.
    ``swallow``: the next config set never reaches the device (the staged-state stand-in), and reports success."""

    def __init__(self, inner):
        self.inner, self.lose_response, self.swallow, self.sets = inner, False, False, []

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def send_config_set(self, commands, **kwargs):
        self.sets.append(list(commands))
        if self.swallow:
            self.swallow = False
            return ""
        output = self.inner.send_config_set(commands, **kwargs)
        if self.lose_response:
            self.lose_response = False
            raise TimeoutError("response lost after the device accepted the commands")
        return output


def main():
    from core.services.health import inventory
    from core.tests.live_isolation_commissioning_fixture import EVIDENCE, Harness

    Harness()                                              # the fixture's inventory, credential store and redirections
    device = inventory.managed_devices()[DEVICE]
    holder = {}

    def factory(dev):
        holder["conn"] = Lossy(ceos.netmiko_connection(dev))
        return holder["conn"]

    executor = ceos.CeosExecutor(device, connection_factory=factory)
    executor.connect()
    conn = holder["conn"]
    out = {"device": DEVICE, "transport": "SSH (CeosExecutor / netmiko_connection), reader live.read_device"}
    try:
        original = executor.config_state_digest()
        out["original_digest"] = original
        out["ethernet9_in_telemetry_before"] = "Ethernet9" in (executor._read().facts("interfaces") or {})

        def finish(label):
            out[label]["config_mode_left"] = conn.check_config_mode()
            out[label]["digest_after"] = executor.config_state_digest()
            out[label]["exact"] = out[label]["digest_after"] == original
            assert out[label]["exact"] and not out[label]["config_mode_left"], (label, out[label])

        # A: multi-step, then reverse compensation
        a1, a2 = executor.assess(INTERFACE), executor.assess(ADDRESS)
        out["A"] = {"assess": [[a1.action, a1.restorable], [a2.action, a2.restorable]],
                    "apply": [executor.apply(INTERFACE, a1).ok, executor.apply(ADDRESS, a2).ok]}
        applied = executor._read()
        out["A"]["ethernet9_in_telemetry_after_apply"] = "Ethernet9" in (applied.facts("interfaces") or {})
        out["A"]["running_holds_ethernet9"] = "interface Ethernet9" in executor._config_text()
        out["A"]["read_groups_alone_say_restored"] = [state.restored(ADDRESS, applied, a2.previous_state),
                                                     state.restored(INTERFACE, applied, a1.previous_state)]
        comp = [executor.compensate(ADDRESS, a2), executor.compensate(INTERFACE, a1)]
        out["A"]["compensation"] = [[c.status, c.error_code, c.detail] for c in comp]
        assert [c.status for c in comp] == ["COMPENSATED", "COMPENSATED"], out["A"]
        assert [c.detail.get("action") for c in comp] == ["INVERSE_APPLIED", "INVERSE_APPLIED"], out["A"]
        finish("A")

        # B: a lost CLI response on the second Configlet
        b1, b2 = executor.assess(INTERFACE), executor.assess(ADDRESS)
        first = executor.apply(INTERFACE, b1)
        conn.lose_response = True
        second = executor.apply(ADDRESS, b2)
        out["B"] = {"apply": [[first.ok, first.error_code], [second.ok, second.error_code, second.partial_effects]],
                    "address_on_device": "ip address 192.0.2.9/31" in executor._config_text()}
        comp = [executor.compensate(ADDRESS, b2), executor.compensate(INTERFACE, b1)]
        out["B"]["compensation"] = [[c.status, c.error_code, c.detail] for c in comp]
        assert second.error_code == "TIMEOUT" and [c.status for c in comp] == ["COMPENSATED", "COMPENSATED"], out["B"]
        finish("B")

        # C: the inverse never reaches the device; then a retry
        c1 = executor.assess(INTERFACE)
        executor.apply(INTERFACE, c1)
        conn.swallow = True
        swallowed = executor.compensate(INTERFACE, c1)
        out["C"] = {"swallowed": [swallowed.status, swallowed.error_code, swallowed.detail],
                    "running_still_holds_ethernet9": "interface Ethernet9" in executor._config_text()}
        assert swallowed.status != "COMPENSATED", out["C"]
        retry = executor.compensate(INTERFACE, c1)
        out["C"]["retry"] = [retry.status, retry.error_code, retry.detail]
        assert retry.status == "COMPENSATED", out["C"]
        finish("C")

        # D: repeated compensation once exact
        sets = len(conn.sets)
        again = executor.compensate(INTERFACE, c1)
        out["D"] = {"repeat": [again.status, again.detail], "commands_sent": len(conn.sets) - sets}
        assert again.detail.get("action") == "NONE_NEEDED" and out["D"]["commands_sent"] == 0, out["D"]
        out["D"]["config_mode_left"] = conn.check_config_mode()
        out["final_exact"] = executor.config_state_digest() == original
    finally:
        executor.close()
    target = Path(os.environ.get("NMAS_CEOS_COMP_EVIDENCE") or EVIDENCE) / "80-ceos-exact-compensation.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    print(f"[evidence] {target.name}")
    assert out["final_exact"], out
