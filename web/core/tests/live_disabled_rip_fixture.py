"""V2 Phase 9 LIVE harness -- a RIP instance disabled in intent, on cEOS, with real route exchange.

NOT part of any automated suite (the module name does not match ``test*.py``).  It runs inside the NMAS namespace of the
isolated decommission fixture (``labs/decommission-isolated``; STUB Et1 10.254.86.1/31 <-> E2 Et4 10.254.86.0/31):

    labs/decommission-isolated/fixture.sh up
    labs/decommission-isolated/run-harness.sh migrate
    NMAS_LIVE_MODULE=core.tests.live_disabled_rip_fixture labs/decommission-isolated/run-harness.sh

The device under test is STUB.  Every STUB change is rendered by NMAS's own renderer (``platform_drivers._ceos_rip_descriptors``)
and applied / compensated by ``CeosExecutor`` over NMAS's SSH transport (the fixture's key-only ``nmas-svc``).  The fixture
console (``fixture.sh cli``) is used only for the scaffolding NMAS does not own: the two loopbacks and the RIP peer on E2, and
for removing them afterwards.

    1 baseline        no RIP anywhere; neither RIP-only prefix is routed
    2 enable          NMAS renders the ENABLED instance (``no shutdown``) and applies it; both prefixes are learned via RIP
    3 disable         NMAS renders the DISABLED instance (``shutdown``) and applies it; both RIP routes are withdrawn
    4 undo disable    compensation restores the exact enabled digest; both RIP routes return
    5 undo enable     compensation restores the exact baseline digest; no RIP route remains
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from django.conf import settings

from core.tests import live_decommission_fixture as P7

REPO = Path(settings.REPO_ROOT)
EVIDENCE = Path(os.environ.get("NMAS_RIP_LIVE_EVIDENCE") or P7.RUNTIME / "evidence-rip")
STUB_PREFIX, PEER_PREFIX = "203.0.113.0/24", "198.51.100.0/24"
INTERFACES = {"if_e1": {"id": "if_e1", "name": "Ethernet1", "addresses": {"a1": {"id": "a1", "sequence": 1, "family": "IPV4", "cidr": "10.254.86.1/31"}}},
              "if_lo": {"id": "if_lo", "name": "Loopback77", "addresses": {"a2": {"id": "a2", "sequence": 1, "family": "IPV4", "cidr": "203.0.113.1/24"}}}}


def instance(enabled: bool) -> dict:
    return {"id": "rip_live", "address_family": "IPV4", "enabled": enabled,
            "interfaces": {"b1": {"id": "b1", "interface_id": "if_e1", "passive": False, "sequence": 1},
                           "b2": {"id": "b2", "interface_id": "if_lo", "passive": False, "sequence": 2}}}


def rendered(enabled: bool) -> list[str]:
    from core.services import candidate_renderer, platform_drivers

    lines = [text for d in platform_drivers._ceos_rip_descriptors(instance(enabled), INTERFACES)   # pylint: disable=protected-access
             if (text := candidate_renderer.descriptor_text(d)) is not None]
    assert not any(line.startswith(platform_drivers.UNSUPPORTED_OBJECT_MARKER) for line in lines), lines
    return lines


def spec(cfg_id: str, lines: list[str]):
    from core.services.execution.executors.base import ConfigletSpec

    return ConfigletSpec(cfg_id=cfg_id, sequence=1, device="STUB", platform="arista_ceos", object_type="routing_rip",
                         operation="CREATE_DEFINE", lines=tuple(lines), expected={"protocol": "rip", "version": "IPV4"})


def evidence(name: str, payload) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    for marker in ("PRIVATE KEY", "secret sha512", "$6$"):
        assert marker not in text, f"evidence {name} would carry secret material ({marker})"
    (EVIDENCE / name).write_text(text + "\n", encoding="utf-8")
    print(f"[evidence] {name}", flush=True)


def scaffold(node: str, command: str) -> None:
    done = P7.fixture("cli", node, f"configure\n{command}", check=False)
    assert done.returncode == 0 and "% " not in done.stdout, (node, command, done.stdout[-300:], done.stderr[-300:])


def wait_rip_available(node: str, timeout: float = 900.0) -> float:
    """cEOS on a loaded host offers ``router rip`` only late in boot (live finding: "% Unavailable command (not supported on
    this hardware platform)" for minutes after the CLI answers).  Probed in a configuration session that is aborted, so the
    probe never commits anything."""
    started = time.monotonic()
    while True:
        done = P7.fixture("cli", node, "configure session nmas-rip-ready\nrouter rip\nabort", check=False)
        if "Unavailable command (not supported" not in done.stdout and done.returncode == 0:
            return round(time.monotonic() - started, 1)
        assert time.monotonic() - started < timeout, (node, done.stdout[-300:])
        time.sleep(10)


class Run:
    def __init__(self):
        from core.services.execution.executors.ceos import CeosExecutor

        self.h = P7.Harness()
        self.stub = CeosExecutor({"name": "STUB", "platform": "ceos"})
        self.peer = CeosExecutor({"name": "E2", "platform": "ceos"})

    def rip_route(self, executor, prefix: str) -> str:
        """The RIP route to ``prefix`` as the device shows it ("" when none), read over NMAS's SSH session."""
        text = executor.show(f"show ip route {prefix}")
        return next((line.strip() for line in text.splitlines() if re.match(rf"^\s*R\s+{re.escape(prefix)}\b", line)), "")

    def routes(self) -> dict:
        return {"STUB learns peer": self.rip_route(self.stub, PEER_PREFIX), "E2 learns STUB": self.rip_route(self.peer, STUB_PREFIX)}

    def wait(self, present: bool, timeout: float = 300.0) -> tuple[dict, float]:
        started = time.monotonic()
        while True:
            seen = self.routes()
            if all(bool(v) == present for v in seen.values()) or time.monotonic() - started > timeout:
                return seen, round(time.monotonic() - started, 1)
            time.sleep(3)

    def section(self) -> list[str]:
        return [line for line in self.stub.show("show running-config section router rip").splitlines() if line.strip()]

    def main(self) -> None:
        self.readiness = {node: wait_rip_available(node) for node in ("stub", "e2")}
        try:
            scaffold("stub", "interface Loopback77\nip address 203.0.113.1/24")
            scaffold("e2", "interface Loopback78\nip address 198.51.100.1/24\nrouter rip\nnetwork 10.254.86.0/31\nnetwork 198.51.100.0/24\nno shutdown")
            self.stub.connect()
            self.peer.connect()
            self.run_stages()
        finally:
            self.stub.close()
            self.peer.close()
            P7.fixture("cli", "e2", "configure\nno router rip\nno interface Loopback78", check=False)
            P7.fixture("cli", "stub", "configure\nno interface Loopback77", check=False)

    def run_stages(self) -> None:
        baseline = self.stub.config_state_digest()
        evidence("10-baseline.json", {"rip_available_after_seconds": self.readiness, "stub_digest": baseline, "routes": self.routes(), "stub_rip_section": self.section()})
        assert not any(self.routes().values())

        enable = spec("CFG-RIP-ENABLE", rendered(True))
        a_enable = self.stub.assess(enable)
        assert a_enable.restorable, a_enable
        applied = self.stub.apply(enable, a_enable)
        assert applied.ok, applied
        learned, seconds = self.wait(True)
        enabled_digest = self.stub.config_state_digest()
        evidence("20-enable.json", {"configlet": list(enable.lines), "assessment": {"action": a_enable.action, "restorable": a_enable.restorable},
                                    "applied": applied.ok, "routes": learned, "seconds_to_learn": seconds, "stub_rip_section": self.section(),
                                    "stub_digest": enabled_digest})
        assert all(learned.values()), learned

        disable = spec("CFG-RIP-DISABLE", rendered(False))
        a_disable = self.stub.assess(disable)
        assert a_disable.restorable, a_disable
        applied = self.stub.apply(disable, a_disable)
        assert applied.ok, applied
        withdrawn, seconds = self.wait(False)
        section = self.section()
        evidence("30-disable.json", {"configlet": list(disable.lines), "previous_renderer_output": ["! RIP instance disabled in intent; not rendered"],
                                     "assessment": {"action": a_disable.action, "restorable": a_disable.restorable}, "applied": applied.ok,
                                     "routes": withdrawn, "seconds_to_withdraw": seconds, "stub_rip_section": section,
                                     "stub_digest": self.stub.config_state_digest()})
        assert not any(withdrawn.values()), withdrawn
        assert "shutdown" in [line.strip() for line in section], section

        undo = self.stub.compensate(disable, a_disable)
        relearned, seconds = self.wait(True)
        digest = self.stub.config_state_digest()
        evidence("40-undo-disable.json", {"compensation": {"status": undo.status, "error": undo.error_code}, "routes": relearned,
                                          "seconds_to_relearn": seconds, "stub_digest": digest, "equals_enabled_digest": digest == enabled_digest,
                                          "stub_rip_section": self.section()})
        assert undo.status == "COMPENSATED" and digest == enabled_digest and all(relearned.values())

        undo = self.stub.compensate(enable, a_enable)
        gone, seconds = self.wait(False)
        digest = self.stub.config_state_digest()
        evidence("50-undo-enable.json", {"compensation": {"status": undo.status, "error": undo.error_code}, "routes": gone,
                                         "seconds_to_withdraw": seconds, "stub_digest": digest, "equals_baseline_digest": digest == baseline,
                                         "stub_rip_section": self.section()})
        assert undo.status == "COMPENSATED" and digest == baseline and not any(gone.values())


def main():
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    Run().main()
    evidence("99-index.json", {"started": started, "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                               "files": sorted(p.name for p in EVIDENCE.glob("*.json")),
                               "fixture": "labs/decommission-isolated (cEOS 4.36.2F), STUB under test, E2 the RIP peer",
                               "transport": "CeosExecutor over SSH as nmas-svc (key only) from the fixture NMAS namespace"})
