"""Shared fixtures for the V2 Phase 3 native-ZTP tests.

NMAS database plus a temporary isolated provider root only: no DHCP service, device or network is touched.  The EOS
verification outputs are the ones NMAS read from the live cEOS 4.36.2F bootstrap (``fixtures/ztp``), re-keyed to the test
device's identity and enrollment key.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from datetime import timedelta
from pathlib import Path

from unittest import mock

from django.test import override_settings
from django.utils import timezone

from core.services.isolation import service as isolation_service
from core.services.ztp import discovery, policy, workflow
from core.tests.helpers import lifecycle as L

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ztp"
RELAY = "10.254.30.1"
CLIENT_ID = "0:1c:73:0:0:1"              # L.MAC 00:1c:73:00:00:01 as ISC's binary-to-ascii writes the client identifier
VENDOR = f"Arista;cEOSLab;{L.SERIAL}"
NET = {"name": "ztp-test", "ipv4_prefix": "10.254.30.0/24", "gateway": RELAY, "pool_start": "10.254.30.10",
       "pool_end": "10.254.30.20", "service_prefix": "10.254.31.0/30", "service_address": "10.254.31.2"}
VALIDATE = ["dhcpd", "-t", "-cf", "{path}"]
STATUS = ["pgrep", "-x", "dhcpd"]


class FakeRunner:
    """Stands in for the isolated provider's validate / status commands; records every argv."""

    def __init__(self, rc=0, output=""):
        self.rc, self.output, self.calls = rc, output, []

    def __call__(self, argv):
        self.calls.append(list(argv))
        return self.rc, self.output


class ZtpTestMixin:
    """A temporary isolated provider root, a temporary enrollment-key store and fake provider commands per test."""

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="nmas-ztp-test-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "dhcp").mkdir()
        override = override_settings(NMAS_ZTP_ENROLLMENT_STORE=str(self.root / "enrollment-store.json"),
                                     NMAS_ZTP_DHCP_COMMANDS={"ISC_DHCP": {"validate": VALIDATE, "status": STATUS}},
                                     NMAS_ZTP_PROVIDER_ROOTS=[str(self.root)])
        override.enable()
        self.addCleanup(override.disable)
        if not getattr(self, "real_isolation_gate", False):
            # Phase 3 behaviour under test: the Phase 5 trusted-isolation gate is satisfied here and exercised on its own in
            # test_isolation_service / test_isolation_ztp_gate (a class sets ``real_isolation_gate = True`` to keep it)
            for name, value in (("ztp_problems", []), ("enforced", True)):
                patcher = mock.patch.object(isolation_service, name, return_value=value)
                patcher.start()
                self.addCleanup(patcher.stop)
        if getattr(self, "relay_readback_present", True) and "default" in (getattr(type(self), "databases", None) or ()):
            # V2 Phase 9: ZTP through a cEOS relay needs NMAS's fresh read-back of the relay's option 82 configuration.  This is
            # the read-back of S1 as it really relays the test network (no gate is stubbed: ``relay_option82`` evaluates it), and
            # ``test_relay_option82`` exercises a missing / stale / forged one (a class sets ``relay_readback_present = False``).
            record_relay_readback()

    def network(self, *, relays=None, **overrides):
        fields = {**NET, "config_root": str(self.root / "dhcp"), **overrides}
        row, problems = policy.create_network(actor=L.APPROVER, trusted_relays=relays or [{"relay_address": RELAY, "upstream_device": "S1"}],
                                              **fields)
        assert not problems, problems
        return row

    def open_session(self, **ready):
        device, _attachment, auth = L.ready_device(**ready)
        result = workflow.open_session(device, authorization=auth, network=self.network(), actor=L.OPERATOR)
        assert result.ok, result.codes
        return result.session

    def discovered(self, **ready):
        session = self.open_session(**ready)
        discovery.ingest(session.network, text=lease())
        session.refresh_from_db()
        return session


def relay_readback(*, enabled=True, circuit_id="", helper=None, address=RELAY, port="Ethernet7") -> dict:
    """``dhcp_relay_option82.parse_eos`` of S1 relaying the test network on ``port`` (option 82 on, default circuit id)."""
    return {"enabled": enabled, "interfaces": {port: {"circuit_id": circuit_id, "remote_id": "",
                                                      "helpers": [helper or NET["service_address"]], "addresses": [address]}}}


def record_relay_readback(device="S1", *, now=None, **fields):
    from core import models
    from core.services.ztp import relay_option82

    return relay_option82.record_readback(device, relay_readback(**fields), source=models.DhcpRelayReadbackSource.READ, digest="0" * 64,
                                          actor=L.OPERATOR, now=now)


def lease(address="10.254.30.10", *, mac="a2:27:1c:9a:b6:7b", client_id=CLIENT_ID, vendor=VENDOR, relay=RELAY, circuit="Ethernet7",
          state="active", minutes=10, start=None) -> str:
    """One ISC ``dhcpd.leases`` block in the shape NMAS's ``on commit`` stash produces (see the live lease evidence)."""
    start = start or timezone.now() - timedelta(minutes=1)
    fmt = "%Y/%m/%d %H:%M:%S"
    lines = [f"lease {address} {{", f"  starts 6 {start.strftime(fmt)};", f"  ends 6 {(start + timedelta(minutes=minutes)).strftime(fmt)};",
             f"  binding state {state};", f"  hardware ethernet {mac};"]
    if client_id:
        lines.append(f'  set nmas-client-id = "{client_id}";')
    if vendor:
        lines.append(f'  set nmas-vendor-class = "{vendor}";')
    if circuit:
        lines.append(f'  set nmas-circuit-id = "{circuit}";')
    if relay:
        lines.append(f'  set nmas-giaddr = "{relay}";')
    return "\n".join(lines + ["}", ""])


def released(address="10.254.30.10", *, mac="a2:27:1c:9a:b6:7b") -> str:
    """The block ISC appends when the device releases its lease: no relay data at all."""
    now = timezone.now().strftime("%Y/%m/%d %H:%M:%S")
    return f"lease {address} {{\n  starts 6 {now};\n  ends 6 {now};\n  binding state free;\n  hardware ethernet {mac};\n}}\n"


def eos_capture() -> dict:
    return json.loads((FIXTURES / "ceos_4.36.2F_verification.json").read_text(encoding="utf-8"))


def eos_outputs(session=None, **replace) -> dict:
    """The live EOS outputs, re-keyed to ``session``'s device (name, serial, MAC) and enrollment key; ``replace`` patches
    individual command outputs."""
    capture = eos_capture()
    outputs = dict(capture["outputs"])
    if session is not None:
        live_key = capture["context"]["enrollment_public_key"].split()[1]
        test_key = session.enrollment_public_key.split()[1]
        for command, text in outputs.items():
            text = text.replace("ZTPNEW1", session.device.name).replace("ZTPP3NEW0001", L.SERIAL)
            text = text.replace("02:5a:70:00:00:01", L.MAC).replace(live_key, test_key).replace("ZTP-000001", session.session_id)
            outputs[command] = text
    outputs.update(replace)
    return outputs


def fake_run(outputs, host_key=L.HOST_KEY):
    """A ``management.run_commands`` stand-in returning ``outputs`` over a session that presented ``host_key``."""
    calls = []

    def run(address, *, username, key_reference, enrolled_host_key, commands):
        calls.append({"address": address, "username": username, "key_reference": key_reference,
                      "enrolled_host_key": enrolled_host_key, "commands": list(commands)})
        return {"host_key": host_key, "outputs": outputs}

    run.calls = calls
    return run
