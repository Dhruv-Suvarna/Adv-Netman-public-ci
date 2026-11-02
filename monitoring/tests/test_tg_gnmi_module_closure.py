"""Lab 7 closure -- ``modules/gnmi.py`` (gNMI TLS/auth IaC, one-shot verification and the streaming-collector
lifecycle), each function called directly.

Hermetic: ``BASE`` / ``RUNTIME`` point into a temporary directory with a synthetic inventory and the real monitoring
templates copied in, ``docker`` / ``cli`` / ``command`` / ``influx`` are recording fakes, ``pygnmi``'s client is a
scripted in-memory fake and ``time.sleep`` is patched.  No device, container, collector or InfluxDB is contacted;
secrets are fake.  POSITIVE: exact device list, protected secrets, CA capture, two-phase convergence, target dicts,
verification rows, collector payload and streaming evidence.  NEGATIVE: missing / insecure / malformed secrets,
unsupported platforms, stopped containers, an unreadable CA, an ssl profile that never validates, a gNMI server that
stays down, hostname / CPU / memory / PathElem violations, an accepted wrong password, and stale streams are refused.
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml

from modules import gnmi
from modules.nmas import NmasError

CEOS = {"platform": "ceos", "address": "192.168.200.1", "source_interface": "Vlan200", "device": "R1", "container": "clab-lab-R1"}
LINUX = {"platform": "linux", "address": "192.168.200.3", "source_interface": "eth1.103", "device": "R3", "container": "clab-lab-R3"}
ENV = {"INFLUXDB_ORG": "nmas", "INFLUXDB_BUCKET": "network-monitoring", "INFLUXDB_TOKEN": "fake-Influx-Token-5"}
PASSWORD = "fake-Telemetry-Pass-77"
CA = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"


class GnmiBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.runtime = self.root / "runtime"
        templates = self.root / "templates" / "monitoring"
        templates.mkdir(parents=True)
        for name in ("ceos_gnmi_security.j2", "ceos_gnmi_enable.j2"):
            (templates / name).write_text((Path(gnmi.__file__).resolve().parents[1] / "templates" / "monitoring" / name).read_text())
        for name, value in (("RUNTIME", self.runtime), ("BASE", self.root)):
            patcher = mock.patch.object(gnmi, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def secrets(self, value=None, mode=0o600):
        gnmi.protected_json(self.runtime / "telemetry-secrets.json", value or {"password": PASSWORD})
        (self.runtime / "telemetry-secrets.json").chmod(mode)


class DevicesSecretsTests(GnmiBase):
    def inventory(self, devices):
        self.root.joinpath("inventory.yml").write_text(yaml.safe_dump({"lab_name": "lab", "network_devices": devices}))

    def inspect(self, running=True):
        return json.dumps([{"State": {"Running": running}, "NetworkSettings": {"Networks": {"clab": {"IPAddress": "172.20.20.15"}}}}])

    def test_devices_returns_running_ceos_and_linux_adapters(self):
        self.inventory({"R1": {"monitoring": {"platform": "ceos", "address": "auto", "source_interface": "Management0"}},
                        "R3": {"monitoring": {"platform": "linux", "address": "192.168.200.3", "source_interface": "eth1.103"}}})
        with mock.patch.object(gnmi, "docker", return_value=self.inspect()):
            found = gnmi.devices()
        self.assertEqual([(d["device"], d["platform"], d["address"], d["container"]) for d in found],
                         [("R1", "ceos", "172.20.20.15", "clab-lab-R1"), ("R3", "linux", "192.168.200.3", "clab-lab-R3")])

    def test_devices_refuses_missing_metadata_unsupported_or_stopped_devices(self):
        for label, devices, running, message in (("metadata", {"R1": {}}, True, "R1: monitoring metadata missing"),
                                                 ("platform", {"R1": {"monitoring": {"platform": "srl", "address": "x"}}}, True, "R1: unsupported telemetry platform"),
                                                 ("stopped", {"R1": {"monitoring": {"platform": "ceos", "address": "1.1.1.1"}}}, False, "R1: container is not running")):
            with self.subTest(case=f"refused {label}"):
                self.inventory(devices)
                with mock.patch.object(gnmi, "docker", return_value=self.inspect(running)) as docker, self.assertRaisesRegex(NmasError, message):
                    gnmi.devices()
                if label == "platform":
                    docker.assert_not_called()

    def test_protected_json_returns_after_writing_an_owner_only_file(self):
        self.assertIsNone(gnmi.protected_json(self.runtime / "a" / "x.json", {"k": 1}))
        self.assertEqual(oct((self.runtime / "a" / "x.json").stat().st_mode & 0o777), "0o600")

    def test_protected_json_never_keeps_an_existing_files_open_mode(self):
        self.runtime.mkdir()
        path = self.runtime / "x.json"
        path.write_text("old")
        path.chmod(0o666)
        gnmi.protected_json(path, [])
        self.assertEqual(path.stat().st_mode & 0o077, 0)

    def test_credentials_create_returns_a_generated_password(self):
        found = gnmi.credentials(create=True)
        self.assertRegex(found["password"], r"^[A-Za-z0-9_-]{32}$")
        self.assertEqual(gnmi.credentials(), found)

    def test_credentials_refuse_missing_insecure_or_malformed_secrets(self):
        with self.subTest(case="refused missing"), self.assertRaisesRegex(NmasError, "missing or insecure"):
            gnmi.credentials()
        for label, value, mode, message in (("insecure", None, 0o640, "missing or insecure"),
                                            ("malformed", {"password": "bad pass!"}, 0o600, "Invalid telemetry runtime credentials")):
            with self.subTest(case=f"refused {label}"):
                self.secrets(value, mode)
                with self.assertRaisesRegex(NmasError, message):
                    gnmi.credentials()


class CeosStateTests(GnmiBase):
    def test_profile_state_returns_the_profile_status(self):
        with mock.patch.object(gnmi, "cli", return_value="Profile    State\nNMAS_GNMI  valid\n") as cli:
            self.assertEqual(gnmi.profile_state(CEOS), "valid")
        cli.assert_called_once_with(CEOS, "show management security ssl profile NMAS_GNMI")

    def test_profile_state_of_a_missing_profile_is_absent(self):
        with mock.patch.object(gnmi, "cli", return_value="% Profile not found\n"):
            self.assertEqual(gnmi.profile_state(CEOS), "absent")

    def test_fetch_ca_returns_the_saved_public_ca(self):
        with mock.patch.object(gnmi, "docker", return_value=CA) as docker:
            dest = gnmi.fetch_ca(CEOS)
        docker.assert_called_once_with("exec", "clab-lab-R1", "cat", "/persist/secure/ssl/certs/ca.crt")
        self.assertEqual((dest, dest.read_text(), oct(dest.stat().st_mode & 0o777)), (self.runtime / "gnmi-ca" / "R1.crt", CA, "0o644"))
        with mock.patch("modules.linux_telemetry_adapter.fetch_certificate", return_value="adapter.crt") as adapter:
            self.assertEqual(gnmi.fetch_ca(LINUX), "adapter.crt")
        adapter.assert_called_once_with(LINUX, self.runtime / "gnmi-ca" / "R3.crt")

    def test_fetch_ca_refuses_text_that_is_not_a_certificate(self):
        with mock.patch.object(gnmi, "docker", return_value="cat: no such file"), self.assertRaisesRegex(NmasError, "R1: could not read lab CA certificate"):
            gnmi.fetch_ca(CEOS)
        self.assertFalse((self.runtime / "gnmi-ca" / "R1.crt").exists())

    def converge(self, cli_outputs, profile_states):
        out = io.StringIO()
        with mock.patch.object(gnmi, "cli", side_effect=cli_outputs) as cli, mock.patch.object(gnmi, "profile_state", side_effect=profile_states), \
                mock.patch.object(gnmi.time, "sleep") as sleep, contextlib.redirect_stdout(out):
            gnmi.configure_device(CEOS, PASSWORD)
        return cli, sleep, out.getvalue()

    def test_configure_device_converges_in_two_phases_then_reports_unchanged(self):
        cli, sleep, printed = self.converge(["running", "", "", "Enabled: yes", "", "running"], ["absent", "valid"])
        commands = [c.args[1] for c in cli.call_args_list]
        self.assertTrue(commands[1].startswith("configure terminal\n") and "NMAS_GNMI" in commands[1] and PASSWORD in commands[1])
        self.assertTrue(commands[2].startswith("configure terminal\n") and commands[2].endswith("end"))
        self.assertEqual((commands[3], commands[4], sleep.call_count, printed), ("show management api gnmi", "write memory", 1, "R1: gNMI TLS/auth converged\n"))
        self.assertNotIn(PASSWORD, (self.runtime / "R1-gnmi-state.json").read_text())
        _cli, _sleep, printed = self.converge(["running"], ["valid"])
        self.assertEqual(printed, "R1: gNMI TLS/auth unchanged\n")

    def test_configure_device_refuses_a_profile_that_never_validates_or_a_server_that_stays_down(self):
        with self.subTest(case="refused invalid profile"), self.assertRaisesRegex(NmasError, "ssl profile NMAS_GNMI did not become valid"):
            self.converge(["running", ""], ["absent"] * 10)
        with self.subTest(case="refused gnmi down"), self.assertRaisesRegex(NmasError, "gNMI server did not come up"):
            self.converge(["running", "", "", "Enabled: no"], ["valid"])
        self.assertFalse((self.runtime / "R1-gnmi-state.json").exists())

    def test_configure_device_delegates_linux_to_the_adapter(self):
        with mock.patch("modules.linux_telemetry_adapter.configure") as configure, mock.patch.object(gnmi, "fetch_ca") as fetch, mock.patch.object(gnmi, "cli") as cli:
            self.assertIsNone(gnmi.configure_device(LINUX, PASSWORD))
        configure.assert_called_once_with(LINUX, "nmas-telemetry", PASSWORD)
        fetch.assert_called_once_with(LINUX)
        cli.assert_not_called()


class FakeGnmi:
    """pygnmi.client.gNMIclient stand-in: answers by path; records the kwargs it was opened with."""
    opened = []

    def __init__(self, gets=None, models=("openconfig-system",), stream=None, accept_any=False):
        self.gets, self.models, self.stream, self.accept_any = gets or {}, models, stream, accept_any

    def __call__(self, **kwargs):
        FakeGnmi.opened.append(kwargs)
        if kwargs["password"] != PASSWORD and not self.accept_any:
            raise ConnectionError("UNAUTHENTICATED")
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def capabilities(self):
        return {"supported_models": list(self.models)}

    def get(self, path):
        return {"notification": [{"update": [{"path": path[0], "val": self.gets[path[0]]}] if path[0] in self.gets else []}]} \
            if not isinstance(self.gets.get(path[0]), dict) or "update" not in self.gets[path[0]] else self.gets[path[0]]

    def subscribe(self, subscribe):
        self.subscribed = subscribe
        return iter([self.stream])


def stream_message(*names, timestamp=99):
    updates = [SimpleNamespace(path=SimpleNamespace(elem=[SimpleNamespace(name="interfaces", key={}), SimpleNamespace(name="interface", key={"name": n})])) for n in names]
    return SimpleNamespace(update=SimpleNamespace(update=updates, timestamp=timestamp))


LINUX_GETS = {"/system/state/hostname": "R3", "/system/cpus/cpu[index=0]/state/total/instant": 12,
              "/system/memory/state": {"openconfig-system:physical": "1", "openconfig-system:used": "1", "openconfig-system:free": "1", "openconfig-system:reserved": "1"},
              "/interfaces/interface[name=eth1.103]/state/oper-status": {"update": [{"path": "interfaces/interface[name=eth1.103]/state/oper-status", "val": "UP"}]}}
LINUX_GETS_RESPONSE = dict(LINUX_GETS)
LINUX_GETS_RESPONSE["/interfaces/interface[name=eth1.103]/state/oper-status"] = {
    "notification": [{"update": [{"path": "interfaces/interface[name=eth1.103]/state/oper-status", "val": "UP"}]}], "update": True}


class VerifyTests(GnmiBase):
    def setUp(self):
        super().setUp()
        self.secrets()
        FakeGnmi.opened = []
        patcher = mock.patch.object(gnmi, "fetch_ca", side_effect=lambda item: self.runtime / "gnmi-ca" / f"{item['device']}.crt")
        patcher.start()
        self.addCleanup(patcher.stop)

    def client(self, **kwargs):
        return mock.patch("pygnmi.client.gNMIclient", FakeGnmi(**kwargs))

    def test_gnmi_target_returns_a_validated_tls_target(self):
        self.assertEqual(gnmi.gnmi_target(CEOS), {"target": ("192.168.200.1", 6030), "username": "nmas-telemetry", "password": PASSWORD, "insecure": False,
                                                  "path_root": str(self.runtime / "gnmi-ca" / "R1.crt"), "override": "R1", "gnmi_timeout": 15})

    def test_gnmi_target_without_credentials_is_refused(self):
        (self.runtime / "telemetry-secrets.json").unlink()
        with self.assertRaisesRegex(NmasError, "Telemetry credentials missing"):
            gnmi.gnmi_target(CEOS)

    def test_verify_capabilities_and_get_returns_the_model_count(self):
        with self.client(gets={"/system/state/hostname": "R1"}, models=("a", "b")):
            self.assertEqual(gnmi.verify_capabilities_and_get(CEOS), 2)
        with self.client(gets=LINUX_GETS_RESPONSE):
            self.assertEqual(gnmi.verify_capabilities_and_get(LINUX), 1)

    def test_verify_capabilities_and_get_refuses_bad_models_hostname_cpu_memory_or_pathelem(self):
        bad_cpu = {**LINUX_GETS_RESPONSE, "/system/cpus/cpu[index=0]/state/total/instant": 140}
        bad_memory = {**LINUX_GETS_RESPONSE, "/system/memory/state": {"openconfig-system:physical": "1"}}
        bad_key = {**LINUX_GETS_RESPONSE, "/interfaces/interface[name=eth1.103]/state/oper-status": {
            "notification": [{"update": [{"path": "interfaces/interface[name=eth9]/state/oper-status"}, {"path": "x"}]}], "update": True}}
        for label, item, kwargs, message in (("models", CEOS, {"models": ()}, "returned no supported models"),
                                             ("hostname", CEOS, {"gets": {"/system/state/hostname": "R9"}}, "Get hostname mismatch"),
                                             ("cpu", LINUX, {"gets": bad_cpu}, "invalid CPU state"),
                                             ("memory", LINUX, {"gets": bad_memory}, "incomplete memory state"),
                                             ("pathelem", LINUX, {"gets": bad_key}, "did not honor the interface PathElem key")):
            with self.subTest(case=f"refused {label}"), self.client(**kwargs), self.assertRaisesRegex(NmasError, message):
                gnmi.verify_capabilities_and_get(item)

    def test_verify_subscribe_once_returns_the_update_timestamp(self):
        fake = FakeGnmi(stream=stream_message("eth1.103", timestamp=1234))
        with mock.patch("pygnmi.client.gNMIclient", fake):
            self.assertEqual(gnmi.verify_subscribe_once(LINUX), 1234)
        self.assertEqual(fake.subscribed["subscription"][0]["path"], "/interfaces/interface[name=eth1.103]/state/oper-status")

    def test_verify_subscribe_once_refuses_empty_or_keyless_updates(self):
        with self.subTest(case="refused empty"), self.client(stream=SimpleNamespace(update=SimpleNamespace(update=[], timestamp=1))), \
                self.assertRaisesRegex(NmasError, "Subscribe returned an empty update"):
            gnmi.verify_subscribe_once(CEOS)
        with self.subTest(case="refused lost key"), self.client(stream=stream_message("eth9")), self.assertRaisesRegex(NmasError, "lost its interface PathElem key"):
            gnmi.verify_subscribe_once(LINUX)

    def test_verify_gnmi_returns_rows_when_wrong_passwords_are_rejected(self):
        out = io.StringIO()
        with mock.patch.object(gnmi, "verify_capabilities_and_get", return_value=3), mock.patch.object(gnmi, "verify_subscribe_once", return_value=55), \
                self.client(), contextlib.redirect_stdout(out):
            found = gnmi.verify_gnmi([CEOS])
        self.assertEqual(found, [{"device": "R1", "models": 3, "subscribe_timestamp_ns": 55}])
        self.assertEqual(FakeGnmi.opened[-1]["password"], "wrong-password")
        self.assertIn("R1         PASS  PASS  PASS  PASS PASS", out.getvalue())

    def test_verify_gnmi_refuses_an_accepted_wrong_password_or_a_failed_check(self):
        for label, kwargs, caps in (("wrong password accepted", {"accept_any": True}, 3), ("capabilities failed", {}, NmasError("no models"))):
            with self.subTest(case=f"refused {label}"), contextlib.redirect_stdout(io.StringIO()), \
                    mock.patch.object(gnmi, "verify_capabilities_and_get", **({"side_effect": caps} if isinstance(caps, Exception) else {"return_value": caps})), \
                    mock.patch.object(gnmi, "verify_subscribe_once", return_value=1), self.client(**kwargs), \
                    self.assertRaisesRegex(NmasError, "gNMI verification failed: R1"):
                gnmi.verify_gnmi([CEOS])

    def test_ensure_collector_hands_the_collector_every_device_and_secret(self):
        (self.runtime / "gnmi-ca").mkdir()
        for name in ("R1", "R3"):
            (self.runtime / "gnmi-ca" / f"{name}.crt").write_text(CA)
        out = io.StringIO()
        with mock.patch.object(gnmi, "influx", return_value=(None, ENV)), mock.patch.object(gnmi, "command", return_value="collector converged\n") as command, \
                contextlib.redirect_stdout(out):
            gnmi.ensure_collector([CEOS, LINUX])
        argv, data = command.call_args.args
        payload = json.loads(data)
        self.assertEqual((argv[:4], [d["device"] for d in payload["devices"]], payload["devices"][0]["ca_cert"], payload["password"], payload["influx_token"], out.getvalue()),
                         (["sudo", "-n", "python3", "-c"], ["R1", "R3"], CA, PASSWORD, "fake-Influx-Token-5", "collector converged\n"))
        self.assertEqual(payload["paths"], gnmi.PATHS_CONFIG)

    def test_ensure_collector_without_credentials_never_provisions(self):
        (self.runtime / "telemetry-secrets.json").chmod(0o644)
        with mock.patch.object(gnmi, "command") as command, self.assertRaisesRegex(NmasError, "missing or insecure"):
            gnmi.ensure_collector([CEOS])
        command.assert_not_called()

    REQUIRED = ("system_identity system_cpu system_memory interface_state interface_counters hostname cpu_total_pct mem_physical_bytes mem_used_bytes "
                "mem_free_bytes mem_reserved_bytes oper_status admin_status in_octets out_octets in_errors out_errors in_discards out_discards")

    def stream(self, text, quiet=False):
        session = mock.Mock()
        session.post.return_value = SimpleNamespace(text=text, raise_for_status=lambda: None)
        out = io.StringIO()
        with mock.patch.object(gnmi, "influx", return_value=(session, ENV)), contextlib.redirect_stdout(out):
            try:
                return gnmi.verify_collector_stream([CEOS], quiet=quiet), out.getvalue()
            except NmasError as exc:
                return exc, out.getvalue()

    def test_verify_collector_stream_returns_after_finding_every_field(self):
        found, printed = self.stream("R1 " + self.REQUIRED)
        self.assertEqual((found, printed), (None, "DEVICE     STREAM INFLUX\nR1         PASS   PASS\n"))
        self.assertEqual(self.stream("R1 " + self.REQUIRED, quiet=True), (None, ""))

    def test_verify_collector_stream_refuses_missing_fields_or_no_fresh_point(self):
        error, printed = self.stream("R1 system_identity")
        self.assertEqual(str(error), "gNMI streaming verification failed: R1")
        self.assertIn("R1         FAIL   FAIL (missing admin_status,cpu_total_pct,hostname,in_discards in the last 90s)", printed)
        error, printed = self.stream(self.REQUIRED)
        self.assertIn("(no fresh point in the last 90s)", printed)

    def test_ensure_gnmi_infrastructure_runs_every_stage_in_order(self):
        calls = []
        stub = lambda name, value=None: mock.patch.object(gnmi, name, side_effect=lambda *a, **k: calls.append(name) or value)  # noqa: E731
        with stub("verify_nmas"), stub("devices", [CEOS]), stub("credentials", {"password": PASSWORD}), stub("configure_device"), stub("verify_gnmi"), \
                stub("ensure_collector"), stub("verify_collector_stream"), mock.patch.object(gnmi.time, "sleep") as sleep:
            self.assertEqual(gnmi.ensure_gnmi_infrastructure(), [CEOS])
        self.assertEqual(calls, ["verify_nmas", "devices", "credentials", "configure_device", "verify_gnmi", "ensure_collector", "verify_collector_stream"])
        sleep.assert_called_once_with(25)

    def test_ensure_gnmi_infrastructure_never_provisions_the_collector_after_failed_verification(self):
        with mock.patch.object(gnmi, "verify_nmas"), mock.patch.object(gnmi, "devices", return_value=[CEOS]), mock.patch.object(gnmi, "configure_device"), \
                mock.patch.object(gnmi, "verify_gnmi", side_effect=NmasError("gNMI verification failed: R1")), mock.patch.object(gnmi, "ensure_collector") as collector, \
                self.assertRaisesRegex(NmasError, "verification failed"):
            gnmi.ensure_gnmi_infrastructure()
        collector.assert_not_called()


if __name__ == "__main__":
    unittest.main()
