"""Lab 7 closure -- ``modules/syslog.py`` (critical-event forwarding IaC, the NMAS ingestion receiver and end-to-end
verification), each function called directly.

Hermetic: ``BASE`` / ``RUNTIME`` point into a temporary directory with a synthetic inventory, ``docker`` / ``cli`` /
``command`` are recording fakes, InfluxDB is an in-memory session, ``time`` is a fake clock and the raw-log path is
remapped into the temporary root.  No device, container, receiver or InfluxDB is contacted.  POSITIVE: exact policy,
device list, rendered / converged configuration, forwarder substitution, receiver payload, evidence lookups and the
verification table.  NEGATIVE: missing metadata, stopped containers and unsupported platforms are refused, drifted or
unreadable configuration is not present, a marker that never arrives times out False, and failed steps fail the
verification without hiding which device failed.
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from modules import syslog
from modules.nmas import NmasError

POLICY = {"receiver": "192.168.200.100", "port": 514, "max_severity": 2}
CEOS = {"platform": "ceos", "address": "192.168.200.1", "source_interface": "Vlan200", "device": "R1", "container": "clab-lab-R1"}
LINUX = {"platform": "linux", "address": "192.168.200.3", "source_interface": "Vlan200", "device": "R3", "container": "clab-lab-R3"}
MGMT = {"platform": "ceos", "address": "192.168.200.10", "source_interface": "Vlan200", "device": "mgmt_swt", "container": "clab-lab-mgmt_swt"}
ENV = {"INFLUXDB_ORG": "nmas", "INFLUXDB_BUCKET": "network-monitoring", "INFLUXDB_TOKEN": "fake-Influx-Token-4"}
RUNNING_LOGGING = "logging host 192.168.200.100\nlogging trap critical\nlogging local-interface Vlan200\n"


class FakeClock:
    def __init__(self):
        self.now, self.sleeps = 0.0, 0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps += 1
        self.now += seconds

    def time_ns(self):
        return 42


class FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        return None


class SyslogBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        (self.runtime / "monitoring.env").write_text("".join(f"{k}={v}\n" for k, v in ENV.items()))
        self.root.joinpath("inventory.yml").write_text(yaml.safe_dump({"lab_name": "lab", "syslog": POLICY, "network_devices": {
            "R1": {"monitoring": {"platform": "ceos", "address": "192.168.200.1", "source_interface": "Vlan200"}},
            "R5": {"monitoring": {"platform": "ceos", "address": "auto", "source_interface": "Management0"}}}}))
        for name, value in (("RUNTIME", self.runtime), ("BASE", self.root)):
            patcher = mock.patch.object(syslog, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        templates = self.root / "templates" / "monitoring"
        templates.mkdir(parents=True)
        for name in ("ceos_syslog.j2", "linux_syslog.conf.j2"):
            (templates / name).write_text((Path(syslog.__file__).resolve().parents[1] / "templates" / "monitoring" / name).read_text())


class PolicyDevicesTests(SyslogBase):
    def test_policy_returns_the_inventory_syslog_block(self):
        self.assertEqual(syslog.policy(), POLICY)

    def inspect(self, running=True):
        return json.dumps([{"State": {"Running": running}, "NetworkSettings": {"Networks": {"clab": {"IPAddress": "172.20.20.15"}}}}])

    def test_devices_returns_running_devices_with_resolved_addresses(self):
        with mock.patch.object(syslog, "docker", return_value=self.inspect()) as docker:
            found = syslog.devices()
        self.assertEqual([(d["device"], d["container"], d["address"]) for d in found], [("R1", "clab-lab-R1", "192.168.200.1"), ("R5", "clab-lab-R5", "172.20.20.15")])
        self.assertEqual(docker.call_args_list[0].args, ("inspect", "clab-lab-R1"))

    def test_devices_refuses_missing_metadata_stopped_or_unsupported_devices(self):
        for label, devices, running, message in (("metadata", {"R1": {}}, True, "R1: monitoring metadata missing"),
                                                 ("stopped", None, False, "R1: container is not running"),
                                                 ("platform", {"R1": {"monitoring": {"platform": "junos", "address": "1.1.1.1"}}}, True, "R1: unsupported platform")):
            with self.subTest(case=f"refused {label}"):
                devices = devices or {"R1": {"monitoring": {"platform": "ceos", "address": "192.168.200.1", "source_interface": "Vlan200"}}}
                self.root.joinpath("inventory.yml").write_text(yaml.safe_dump({"lab_name": "lab", "syslog": POLICY, "network_devices": devices}))
                with mock.patch.object(syslog, "docker", return_value=self.inspect(running)), self.assertRaisesRegex(NmasError, message):
                    syslog.devices()

    def test_docker_exec_json_returns_the_container_output(self):
        with mock.patch.object(syslog, "docker", return_value="ok\n") as docker:
            self.assertEqual(syslog.docker_exec_json("clab-lab-R3", "print(1)", {"a": 1}, timeout=30), "ok\n")
        docker.assert_called_once_with("exec", "-i", "clab-lab-R3", "python3", "-c", "print(1)", data='{"a": 1}', timeout=30)

    def test_docker_exec_json_failure_is_refused(self):
        with mock.patch.object(syslog, "docker", side_effect=NmasError("SNMP command failed (docker): exec failed")), self.assertRaisesRegex(NmasError, "exec failed"):
            syslog.docker_exec_json("clab-lab-R3", "x", {})

    def test_tag_escapes_line_protocol_separators(self):
        self.assertEqual(syslog.tag("a b,c=d"), "a\\ b\\,c\\=d")

    def test_tag_of_empty_text_is_empty(self):
        self.assertEqual(syslog.tag(""), "")

    def test_influx_returns_an_authorized_session(self):
        session, env = syslog.influx()
        self.assertEqual((env, session.trust_env, session.headers["Authorization"]), (ENV, False, "Token fake-Influx-Token-4"))


class ConfigureTests(SyslogBase):
    def test_configure_ceos_converges_then_installs_the_substituted_forwarder(self):
        out = io.StringIO()
        with mock.patch.object(syslog, "cli", return_value=RUNNING_LOGGING) as cli, mock.patch.object(syslog, "docker_exec_json", return_value="forwarder ok\n") as push, \
                contextlib.redirect_stdout(out):
            syslog.configure_ceos(CEOS, POLICY)
            syslog.configure_ceos(CEOS, POLICY)
        commands = [c.args[1] for c in cli.call_args_list]
        self.assertEqual(commands[1], "configure terminal\n" + RUNNING_LOGGING + "end")
        self.assertEqual((commands[2], len(commands)), ("write memory", 5))
        script = push.call_args.args[2]["script"]
        self.assertNotIn("__RECEIVER__", script)
        self.assertNotIn("__MAX_SEVERITY__", script)
        self.assertEqual(out.getvalue(), "R1: syslog config converged\nR1: forwarder ok\nR1: syslog config unchanged\nR1: forwarder ok\n")

    def test_configure_ceos_never_records_state_after_an_eos_rejection(self):
        with mock.patch.object(syslog, "cli", side_effect=["", NmasError("R1: EOS rejected")]), self.assertRaisesRegex(NmasError, "EOS rejected"):
            syslog.configure_ceos(CEOS, POLICY)
        self.assertFalse((self.runtime / "R1-syslog-state.json").exists())

    def test_configure_linux_hands_over_the_rendered_config(self):
        out = io.StringIO()
        with mock.patch.object(syslog, "docker_exec_json", return_value="rsyslog running\n") as push, contextlib.redirect_stdout(out):
            syslog.configure_linux(LINUX, POLICY)
        container, _script, payload = push.call_args.args
        self.assertEqual((container, payload["config"], push.call_args.kwargs, out.getvalue()),
                         ("clab-lab-R3", syslog.render("linux_syslog.conf.j2", POLICY), {"timeout": 600}, "R3: rsyslog running\n"))

    def test_configure_linux_failure_is_refused(self):
        with mock.patch.object(syslog, "docker_exec_json", side_effect=NmasError("provisioning failed")), self.assertRaisesRegex(NmasError, "provisioning failed"):
            syslog.configure_linux(LINUX, POLICY)

    def test_ensure_receiver_maps_both_hostname_spellings_then_converges(self):
        out = io.StringIO()
        with mock.patch.object(syslog, "command", side_effect=["receiver converged\n", ""]) as command, contextlib.redirect_stdout(out):
            syslog.ensure_receiver([CEOS, MGMT])
        sudo, install = command.call_args_list
        payload = json.loads(sudo.args[1])
        self.assertEqual(payload["devices"], {"R1": {"device": "R1", "platform": "ceos"}, "mgmt_swt": {"device": "mgmt_swt", "platform": "ceos"},
                                              "mgmt-swt": {"device": "mgmt_swt", "platform": "ceos"}})
        self.assertEqual((sudo.args[0][:4], payload["influx_token"], install.args[0][0], out.getvalue()),
                         (["sudo", "-n", "python3", "-c"], "fake-Influx-Token-4", "bash", "receiver converged\n"))

    def test_ensure_receiver_never_runs_the_base_install_after_a_failed_receiver(self):
        with mock.patch.object(syslog, "command", side_effect=NmasError("sudo refused")) as command, self.assertRaisesRegex(NmasError, "sudo refused"):
            syslog.ensure_receiver([CEOS])
        self.assertEqual(command.call_count, 1)


class EvidenceTests(SyslogBase):
    def test_config_present_returns_true_for_matching_ceos_and_linux_state(self):
        with mock.patch.object(syslog, "cli", return_value=RUNNING_LOGGING):
            self.assertTrue(syslog.config_present(CEOS, POLICY))
        expected = syslog.render("linux_syslog.conf.j2", POLICY)
        with mock.patch.object(syslog, "docker", side_effect=[expected, "123\n", ""]) as docker:
            self.assertTrue(syslog.config_present(LINUX, POLICY))
        self.assertEqual(docker.call_args_list[2].args, ("exec", "clab-lab-R3", "test", "-d", "/proc/123"))

    def test_config_present_is_false_for_drifted_missing_or_stopped_config(self):
        with self.subTest(case="refused drifted ceos"), mock.patch.object(syslog, "cli", return_value="logging host 10.0.0.9\n"):
            self.assertFalse(syslog.config_present(CEOS, POLICY))
        with self.subTest(case="refused drifted linux"), mock.patch.object(syslog, "docker", side_effect=["other", "1", ""]):
            self.assertFalse(syslog.config_present(LINUX, POLICY))
        with self.subTest(case="refused stopped rsyslogd"), mock.patch.object(syslog, "docker", side_effect=["x", "1", NmasError("no such pid")]):
            self.assertFalse(syslog.config_present(LINUX, POLICY))

    def test_generate_critical_sends_native_and_direct_udp_markers(self):
        with mock.patch.object(syslog, "cli") as cli, mock.patch.object(syslog, "docker") as docker:
            syslog.generate_critical(CEOS, "M1", POLICY)
            syslog.generate_critical(LINUX, "M2", POLICY)
        cli.assert_called_once_with(CEOS, "send log level critical message M1")
        self.assertEqual([c.args for c in docker.call_args_list], [
            ("exec", "clab-lab-R1", "logger", "-n", "192.168.200.100", "-P", "514", "--udp", "--rfc5424=notq", "-p", "local4.crit", "-t", "R1", "M1"),
            ("exec", "clab-lab-R3", "logger", "-p", "local4.crit", "-t", "R3", "M2")])

    def test_generate_critical_failure_is_refused(self):
        with mock.patch.object(syslog, "docker", side_effect=NmasError("logger missing")), self.assertRaisesRegex(NmasError, "logger missing"):
            syslog.generate_critical(LINUX, "M", POLICY)

    def raw_log(self, text):
        log = self.root / "var" / "log" / "lab-monitoring" / "remote-syslog.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(text)
        root = self.root
        return mock.patch.object(syslog, "Path", side_effect=lambda p: root / str(p).lstrip("/"))

    def test_raw_log_contains_returns_true_when_the_marker_is_logged(self):
        clock = FakeClock()
        with self.raw_log("x\nNMAS_MARK_1\n"), mock.patch.object(syslog, "time", clock):
            self.assertTrue(syslog.raw_log_contains("NMAS_MARK_1"))
        self.assertEqual(clock.sleeps, 0)

    def test_raw_log_contains_times_out_false_without_the_marker(self):
        clock = FakeClock()
        with self.raw_log("nothing here\n"), mock.patch.object(syslog, "time", clock):
            self.assertFalse(syslog.raw_log_contains("NMAS_MARK_2", timeout=3))
        self.assertEqual(clock.sleeps, 3)

    def influx_session(self, texts):
        session = mock.Mock()
        session.post.side_effect = [FakeResponse(t) for t in texts]
        return mock.patch.object(syslog, "influx", return_value=(session, ENV)), session

    def test_influx_contains_returns_true_once_the_marker_is_stored(self):
        patch, session = self.influx_session(["", "row NMAS_MARK_3"])
        with patch, mock.patch.object(syslog, "time", FakeClock()):
            self.assertTrue(syslog.influx_contains("NMAS_MARK_3", "R1"))
        query = session.post.call_args.kwargs["data"]
        self.assertIn('r._measurement == "syslog_event" and r.device == "R1"', query)
        self.assertIn("/NMAS_MARK_3/", query)

    def test_influx_contains_times_out_false_when_never_stored(self):
        patch, session = self.influx_session([""] * 5)
        with patch, mock.patch.object(syslog, "time", FakeClock()):
            self.assertFalse(syslog.influx_contains("NMAS_MARK_4", "R1", timeout=2))
        self.assertEqual(session.post.call_count, 2)


class VerifyTests(SyslogBase):
    def verify(self, **overrides):
        values = {"config_present": True, "generate_critical": None, "raw_log_contains": True, "influx_contains": True, **overrides}
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in values.items():
                stack.enter_context(mock.patch.object(syslog, name, **({"side_effect": value} if isinstance(value, Exception) else {"return_value": value})))
            stack.enter_context(contextlib.redirect_stdout(out))
            try:
                return syslog.verify_syslog([CEOS, LINUX], POLICY), out.getvalue()
            except NmasError as exc:
                return exc, out.getvalue()

    def test_verify_syslog_returns_a_passing_row_per_device(self):
        found, printed = self.verify()
        self.assertEqual(found, [{"device": "R1", "config": "PASS", "critical": "PASS", "rawlog": "PASS", "storage": "PASS"},
                                 {"device": "R3", "config": "PASS", "critical": "PASS", "rawlog": "PASS", "storage": "PASS"}])
        self.assertIn("R1          PASS    PASS      PASS    PASS", printed)
        self.assertEqual(json.loads((self.runtime / "syslog-verification.json").read_text()), found)

    def test_verify_syslog_refuses_missing_evidence_naming_each_failed_device(self):
        for label, overrides, row in (("config", {"config_present": False}, {"config": "FAIL"}),
                                      ("critical", {"generate_critical": NmasError("logger missing")}, {"critical": "FAIL", "rawlog": "FAIL", "storage": "FAIL"}),
                                      ("storage", {"influx_contains": NmasError("influx down")}, {"storage": "FAIL"})):
            with self.subTest(case=f"refused {label}"):
                error, _printed = self.verify(**overrides)
                self.assertEqual(str(error), "Syslog verification failed: R1, R3")
                stored = json.loads((self.runtime / "syslog-verification.json").read_text())[0]
                self.assertEqual({k: stored[k] for k in row}, row)

    def test_ensure_syslog_infrastructure_configures_each_platform_then_verifies(self):
        calls = []
        record = lambda name: (lambda *a, **k: calls.append((name, a[0]["device"] if a and isinstance(a[0], dict) else None)))  # noqa: E731
        with mock.patch.object(syslog, "verify_nmas", side_effect=record("verify_nmas")), mock.patch.object(syslog, "devices", return_value=[CEOS, LINUX]), \
                mock.patch.object(syslog, "configure_ceos", side_effect=record("ceos")), mock.patch.object(syslog, "configure_linux", side_effect=record("linux")), \
                mock.patch.object(syslog, "ensure_receiver", side_effect=record("receiver")), mock.patch.object(syslog, "verify_syslog", side_effect=record("verify")):
            self.assertIsNone(syslog.ensure_syslog_infrastructure(verbose=True))
        self.assertEqual([c[0] for c in calls], ["verify_nmas", "ceos", "linux", "receiver", "verify", "verify_nmas"])
        self.assertEqual((calls[1][1], calls[2][1]), ("R1", "R3"))

    def test_ensure_syslog_infrastructure_never_configures_after_a_failed_nmas_check(self):
        with mock.patch.object(syslog, "verify_nmas", side_effect=NmasError("NMAS unhealthy")), mock.patch.object(syslog, "configure_ceos") as ceos, \
                self.assertRaisesRegex(NmasError, "NMAS unhealthy"):
            syslog.ensure_syslog_infrastructure()
        ceos.assert_not_called()


if __name__ == "__main__":
    unittest.main()
