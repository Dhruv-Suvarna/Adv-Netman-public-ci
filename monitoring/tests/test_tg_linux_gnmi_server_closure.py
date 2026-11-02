"""Lab 7 closure -- the Linux/FRR gNMI telemetry adapter (``monitoring/scripts/linux_gnmi_server.py``) and the shared
``nmas_linux_telemetry_metrics.py`` readers, each called directly.

Hermetic: the script is loaded as a module (exactly as ``test_linux_telemetry_adapter`` does), ``ETC`` / ``LOG_PATH``
point into a temporary directory, the metric readers read a fake ``/sys/class/net`` tree and canned ``/proc`` text,
the gRPC context is an in-memory fake and ``grpc.server`` is replaced -- no port is bound, no router is touched.
POSITIVE: exact notifications, Get / Capabilities responses, one Subscribe cycle with its sync marker, real metric
parsing and a started server.  NEGATIVE: wrong credentials abort UNAUTHENTICATED, Set is refused UNIMPLEMENTED,
POLL / ON_CHANGE subscriptions are refused, unknown interfaces / CPU indexes / paths yield nothing, an unwritable
log is ignored, and a port that cannot be bound is refused.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pygnmi.spec.v080 import gnmi_ext_pb2, gnmi_pb2, gnmi_pb2_grpc

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.modules.setdefault("gnmi_ext_pb2", gnmi_ext_pb2)
sys.modules.setdefault("gnmi_pb2", gnmi_pb2)
sys.modules.setdefault("gnmi_pb2_grpc", gnmi_pb2_grpc)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gnmi = load("tg_linux_gnmi_server", SCRIPTS / "linux_gnmi_server.py")
metrics = gnmi.metrics
pb = gnmi.pb

IFACES = {"eth1": {"admin_status": "UP", "oper_status": "UP", "counters": {"in-octets": 10, "out-errors": 2}},
          "lo": {"admin_status": "UP", "oper_status": "UP", "counters": {}}}
MEMORY = {"physical": 1000, "used": 400, "free": 500, "reserved": 100}


class Abort(Exception):
    pass


class FakeContext:
    def __init__(self, username="tele", password="fake-Tele-Pass-1", active=1, raises=True):
        self.metadata = [("username", username), ("password", password)]
        self.active, self.raises, self.aborted = active, raises, []

    def invocation_metadata(self):
        return self.metadata

    def abort(self, code, details):
        self.aborted.append((code, details))
        if self.raises:
            raise Abort(details)

    def is_active(self):
        self.active -= 1
        return self.active >= 0

    def peer(self):
        return "ipv4:192.0.2.10:50000"


def path(*elems):
    return pb.Path(elem=[gnmi.pe(name, **keys) for name, keys in elems])


def leaf(notification):
    return [(gnmi.path_key(u.path), u.val.WhichOneof("value"), getattr(u.val, u.val.WhichOneof("value"))) for u in notification.update]


class AdapterBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.etc, self.log = Path(tmp.name), Path(tmp.name) / "adapter.log"
        (self.etc / "credentials.env").write_text("TELEMETRY_USERNAME=tele\nTELEMETRY_PASSWORD=fake-Tele-Pass-1\n# comment\n")
        for target, value in ((gnmi, ("ETC", self.etc)), (gnmi, ("LOG_PATH", self.log)), (metrics, ("interfaces", lambda: IFACES)),
                              (metrics, ("memory", lambda: dict(MEMORY))), (metrics, ("hostname", lambda: "R3")), (gnmi.STATE, ("_cpu_pct", 37))):
            patcher = mock.patch.object(target, *value)
            patcher.start()
            self.addCleanup(patcher.stop)


class HelperTests(AdapterBase):
    def test_log_appends_a_timestamped_line(self):
        gnmi.log("listening")
        self.assertRegex(self.log.read_text(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d listening\n$")

    def test_log_to_an_unwritable_path_is_ignored_without_error(self):
        with mock.patch.object(gnmi, "LOG_PATH", self.etc / "missing-dir" / "x.log"):
            self.assertIsNone(gnmi.log("x"))
        self.assertFalse((self.etc / "missing-dir").exists())

    def test_load_env_returns_key_values(self):
        self.assertEqual(gnmi.load_env("credentials.env"), {"TELEMETRY_USERNAME": "tele", "TELEMETRY_PASSWORD": "fake-Tele-Pass-1"})

    def test_load_env_of_a_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            gnmi.load_env("absent.env")

    def test_scalar_returns_a_typed_value(self):
        self.assertEqual((gnmi.scalar(string_val="R3").string_val, gnmi.scalar(uint_val=5).uint_val), ("R3", 5))

    def test_scalar_refuses_an_unknown_field(self):
        with self.assertRaises(ValueError):
            gnmi.scalar(no_such_val=1)

    def test_path_key_returns_the_slash_joined_names(self):
        self.assertEqual(gnmi.path_key(path(("interfaces", {}), ("interface", {"name": "eth1"}), ("state", {}))), "interfaces/interface/state")

    def test_path_key_and_path_elem_key_of_an_empty_path_are_empty(self):
        self.assertEqual((gnmi.path_key(pb.Path()), gnmi.path_elem_key(pb.Path(), "interface", "name")), ("", None))
        self.assertIsNone(gnmi.path_elem_key(path(("interface", {"index": "1"})), "interface", "name"))

    def test_selected_interfaces_returns_all_for_wildcard_or_the_named_one(self):
        self.assertEqual(dict(gnmi.selected_interfaces(path(("interface", {"name": "*"})))), IFACES)
        self.assertEqual(list(gnmi.selected_interfaces(path(("interface", {"name": "eth1"})))), [("eth1", IFACES["eth1"])])

    def test_selected_interfaces_of_an_unknown_interface_is_empty(self):
        self.assertEqual(tuple(gnmi.selected_interfaces(path(("interface", {"name": "eth9"})))), ())

    def test_check_auth_accepts_the_configured_credentials(self):
        context = FakeContext()
        self.assertIsNone(gnmi.check_auth(context))
        self.assertEqual(context.aborted, [])

    def test_check_auth_refuses_wrong_credentials(self):
        context = FakeContext(password="wrong")
        with self.assertRaises(Abort):
            gnmi.check_auth(context)
        self.assertEqual(context.aborted, [(gnmi.grpc.StatusCode.UNAUTHENTICATED, "invalid credentials")])


class NotificationTests(AdapterBase):
    def test_notif_hostname_returns_the_live_hostname(self):
        (n,) = gnmi.notif_hostname(5)
        self.assertEqual((n.timestamp, leaf(n)), (5, [("system/state/hostname", "string_val", "R3")]))

    def test_notif_hostname_of_an_empty_hostname_is_empty_never_fabricated(self):
        with mock.patch.object(metrics, "hostname", return_value=""):
            (n,) = gnmi.notif_hostname(5)
        self.assertEqual(leaf(n), [("system/state/hostname", "string_val", "")])

    def test_notif_cpu_returns_the_sampled_percentage(self):
        (n,) = gnmi.notif_cpu(7, path(("cpu", {"index": "0"})))
        self.assertEqual(leaf(n), [("system/cpus/cpu/state/total/instant", "int_val", 37)])

    def test_notif_cpu_of_another_cpu_index_is_empty(self):
        self.assertEqual(gnmi.notif_cpu(7, path(("cpu", {"index": "3"}))), [])

    def test_notif_memory_returns_four_counters(self):
        (n,) = gnmi.notif_memory(1)
        self.assertEqual([(gnmi.path_key(u.path), u.val.uint_val) for u in n.update], [("physical", 1000), ("used", 400), ("free", 500), ("reserved", 100)])
        self.assertEqual(gnmi.path_key(n.prefix), "system/memory/state")

    def test_notif_memory_of_zero_memory_reports_zero(self):
        with mock.patch.object(metrics, "memory", return_value={"physical": 0, "used": 0, "free": 0, "reserved": 0}):
            (n,) = gnmi.notif_memory(1)
        self.assertEqual({u.val.uint_val for u in n.update}, {0})

    def test_notif_interface_leaf_returns_each_selected_interface(self):
        found = gnmi.notif_interface_leaf(1, "admin-status")
        self.assertEqual([leaf(n)[0][2] for n in found], ["UP", "UP"])
        self.assertEqual(found[0].update[0].path.elem[1].key["name"], "eth1")

    def test_notif_interface_leaf_of_an_unknown_interface_is_empty(self):
        self.assertEqual(gnmi.notif_interface_leaf(1, "oper-status", path(("interface", {"name": "eth9"}))), [])

    def test_notif_interface_counters_returns_counters_of_interfaces_with_any(self):
        (n,) = gnmi.notif_interface_counters(1)
        self.assertEqual(([(gnmi.path_key(u.path), u.val.uint_val) for u in n.update], n.prefix.elem[1].key["name"]),
                         ([("in-octets", 10), ("out-errors", 2)], "eth1"))

    def test_notif_interface_counters_without_counters_is_empty(self):
        self.assertEqual(gnmi.notif_interface_counters(1, path(("interface", {"name": "lo"}))), [])

    def test_get_container_json_returns_memory_and_interface_blobs(self):
        self.assertEqual(gnmi.get_container_json(path(("system", {}), ("memory", {}), ("state", {}))),
                         {"openconfig-system:physical": "1000", "openconfig-system:used": "400", "openconfig-system:free": "500",
                          "openconfig-system:reserved": "100"})
        self.assertEqual(gnmi.get_container_json(path(("interfaces", {}), ("interface", {"name": "eth1"}), ("state", {}))),
                         {"openconfig-interfaces:name": "eth1", "openconfig-interfaces:admin-status": "UP", "openconfig-interfaces:oper-status": "UP",
                          "openconfig-interfaces:counters": {"openconfig-interfaces:in-octets": "10", "openconfig-interfaces:out-errors": "2"}})

    def test_get_container_json_of_unknown_paths_or_interfaces_is_none(self):
        self.assertEqual((gnmi.get_container_json(path(("bgp", {}))),
                          gnmi.get_container_json(path(("interfaces", {}), ("interface", {"name": "eth9"}), ("state", {})))), (None, None))


class ServicerTests(AdapterBase):
    def test_capabilities_returns_the_two_subset_models(self):
        found = gnmi.LinuxGnmiServicer().Capabilities(None, FakeContext())
        self.assertEqual(([m.name for m in found.supported_models], found.gNMI_version, list(found.supported_encodings)),
                         (["openconfig-system", "openconfig-interfaces"], "0.8.0", [pb.JSON_IETF]))

    def test_capabilities_refuses_wrong_credentials(self):
        with self.assertRaises(Abort):
            gnmi.LinuxGnmiServicer().Capabilities(None, FakeContext(username="intruder"))

    def test_get_returns_one_notification_per_supported_path(self):
        request = pb.GetRequest(path=[
            path(("system", {}), ("state", {}), ("hostname", {})),
            path(("system", {}), ("cpus", {}), ("cpu", {"index": "*"}), ("state", {}), ("total", {}), ("instant", {})),
            path(("interfaces", {}), ("interface", {"name": "eth1"}), ("state", {}), ("oper-status", {})),
            path(("interfaces", {}), ("interface", {"name": "eth1"}), ("state", {}), ("admin-status", {})),
            path(("interfaces", {}), ("interface", {"name": "*"}), ("state", {}), ("counters", {})),
            path(("system", {}), ("memory", {}), ("state", {})),
        ])
        found = gnmi.LinuxGnmiServicer().Get(request, FakeContext())
        self.assertEqual(len(found.notification), 6)
        self.assertEqual(found.notification[-1].update[0].val.json_ietf_val,
                         b'{"openconfig-system:physical": "1000", "openconfig-system:used": "400", "openconfig-system:free": "500", "openconfig-system:reserved": "100"}')

    def test_get_of_unknown_paths_is_empty_and_wrong_credentials_are_refused(self):
        with self.subTest(case="unknown path yields no notification"):
            self.assertEqual(len(gnmi.LinuxGnmiServicer().Get(pb.GetRequest(path=[path(("bgp", {}))]), FakeContext()).notification), 0)
        with self.subTest(case="refused credentials"), self.assertRaises(Abort):
            gnmi.LinuxGnmiServicer().Get(pb.GetRequest(path=[]), FakeContext(password="wrong"))

    def test_set_returns_after_recording_the_unimplemented_status(self):
        context = FakeContext(raises=False)
        self.assertIsNone(gnmi.LinuxGnmiServicer().Set(pb.SetRequest(), context))
        self.assertEqual(context.aborted, [(gnmi.grpc.StatusCode.UNIMPLEMENTED, "this adapter is read-only; Set is not implemented")])

    def test_set_is_refused_as_read_only(self):
        with self.assertRaisesRegex(Abort, "read-only"):
            gnmi.LinuxGnmiServicer().Set(pb.SetRequest(), FakeContext())

    def subscribe_request(self, mode=None, sub_mode=None):
        sub = pb.Subscription(path=path(("system", {}), ("state", {}), ("hostname", {})), mode=sub_mode or pb.SAMPLE, sample_interval=1_000_000_000)
        return pb.SubscribeRequest(subscribe=pb.SubscriptionList(mode=pb.SubscriptionList.STREAM if mode is None else mode, subscription=[sub]))

    def test_subscribe_streams_one_sample_cycle_then_sync(self):
        with mock.patch.object(gnmi.time, "sleep") as sleep:
            found = list(gnmi.LinuxGnmiServicer().Subscribe(iter([self.subscribe_request()]), FakeContext(active=1)))
        self.assertEqual(([r.WhichOneof("response") for r in found], leaf(found[0].update)), (["update", "sync_response"], [("system/state/hostname", "string_val", "R3")]))
        sleep.assert_called_once_with(1.0)
        self.assertIn("Subscribe: 1 path(s), interval=1.0s, peer=ipv4:192.0.2.10:50000", self.log.read_text())

    def test_subscribe_refuses_poll_on_change_and_wrong_credentials(self):
        for label, request, context in (("poll", self.subscribe_request(mode=pb.SubscriptionList.POLL), FakeContext()),
                                        ("on_change", self.subscribe_request(sub_mode=pb.ON_CHANGE), FakeContext()),
                                        ("credentials", self.subscribe_request(), FakeContext(password="wrong"))):
            with self.subTest(case=f"refused {label}"), self.assertRaises(Abort):
                list(gnmi.LinuxGnmiServicer().Subscribe(iter([request]), context))
        self.assertEqual(list(gnmi.LinuxGnmiServicer().Subscribe(iter([]), FakeContext())), [])


class MetricStateTests(unittest.TestCase):
    def test_metric_state_init_samples_cpu_and_starts_one_daemon_sampler(self):
        with mock.patch.object(metrics, "cpu_snapshot", return_value=(1, 2, 3, 4, 5, 6, 7)), mock.patch.object(gnmi.threading, "Thread") as thread:
            state = gnmi.MetricState()
        thread.assert_called_once_with(target=state._loop, daemon=True)
        thread.return_value.start.assert_called_once_with()
        self.assertEqual((state._prev_cpu, state.cpu_percent()), ((1, 2, 3, 4, 5, 6, 7), 0))

    def test_metric_state_init_without_proc_stat_never_starts_a_sampler(self):
        with mock.patch.object(metrics, "cpu_snapshot", side_effect=FileNotFoundError("/proc/stat")), mock.patch.object(gnmi.threading, "Thread") as thread, \
                self.assertRaises(FileNotFoundError):
            gnmi.MetricState()
        thread.assert_not_called()


class MetricsReaderTests(unittest.TestCase):
    def test_cpu_snapshot_and_cpu_percent_return_delta_utilization(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3\n")):
            first = metrics.cpu_snapshot()
        self.assertEqual(first, (100, 0, 50, 800, 50, 0, 0))
        self.assertEqual(metrics.cpu_percent(first, (150, 0, 100, 850, 50, 0, 0)), 67)

    def test_cpu_percent_without_a_previous_sample_or_elapsed_time_is_zero(self):
        sample = (1, 0, 1, 10, 0, 0, 0)
        self.assertEqual((metrics.cpu_percent(None, sample), metrics.cpu_percent(sample, sample)), (0, 0))

    def test_memory_returns_the_documented_mapping(self):
        text = "MemTotal: 1000 kB\nMemFree: 300 kB\nMemAvailable: 600 kB\nBuffers: 100 kB\nCached: 200 kB\nSwapTotal: 9 kB\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=text)):
            self.assertEqual(metrics.memory(), {"physical": 1024000, "used": 409600, "free": 307200, "reserved": 0})

    def test_hostname_returns_the_container_hostname(self):
        with mock.patch.object(metrics.socket, "gethostname", return_value="R4"):
            self.assertEqual(metrics.hostname(), "R4")

    def test_interfaces_returns_state_and_counters_from_sysfs(self):
        with tempfile.TemporaryDirectory() as tmp:
            net = Path(tmp)
            for name, flags, oper, stats in (("eth1", "0x1003", "up", {"rx_bytes": "10", "tx_errors": "2"}), ("lo", "0x9", "unknown", {}),
                                             ("eth2", "0x1002", "down", {}), ("bad", "zz", "up", {})):
                (net / name / "statistics").mkdir(parents=True)
                (net / name / "flags").write_text(flags + "\n")
                (net / name / "operstate").write_text(oper + "\n")
                for key, value in stats.items():
                    (net / name / "statistics" / key).write_text(value + "\n")
            with mock.patch.object(metrics, "NET", net):
                found = metrics.interfaces()
        self.assertEqual(found, {"eth1": {"admin_status": "UP", "oper_status": "UP", "counters": {"in-octets": 10, "out-errors": 2}},
                                 "eth2": {"admin_status": "DOWN", "oper_status": "DOWN", "counters": {}},
                                 "lo": {"admin_status": "UP", "oper_status": "UP", "counters": {}}})


class MainTests(unittest.TestCase):
    def run_main(self, bound_port):
        with tempfile.TemporaryDirectory() as tmp:
            etc = Path(tmp)
            (etc / "tls").mkdir()
            (etc / "tls" / "server.key").write_bytes(b"fake-key")
            (etc / "tls" / "server.crt").write_bytes(b"fake-crt")
            server = mock.Mock(add_secure_port=mock.Mock(return_value=bound_port))
            with mock.patch.object(gnmi, "ETC", etc), mock.patch.object(gnmi, "LOG_PATH", etc / "log"), \
                    mock.patch.object(gnmi.grpc, "server", return_value=server), \
                    mock.patch.object(gnmi.grpc, "ssl_server_credentials", return_value="creds") as creds, \
                    mock.patch.object(gnmi.pb_grpc, "add_gNMIServicer_to_server") as add, mock.patch.object(sys, "argv", ["x", "127.0.0.1", "6031"]):
                result = gnmi.main()
            return result, server, creds, add, (etc / "log").read_text() if (etc / "log").exists() else ""

    def test_main_serves_tls_on_the_requested_address_until_termination(self):
        result, server, creds, add, log = self.run_main(6031)
        self.assertIsNone(result)
        creds.assert_called_once_with([(b"fake-key", b"fake-crt")])
        server.add_secure_port.assert_called_once_with("127.0.0.1:6031", "creds")
        self.assertEqual((add.call_count, server.start.call_count, server.wait_for_termination.call_count), (1, 1, 1))
        self.assertIn("listening on 127.0.0.1:6031 (TLS)", log)

    def test_main_refuses_a_port_that_could_not_be_bound(self):
        with self.assertRaisesRegex(RuntimeError, "could not bind gNMI adapter to 127.0.0.1:6031"):
            self.run_main(0)


if __name__ == "__main__":
    unittest.main()
