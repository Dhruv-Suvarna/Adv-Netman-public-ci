"""Lab 7 closure -- the NMAS-side gNMI Subscribe collector (``monitoring/scripts/gnmi_collector.py``), each helper
and worker called directly.

Hermetic: the script is loaded as a module (as ``test_linux_telemetry_adapter`` does), ``ETC`` / ``LOG_PATH`` point
into a temporary directory, ``pygnmi.client.gNMIclient`` is a fake that replays real ``gnmi_pb2`` SubscribeResponse
messages, ``requests.Session`` is a fake that records the InfluxDB write, ``time`` is a fake clock and
``threading.Thread`` is a recorder -- no socket is opened, no device or InfluxDB is touched.
POSITIVE: exact line protocol, decoded values, a subscribe request, one streamed update queued, one batch written.
NEGATIVE: unknown / keyless / empty paths are skipped, a failing device session only logs and backs off, a failing
InfluxDB write only logs, a missing env file raises, an unwritable log is ignored.
"""
from __future__ import annotations

import importlib.util
import json
import queue
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pygnmi.spec.v080 import gnmi_pb2

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load("tg_gnmi_collector", SCRIPTS / "gnmi_collector.py")

PATHS_CONFIG = {
    "sample_interval_ns": 10_000_000_000,
    "streams": [{"path": "/interfaces/interface/state/counters"}, {"path": "/system/memory/state"}],
}
CREDS = {"TELEMETRY_USERNAME": "telemetry", "TELEMETRY_PASSWORD": "pw-not-real"}
DEVICE = {"device": "R1", "platform": "ceos", "address": "172.20.20.11", "port": 6030}


def gpath(*elems):
    """Build a gnmi_pb2.Path from (name, {keys}) pairs."""
    return gnmi_pb2.Path(elem=[gnmi_pb2.PathElem(name=name, key=keys or {}) for name, keys in elems])


def counter_reply():
    notification = gnmi_pb2.Notification(
        prefix=gpath(("interfaces", None), ("interface", {"name": "Ethernet1"})),
        update=[gnmi_pb2.Update(path=gpath(("state", None), ("counters", None), ("in-octets", None)),
                                val=gnmi_pb2.TypedValue(uint_val=1234))],
    )
    return gnmi_pb2.SubscribeResponse(update=notification)


class FakeClock:
    def __init__(self, stop_event=None, step=10.0):
        self.now, self.step, self.stop_event, self.sleeps = 1_000.0, step, stop_event, []

    def time(self):
        self.now += self.step
        return self.now

    def time_ns(self):
        return 1_700_000_000_000_000_000

    def strftime(self, fmt):
        return "2026-10-19T00:00:00 "

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        if self.stop_event is not None:
            self.stop_event.set()


class FakeGnmiClient:
    """Context manager replaying canned replies; ``error`` makes ``subscribe`` raise instead."""

    def __init__(self, replies=(), error=None):
        self.replies, self.error, self.kwargs, self.requests = list(replies), error, None, []

    def __call__(self, **kwargs):
        self.kwargs = kwargs
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def subscribe(self, subscribe):
        self.requests.append(subscribe)
        if self.error is not None:
            raise self.error
        return iter(self.replies)


class FakeResponse:
    def __init__(self, error=None):
        self.error = error

    def raise_for_status(self):
        if self.error is not None:
            raise self.error


class FakeSession:
    def __init__(self, error=None):
        self.error, self.posts = error, []

    def __call__(self):
        return self

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return FakeResponse(self.error)


class FakeThread:
    started = []

    def __init__(self, target=None, args=(), daemon=None, name=None):
        self.target, self.args, self.daemon, self.name = target, args, daemon, name

    def start(self):
        FakeThread.started.append(self)


class CollectorTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.etc = Path(self.tmp.name) / "etc"
        self.etc.mkdir()
        self.log_path = Path(self.tmp.name) / "collector.log"
        for target, value in (("ETC", self.etc), ("LOG_PATH", self.log_path)):
            patcher = mock.patch.object(collector, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def log_text(self):
        return self.log_path.read_text() if self.log_path.exists() else ""


class HelperTests(CollectorTestCase):
    def test_log_appends_a_timestamped_line(self):
        collector.log("hello")
        collector.log("again")
        lines = self.log_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].endswith(" hello"))
        self.assertRegex(lines[1], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d again$")

    def test_log_to_an_unwritable_path_is_ignored_never_raised(self):
        with mock.patch.object(collector, "LOG_PATH", Path(self.tmp.name) / "missing-dir" / "x.log"):
            self.assertIsNone(collector.log("lost"))
        self.assertFalse((Path(self.tmp.name) / "missing-dir").exists())

    def test_load_env_returns_key_value_pairs(self):
        (self.etc / "ingest.env").write_text("INFLUXDB_ORG=lab\nINFLUXDB_TOKEN=a=b\n# comment\n")
        self.assertEqual(collector.load_env("ingest.env"), {"INFLUXDB_ORG": "lab", "INFLUXDB_TOKEN": "a=b"})

    def test_load_env_of_a_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            collector.load_env("missing.env")

    def test_tag_escape_returns_escaped_separators(self):
        self.assertEqual(collector.tag_escape("a b,c=d\\e"), "a\\ b\\,c\\=d\\\\e")
        self.assertEqual(collector.tag_escape(7), "7")

    def test_tag_escape_never_alters_a_plain_value(self):
        self.assertEqual(collector.tag_escape("Ethernet1"), "Ethernet1")

    def test_field_value_returns_typed_line_protocol_fields(self):
        cases = {"true": (True, "true"), "false": (False, "false"), "int": (5, "5i"), "float": (2.9, "2i"),
                 "numeric text": ("-12", "-12i"), "text": ('UP "x"\\', '"UP \\"x\\"\\\\"')}
        for label, (value, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(collector.field_value(value), expected)

    def test_field_value_of_non_numeric_text_is_not_an_integer(self):
        self.assertEqual(collector.field_value("12abc"), '"12abc"')
        self.assertEqual(collector.field_value(None), '"None"')

    def test_path_to_dict_returns_the_joined_path_and_keys(self):
        path = gpath(("interfaces", None), ("interface", {"name": "Ethernet1"}), ("state", None))
        self.assertEqual(collector.path_to_dict(path), ("interfaces/interface/state", {"name": "Ethernet1"}))

    def test_path_to_dict_of_an_empty_path_has_no_elements_and_no_keys(self):
        self.assertEqual(collector.path_to_dict(gnmi_pb2.Path()), ("", {}))

    def test_decode_val_returns_scalars_and_namespace_stripped_containers(self):
        self.assertEqual(collector.decode_val(gnmi_pb2.TypedValue(uint_val=9)), (9, False))
        self.assertEqual(collector.decode_val(gnmi_pb2.TypedValue(string_val="UP")), ("UP", False))
        blob = gnmi_pb2.TypedValue(json_ietf_val=json.dumps({"openconfig-system:used": 5, "free": 6}).encode())
        self.assertEqual(collector.decode_val(blob), ({"used": 5, "free": 6}, True))

    def test_decode_val_of_non_object_json_is_not_a_container(self):
        self.assertEqual(collector.decode_val(gnmi_pb2.TypedValue(json_ietf_val=b"[1, 2]")), ([1, 2], False))
        self.assertEqual(collector.decode_val(gnmi_pb2.TypedValue(json_ietf_val=b'"UP"')), ("UP", False))

    def test_build_subscribe_request_returns_a_stream_sample_request(self):
        self.assertEqual(collector.build_subscribe_request(PATHS_CONFIG), {
            "subscription": [
                {"path": "/interfaces/interface/state/counters", "mode": "sample", "sample_interval": 10_000_000_000},
                {"path": "/system/memory/state", "mode": "sample", "sample_interval": 10_000_000_000},
            ],
            "mode": "stream", "encoding": "json_ietf",
        })

    def test_build_subscribe_request_without_streams_or_interval_raises(self):
        for label, config in (("missing streams", {"sample_interval_ns": 1}), ("missing interval", {"streams": []})):
            with self.subTest(case=label):
                with self.assertRaises(KeyError):
                    collector.build_subscribe_request(config)


class ClassifyTests(unittest.TestCase):
    def classify(self, path, keys, value, container=False):
        return collector.classify(path, keys, value, container, "R1", "ceos")

    def test_classify_returns_a_line_for_every_documented_category(self):
        base = "gnmi_telemetry,device=R1,platform=ceos,source_protocol=gnmi"
        cases = {
            "hostname": (("system/state/hostname", {}, "R1"), f"{base},category=system_identity hostname=\"R1\""),
            "cpu": (("system/cpus/cpu/state/total/instant", {"index": "ALL"}, 7),
                    f"{base},category=system_cpu,cpu_index=ALL cpu_total_pct=7i"),
            "memory leaf": (("system/memory/state/used", {}, 10), f"{base},category=system_memory mem_used_bytes=10i"),
            "oper status": (("interfaces/interface/state/oper-status", {"name": "Ethernet1"}, "UP"),
                            f"{base},interface=Ethernet1,category=interface_state oper_status=\"UP\""),
            "counter leaf": (("interfaces/interface/state/counters/in-octets", {"name": "Ethernet1"}, 5),
                             f"{base},interface=Ethernet1,category=interface_counters in_octets=5i"),
        }
        for label, (args, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.classify(*args), expected)
        with self.subTest(case="memory container"):
            self.assertEqual(self.classify("system/memory/state", {}, {"physical": 1, "used": 2, "x": 3}, True),
                             f"{base},category=system_memory mem_physical_bytes=1i,mem_used_bytes=2i")
        with self.subTest(case="counter container"):
            self.assertEqual(
                self.classify("interfaces/interface/state/counters", {"name": "Et 1"}, {"out-errors": 4, "y": 1}, True),
                f"{base},interface=Et\\ 1,category=interface_counters out_errors=4i")

    def test_classify_skips_unknown_keyless_or_empty_updates(self):
        cases = {
            "unknown path": ("bgp/neighbors", {}, 1, False),
            "interface without a name key": ("interfaces/interface/state/oper-status", {}, "UP", False),
            "uncollected interface leaf": ("interfaces/interface/state/mtu", {"name": "Ethernet1"}, 1500, False),
            "unknown memory leaf": ("system/memory/state/utilized", {}, 1, False),
            "container with no known field": ("interfaces/interface/state/counters", {"name": "E1"}, {"x": 1}, True),
            "unknown counter leaf": ("interfaces/interface/state/counters/in-pkts", {"name": "E1"}, 1, False),
        }
        for label, (path, keys, value, container) in cases.items():
            with self.subTest(case=f"skipped {label}"):
                self.assertIsNone(self.classify(path, keys, value, container))


class DeviceWorkerTests(CollectorTestCase):
    def run_worker(self, client):
        out = queue.Queue()
        stop = collector.threading.Event()
        clock = FakeClock(stop_event=stop)
        with mock.patch("pygnmi.client.gNMIclient", client), mock.patch.object(collector, "time", clock):
            collector.device_worker(DEVICE, CREDS, PATHS_CONFIG, out, stop)
        lines = []
        while not out.empty():
            lines.append(out.get_nowait())
        return lines, clock

    def test_device_worker_returns_after_queueing_streamed_updates(self):
        sync_only = gnmi_pb2.SubscribeResponse(sync_response=True)
        client = FakeGnmiClient(replies=[sync_only, counter_reply()])
        lines, clock = self.run_worker(client)
        self.assertEqual(lines, ["gnmi_telemetry,device=R1,platform=ceos,source_protocol=gnmi,interface=Ethernet1,"
                                 "category=interface_counters in_octets=1234i"])
        self.assertEqual(client.kwargs, {
            "target": ("172.20.20.11", 6030), "username": "telemetry", "password": "pw-not-real",
            "insecure": False, "path_root": str(self.etc / "ca" / "R1.crt"), "override": "R1", "gnmi_timeout": 15,
        })
        self.assertEqual(client.requests, [collector.build_subscribe_request(PATHS_CONFIG)])
        self.assertEqual(clock.sleeps, [2])
        self.assertIn("R1: subscribed", self.log_text())
        self.assertNotIn("pw-not-real", self.log_text())

    def test_device_worker_with_a_failing_session_only_logs_and_backs_off_never_queues(self):
        lines, clock = self.run_worker(FakeGnmiClient(error=ConnectionError("refused by peer")))
        self.assertEqual(lines, [])
        self.assertEqual(clock.sleeps, [2])
        self.assertIn("R1: ERROR ConnectionError('refused by peer'); reconnecting in 2s", self.log_text())
        self.assertNotIn("pw-not-real", self.log_text())

    def test_device_worker_with_an_already_set_stop_event_never_connects(self):
        client = FakeGnmiClient()
        stop = collector.threading.Event()
        stop.set()
        with mock.patch("pygnmi.client.gNMIclient", client):
            collector.device_worker(DEVICE, CREDS, PATHS_CONFIG, queue.Queue(), stop)
        self.assertIsNone(client.kwargs)


class WriterWorkerTests(CollectorTestCase):
    def setUp(self):
        super().setUp()
        (self.etc / "ingest.env").write_text("INFLUXDB_ORG=lab\nINFLUXDB_BUCKET=network-monitoring\nINFLUXDB_TOKEN=tok-secret\n")

    def run_writer(self, session, lines):
        out = queue.Queue()
        for line in lines:
            out.put(line)
        stop = collector.threading.Event()
        stop.set()
        with mock.patch("requests.Session", session), mock.patch.object(collector, "time", FakeClock()):
            collector.writer_worker(out, stop)
        return out

    def test_writer_worker_returns_after_writing_the_drained_batch(self):
        session = FakeSession()
        out = self.run_writer(session, ["m,a=1 f=1i"])
        self.assertTrue(out.empty())
        self.assertEqual(session.posts, [("http://127.0.0.1:8086/api/v2/write", {
            "params": {"org": "lab", "bucket": "network-monitoring", "precision": "ns"},
            "headers": {"Authorization": "Token tok-secret"},
            "data": "m,a=1 f=1i 1700000000000000000", "timeout": 15,
        })])
        self.assertIn("wrote 1 point(s)", self.log_text())
        self.assertNotIn("tok-secret", self.log_text())

    def test_writer_worker_with_a_failing_write_only_logs_the_failure(self):
        session = FakeSession(error=RuntimeError("HTTP 401"))
        self.run_writer(session, ["m f=1i"])
        self.assertEqual(len(session.posts), 1)
        self.assertIn("FAIL InfluxDB write: HTTP 401", self.log_text())
        self.assertNotIn("wrote", self.log_text())

    def test_writer_worker_with_an_empty_queue_never_writes(self):
        session = FakeSession()
        self.run_writer(session, [])
        self.assertEqual(session.posts, [])


class MainTests(CollectorTestCase):
    def test_main_returns_after_starting_one_writer_and_one_worker_per_device(self):
        (self.etc / "devices.json").write_text(json.dumps([DEVICE, {**DEVICE, "device": "R3", "platform": "linux"}]))
        (self.etc / "paths.json").write_text(json.dumps(PATHS_CONFIG))
        (self.etc / "credentials.env").write_text("TELEMETRY_USERNAME=telemetry\nTELEMETRY_PASSWORD=pw-not-real\n")
        clock = FakeClock()
        clock.sleep = mock.Mock(side_effect=KeyboardInterrupt)
        FakeThread.started = []
        with mock.patch.object(collector.threading, "Thread", FakeThread), mock.patch.object(collector, "time", clock):
            self.assertIsNone(collector.main())
        started = FakeThread.started
        self.assertEqual([t.target for t in started], [collector.writer_worker, collector.device_worker, collector.device_worker])
        self.assertEqual([t.name for t in started[1:]], ["R1", "R3"])
        self.assertTrue(all(t.daemon for t in started))
        self.assertEqual(started[1].args[1], CREDS)
        self.assertTrue(started[1].args[4].is_set())
        self.assertIn("started with 2 device(s)", self.log_text())

    def test_main_without_a_device_file_raises_and_starts_nothing(self):
        FakeThread.started = []
        with mock.patch.object(collector.threading, "Thread", FakeThread):
            with self.assertRaises(FileNotFoundError):
                collector.main()
        self.assertEqual(FakeThread.started, [])


if __name__ == "__main__":
    unittest.main()
