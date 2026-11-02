"""Lab 7 closure -- the NMAS-side syslog tailer (``monitoring/scripts/syslog_ingest_daemon.py``), each helper called
directly.

Hermetic: the script is loaded as a module, ``LOGFILE`` / ``STATE_DIR`` / ``OFFSET_FILE`` / ``ETC`` / ``INGEST_LOG``
point into a temporary directory and ``requests.Session`` is a fake -- nothing reads /var/log, nothing reaches
InfluxDB.  POSITIVE: exact escaping, timestamps and line protocol, loaded config.  NEGATIVE: unknown severities and
facilities get sentinel codes, bad timestamps fall back to "now", missing / corrupt device maps are empty, a missing
env file raises, an unwritable log is ignored.  ``main`` is an endless tail loop that can only exit by raising, so
its POSITIVE case is structurally unreachable (documented debt); one driven cycle is still asserted below.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


daemon = load("tg_syslog_ingest_daemon", SCRIPTS / "syslog_ingest_daemon.py")
RAW = "2026-10-19T01:02:03+00:00 device=r1 source=172.20.20.11 facility=local4 severity=crit message=Link \"down\" a,b"


class StopLoop(Exception):
    pass


class FakeSession:
    def __init__(self):
        self.posts = []

    def __call__(self):
        return self

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return mock.Mock(raise_for_status=mock.Mock())


class DaemonTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.etc = self.root / "etc"
        self.etc.mkdir()
        state = self.root / "state"
        targets = {"LOGFILE": self.root / "remote-syslog.log", "STATE_DIR": state, "OFFSET_FILE": state / "offset",
                   "ETC": self.etc, "INGEST_LOG": self.root / "ingest.log"}
        for name, value in targets.items():
            patcher = mock.patch.object(daemon, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def ingest_log(self):
        return daemon.INGEST_LOG.read_text() if daemon.INGEST_LOG.exists() else ""


class HelperTests(DaemonTestCase):
    def test_log_appends_a_timestamped_line(self):
        daemon.log("OK wrote 1 point(s)")
        self.assertRegex(self.ingest_log(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d OK wrote 1 point\(s\)\n$")

    def test_log_to_an_unwritable_path_is_ignored_never_raised(self):
        with mock.patch.object(daemon, "INGEST_LOG", self.root / "missing-dir" / "x.log"):
            self.assertIsNone(daemon.log("lost"))
        self.assertFalse((self.root / "missing-dir").exists())

    def test_tag_returns_escaped_separators(self):
        self.assertEqual(daemon.tag("a b,c=d\\e"), "a\\ b\\,c\\=d\\\\e")

    def test_tag_never_alters_a_plain_value(self):
        self.assertEqual(daemon.tag("R1"), "R1")

    def test_field_str_returns_a_quoted_escaped_string(self):
        self.assertEqual(daemon.field_str('say "hi" \\'), '"say \\"hi\\" \\\\"')

    def test_field_str_of_an_empty_value_is_an_empty_quoted_string(self):
        self.assertEqual(daemon.field_str(""), '""')

    def test_load_env_returns_key_value_pairs(self):
        (self.etc / "ingest.env").write_text("INFLUXDB_ORG=lab\nINFLUXDB_TOKEN=x=y\n\n")
        self.assertEqual(daemon.load_env(), {"INFLUXDB_ORG": "lab", "INFLUXDB_TOKEN": "x=y"})

    def test_load_env_of_a_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            daemon.load_env()

    def test_load_devices_returns_the_device_map(self):
        (self.etc / "devices.json").write_text(json.dumps({"r1": {"device": "R1", "platform": "ceos"}}))
        self.assertEqual(daemon.load_devices(), {"r1": {"device": "R1", "platform": "ceos"}})

    def test_load_devices_of_a_missing_or_corrupt_file_is_empty(self):
        with self.subTest(case="missing file"):
            self.assertEqual(daemon.load_devices(), {})
        (self.etc / "devices.json").write_text("{not json")
        with self.subTest(case="invalid json"):
            self.assertEqual(daemon.load_devices(), {})

    def test_to_nanos_returns_utc_epoch_nanoseconds(self):
        self.assertEqual(daemon.to_nanos("1970-01-01T00:00:01+00:00"), 1_000_000_000)
        self.assertEqual(daemon.to_nanos("1970-01-01T01:00:02+01:00"), 2_000_000_000)

    def test_to_nanos_of_an_invalid_timestamp_falls_back_to_now(self):
        with mock.patch.object(daemon.time, "time_ns", return_value=42):
            self.assertEqual(daemon.to_nanos("not-a-time"), 42)

    def test_build_point_returns_line_protocol_with_the_mapped_device(self):
        match = daemon.LINE.match(RAW)
        point = daemon.build_point(match, {"r1": {"device": "R1", "platform": "ceos"}})
        self.assertEqual(point, (
            "syslog_event,device=R1,source_ip=172.20.20.11,source_protocol=syslog,severity=crit,facility=local4,"
            "platform=ceos message=\"Link \\\"down\\\" a,b\",hostname=\"r1\",severity_code=2i,facility_code=20i "
            f"{daemon.to_nanos('2026-10-19T01:02:03+00:00')}"))

    def test_build_point_of_an_unknown_device_severity_or_facility_uses_sentinels(self):
        raw = "2026-10-19T01:02:03+00:00 device=mystery source=10.0.0.9 facility=bogus severity=loud message=x"
        for label, devices in (("unknown device", {}), ("malformed entry", {"mystery": "not-a-dict"})):
            with self.subTest(case=label):
                point = daemon.build_point(daemon.LINE.match(raw), devices)
                self.assertTrue(point.startswith("syslog_event,device=mystery,source_ip=10.0.0.9,source_protocol=syslog,"
                                                 "severity=loud,facility=bogus message="))
                self.assertNotIn("platform=", point)
                self.assertIn("severity_code=8i,facility_code=-1i", point)


class MainCycleTests(DaemonTestCase):
    def test_main_never_returns_but_writes_new_lines_and_saves_the_offset(self):
        daemon.LOGFILE.write_text("old line\n")
        (self.etc / "ingest.env").write_text("INFLUXDB_ORG=lab\nINFLUXDB_BUCKET=b\nINFLUXDB_TOKEN=tok-secret\n")
        session = FakeSession()
        appended = []

        def fake_sleep(seconds):
            # First idle poll: append one new line; second idle poll: stop the endless loop.
            if appended:
                raise StopLoop
            appended.append(seconds)
            with daemon.LOGFILE.open("a") as handle:
                handle.write(RAW + "\nunparseable\n")

        with mock.patch("requests.Session", session), mock.patch.object(daemon.time, "sleep", fake_sleep):
            with self.assertRaises(StopLoop):
                daemon.main()
        self.assertEqual(len(session.posts), 1)
        url, kwargs = session.posts[0]
        self.assertEqual(url, "http://127.0.0.1:8086/api/v2/write")
        self.assertTrue(kwargs["data"].startswith("syslog_event,device=r1,"))
        self.assertEqual(kwargs["data"].count("\n"), 0)
        self.assertEqual(int(daemon.OFFSET_FILE.read_text()), daemon.LOGFILE.stat().st_size)
        self.assertIn("OK wrote 1 point(s)", self.ingest_log())
        self.assertNotIn("tok-secret", self.ingest_log())


if __name__ == "__main__":
    unittest.main()
