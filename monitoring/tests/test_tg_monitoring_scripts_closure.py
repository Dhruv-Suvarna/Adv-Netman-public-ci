"""Lab 7 closure -- the deployed monitoring scripts that run on devices / the NMAS host, each function called directly:
``ceos_syslog_forward`` (tail / forward / main), ``ingest_snmp_trap`` (log / fail / load / parse_varbind / main),
``influxdb_retention`` (correct), ``linux_link_notifications`` (links) and ``linux_mfa_rollback`` (rollback / main).

The deployed files are never edited (they are copied byte-for-byte onto devices).  Scripts that do work at import time
are loaded with ``script_namespace``: the tracked source is compiled under its own real path -- so each function keeps
its identity -- and executed against fakes (``requests``, ``subprocess``, ``sys.argv``) and temporary paths, or, for
the container-local watcher whose module body is an endless loop, only the named function definitions are compiled.

Hermetic: no UDP packet, no ``logger``/``snmptrap``/``docker`` process, no InfluxDB request, no read of
``/sys/class/net``, ``/etc/snmp`` or the real ``monitoring.env``.  POSITIVE: exact command lines, line protocol, parsed
values.  NEGATIVE: lines above the severity policy are never forwarded, malformed input exits 1 after logging, an
unwritable log is ignored, unknown devices / malformed tokens never reach docker, wrong retention is corrected and a
still-wrong bucket fails.
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import monitoring.scripts.ingest_snmp_trap as trap
from monitoring.scripts import linux_mfa_rollback

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def script_namespace(name, *, replacements=None, functions=None, module_globals=None):
    """Execute ``monitoring/scripts/<name>`` (or only its ``functions`` definitions) compiled under the real path."""
    path = SCRIPTS / name
    source = path.read_text()
    for old, new in (replacements or {}).items():
        source = source.replace(old, new)
    tree = ast.parse(source, filename=str(path))
    if functions is not None:
        tree.body = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
                     or (isinstance(node, ast.FunctionDef) and node.name in functions)]
    namespace = {"__name__": "nmas_script_" + path.stem, "__file__": str(path), **(module_globals or {})}
    exec(compile(tree, str(path), "exec"), namespace)   # noqa: S102 - the tracked repository script, under test
    return namespace


def temp_dir(test):
    tmp = tempfile.TemporaryDirectory()
    test.addCleanup(tmp.cleanup)
    return Path(tmp.name)


class StopLoop(Exception):
    pass


# --------------------------------------------------------------------------------------------- cEOS syslog forwarder


class CeosSyslogForwardTests(unittest.TestCase):
    def setUp(self):
        self.ns = script_namespace("ceos_syslog_forward.py", replacements={"__RECEIVER__": "192.168.200.100", "__PORT__": "514",
                                                                             "__MAX_SEVERITY__": "2"})
        self.runs = []
        self.ns["subprocess"] = types.SimpleNamespace(run=lambda args, **kw: self.runs.append((args, kw)))

    def test_forward_relays_a_critical_eos_event_as_rfc5424_local4(self):
        line = "Oct 19 07:00:00 R1 Ebra: %LINEPROTO-2-UPDOWN: Line protocol on Interface Ethernet1, changed state to down"
        self.assertIsNone(self.ns["forward"](line))
        self.assertEqual(self.runs, [(["logger", "-n", "192.168.200.100", "-P", "514", "--udp", "--rfc5424=notq", "-p", "local4.crit",
                                       "-t", "EOS-CRITWATCH", line], {"check": False, "timeout": 5})])

    def test_forward_never_relays_events_below_the_policy_or_unknown_lines(self):
        for label, line in (("refused severity 5 notice", "R1 Ebra: %SYS-5-CONFIG_I: Configured from console"),
                            ("refused unknown format", "kernel: eth1 link down")):
            with self.subTest(label):
                self.assertIsNone(self.ns["forward"](line))
        self.assertEqual(self.runs, [])

    def test_tail_yields_only_lines_appended_after_start(self):
        log = temp_dir(self) / "messages"
        log.write_text("old history line\n")

        def sleep(_seconds):
            with log.open("a") as stream:
                stream.write("%SYS-2-NEW: appended\n")

        self.ns["time"] = types.SimpleNamespace(sleep=sleep)
        lines = self.ns["tail"](str(log))
        self.assertEqual(next(lines), "%SYS-2-NEW: appended")
        # The deployed generator owns its handle for the process lifetime. Close both in cleanup, outside the test body:
        # closing a generator unwinds it with GeneratorExit, which is teardown, not the behaviour this test proves.
        self.addCleanup(lines.close)
        self.addCleanup(lines.gi_frame.f_locals["handle"].close)

    def test_tail_of_a_missing_file_keeps_waiting_and_never_yields(self):
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 3:
                raise StopLoop

        self.ns["time"] = types.SimpleNamespace(sleep=sleep)
        lines = self.ns["tail"](str(temp_dir(self) / "absent"))
        with self.assertRaises(StopLoop):
            next(lines)
        self.assertEqual(sleeps, [2, 2, 2])

    def test_main_forwards_each_tailed_line(self):
        seen = []
        self.ns["tail"] = lambda path: iter(["%A-1-X: one", "%B-6-Y: two"])
        self.ns["forward"] = seen.append
        self.assertIsNone(self.ns["main"]())
        self.assertEqual(seen, ["%A-1-X: one", "%B-6-Y: two"])


# ------------------------------------------------------------------------------------------------- SNMP trap ingest


ADDRESS = "UDP: [192.168.200.11]:41234->[192.168.200.100]:162"
OIDS = {"snmpTrapOID": ".1.3.6.1.6.3.1.1.4.1.0", "linkDown": ".1.3.6.1.6.3.1.1.5.3", "linkUp": ".1.3.6.1.6.3.1.1.5.4",
        "ifIndex": ".1.3.6.1.2.1.2.2.1.1", "ifAdminStatus": ".1.3.6.1.2.1.2.2.1.7", "ifOperStatus": ".1.3.6.1.2.1.2.2.1.8"}


class SnmpTrapIngestTests(unittest.TestCase):
    def setUp(self):
        root = temp_dir(self)
        self.etc, self.log = root / "etc", root / "ingest.log"
        self.etc.mkdir()
        for name, value in (("ETC", self.etc), ("LOG", self.log)):
            patcher = mock.patch.object(trap, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_log_appends_a_timestamped_line(self):
        self.assertIsNone(trap.log("OK device=R1"))
        self.assertRegex(self.log.read_text(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d OK device=R1\n$")

    def test_log_to_an_unwritable_path_never_raises(self):
        with mock.patch.object(trap, "LOG", self.etc / "absent-dir/ingest.log"):
            self.assertIsNone(trap.log("dropped"))
        self.assertFalse((self.etc / "absent-dir").exists())

    def test_fail_logs_then_requests_exit_status_1(self):
        with mock.patch.object(trap.sys, "exit") as exit_, self.subTest("logs then requests exit status 1"):
            self.assertIsNone(trap.fail("bad input"))
        exit_.assert_called_once_with(1)
        self.assertTrue(self.log.read_text().endswith(" FAIL bad input\n"))

    def test_fail_raises_system_exit_1(self):
        with self.assertRaises(SystemExit) as caught:
            trap.fail("bad input")
        self.assertEqual(caught.exception.code, 1)

    def test_load_returns_the_parsed_json(self):
        (self.etc / "x.json").write_text('{"10.0.0.1": "R1"}')
        self.assertEqual(trap.load(self.etc / "x.json"), {"10.0.0.1": "R1"})

    def test_load_of_unreadable_or_invalid_json_exits_1(self):
        (self.etc / "bad.json").write_text("{not json")
        for label, path in (("refused invalid json", self.etc / "bad.json"), ("refused missing file", self.etc / "absent.json")):
            with self.subTest(label), self.assertRaises(SystemExit):
                trap.load(path)
        self.assertEqual(self.log.read_text().count("FAIL cannot read"), 2)

    def test_parse_varbind_returns_oid_and_value_for_both_formats(self):
        self.assertEqual(trap.parse_varbind(".1.3.6.1.2.1.2.2.1.1.3 = INTEGER: 3"), ("1.3.6.1.2.1.2.2.1.1.3", "3"))
        self.assertEqual(trap.parse_varbind("1.3.6.1.6.3.1.1.4.1.0 .1.3.6.1.6.3.1.1.5.3"), ("1.3.6.1.6.3.1.1.4.1.0", ".1.3.6.1.6.3.1.1.5.3"))

    def test_parse_varbind_of_unparsable_text_is_none(self):
        for label, line in (("none for prose", "hello world"), ("none for empty", "")):
            with self.subTest(label):
                self.assertEqual(trap.parse_varbind(line), (None, None))

    def test_main_writes_one_snmp_trap_line_for_a_link_down(self):
        (self.etc / "nmas-trap-oids.json").write_text(json.dumps(OIDS))
        (self.etc / "nmas-trap-devices.json").write_text('{"192.168.200.11": "R1"}')
        (self.etc / "nmas-trap-ingest.env").write_text("INFLUXDB_ORG=nmas\nINFLUXDB_BUCKET=telemetry\nINFLUXDB_TOKEN=trap-token-not-real\n")
        stdin = "\n".join(["R1", ADDRESS, ".1.3.6.1.2.1.1.3.0 = Timeticks: (100) 0:00:01.00",
                           ".1.3.6.1.6.3.1.1.4.1.0 = OID: .1.3.6.1.6.3.1.1.5.3", ".1.3.6.1.2.1.2.2.1.1.3 = INTEGER: 3",
                           ".1.3.6.1.2.1.2.2.1.7.3 = INTEGER: 1", ".1.3.6.1.2.1.2.2.1.8.3 = INTEGER: 2"]) + "\n"
        response = mock.Mock()
        with mock.patch.object(trap.sys, "stdin", io.StringIO(stdin)), mock.patch("requests.post", return_value=response) as post, \
                mock.patch.object(trap.time, "time_ns", return_value=99):
            self.assertIsNone(trap.main())
        data = post.call_args.kwargs["data"]
        self.assertTrue(data.startswith("snmp_trap,device=R1,source_ip=192.168.200.11,source_protocol=snmp,event_type=linkDown,"
                                        "notification_oid=1.3.6.1.6.3.1.1.5.3,severity=warning,ifindex=3 value=1i,ifadminstatus=1i,"
                                        "ifoperstatus=2i,raw_varbinds="))
        self.assertTrue(data.endswith(" 99"))
        self.assertEqual(post.call_args.kwargs["headers"], {"Authorization": "Token trap-token-not-real"})
        response.raise_for_status.assert_called_once_with()
        self.assertNotIn("trap-token-not-real", self.log.read_text())
        self.assertIn("OK device=R1 event_type=linkDown", self.log.read_text())


# ------------------------------------------------------------------------------------------------ InfluxDB retention


class FakeBucketSession:
    def __init__(self, bucket):
        self.bucket, self.headers, self.patches = bucket, {}, []

    def get(self, url, params=None, timeout=None):
        payload = {"buckets": [self.bucket]} if params else self.bucket
        return mock.Mock(json=lambda: payload)

    def patch(self, url, json=None, timeout=None):   # noqa: A002 - requests keyword
        self.patches.append((url, json))
        self.bucket = dict(self.bucket, **json)
        return mock.Mock()


class InfluxdbRetentionTests(unittest.TestCase):
    THIRTY_DAYS = [{"type": "expire", "everySeconds": 2592000}]

    def run_script(self, bucket, *argv):
        root = temp_dir(self)
        (root / "runtime").mkdir()
        (root / "runtime/monitoring.env").write_text("INFLUXDB_ORG=nmas\nINFLUXDB_BUCKET=telemetry\nINFLUXDB_TOKEN=retention-token-not-real\n")
        session = FakeBucketSession(bucket)
        out = io.StringIO()
        with mock.patch("requests.Session", return_value=session), mock.patch.object(sys, "argv", ["influxdb_retention.py", *argv]), \
                contextlib.redirect_stdout(out):
            namespace = script_namespace("influxdb_retention.py", module_globals={"__file__": str(root / "scripts/influxdb_retention.py")})
        return namespace, session, out.getvalue()

    def test_correct_returns_true_for_exactly_one_30_day_expire_rule(self):
        namespace, session, out = self.run_script({"id": "b1", "name": "telemetry", "retentionRules": self.THIRTY_DAYS})
        self.assertTrue(namespace["correct"]({"retentionRules": self.THIRTY_DAYS}))
        self.assertEqual((session.patches, out), ([], "Bucket: telemetry retention: " + str(self.THIRTY_DAYS) + "\n"))
        self.assertEqual(session.headers["Authorization"], "Token retention-token-not-real")

    def test_correct_refuses_other_retention_and_apply_repairs_it(self):
        namespace, session, _ = self.run_script({"id": "b1", "name": "telemetry", "retentionRules": []}, "--apply")
        for label, value in (("refused empty rules", {}), ("refused 7 days", {"retentionRules": [{"type": "expire", "everySeconds": 604800}]}),
                             ("refused two rules", {"retentionRules": self.THIRTY_DAYS * 2})):
            with self.subTest(label):
                self.assertFalse(namespace["correct"](value))
        self.assertEqual(session.patches, [("http://127.0.0.1:8086/api/v2/buckets/b1", {"retentionRules": self.THIRTY_DAYS})])

    def test_read_only_run_with_wrong_retention_fails_and_never_patches(self):
        with self.assertRaisesRegex(SystemExit, "FAIL: expected 30-day retention"):
            self.run_script({"id": "b1", "name": "telemetry", "retentionRules": []})


# ------------------------------------------------------------------------------------------ Linux link notifications


class LinuxLinkNotificationsTests(unittest.TestCase):
    def test_links_returns_admin_and_oper_state_per_ifindex(self):
        net = temp_dir(self)
        for name, index, flags, oper in (("lo", 1, "0x9", "unknown"), ("eth1", 2, "0x1003", "up"), ("eth2", 3, "0x1003", "down"),
                                         ("eth3", 4, "0x1002", "down")):
            (net / name).mkdir()
            (net / name / "ifindex").write_text(f"{index}\n")
            (net / name / "flags").write_text(flags + "\n")
            (net / name / "operstate").write_text(oper + "\n")
        (net / "bonding_masters").mkdir()          # an entry without ifindex is skipped
        fake_pathlib = types.SimpleNamespace(Path=lambda value: net if value == "/sys/class/net" else Path(value))
        namespace = script_namespace("linux_link_notifications.py", functions={"links"})
        namespace["pathlib"] = fake_pathlib
        self.assertEqual(namespace["links"](), {1: (1, 1), 2: (1, 1), 3: (1, 2), 4: (2, 2)})


# -------------------------------------------------------------------------------------------------- Linux MFA rollback


class LinuxMfaRollbackTests(unittest.TestCase):
    def test_rollback_refuses_unknown_devices_and_malformed_tokens_without_docker(self):
        with mock.patch.object(linux_mfa_rollback.subprocess, "run") as run:
            for label, device, token in (("refused unknown device", "R1", "a" * 24), ("refused short token", "R3", "abc"),
                                         ("refused uppercase token", "R4", "A" * 24)):
                with self.subTest(label):
                    self.assertEqual(linux_mfa_rollback.rollback(device, token), 2)
        run.assert_not_called()

    def test_main_prints_pass_and_returns_the_rollback_status(self):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["linux_mfa_rollback.py", "--device", "R4", "--token", "b" * 24]), \
                mock.patch.object(linux_mfa_rollback, "rollback", return_value=0) as rollback, contextlib.redirect_stdout(out):
            self.assertEqual(linux_mfa_rollback.main(), 0)
        rollback.assert_called_once_with("R4", "b" * 24)
        self.assertEqual(out.getvalue(), "Linux MFA rollback for R4: PASS\n")


if __name__ == "__main__":
    unittest.main()
