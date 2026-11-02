"""Lab 7 closure -- the console's session log, supervisor / runtime surface, launcher, configuration, read-only adapters and collector
hooks, each called directly.

Nothing reaches a device, a service or the network: process calls go through the scripted ``FakeRunner`` (which still enforces the
real read-only allowlist), HTTP through ``FakeGetter`` or a fake ``build_opener``, the automation database is a temporary read-only
SQLite file, and the session log writes only inside a temporary directory.

POSITIVE: the exact record, file, check, verdict, address, row and snapshot.  NEGATIVE: unreadable sources become fixed codes,
missing files / addresses / units are reported (never guessed), a closed log drops records, a soak that failed is never eligible and
a launcher without Tk exits with guidance -- and nothing writes outside the temporary directory.
"""

from __future__ import annotations

import builtins
import io
import json
import socket
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from urllib.error import URLError

from challenge_console import __main__ as launcher
from challenge_console import models as m
from challenge_console.adapters import automation_db, endpoints, http, inventory, netbox, telemetry
from challenge_console.adapters import services as svc
from challenge_console.adapters.http import HttpResult
from challenge_console.adapters.process import CommandResult
from challenge_console.collectors import build_default
from challenge_console.collectors.connectivity import ConnectivityCollector
from challenge_console.collectors.counters import InterfaceCounterCollector
from challenge_console.collectors.nsot import NsotCollector
from challenge_console.runtime import ConsoleRuntime
from challenge_console.sessionlog import SessionLog, read_session, safe_filename
from challenge_console.supervisor import Collector, CollectorError, Supervisor

from .helpers import INVENTORY, ConsoleTestCase, FakeGetter, FakeRunner, addr_json, ok_json, ping_ok, ping_timeout

T0 = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)


class SessionLogTests(ConsoleTestCase):
    def log(self):
        session = SessionLog(self.tmp / "spool", started_at=T0)
        self.addCleanup(session.close)
        return session

    def test_safe_filename_returns_a_filesystem_safe_name(self):
        self.assertEqual((safe_filename("a b/../c?.jsonl"), safe_filename("../..")), ("a-b-..-c-.jsonl", "session"))

    def test_append_record_flush_and_save_keep_every_record_scrubbed(self):
        session = self.log()
        session.append_record({"ts": "t", "collector": "app", "kind": "x", "data": {"password": "hunter2"}})
        self.assertTrue(session.flush())
        session.close()
        (self.tmp / "saved").mkdir()
        saved = session.save(self.tmp / "saved")
        records = read_session(saved)
        self.assertEqual((records[0]["kind"], records[1]["data"]), ("session.meta", {"password": "[REDACTED]"}))
        self.assertEqual(saved, self.tmp / "saved" / session.default_name)

    def test_append_record_after_close_is_dropped_never_written(self):
        session = self.log()
        session.close()
        session.append_record({"kind": "late"})
        self.assertEqual(session.status()["dropped"], 1)
        self.assertNotIn("late", session.path.read_text())

    def test_flush_after_close_never_blocks(self):
        session = self.log()
        session.close()
        self.assertTrue(session.flush(timeout=0.1))

    def test_default_destination_returns_the_save_path(self):
        session = self.log()
        self.assertEqual(session.default_destination(self.tmp / "sessions"), self.tmp / "sessions" / session.default_name)

    def test_default_destination_never_escapes_the_save_directory(self):
        session = self.log()
        self.assertEqual(session.default_destination(self.tmp).parent, self.tmp)
        self.assertNotIn("/", session.default_name)

    def test_save_never_overwrites_and_discard_deletes(self):
        first, second = self.log(), self.log()
        first.close(), second.close()
        target = self.tmp / "out" / "session.jsonl"
        self.assertEqual((first.save(target).name, second.save(target).name), ("session.jsonl", "session-1.jsonl"))
        third = self.log()
        third.close()
        third.discard()
        self.assertFalse(third.path.exists())


class SupervisorSurfaceTests(ConsoleTestCase):
    def test_collector_exception_keeps_the_code_and_target(self):
        error = CollectorError("NETBOX_UNAVAILABLE", "netbox")
        self.assertEqual((str(error), error.code, error.target), ("NETBOX_UNAVAILABLE", "NETBOX_UNAVAILABLE", "netbox"))

    def test_collector_error_without_a_target_has_an_empty_target(self):
        self.assertEqual(CollectorError("TIMEOUT").target, "")

    def test_collector_emit_publishes_under_its_name_and_stopping_follows_the_event(self):
        collector = Collector(self.config, self.store, self.bus, interval=1)
        collector.name = m.NSOT
        event = collector.emit("nsot.read", "R1", m.OK, {"devices": 1}, ts=T0)
        self.assertEqual((event.collector, self.events[-1]), (m.NSOT, event))
        self.assertFalse(collector.stopping)
        collector.stop_event.set()
        self.assertTrue(collector.stopping)

    def test_collector_emit_without_data_publishes_an_empty_info_event(self):
        collector = Collector(self.config, self.store, self.bus, interval=1)
        self.assertEqual((collector.emit("x").data, collector.emit("x").outcome), ({}, m.INFO))

    def test_supervisor_stopped_returns_the_stop_state(self):
        supervisor = Supervisor(self.config, self.store, self.bus, [])
        self.assertFalse(supervisor.stopped)
        supervisor.stop()
        self.assertTrue(supervisor.stopped)

    def test_runtime_running_and_stop_report_the_lifecycle(self):
        runtime = ConsoleRuntime(self.config, collectors=[])
        self.assertFalse(runtime.running)
        runtime.start()
        self.assertTrue(runtime.running)
        self.assertEqual((runtime.stop(), runtime.stop(), runtime.running), ([], [], False))  # idempotent
        kinds = [r["kind"] for r in read_session(runtime.log.path)]
        self.assertEqual(kinds[-2:], ["session.summary", "app.stop"])
        runtime.log.discard()


class LauncherAndConfigTests(ConsoleTestCase):
    def test_main_prints_the_effective_configuration(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch.dict("os.environ", {}, clear=False):
            self.assertEqual(launcher.main(["--print-config"]), 0)
        self.assertEqual(json.loads(out.getvalue())["lab_name"], "srlceos01")

    def test_main_without_tkinter_exits_with_guidance_never_a_traceback(self):
        real_import = builtins.__import__

        def no_tk(name, *args, **kwargs):
            if name == "ui.app" or name.endswith("ui.app"):
                raise ImportError("No module named 'tkinter'")
            return real_import(name, *args, **kwargs)

        err = io.StringIO()
        with mock.patch("builtins.__import__", no_tk), mock.patch("sys.stderr", err):
            self.assertEqual(launcher.main([]), 2)
        self.assertIn("sudo apt install python3-tk", err.getvalue())

    def test_container_name_and_overrides_never_mutate_the_original(self):
        changed = self.config.with_overrides(lab_name="other")
        self.assertEqual((self.config.container("R1"), changed.container("R1")), ("clab-lab-R1", "clab-other-R1"))
        with self.assertRaises(TypeError):
            self.config.with_overrides(not_a_field=1)


class EndpointAndHttpAdapterTests(ConsoleTestCase):
    def test_parse_addresses_returns_the_first_global_data_address_per_family(self):
        self.assertEqual(endpoints.parse_addresses(addr_json("192.168.10.102", "2001:db8:10::2001")),
                         {m.V4: "192.168.10.102", m.V6: "2001:db8:10::2001"})

    def test_discover_and_ping_read_through_the_runner(self):
        runner = FakeRunner()
        self.assertEqual(endpoints.discover("clab-lab-H1", runner=runner)[m.V4], "192.168.10.102")
        self.assertEqual(endpoints.ping("clab-lab-H1", "192.168.20.101", m.V4, runner=runner), (True, 3.1, ""))
        self.assertEqual(runner.calls[-1][-2:], ("-4", "192.168.20.101"))

    def test_discover_and_ping_of_an_unavailable_container_fail_with_fixed_codes(self):
        runner = FakeRunner()
        runner.down_containers.add("clab-lab-H9")
        with self.assertRaises(endpoints.DiscoveryError) as caught:
            endpoints.discover("clab-lab-H9", runner=runner)
        self.assertEqual(caught.exception.code, "CONTAINER_NOT_RUNNING")
        self.assertFalse(endpoints.ping("clab-lab-H9", "192.168.20.101", m.V4, runner=runner)[0])
        stopped = lambda argv, timeout=8.0: CommandResult(126, stderr_class="CONTAINER_NOT_RUNNING")  # noqa: E731
        self.assertEqual(endpoints.ping("clab-lab-H9", "192.168.20.101", m.V4, runner=stopped), (False, None, "SOURCE_CONTAINER_NOT_RUNNING"))
        runner.ping_results[("clab-lab-H1", "2001:db8:20::2001")] = ping_timeout()
        self.assertFalse(endpoints.ping("clab-lab-H1", "2001:db8:20::2001", m.V6, runner=runner)[0])
        unreachable = lambda argv, timeout=8.0: CommandResult(2, stderr_class="NETWORK_UNREACHABLE")  # noqa: E731
        self.assertEqual(endpoints.ping("clab-lab-H1", "10.9.9.9", m.V4, runner=unreachable), (False, None, "UNREACHABLE"))

    def test_http_result_ok_and_json_return_the_parsed_body(self):
        result = ok_json({"status": "ok"})
        self.assertEqual((result.ok, result.json()), (True, {"status": "ok"}))

    def test_get_returns_the_status_and_body(self):
        response = mock.MagicMock(status=200)
        response.read.return_value = b'{"ok": true}'
        response.__enter__.return_value = response
        opener = mock.MagicMock()
        opener.open.return_value = response
        with mock.patch.object(http, "build_opener", return_value=opener):
            result = http.get("https://grafana.test/api/health", verify_tls=False, headers={"X": "1"})
        self.assertEqual((result.status, result.body, result.error), (200, b'{"ok": true}', ""))
        self.assertEqual(opener.open.call_args.args[0].get_method(), "GET")

    def test_get_refuses_credentials_in_the_url_and_reports_unreachable_hosts(self):
        with mock.patch.object(http, "build_opener") as opener:
            self.assertEqual(http.get("http://user:pw@netbox.test/").error, "INVALID_URL")
            self.assertEqual(http.get("ftp://netbox.test/").error, "INVALID_URL")
            opener.assert_not_called()
            opener.return_value.open.side_effect = URLError(ConnectionRefusedError())
            self.assertEqual(http.get("http://netbox.test/").error, "CONNECTION_REFUSED")
            opener.return_value.open.side_effect = socket.timeout()
            self.assertEqual(http.get("http://netbox.test/").error, "TIMEOUT")
            response = mock.MagicMock(status=200)
            response.read.return_value = b"x" * 11
            response.__enter__.return_value = response
            opener.return_value.open.side_effect, opener.return_value.open.return_value = None, response
            self.assertEqual(http.get("http://netbox.test/", max_bytes=10).error, "RESPONSE_TOO_LARGE")


class InventoryAndNetboxAdapterTests(ConsoleTestCase):
    def test_load_and_names_return_the_inventory(self):
        document = inventory.load(self.config.inventory_path)
        self.assertEqual((inventory.network_device_names(document), [d.name for d in inventory.managed_devices(document)]), (["R1", "R3", "R5"], ["R1", "R3"]))

    def test_load_of_an_empty_file_and_names_of_an_empty_document_are_empty(self):
        empty = self.tmp / "empty.yml"
        empty.write_text("")
        self.assertEqual((inventory.load(empty), inventory.network_device_names({}), inventory.managed_devices({"network_devices": {"X": None}})), ({}, [], []))
        with self.assertRaises(FileNotFoundError):
            inventory.load(self.tmp / "missing.yml")

    def test_parse_env_file_missing_file_or_comment_lines_yield_nothing(self):
        env = self.tmp / ".env"
        env.write_text("# comment\nNETBOX_URL='http://netbox.test'\nnot a pair\n")
        self.assertEqual((netbox.parse_env_file(env), netbox.parse_env_file(self.tmp / "absent.env")), ({"NETBOX_URL": "http://netbox.test"}, {}))

    def test_auth_header_never_sends_a_v2_token_as_a_legacy_token(self):
        self.assertEqual((netbox.auth_header("nbt_key.secret"), netbox.auth_header("0123abcd")),
                         ({"Authorization": "Bearer nbt_key.secret"}, {"Authorization": "Token 0123abcd"}))

    def test_reader_health_headers_return_a_copy_of_the_auth_header(self):
        reader = netbox.NetboxReader("http://netbox.test/", "0123abcd")
        headers = reader.health_headers()
        headers["Authorization"] = "changed"
        self.assertEqual((reader.url, reader.health_headers()), ("http://netbox.test", {"Authorization": "Token 0123abcd"}))

    def test_from_config_without_an_env_file_has_no_token_and_the_default_url(self):
        reader = netbox.NetboxReader.from_config(self.config.with_overrides(netbox_url="", netbox_env_file=self.tmp / "absent.env"))
        self.assertEqual((reader.url, reader.health_headers()), ("http://127.0.0.1:8000", {}))

    def test_normalise_builds_devices_interfaces_and_addresses(self):
        snapshot = netbox.normalise(
            [{"name": "R1", "role": {"name": "Router"}, "tags": [{"slug": netbox.MANAGED_TAG}]}],
            [{"id": 7, "name": "Ethernet1", "device": {"name": "R1"}}, {"id": 8, "name": "eth0", "device": {"name": "ghost"}}],
            [{"address": "192.0.2.1/24", "assigned_object_type": "dcim.interface", "assigned_object_id": 7}, {"address": "198.51.100.9/32"}],
            [{"prefix": "192.0.2.0/24"}], [{"vid": 10, "name": "users"}])
        device = snapshot["devices"][0]
        self.assertEqual((device["name"], device["managed"], device["address_count"], device["interfaces"][0]["addresses"][0]["address"]),
                         ("R1", True, 1, "192.0.2.1/24"))
        self.assertEqual((len(snapshot["unassigned_addresses"]), snapshot["counts"]["vlans"]), (1, 1))

    def test_normalise_of_unnamed_rows_is_empty(self):
        self.assertEqual(netbox.normalise([{"name": ""}], [], [], [], [])["devices"], [])

    def test_consistency_matches_inventory_and_runtime(self):
        snapshot = {"devices": [{"name": "R1", "managed": True, "interfaces": [{"addresses": [{"address": "192.0.2.1/24"}, {"address": "2001:db8::1/64"}]}]}]}
        found = netbox.consistency(snapshot, inventory_devices={"R1": {"address": "192.0.2.1", "address_v6": "2001:db8::1", "managed": True}}, running={"R1"})
        self.assertEqual(found, [{"device": "R1", "management_address": "MATCH", "managed_scope": "MATCH", "runtime": "RUNNING"}])

    def test_consistency_reports_mismatch_unknown_and_not_in_inventory(self):
        snapshot = {"devices": [{"name": "R1", "managed": False, "interfaces": []}, {"name": "X9", "managed": None, "interfaces": []}]}
        found = netbox.consistency(snapshot, inventory_devices={"R1": {"address": "192.0.2.1", "managed": True}}, running=None)
        self.assertEqual([(f["management_address"], f["managed_scope"], f["runtime"]) for f in found],
                         [("MISMATCH", "MISMATCH", "UNKNOWN"), ("NOT_IN_INVENTORY", "N/A", "UNKNOWN")])


class ServiceAdapterTests(ConsoleTestCase):
    def runner(self, outputs):
        fake = FakeRunner()
        fake.outputs.update(outputs)
        return fake

    def test_systemd_properties_and_check_return_the_unit_state(self):
        runner = self.runner({("systemctl", "show", "nmas-web.service", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState"):
                              CommandResult(0, stdout="LoadState=loaded\nActiveState=active\nSubState=running\n")})
        self.assertEqual(svc.systemd_properties("nmas-web.service", ("LoadState", "ActiveState", "SubState"), runner=runner)["ActiveState"], "active")
        self.assertEqual(svc.systemd_check("nmas-web.service", runner=runner), m.Check("systemd", True, "active/running"))

    def test_systemd_unreadable_or_not_installed_is_unknown_or_false(self):
        self.assertIsNone(svc.systemd_properties("x.service", ("ActiveState",), runner=self.runner({})))
        self.assertEqual(svc.systemd_check("x.service", runner=self.runner({})), m.Check("systemd", None, "service manager not readable"))
        missing = self.runner({("systemctl", "show", "x.service", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState"): CommandResult(0, stdout="LoadState=not-found\n")})
        self.assertEqual(svc.systemd_check("x.service", runner=missing), m.Check("systemd", False, "x.service not installed"))

    def test_container_check_returns_running_and_healthy(self):
        argv = ("docker", "inspect", "-f", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}", "netbox")
        self.assertEqual(svc.container_check("netbox", runner=self.runner({argv: CommandResult(0, stdout="running|healthy\n")})), m.Check("container", True, "running/healthy"))

    def test_container_check_reports_missing_unhealthy_stopped_or_unreadable(self):
        argv = ("docker", "inspect", "-f", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}", "netbox")
        cases = ((CommandResult(1), m.Check("container", False, "container not found")),
                 (CommandResult(0, stdout="running|unhealthy"), m.Check("container", False, "running/unhealthy")),
                 (CommandResult(0, stdout="exited|"), m.Check("container", False, "exited")),
                 (CommandResult(None, error="RUNTIME_UNAVAILABLE"), m.Check("container", None, "container runtime not readable")))
        for result, expected in cases:
            with self.subTest("not running", detail=expected.detail):
                self.assertEqual(svc.container_check("netbox", runner=self.runner({argv: result})), expected)

    def test_http_check_returns_ok_with_latency(self):
        check, latency = svc.http_check("http://web.test/health", getter=FakeGetter({"http://web.test": ok_json({"status": "ok"})}))
        self.assertEqual((check, latency), (m.Check("http", True, "HTTP 200"), 1.5))

    def test_http_check_reports_unreachable_error_status_and_wrong_body(self):
        getter = FakeGetter({"http://bad.test": HttpResult(503, elapsed_ms=2.0), "http://body.test": ok_json({"status": "down"})})
        self.assertEqual(svc.http_check("http://none.test/", getter=getter)[0], m.Check("http", False, "CONNECTION_REFUSED"))
        self.assertEqual(svc.http_check("http://bad.test/", getter=getter)[0], m.Check("http", False, "HTTP 503"))
        self.assertEqual(svc.http_check("http://body.test/", getter=getter, expect=lambda r: "status is not ok")[0], m.Check("http", False, "status is not ok"))

    def test_socket_check_returns_present_for_a_listening_socket(self):
        path = self.tmp / "s.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(path))
        self.assertEqual(svc.socket_check(path), m.Check("socket", True, "listening socket present"))

    def test_socket_check_of_a_missing_path_or_a_plain_file_is_false(self):
        plain = self.tmp / "plain"
        plain.write_text("")
        self.assertEqual((svc.socket_check(self.tmp / "absent").ok, svc.socket_check(plain)), (False, m.Check("socket", False, "path is not a socket")))

    def test_verdict_returns_up_when_every_check_passed(self):
        self.assertEqual(svc.verdict([m.Check("systemd", True), m.Check("http", True)]), m.UP)

    def test_verdict_reports_down_degraded_or_unknown_never_up_for_a_failure(self):
        self.assertEqual([svc.verdict([m.Check("a", True), m.Check("b", False)]), svc.verdict([m.Check("a", False), m.Check("b", True)]),
                          svc.verdict([m.Check("a", None)])], [m.DOWN, m.DEGRADED, m.UNKNOWN])


class TelemetryAdapterTests(ConsoleTestCase):
    THRESHOLDS = {"healthy": 60.0, "stale": 120.0}
    PAYLOAD = {"graph": {"nodes": [{"id": "R1", "monitored": True, "last_telemetry_timestamp": "2026-10-19T11:59:30Z", "health": "OK", "cpu_percent": 4}]},
               "backend": {"status": "ok"}, "generated_at": "2026-10-19T12:00:00Z"}

    def test_rows_from_payload_returns_fresh_rows_and_unknown_for_missing_managed(self):
        rows = telemetry.rows_from_payload(self.PAYLOAD, now=T0, thresholds=self.THRESHOLDS, managed={"R1", "R3"})
        self.assertEqual([(r.device, r.freshness, r.age_seconds) for r in rows], [("R1", "FRESH", 30.0), ("R3", "UNKNOWN", None)])

    def test_rows_from_payload_without_nodes_reports_every_managed_device_unknown(self):
        rows = telemetry.rows_from_payload({"graph": {}}, now=T0, thresholds=self.THRESHOLDS, managed={"R1"})
        self.assertEqual([(r.device, r.freshness) for r in rows], [("R1", "UNKNOWN")])

    def test_read_returns_rows_thresholds_and_backend(self):
        getter = FakeGetter({self.config.topology_api_url: ok_json(self.PAYLOAD)})
        snapshot = telemetry.read(self.config, managed={"R1"}, now=T0, getter=getter)
        self.assertEqual((snapshot["backend"], snapshot["thresholds"], snapshot["rows"][0].freshness), ("OK", self.THRESHOLDS, "FRESH"))

    def test_read_reports_unreachable_http_errors_and_malformed_payloads(self):
        for label, result, code in (("unreachable", HttpResult(None, error="TIMEOUT"), "TIMEOUT"), ("error status", HttpResult(500), "HTTP_500"),
                                    ("malformed", ok_json({"graph": []}), "PARSE_ERROR")):
            with self.subTest(label), self.assertRaises(telemetry.TelemetryUnavailable) as caught:
                telemetry.read(self.config, managed=set(), now=T0, getter=FakeGetter({self.config.topology_api_url: result}))
            self.assertEqual(caught.exception.code, code)

    def test_classify_age_of_unknown_or_old_samples_is_unknown_stale_or_expired(self):
        self.assertEqual([telemetry.classify_age(a, self.THRESHOLDS) for a in (None, -5, 90, 500)], ["UNKNOWN", "FRESH", "STALE", "EXPIRED"])

    def test_load_thresholds_without_policy_or_payload_values_is_unavailable(self):
        with self.assertRaises(telemetry.TelemetryUnavailable):
            telemetry.load_thresholds(self.tmp / "absent.yml")
        self.assertEqual(telemetry.load_thresholds(self.tmp / "absent.yml", {"healthy_max": 30, "stale_max": 90}), {"healthy": 30.0, "stale": 90.0})


class AutomationDbAdapterTests(ConsoleTestCase):
    def test_connect_opens_a_read_only_connection(self):
        path = self.tmp / "db.sqlite3"
        sqlite3.connect(path).execute("CREATE TABLE t (x)").connection.commit()
        connection = automation_db.connect(path)
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute("SELECT count(*) FROM t").fetchone()[0], 0)
        with self.assertRaises(sqlite3.OperationalError):
            connection.execute("INSERT INTO t VALUES (1)")

    def test_describe_soak_of_a_failed_soak_is_never_eligible(self):
        row = {"id": 1, "state": "COMPLETED", "result": "FAIL", "terminal_reason": "SAMPLE_FAILED", "bundle_id": "BND-PROB-000001",
               "started_by": "op", "started_at": "2026-10-12T12:00:00Z", "required_end_at": "2026-10-19T12:00:00Z", "finished_at": "2026-10-13T12:00:00Z",
               "policy": json.dumps({"sample_interval_seconds": 900}), "baseline": json.dumps({"devices": {"R1": {"digest": "a" * 64}}})}
        described = automation_db.describe_soak(row, None, {"FAIL": 1}, None, now=T0)
        self.assertEqual((described["eligibility"]["code"], described["collector"]["state"], described["drift"][0]["state"], described["soak_id"]),
                         ("NOT_ELIGIBLE", "STALE", "NOT_SAMPLED", "SOAK-000001"))


class CollectorHookTests(ConsoleTestCase):
    def test_build_default_returns_the_five_production_collectors(self):
        collectors = build_default(self.config, self.store, self.bus)
        self.assertEqual([c.name for c in collectors], [m.CONNECTIVITY, m.SERVICES, m.NSOT, m.AUTOMATION, m.COUNTERS])

    def test_build_default_wires_no_reader_until_a_collector_runs(self):
        nsot = build_default(self.config, self.store, self.bus)[2]
        self.assertIsNone(nsot._reader)  # nothing is read at construction time

    def test_connectivity_record_and_teardown_return_transitions_and_release_the_pool(self):
        collector = ConnectivityCollector(self.config, self.store, self.bus, runner=FakeRunner(), inventory_document=INVENTORY)
        collector.setup()
        ok = m.ProbeSample(T0, "H1/IPV4", "H1", m.V4, "H2", "a", "b", True, 1.0)
        collector.record(ok)
        collector.record(m.ProbeSample(T0 + timedelta(seconds=1), "H1/IPV4", "H1", m.V4, "H2", "a", "b", False, None, "TIMEOUT"))
        self.assertEqual([e.kind for e in self.events if e.target == "H1/IPV4"], ["connectivity.sample", "connectivity.sample", "connectivity.failure"])
        collector.teardown()
        self.assertTrue(collector._pool._shutdown)

    def test_connectivity_record_of_a_missing_address_forces_rediscovery(self):
        collector = ConnectivityCollector(self.config, self.store, self.bus, runner=FakeRunner(), inventory_document=INVENTORY)
        collector._last_discovery = 99.0
        collector.record(m.ProbeSample(T0, "H4/IPV4", "H4", m.V4, "H1", "", "", False, None, "NO_SOURCE_ADDRESS"))
        self.assertEqual(collector._last_discovery, 0.0)

    def test_counters_setup_and_teardown_plan_the_managed_devices(self):
        collector = InterfaceCounterCollector(self.config, self.store, self.bus, runner=FakeRunner())
        collector.setup()
        self.assertEqual([d["name"] for d in self.kinds("counters.plan")[0].data["devices"]], ["R1", "R3"])
        collector.teardown()
        self.assertTrue(collector._pool._shutdown)

    def test_nsot_health_target_returns_the_url_and_headers(self):
        env = self.tmp / ".env"
        env.write_text("NETBOX_TOKEN=0123abcd\n")
        collector = NsotCollector(self.config.with_overrides(netbox_env_file=env), self.store, self.bus, getter=FakeGetter())
        self.assertEqual(collector.health_target(), ("http://netbox.test", {"Authorization": "Token 0123abcd"}))
