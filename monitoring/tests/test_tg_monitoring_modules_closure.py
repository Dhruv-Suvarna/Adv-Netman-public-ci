"""Lab 7 closure -- the remaining ``modules/`` monitoring entry points, each called directly:
``cpu_alerts`` (sample validity, state persistence, the InfluxDB write / read-back), ``grafana`` (runtime env, API,
source validation, datasource status, provisioning, Flux execution, live verification), ``netconf`` (connect, per-device
verification, snapshot storage, fleet verification), ``nmas`` (stage, runtime validation, preparation, verification,
full infrastructure, entrypoint), ``telemetry`` and ``linux_telemetry_adapter``.

Hermetic: every HTTP session, ``docker`` call, ``subprocess.run``, NETCONF manager and stage is a fake; every path that
would be written is redirected into a temporary directory.  Nothing contacts a device, InfluxDB, Grafana, Docker or the
network.  POSITIVE: exact returned values / written line protocol / printed rows.  NEGATIVE: failures raise the module's
``NmasError`` with the exact reason, secrets are redacted and never printed, failed stages stop dependent stages.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from modules import cpu_alerts, grafana, linux_telemetry_adapter, netconf, nmas, telemetry

ENV = {"GRAFANA_ADMIN_USER": "admin", "GRAFANA_ADMIN_PASSWORD": "grafana-pw-not-real", "INFLUXDB_ORG": "nmas",
       "INFLUXDB_BUCKET": "telemetry", "INFLUXDB_TOKEN": "influx-token-not-real"}


class FakeResponse:
    def __init__(self, payload=None, *, status=200, text=None):
        self.payload, self.status_code = payload, status
        self.ok = status < 400
        self.text = text if text is not None else json.dumps(payload)

    def json(self):
        return self.payload

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError(f"HTTP {self.status_code}")


class RecordingSession:
    """``session.post`` fake that records every call and answers from a queue."""

    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def temp_dir(test):
    tmp = tempfile.TemporaryDirectory()
    test.addCleanup(tmp.cleanup)
    return Path(tmp.name)


def quiet():
    return contextlib.redirect_stdout(io.StringIO())


# --------------------------------------------------------------------------------------------------------------- cpu


class CpuAlertsClosureTests(unittest.TestCase):
    EVENT = {"device": "R1", "platform": "ceos", "alert_type": "cpu_threshold", "source": "collector", "severity": "critical",
             "transition": "alert", "monitoring_method": "snmp_polling", "verification": True, "cpu_value": 95,
             "threshold_pct": 90, "consecutive_samples": 3, "previous_state": "normal", "timestamp_ns": 1700}

    def test_is_valid_sample_accepts_finite_real_numbers(self):
        self.assertEqual([cpu_alerts.is_valid_sample(v) for v in (0, 12.5, 100)], [True, True, True])

    def test_is_valid_sample_refuses_invalid_samples(self):
        for value in (None, True, "12", float("nan"), float("inf")):
            with self.subTest(f"refused invalid sample {value!r}"):
                self.assertFalse(cpu_alerts.is_valid_sample(value))

    def test_save_state_writes_a_mode_600_state_file(self):
        root = temp_dir(self)
        with mock.patch.object(cpu_alerts, "STATE_DIR", root / "state"):
            cpu_alerts.save_state("R1", {"state": "warning"}, verification=True)
            self.assertEqual(cpu_alerts.load_state("R1", verification=True), {"state": "warning"})
        path = root / "state/R1-verification.json"
        self.assertEqual((json.loads(path.read_text()), path.stat().st_mode & 0o777), ({"state": "warning"}, 0o600))

    def test_save_state_under_a_file_raises_and_writes_nothing(self):
        root = temp_dir(self)
        (root / "blocker").write_text("x")
        with mock.patch.object(cpu_alerts, "STATE_DIR", root / "blocker/state"):
            with self.assertRaises(OSError):
                cpu_alerts.save_state("R1", {"state": "warning"})
        self.assertEqual(sorted(p.name for p in root.iterdir()), ["blocker"])

    def test_write_event_posts_one_collector_alert_line(self):
        session = RecordingSession(FakeResponse({}, status=204, text=""))
        with mock.patch.object(cpu_alerts, "_influx", return_value=(session, ENV)):
            self.assertIsNone(cpu_alerts.write_event(self.EVENT))
        url, kwargs = session.calls[0]
        self.assertEqual(url, "http://127.0.0.1:8086/api/v2/write")
        self.assertEqual(kwargs["params"], {"org": "nmas", "bucket": "telemetry", "precision": "ns"})
        self.assertEqual(kwargs["data"], "collector_alert,device=R1,platform=ceos,alert_type=cpu_threshold,source=collector,severity=critical,"
                                         "transition=alert,monitoring_method=snmp_polling,verification=true value=1i,cpu_value=95.0,"
                                         "threshold_pct=90.0,consecutive_samples=3i,previous_state=\"normal\" 1700")
        self.assertNotIn("snmp_trap", kwargs["data"])

    def test_write_event_refused_by_influxdb_raises(self):
        session = RecordingSession(FakeResponse({}, status=401, text="unauthorized"))
        with mock.patch.object(cpu_alerts, "_influx", return_value=(session, ENV)):
            with self.assertRaisesRegex(RuntimeError, "HTTP 401"):
                cpu_alerts.write_event(self.EVENT)

    def test_confirm_stored_returns_true_when_the_event_reads_back(self):
        session = RecordingSession(FakeResponse(text=",result,table,_measurement,device\n,,0,collector_alert,R1\n"))
        with mock.patch.object(cpu_alerts, "_influx", return_value=(session, ENV)):
            self.assertTrue(cpu_alerts.confirm_stored(self.EVENT, timeout=3))
        url, kwargs = session.calls[0]
        self.assertEqual((url, kwargs["timeout"], kwargs["headers"]), ("http://127.0.0.1:8086/api/v2/query", 3,
                                                                        {"Content-Type": "application/vnd.flux"}))
        self.assertIn("range(start: time(v: 1700), stop: time(v: 1701))", kwargs["data"])

    def test_confirm_stored_is_false_when_the_event_is_absent(self):
        session = RecordingSession(FakeResponse(text="\r\n"))
        with mock.patch.object(cpu_alerts, "_influx", return_value=(session, ENV)), self.subTest("none read back"):
            self.assertFalse(cpu_alerts.confirm_stored(self.EVENT))


# ----------------------------------------------------------------------------------------------------------- grafana


class FakeGrafana:
    """``requests.Session.request`` fake serving a healthy Grafana that has loaded ``dashboards``."""

    def __init__(self, dashboards, *, datasources=None, points=1, health_db="ok"):
        self.dashboards, self.points, self.health_db = dashboards, points, health_db
        self.datasources = datasources if datasources is not None else [
            {"id": 7, "uid": grafana.DATASOURCE_UID, "name": "NMAS InfluxDB", "type": "influxdb", "access": "proxy"}]
        self.calls = []

    def request(self, method, url, timeout=None, **kwargs):
        path = url.removeprefix("http://127.0.0.1:3000")
        self.calls.append((method, path))
        if path == "/api/health":
            return FakeResponse({"database": self.health_db})
        if path == "/api/datasources":
            return FakeResponse(self.datasources)
        if path.endswith("/health"):
            return FakeResponse({"status": "OK"})
        if path.startswith("/api/admin/provisioning/"):
            return FakeResponse({"message": "reloaded"})
        if path == "/api/search?type=dash-db":
            return FakeResponse([{"uid": uid, "title": value["title"]} for uid, value in self.dashboards.items()])
        if path.startswith("/api/dashboards/uid/"):
            return FakeResponse({"dashboard": self.dashboards[path.rsplit("/", 1)[1]], "meta": {"provisioned": True}})
        if path == "/api/ds/query":
            return FakeResponse({"results": {"A": {"status": 200, "frames": [{"data": {"values": [list(range(self.points))]}}]}}})
        return FakeResponse({"message": "not found"}, status=404)


class GrafanaClosureTests(unittest.TestCase):
    def write_env(self, mode=0o600, env=ENV):
        root = temp_dir(self)
        path = root / "monitoring.env"
        path.write_text("".join(f"{k}={v}\n" for k, v in env.items()))
        path.chmod(mode)
        return root

    def test_runtime_env_returns_the_protected_values(self):
        with mock.patch.object(grafana, "RUNTIME", self.write_env()):
            self.assertEqual(grafana.runtime_env(), ENV)

    def test_runtime_env_refuses_unprotected_or_incomplete_files(self):
        for label, root, reason in (("refused world-readable", self.write_env(0o644), "protected"),
                                    ("refused incomplete", self.write_env(env={"GRAFANA_ADMIN_USER": "a"}), "missing mandatory")):
            with self.subTest(label), mock.patch.object(grafana, "RUNTIME", root):
                with self.assertRaisesRegex(grafana.NmasError, reason):
                    grafana.runtime_env()

    def test_api_returns_the_successful_response(self):
        response = grafana.api(FakeGrafana({}), "GET", "/api/health")
        self.assertEqual(response.json(), {"database": "ok"})

    def test_validate_source_returns_the_tracked_dashboards(self):
        with mock.patch.object(grafana.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            dashboards = grafana.validate_source(ENV)
        self.assertEqual(set(dashboards), set(grafana.EXPECTED))
        self.assertEqual(run.call_args.args[0][-1], "--check")

    def test_validate_source_refuses_stale_json_or_an_embedded_runtime_secret(self):
        with self.subTest("refused stale"), mock.patch.object(grafana.subprocess, "run",
                                                             return_value=subprocess.CompletedProcess([], 1, "STALE: resources.json\n", "")):
            with self.assertRaisesRegex(grafana.NmasError, "^STALE: resources.json$"):
                grafana.validate_source(ENV)
        with self.subTest("refused embedded secret"), mock.patch.object(grafana.subprocess, "run",
                                                                       return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaisesRegex(grafana.NmasError, "Runtime secret INFLUXDB_TOKEN is embedded"):
                grafana.validate_source(dict(ENV, INFLUXDB_TOKEN="nmas-influxdb"))

    def test_datasource_status_returns_the_healthy_identity(self):
        self.assertEqual(grafana.datasource_status(FakeGrafana({})), {"id": 7, "uid": "nmas-influxdb", "health": "OK"})

    def test_datasource_status_refuses_duplicate_or_unknown_datasources(self):
        for label, sources, reason in (("refused duplicate", [{"uid": "nmas-influxdb"}, {"name": "NMAS InfluxDB"}], "found 2"),
                                       ("refused wrong type", [{"uid": "nmas-influxdb", "name": "NMAS InfluxDB", "type": "loki"}], "differs")):
            with self.subTest(label):
                with self.assertRaisesRegex(grafana.NmasError, reason):
                    grafana.datasource_status(FakeGrafana({}, datasources=sources))

    def test_frame_points_counts_the_rows_of_every_frame(self):
        self.assertEqual(grafana.frame_points([{"data": {"values": [[1, 2, 3], [4, 5, 6]]}}, {"data": {"values": [[7]]}}]), 4)

    def test_frame_points_of_empty_frames_is_zero(self):
        self.assertEqual(grafana.frame_points([{}, {"data": {"values": []}}]), 0)

    def test_execute_flux_returns_frame_and_point_counts(self):
        fake = FakeGrafana({}, points=5)
        self.assertEqual(grafana.execute_flux(fake, 'from(bucket: "t") |> filter(fn: (r) => r.device =~ /${device:regex}/)'), (1, 5))
        self.assertEqual(fake.calls, [("POST", "/api/ds/query")])

    def test_provision_grafana_reloads_the_datasource_and_dashboards(self):
        fake = FakeGrafana(grafana.source_dashboards())
        real_status = grafana.datasource_status
        attempts = []

        def status(session):
            attempts.append(1)
            if len(attempts) == 1:
                raise grafana.NmasError("not yet provisioned")
            return real_status(session)

        with mock.patch.object(grafana, "runtime_env", return_value=ENV), mock.patch.object(grafana, "validate_source"), \
                mock.patch.object(grafana, "grafana_session", return_value=fake), mock.patch.object(grafana, "datasource_status", status):
            self.assertIsNone(grafana.provision_grafana())
        self.assertIn(("POST", "/api/admin/provisioning/datasources/reload"), fake.calls)
        self.assertEqual(fake.calls[-2:], [("POST", "/api/admin/provisioning/dashboards/reload"), ("GET", "/api/search?type=dash-db")])
        self.assertEqual(len(attempts), 2)

    def test_verify_grafana_returns_the_per_dashboard_contract(self):
        source = grafana.source_dashboards()
        fake = FakeGrafana(source, points=2)
        out = io.StringIO()
        with mock.patch.object(grafana, "runtime_env", return_value=ENV), mock.patch.object(grafana, "validate_source", return_value=source), \
                mock.patch.object(grafana, "grafana_session", return_value=fake), contextlib.redirect_stdout(out):
            result = grafana.verify_grafana(verbose=True)
        self.assertEqual(set(result["dashboards"]), set(grafana.EXPECTED))
        self.assertEqual(result["datasource"], {"id": 7, "uid": "nmas-influxdb", "health": "OK"})
        for uid, row in result["dashboards"].items():
            self.assertEqual((row["panels"], row["variables"]), (len(grafana.EXPECTED[uid]["panels"]), len(grafana.EXPECTED[uid]["variables"])))
            self.assertEqual(row["points"], 2 * row["queries"])
        self.assertIn("secrets=PASS", out.getvalue())
        self.assertNotIn(ENV["GRAFANA_ADMIN_PASSWORD"], out.getvalue())

    def test_verify_grafana_refuses_a_live_dashboard_whose_title_differs(self):
        source = grafana.source_dashboards()
        live = json.loads(json.dumps(source))
        live["nmas-resources"]["title"] = "Edited by hand"
        with mock.patch.object(grafana, "runtime_env", return_value=ENV), mock.patch.object(grafana, "validate_source", return_value=source), \
                mock.patch.object(grafana, "grafana_session", return_value=FakeGrafana(live)), quiet():
            with self.assertRaisesRegex(grafana.NmasError, "nmas-resources: dashboard API identity/duplicate check failed"):
                grafana.verify_grafana()


# ----------------------------------------------------------------------------------------------------------- netconf


class FakeManager:
    def __init__(self, capabilities, hostname, interfaces):
        self.server_capabilities = capabilities
        self.replies = [f"<data><hostname>{hostname}</hostname></data>", "<data>" + "".join(f"<name>{i}</name>" for i in interfaces) + "</data>"]
        self.filters = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, filter):   # noqa: A002 - ncclient's keyword
        self.filters.append(filter)
        return mock.Mock(xml=self.replies.pop(0))


ITEM = {"device": "R1", "platform": "ceos", "address": "192.168.200.11", "container": "clab-R1"}
CAPS = ["urn:ietf:params:netconf:base:1.1", "urn:ietf:params:netconf:capability:candidate:1.0"]


class NetconfClosureTests(unittest.TestCase):
    def test_connect_returns_the_manager_session_with_lab_options(self):
        with mock.patch("ncclient.manager.connect", return_value="session") as connect:
            self.assertEqual(netconf.connect(ITEM, "pw-not-real"), "session")
        self.assertEqual(connect.call_args.kwargs, {"host": "192.168.200.11", "port": 830, "username": "nmas-telemetry",
                                                    "password": "pw-not-real", "hostkey_verify": False,
                                                    "device_params": {"name": "default"}, "timeout": 15, "allow_agent": False,
                                                    "look_for_keys": False})

    def test_connect_refused_by_the_device_raises(self):
        with mock.patch("ncclient.manager.connect", side_effect=ConnectionRefusedError("refused")):
            with self.assertRaises(ConnectionRefusedError):
                netconf.connect(ITEM, "pw-not-real")

    def test_verify_device_returns_the_capability_and_interface_summary(self):
        manager = FakeManager(CAPS, "R1", ["Ethernet1", "Ethernet2", "Management0"])
        with mock.patch.object(netconf, "connect", return_value=manager):
            result = netconf.verify_device(ITEM, "pw-not-real")
        self.assertEqual(result, {"device": "R1", "platform": "ceos", "capabilities_count": 2, "interface_count": 3,
                                  "has_notifications": False, "has_yang_push": False, "capabilities_sample": CAPS})
        self.assertEqual(manager.filters, [netconf.HOSTNAME_FILTER, netconf.INTERFACES_FILTER])

    def test_verify_device_refuses_mismatches(self):
        for label, manager, reason in (("refused without base capability", FakeManager(["x"], "R1", ["e"]), "base capability"),
                                       ("refused hostname mismatch", FakeManager(CAPS, "R9", ["e"]), "hostname GET did not match"),
                                       ("refused zero interfaces", FakeManager(CAPS, "R1", []), "returned no interfaces")):
            with self.subTest(label), mock.patch.object(netconf, "connect", return_value=manager):
                with self.assertRaisesRegex(netconf.NmasError, "^R1: .*" + reason):
                    netconf.verify_device(ITEM, "pw")

    RESULT = {"device": "R1", "platform": "ceos", "capabilities_count": 2, "interface_count": 3, "has_notifications": False, "has_yang_push": True}

    def test_store_snapshot_writes_and_reads_back_one_sample(self):
        session = RecordingSession(FakeResponse(text=""), FakeResponse(text=",netconf_snapshot,R1"))
        with mock.patch.object(netconf, "influx", return_value=(session, ENV)), mock.patch.object(netconf.time, "time_ns", return_value=42):
            self.assertIsNone(netconf.store_snapshot(self.RESULT))
        self.assertEqual(session.calls[0][1]["data"], "netconf_snapshot,device=R1,platform=ceos,source_protocol=netconf capabilities_count=2i,"
                                                      "interface_count=3i,has_notifications=false,has_yang_push=true 42")
        self.assertIn("range(start: time(v: 42), stop: time(v: 43))", session.calls[1][1]["data"])

    def test_store_snapshot_refuses_a_sample_that_never_reads_back(self):
        session = RecordingSession(FakeResponse(text=""), FakeResponse(text=""))
        with mock.patch.object(netconf, "influx", return_value=(session, ENV)):
            with self.assertRaisesRegex(netconf.NmasError, "R1: InfluxDB query did not return the new netconf_snapshot sample"):
                netconf.store_snapshot(self.RESULT)

    def run_fleet(self, verify):
        stored, written = [], {}
        out = io.StringIO()
        with mock.patch.object(netconf, "credentials", return_value={"password": "pw-not-real"}), \
                mock.patch.object(netconf, "verify_device", side_effect=verify), mock.patch.object(netconf, "store_snapshot", stored.append), \
                mock.patch.object(netconf, "protected_json", side_effect=lambda path, value: written.update({path.name: value})), \
                contextlib.redirect_stdout(out):
            try:
                return netconf.verify_netconf([ITEM, dict(ITEM, device="R2")]), stored, written, out.getvalue(), None
            except netconf.NmasError as exc:
                return None, stored, written, out.getvalue(), exc

    def test_verify_netconf_returns_and_stores_every_device_result(self):
        result, stored, written, out, error = self.run_fleet(lambda item, pw: dict(self.RESULT, device=item["device"]))
        self.assertIsNone(error)
        self.assertEqual([r["device"] for r in result], ["R1", "R2"])
        self.assertEqual((stored, written), (result, {"netconf-verification.json": result}))
        self.assertIn("R2         PASS    PASS  PASS PASS n/a (unsupported)", out)
        self.assertNotIn("pw-not-real", out)

    def test_verify_netconf_with_a_failed_device_raises_after_recording_the_rest(self):
        def verify(item, pw):
            if item["device"] == "R2":
                raise OSError("timed out")
            return dict(self.RESULT, device=item["device"])
        result, stored, written, out, error = self.run_fleet(verify)
        self.assertEqual(str(error), "NETCONF verification failed: R2")
        self.assertEqual([r["device"] for r in written["netconf-verification.json"]], ["R1"])
        self.assertIn("R2: FAIL timed out", out)


# -------------------------------------------------------------------------------------------------------------- nmas


class NmasClosureTests(unittest.TestCase):
    def monitoring(self, env_text=None, mode=0o600):
        root = temp_dir(self)
        (root / "runtime").mkdir()
        if env_text is not None:
            path = root / "runtime/monitoring.env"
            path.write_text(env_text)
            path.chmod(mode)
        return root

    FULL_ENV = ("INFLUXDB_ADMIN_USER=admin\nINFLUXDB_ADMIN_PASSWORD=influx-pw-not-real\nINFLUXDB_ORG=nmas\nINFLUXDB_BUCKET=telemetry\n"
                "INFLUXDB_TOKEN=influx-token-not-real\nGRAFANA_ADMIN_USER=admin\nGRAFANA_ADMIN_PASSWORD=grafana-pw-not-real\n")

    def test_stage_returns_output_with_runtime_secrets_redacted(self):
        result = subprocess.CompletedProcess([], 0, "token=influx-token-not-real ok\n", "")
        out = io.StringIO()
        with mock.patch.object(nmas, "MONITORING", self.monitoring(self.FULL_ENV)), mock.patch.object(nmas.subprocess, "run", return_value=result), \
                contextlib.redirect_stdout(out):
            output = nmas.stage("Retention", ["true"], verbose=True)
        self.assertEqual(output, "token=[REDACTED] ok\n")
        self.assertIn("[ NMAS ] Retention", out.getvalue())
        self.assertNotIn("influx-token-not-real", out.getvalue())

    def test_stage_refuses_a_failed_or_unlaunchable_command(self):
        with self.subTest("refused exit 3"), mock.patch.object(nmas, "MONITORING", self.monitoring()), \
                mock.patch.object(nmas.subprocess, "run", return_value=subprocess.CompletedProcess([], 3, "", "boom")), quiet():
            with self.assertRaisesRegex(nmas.NmasError, r"^Retention failed \(exit 3\); dependent stages stopped$"):
                nmas.stage("Retention", ["false"])
        with self.subTest("refused unlaunchable"), mock.patch.object(nmas.subprocess, "run", side_effect=FileNotFoundError("bash")):
            with self.assertRaisesRegex(nmas.NmasError, "^Retention: bash$"):
                nmas.stage("Retention", ["bash"])

    def test_validate_runtime_accepts_a_fresh_install_and_a_complete_env(self):
        for label, root in (("fresh install", self.monitoring()), ("complete env", self.monitoring(self.FULL_ENV))):
            with self.subTest(label), mock.patch.object(nmas, "MONITORING", root):
                self.assertIsNone(nmas.validate_runtime())

    def stages(self):
        calls = []
        return calls, mock.patch.object(nmas, "stage", side_effect=lambda label, command, verbose=False: calls.append((label, command[-1], verbose)) or "ok")

    def test_prepare_runtime_runs_both_dependency_stages(self):
        calls, patch = self.stages()
        with patch, mock.patch.object(nmas, "validate_runtime"):
            self.assertIsNone(nmas.prepare_runtime(verbose=True))
        self.assertEqual([(c[0], Path(c[1]).name, c[2]) for c in calls],
                         [("Host dependencies", "bootstrap_nmas.sh", True), ("Python dependencies", "install_python_dependencies.sh", True)])

    def test_prepare_runtime_with_unsafe_credentials_never_runs_a_stage(self):
        calls, patch = self.stages()
        with patch, mock.patch.object(nmas, "validate_runtime", side_effect=nmas.NmasError("monitoring.env must be a regular protected file")):
            with self.assertRaisesRegex(nmas.NmasError, "protected file"):
                nmas.prepare_runtime()
        self.assertEqual(calls, [])

    def test_verify_nmas_returns_the_verification_stage_output(self):
        calls, patch = self.stages()
        with patch:
            self.assertEqual(nmas.verify_nmas(verbose=True), "ok")
        self.assertEqual([(c[0], Path(c[1]).name) for c in calls], [("Verification", "verify_nmas_infrastructure.sh")])

    def test_verify_nmas_failed_stage_raises(self):
        with mock.patch.object(nmas, "stage", side_effect=nmas.NmasError("Verification failed (exit 1); dependent stages stopped")):
            with self.assertRaisesRegex(nmas.NmasError, "^Verification failed"):
                nmas.verify_nmas()

    def test_ensure_nmas_infrastructure_runs_every_stage_in_order(self):
        calls, patch = self.stages()
        with patch, mock.patch.object(nmas, "validate_runtime"), mock.patch.object(nmas, "validate_inventory") as inventory, \
                mock.patch.object(nmas, "prepare_runtime") as prepare:
            self.assertEqual(nmas.ensure_nmas_infrastructure(verbose=False, prepared=True), "ok")
        prepare.assert_not_called()
        inventory.assert_called_once_with(require_address=True)
        self.assertEqual([c[0] for c in calls], ["Receivers and logrotate", "InfluxDB and Grafana", "Retention", "Verification"])
        self.assertEqual(calls[2][1], "--apply")

    def test_entrypoint_returns_to_master_for_a_full_lab_run(self):
        with mock.patch.dict(os.environ, {"_NMAS_BOOTSTRAPPED": str(nmas.BASE)}), mock.patch.object(sys, "argv", ["master.py"]), \
                mock.patch.object(sys, "prefix", str(nmas.VENV)), mock.patch.object(nmas, "prepare_runtime") as prepare, \
                mock.patch.object(nmas, "validate_inventory") as inventory, mock.patch.object(nmas.os, "execve") as execve:
            self.assertIsNone(nmas.entrypoint())
            self.assertNotIn("_NMAS_BOOTSTRAPPED", os.environ)
        prepare.assert_not_called()
        execve.assert_not_called()
        inventory.assert_called_once_with()


# ------------------------------------------------------------------------------------------- telemetry / Linux adapter


class TelemetryClosureTests(unittest.TestCase):
    def test_ensure_telemetry_infrastructure_returns_the_nmas_verification(self):
        calls = []
        with mock.patch.object(telemetry, "ensure_gnmi_infrastructure", side_effect=lambda v: calls.append(("gnmi", v)) or ["R1"]), \
                mock.patch.object(telemetry, "verify_netconf", side_effect=lambda items: calls.append(("netconf", items))), \
                mock.patch.object(telemetry, "verify_nmas", side_effect=lambda v: calls.append(("nmas", v)) or "verified"):
            self.assertEqual(telemetry.ensure_telemetry_infrastructure(verbose=True), "verified")
        self.assertEqual(calls, [("gnmi", True), ("netconf", ["R1"]), ("nmas", True)])

    def test_ensure_telemetry_infrastructure_with_failed_netconf_never_verifies_nmas(self):
        verify = mock.Mock()
        with mock.patch.object(telemetry, "ensure_gnmi_infrastructure", return_value=["R1"]), \
                mock.patch.object(telemetry, "verify_netconf", side_effect=nmas.NmasError("NETCONF verification failed: R1")), \
                mock.patch.object(telemetry, "verify_nmas", verify):
            with self.assertRaisesRegex(RuntimeError, "NETCONF verification failed: R1"):
                telemetry.ensure_telemetry_infrastructure()
        verify.assert_not_called()


class LinuxTelemetryAdapterClosureTests(unittest.TestCase):
    LINUX = {"device": "R3", "address": "192.168.200.13", "container": "clab-R3"}

    def test_protobuf_sources_returns_the_three_stubs_with_local_imports(self):
        sources = linux_telemetry_adapter.protobuf_sources()
        self.assertEqual(sorted(sources), ["gnmi_ext_pb2.py", "gnmi_pb2.py", "gnmi_pb2_grpc.py"])
        self.assertIn("import gnmi_pb2 as gnmi__pb2", sources["gnmi_pb2_grpc.py"])
        self.assertNotIn("import pygnmi.spec", "".join(sources.values()))

    def test_configure_sends_the_adapter_payload_through_docker_exec(self):
        out = io.StringIO()
        with mock.patch.object(linux_telemetry_adapter, "docker", return_value="unchanged\n") as docker, contextlib.redirect_stdout(out):
            self.assertIsNone(linux_telemetry_adapter.configure(self.LINUX, "nmas-telemetry", "pw-not-real"))
        args, kwargs = docker.call_args
        self.assertEqual(args[:5], ("exec", "-i", "clab-R3", "python3", "-c"))
        payload = json.loads(kwargs["data"])
        self.assertEqual((payload["device"], payload["username"], kwargs["timeout"]), ("R3", "nmas-telemetry", 900))
        self.assertEqual(sorted(payload["files"]), sorted([*linux_telemetry_adapter.ADAPTER_FILES, *linux_telemetry_adapter.PROTO_FILES]))
        self.assertEqual(out.getvalue(), "R3: unchanged\n")
        self.assertNotIn("pw-not-real", out.getvalue())

    def test_configure_refused_by_docker_raises(self):
        with mock.patch.object(linux_telemetry_adapter, "docker", side_effect=subprocess.CalledProcessError(1, ["docker"])):
            with self.assertRaises(subprocess.CalledProcessError):
                linux_telemetry_adapter.configure(self.LINUX, "u", "p")

    def test_fetch_certificate_returns_the_written_world_readable_certificate(self):
        dest = temp_dir(self) / "tls/R3.crt"
        pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        with mock.patch.object(linux_telemetry_adapter, "docker", return_value=pem):
            self.assertEqual(linux_telemetry_adapter.fetch_certificate(self.LINUX, dest), dest)
        self.assertEqual((dest.read_text(), dest.stat().st_mode & 0o777), (pem, 0o644))

    def test_fetch_certificate_refuses_a_missing_certificate(self):
        dest = temp_dir(self) / "R3.crt"
        with mock.patch.object(linux_telemetry_adapter, "docker", return_value="cat: No such file"):
            with self.assertRaisesRegex(linux_telemetry_adapter.NmasError, "^R3: telemetry adapter certificate missing$"):
                linux_telemetry_adapter.fetch_certificate(self.LINUX, dest)
        self.assertFalse(dest.exists())


if __name__ == "__main__":
    unittest.main()
