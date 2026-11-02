"""Lab 7 -- the Labs 1-3 network-automation modules (master.py, modules/*): positive and negative cases.

These are the code paths the Lab 7 examples name (IP validation, file existence, YAML-driven templating, CPU status,
topology health).  Pure functions are tested exactly; process / container calls go through fakes (``subprocess.run`` is
replaced), so nothing is executed on the host, no container is inspected and no device is contacted.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services.test_governance.cases import NEGATIVE, POSITIVE, case
from core.services.test_governance.constants import REPO_ROOT

if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

import master  # noqa: E402
from modules import cpu_alerts, device_credentials as dc, eos_render, grafana, topology_graph as tg  # noqa: E402

POLICY = {"warning_pct": 70, "critical_pct": 90, "consecutive_samples": 3, "recovery_pct": 60}
NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
REF = "runtime://device-credentials/r1-nmas-automation"


def proc(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class CpuStatusTests(SimpleTestCase):
    @case("CPU_STATUS_CLASSIFIED_AGAINST_POLICY", target="modules/cpu_alerts.py::classify", polarity=POSITIVE,
          condition="CPU samples below, at and above the warning / critical thresholds", expected="normal / warning / critical with the crossed threshold")
    def test_cpu_classification_boundaries(self):
        for value, expected in ((10.0, ("normal", None)), (69.9, ("normal", None)), (70.0, ("warning", 70)), (89.9, ("warning", 70)),
                                (90.0, ("critical", 90)), (100.0, ("critical", 90))):
            with self.subTest(cpu=value):
                self.assertEqual(cpu_alerts.classify(value, POLICY), expected)

    @case("CPU_STATUS_NON_NUMERIC_SAMPLE_REFUSED", target="modules/cpu_alerts.py::classify", polarity=NEGATIVE,
          condition="NaN, +inf, -inf, None, a bool, a numeric string, a non-numeric string / an incomplete policy",
          expected="('invalid', None) -- fail closed, never 'normal' / KeyError")
    def test_non_finite_or_non_numeric_sample_is_invalid_never_normal(self):
        for value in (float("nan"), float("inf"), float("-inf"), None, True, "55", "high", [50]):
            with self.subTest(sample=repr(value)):
                self.assertEqual(cpu_alerts.classify(value, POLICY), ("invalid", None))
        with self.assertRaises(KeyError):
            cpu_alerts.classify(95.0, {"warning_pct": 70})

    def test_valid_sample_accepts_finite_ints_and_floats_only(self):
        self.assertEqual([cpu_alerts.is_valid_sample(v) for v in (0, 55, 99.5, 100.0)], [True] * 4)

    def test_valid_sample_refuses_non_finite_and_non_numeric_values(self):
        self.assertEqual([cpu_alerts.is_valid_sample(v) for v in (float("nan"), float("inf"), None, False, "1")], [False] * 5)

    def test_state_round_trip_and_default(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(cpu_alerts, "STATE_DIR", Path(tmp)):
            self.assertEqual(cpu_alerts.load_state("R1"), {"state": "normal", "streak_level": "normal", "streak": 0})
            cpu_alerts.save_state("R1", {"state": "warning", "streak_level": "warning", "streak": 2})
            self.assertEqual(cpu_alerts.load_state("R1")["streak"], 2)
            self.assertEqual(oct((Path(tmp) / "R1.json").stat().st_mode & 0o777), "0o600")
            self.assertEqual(cpu_alerts.load_state("R1", verification=True)["state"], "normal")   # verification state is separate

    def test_corrupt_state_file_is_not_silently_reset(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(cpu_alerts, "STATE_DIR", Path(tmp)):
            (Path(tmp) / "R2.json").write_text("{not json")
            with self.assertRaises(json.JSONDecodeError):
                cpu_alerts.load_state("R2")


class TopologyHealthTests(SimpleTestCase):
    @case("TOPOLOGY_NODE_FRESHNESS_CLASSIFIED", target="modules/topology_graph.py::classify_node", polarity=POSITIVE,
          condition="telemetry 5 s / 60 s / 600 s old against 30 s healthy / 120 s stale", expected="HEALTHY / STALE / OFFLINE")
    def test_node_freshness(self):
        for age, state in ((5, "HEALTHY"), (60, "STALE"), (600, "OFFLINE")):
            with self.subTest(age=age):
                got, _reason = tg.classify_node(monitored=True, last_update=NOW - timedelta(seconds=age), now=NOW, healthy_seconds=30,
                                                stale_seconds=120)
                self.assertEqual(got, state)

    @case("TOPOLOGY_NODE_WITHOUT_EVIDENCE_IS_UNKNOWN", target="modules/topology_graph.py::classify_node", polarity=NEGATIVE,
          condition="an unmonitored endpoint / no retained telemetry", expected="UNKNOWN (never HEALTHY without evidence)")
    def test_no_evidence_is_unknown(self):
        self.assertEqual(tg.classify_node(monitored=False, last_update=NOW, now=NOW, healthy_seconds=30, stale_seconds=120)[0], "UNKNOWN")
        self.assertEqual(tg.classify_node(monitored=True, last_update=None, now=NOW, healthy_seconds=30, stale_seconds=120)[0], "UNKNOWN")

    def test_time_helpers(self):
        self.assertEqual(tg.isoformat(NOW), "2026-10-18T12:00:00Z")
        self.assertIsNone(tg.isoformat(None))
        self.assertEqual(tg.parse_time("2026-10-18T12:00:00Z"), NOW)
        for bad in ("", None, "yesterday"):
            with self.subTest(case=f"invalid {bad!r}"):
                self.assertIsNone(tg.parse_time(bad))
        self.assertEqual(tg.age_seconds(NOW + timedelta(seconds=5), NOW), 0.0)       # clock skew never yields a negative age
        self.assertIsNone(tg.age_seconds(None, NOW))

    def test_edge_identity_is_order_independent(self):
        a, z = {"node": "R1", "interface": "eth1"}, {"node": "S1", "interface": "eth2"}
        self.assertEqual(tg.canonical_edge_id(a, z), tg.canonical_edge_id(z, a))
        self.assertEqual(tg.canonical_edge_id(a, z), "R1:eth1--S1:eth2")
        with self.assertRaises(KeyError):
            tg.canonical_edge_id({"node": "R1"}, z)

    @case("TOPOLOGY_GRAPH_PAYLOAD_INVALID_REFUSED", target="modules/topology_graph.py::validate_graph_payload", polarity=NEGATIVE,
          condition="duplicate node ids / missing edge id / unknown health state / non-finite coordinates", expected="ValueError for each")
    def test_invalid_graph_payloads_are_refused(self):
        node = {"id": "R1", "health": next(iter(tg.NODE_STATES)), "x": 1, "y": 2}
        edge = {"id": "e1", "status": next(iter(tg.EDGE_STATES))}
        tg.validate_graph_payload({"graph": {"nodes": [node], "edges": [edge]}})
        for label, graph in (("duplicate node", {"nodes": [node, node], "edges": []}), ("edge without id", {"nodes": [node], "edges": [{"status": edge["status"]}]}),
                             ("bad health", {"nodes": [{**node, "health": "GREEN"}], "edges": []}),
                             ("bad edge state", {"nodes": [node], "edges": [{**edge, "status": "?"}]}),
                             ("infinite x", {"nodes": [{**node, "x": float("inf")}], "edges": []})):
            with self.subTest(case=f"invalid {label}"):
                with self.assertRaises(ValueError):
                    tg.validate_graph_payload({"graph": graph})


class CredentialReferenceTests(SimpleTestCase):
    @case("CREDENTIAL_REFERENCE_ROUND_TRIP", target="modules/device_credentials.py::reference_key", polarity=POSITIVE,
          condition="a well-formed runtime credential reference", expected="the key; make_reference(key) gives the same reference back")
    def test_reference_round_trip(self):
        self.assertEqual(dc.reference_key(REF), "r1-nmas-automation")
        self.assertEqual(dc.make_reference("r1-nmas-automation"), REF)

    @case("CREDENTIAL_REFERENCE_MALFORMED_REFUSED", target="modules/device_credentials.py::make_reference", polarity=NEGATIVE,
          condition="a literal password, another scheme, path traversal, upper case or a too-short key", expected="SecretProviderError (fail closed)")
    def test_malformed_references_are_refused(self):
        for bad in ("hunter2", "file:///etc/shadow", "runtime://device-credentials/../x", "runtime://device-credentials/AB", None, 5):
            with self.subTest(case=f"invalid {bad!r}"):
                with self.assertRaises(dc.SecretProviderError):
                    dc.reference_key(bad)
        for bad in ("../x", "A", "ok key", ""):
            with self.subTest(case=f"invalid key {bad!r}"):
                with self.assertRaises(dc.SecretProviderError):
                    dc.make_reference(bad)

    def _inventory(self):
        return {"ceos_username": "admin", "ceos_credential_ref": "runtime://device-credentials/fleet-admin",
                "network_devices": {"R1": {"username": "nmas-automation", "credential_ref": REF, "monitoring": {"platform": "ceos"}},
                                    "R3": {"username": "nmas-automation", "ssh_key_ref": "runtime://device-credentials/r3-key",
                                           "monitoring": {"platform": "linux"}}}}

    @case("ACCESS_PROFILES_RESOLVED_WITH_FLEET_FALLBACK", target="modules/device_credentials.py::ceos_access_profiles", polarity=POSITIVE,
          condition="a device with its own identity plus obsolete fleet metadata", expected="only the dedicated device profile")
    def test_access_profiles(self):
        (primary,) = dc.ceos_access_profiles(self._inventory(), "R1")
        self.assertEqual((primary.username, primary.credential_ref), ("nmas-automation", REF))
        self.assertEqual(dc.linux_access_profile(self._inventory(), "R3").ssh_key_ref, "runtime://device-credentials/r3-key")

    @case("ACCESS_PROFILE_MISCONFIGURED_FAILS_CLOSED", target="modules/device_credentials.py::linux_access_profile", polarity=NEGATIVE,
          condition="a Linux profile for a cEOS device / no username / a malformed device reference", expected="SecretProviderError; no session")
    def test_misconfigured_profiles_fail_closed(self):
        inv = self._inventory()
        with self.assertRaises(dc.SecretProviderError):
            dc.linux_access_profile(inv, "R1")
        inv["network_devices"]["R3"]["username"] = ""
        with self.assertRaises(dc.SecretProviderError):
            dc.linux_access_profile(inv, "R3")
        broken = self._inventory()
        broken["network_devices"]["R1"]["credential_ref"] = "plaintext-password"
        with self.assertRaises(dc.SecretProviderError):
            dc.ceos_access_profiles(broken, "R1")
        with self.assertRaises(dc.SecretProviderError):
            dc.ceos_access_profile({"network_devices": {}}, "R1")


class EosCommandTests(SimpleTestCase):
    @case("EOS_CONFIG_FLATTENED_TO_COMMANDS", target="modules/eos_render.py::eos_commands", polarity=POSITIVE,
          condition="indented EOS configuration with nested modes", expected="the exact flat command list with an exit per closed mode")
    def test_nested_modes_are_flattened(self):
        text = "hostname R1\n!\ninterface Ethernet1\n   description up\nrouter bgp 65001\n   neighbor 1.1.1.1 remote-as 65002\n   address-family ipv4\n      network 10.0.0.0/8\n"
        self.assertEqual(eos_render.eos_commands(text), ["hostname R1", "interface Ethernet1", "description up", "exit", "router bgp 65001",
                                                          "neighbor 1.1.1.1 remote-as 65002", "address-family ipv4", "network 10.0.0.0/8", "exit", "exit"])

    @case("EOS_CONFIG_NOISE_PRODUCES_NO_COMMAND", target="modules/eos_render.py::eos_commands", polarity=NEGATIVE,
          condition="only separators / configure / end lines; the per-interface 'dhcp server ipv4' leaf", expected="no command; the leaf opens no phantom mode")
    def test_noise_and_leaf_commands(self):
        self.assertEqual(eos_render.eos_commands("!\nconfigure\n\nend\n"), [])
        self.assertEqual(eos_render.eos_commands("interface Vlan10\n   dhcp server ipv4\n   ip address 10.0.0.1/24\n"),
                         ["interface Vlan10", "dhcp server ipv4", "ip address 10.0.0.1/24", "exit"])


class GrafanaQueryTests(SimpleTestCase):
    @case("GRAFANA_QUERY_VARIABLES_SUBSTITUTED", target="modules/grafana.py::substitute_variables", polarity=POSITIVE,
          condition="a dashboard Flux query using the regex variables", expected="variables replaced by '.*'; nothing unresolved")
    def test_variables_are_substituted(self):
        self.assertEqual(grafana.substitute_variables('r.device =~ /${device:regex}/ and r.interface =~ /${interface:regex}/'),
                         "r.device =~ /.*/ and r.interface =~ /.*/")

    @case("GRAFANA_UNRESOLVED_VARIABLE_REFUSED", target="modules/grafana.py::substitute_variables", polarity=NEGATIVE,
          condition="a query with an unknown ${variable}", expected="NmasError (the query is never sent half-substituted)")
    def test_unknown_variable_is_refused(self):
        with self.assertRaises(grafana.NmasError):
            grafana.substitute_variables("r.x == ${not_a_variable}")

    def test_frame_points_and_panel_classification(self):
        self.assertEqual(grafana.frame_points([{"data": {"values": [[1, 2, 3], [4, 5, 6]]}}, {"data": {"values": [[7]]}}]), 4)
        self.assertEqual(grafana.frame_points([{}, {"data": {}}]), 0)
        self.assertTrue(grafana.panel_requires_data({"title": "CPU"}))
        self.assertFalse(grafana.panel_requires_data({"eventOptional": True}))


class MasterOrchestratorTests(SimpleTestCase):
    """master.py helpers with subprocess faked: nothing runs on the host."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = mock.patch.object(master, "RUN_LOG", Path(self.tmp.name) / "Run_Logs.log")
        self.log.start()

    def tearDown(self):
        self.log.stop()
        self.tmp.cleanup()

    @case("MASTER_COMMAND_RUN_AND_LOGGED", target="master.py::run", polarity=POSITIVE,
          condition="a command string that succeeds", expected="split without a shell, run once, the result returned and logged")
    def test_run_success_is_logged(self):
        with mock.patch.object(master.subprocess, "run", return_value=proc(0, "ok")) as fake:
            self.assertEqual(master.run("docker ps -a").stdout, "ok")
        self.assertEqual(fake.call_args.args[0], ["docker", "ps", "-a"])
        self.assertNotIn("shell", fake.call_args.kwargs)
        self.assertIn("$ docker ps -a", master.RUN_LOG.read_text())

    @case("MASTER_COMMAND_FAILURE_RAISES", target="master.py::run", polarity=NEGATIVE,
          condition="a command that exits non-zero with check=True", expected="RuntimeError carrying its output; check=False returns it")
    def test_run_failure_raises(self):
        with mock.patch.object(master.subprocess, "run", return_value=proc(2, "", "boom")):
            with self.assertRaises(RuntimeError):
                master.run(["false"])
            self.assertEqual(master.run(["false"], check=False).returncode, 2)

    @case("MASTER_DOCKER_SUDO_FALLBACK_ONLY_ON_PERMISSION", target="master.py::docker", polarity=NEGATIVE,
          condition="docker fails with an unrelated error / with permission denied", expected="no sudo retry for the unrelated error; sudo retry for permission denied")
    def test_docker_sudo_fallback(self):
        with mock.patch.object(master.subprocess, "run", side_effect=[proc(1, "", "No such container")]) as fake:
            with self.assertRaises(RuntimeError):
                master.docker(["inspect", "x"])
        self.assertEqual(fake.call_count, 1)
        with mock.patch.object(master.subprocess, "run", side_effect=[proc(1, "", "permission denied"), proc(0, "[]")]) as fake:
            self.assertEqual(master.docker(["inspect", "x"]).stdout, "[]")
        self.assertEqual(fake.call_args.args[0][:2], ["sudo", "docker"])

    @case("MASTER_MANAGEMENT_IP_DISCOVERED", target="master.py::discover_ip", polarity=POSITIVE,
          condition="a container with a lab-management and another network address", expected="the 172.20.20.0/24 management address is preferred")
    def test_discover_ip_prefers_the_management_network(self):
        inspect = json.dumps([{"NetworkSettings": {"Networks": {"other": {"IPAddress": "10.1.1.5"}, "clab": {"IPAddress": "172.20.20.3"}}}}])
        with mock.patch.object(master.subprocess, "run", return_value=proc(0, inspect)):
            self.assertEqual(master.discover_ip("srlceos01", "R3"), "172.20.20.3")

    @case("MASTER_NO_MANAGEMENT_IP_REFUSED", target="master.py::discover_ip", polarity=NEGATIVE,
          condition="a container with no IP address", expected="RuntimeError naming the node; nothing is pushed")
    def test_discover_ip_without_address_fails(self):
        inspect = json.dumps([{"NetworkSettings": {"Networks": {"clab": {"IPAddress": ""}}}}])
        with mock.patch.object(master.subprocess, "run", return_value=proc(0, inspect)):
            with self.assertRaisesRegex(RuntimeError, "No management IP for R3"):
                master.discover_ip("srlceos01", "R3")

    def test_log_appends_a_timestamped_section(self):
        master.log("SECTION", "body")
        master.log("SECTION2")
        text = master.RUN_LOG.read_text()
        self.assertEqual(text.count("] SECTION"), 2)
        self.assertIn("body", text)

    @case("MASTER_EOS_AUTH_FAILS_CLOSED", target="master.py::eos_conn", polarity=NEGATIVE,
          condition="every protected credential candidate is refused by the device", expected="RuntimeError without the password; no fallback to plaintext")
    def test_eos_connection_fails_closed(self):
        inv = {"ceos_username": "admin", "ceos_credential_ref": "runtime://device-credentials/fleet-admin",
               "network_devices": {"R1": {"username": "nmas-automation", "credential_ref": REF}}}
        material = dc.SecretMaterial("v1", "not-a-real-secret")
        with mock.patch.object(master, "FileSecretProvider") as provider, mock.patch.object(master, "ConnectHandler", side_effect=OSError("auth")):
            provider.return_value.candidates.return_value = (material,)
            with self.assertRaises(RuntimeError) as ctx:
                master.eos_conn("R1", "172.20.20.2", inv)
        self.assertNotIn("not-a-real-secret", str(ctx.exception))
