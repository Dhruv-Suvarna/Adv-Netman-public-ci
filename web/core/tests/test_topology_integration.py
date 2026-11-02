import ast
import inspect
import json
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from django.conf import settings
from django.contrib.staticfiles import finders
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from core import views
from core.services import topology_service


def topology_fixture():
    return {
        "schema_version": 1,
        "generated_at": "2026-09-20T10:00:00Z",
        "refresh_interval_seconds": 20,
        "health_thresholds_seconds": {"healthy_max": 60, "stale_max": 120},
        "event_window_seconds": 900,
        "demo": {"active": False, "mode": "REAL", "label": "REAL MONITORING STATE", "target_edge": None},
        "backend": {"status": "OK", "source": "existing monitoring", "error": None},
        "grafana_url": "http://127.0.0.1:3000/d/nmas-fleet-overview",
        "graph": {
            "directed": False,
            "multigraph": False,
            "graph": {"lab_name": "srlceos01", "excluded_host_links": 1},
            "nodes": [
                {
                    "id": "R1", "canonical_name": "R1", "health": "HEALTHY",
                    "health_reason": "Latest telemetry is current", "role": "router",
                    "platform": "ceos", "image": "ceos:4.36.2F", "runtime_state": "running",
                    "management_ipv4": "172.20.20.12", "management_ipv6": "3fff:172:20:20::c",
                    "monitoring_address": "192.168.200.1", "monitoring_address_v6": "2001:db8:200::1",
                    "monitoring_interface": "Vlan200", "monitoring_implementation": "native cEOS gNMI",
                    "last_telemetry_timestamp": "2026-09-20T09:59:55Z", "telemetry_age_seconds": 5,
                    "recent_critical_syslog_count": 0, "recent_snmp_trap_count": 0,
                    "latest_event_timestamp": None, "cpu_percent": 4.2, "memory_percent": 30.1,
                    "x": -75.0, "y": 100.0,
                },
                {
                    "id": "S1", "canonical_name": "S1", "health": "HEALTHY",
                    "health_reason": "Latest telemetry is current", "role": "switch",
                    "platform": "ceos", "image": "ceos:4.36.2F", "runtime_state": "running",
                    "management_ipv4": "172.20.20.13", "management_ipv6": "3fff:172:20:20::d",
                    "monitoring_address": "192.168.200.5", "monitoring_address_v6": "2001:db8:200::5",
                    "monitoring_interface": "Vlan200", "monitoring_implementation": "native cEOS gNMI",
                    "last_telemetry_timestamp": "2026-09-20T09:59:55Z", "telemetry_age_seconds": 5,
                    "recent_critical_syslog_count": 0, "recent_snmp_trap_count": 0,
                    "latest_event_timestamp": None, "cpu_percent": 2.1, "memory_percent": 22.0,
                    "x": 75.0, "y": 230.0,
                },
            ],
            "edges": [
                {
                    "id": "R1:eth3--S1:eth1", "source": "R1", "target": "S1", "plane": "data",
                    "status": "UP", "health": "UP", "health_reason": "Both endpoints report UP",
                    "status_source": "gnmi_telemetry", "last_state_update": "2026-09-20T09:59:55Z",
                    "recent_link_event_count": 0, "latest_link_event": None,
                    "endpoint_state": [
                        {"node": "R1", "interface": "eth3", "monitor_interface": "Ethernet3", "admin_status": "UP", "oper_status": "UP", "age_seconds": 5, "evidence_fresh": True, "errors": 0, "discards": 0},
                        {"node": "S1", "interface": "eth1", "monitor_interface": "Ethernet1", "admin_status": "UP", "oper_status": "UP", "age_seconds": 5, "evidence_fresh": True, "errors": 0, "discards": 0},
                    ],
                }
            ],
        },
    }


def available_summary():
    payload = topology_fixture()
    return {
        "status": "available", "message": "Live read-only topology loaded.",
        "data": payload, "node_count": 2, "edge_count": 1,
        "generated_at": payload["generated_at"], "backend_status": "OK",
    }


def mocked_response(payload):
    response = MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.read.return_value = json.dumps(payload).encode()
    return response


@override_settings(
    TOPOLOGY_SERVICE_URL="http://127.0.0.1:8050/api/topology",
    TOPOLOGY_SERVICE_TIMEOUT_SECONDS=0.5,
)
class TopologyServiceTests(SimpleTestCase):
    @patch("core.services.topology_service.urlopen")
    def test_valid_upstream_response_is_consumed(self, mocked_open):
        mocked_open.return_value = mocked_response(topology_fixture())
        result = topology_service.get_topology_summary()
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["node_count"], 2)
        self.assertEqual(result["edge_count"], 1)
        request = mocked_open.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, settings.TOPOLOGY_SERVICE_URL)

    @patch("core.services.topology_service.urlopen")
    def test_malformed_json_is_handled(self, mocked_open):
        response = MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        response.read.return_value = b"{not-json"
        mocked_open.return_value = response
        self.assertEqual(topology_service.get_topology_summary()["status"], "unavailable")

    @patch("core.services.topology_service.urlopen", side_effect=socket.timeout("slow"))
    def test_timeout_is_handled(self, mocked_open):
        result = topology_service.get_topology_summary()
        self.assertEqual(result["message"], topology_service.UNAVAILABLE_MESSAGE)

    @patch("core.services.topology_service.urlopen", side_effect=URLError("refused"))
    def test_connection_failure_is_handled(self, mocked_open):
        self.assertEqual(topology_service.get_topology_summary()["status"], "unavailable")

    @patch("core.services.topology_service.urlopen")
    def test_unexpected_schema_is_handled(self, mocked_open):
        mocked_open.return_value = mocked_response({"schema_version": 2, "graph": {}})
        self.assertEqual(topology_service.get_topology_summary()["status"], "unavailable")

    @patch("core.services.topology_service.urlopen")
    def test_unhashable_identity_in_malformed_schema_is_handled(self, mocked_open):
        payload = topology_fixture()
        payload["graph"]["nodes"][0]["id"] = ["not", "a", "string"]
        mocked_open.return_value = mocked_response(payload)
        self.assertEqual(topology_service.get_topology_summary()["status"], "unavailable")

    @patch("core.services.topology_service.urlopen")
    def test_secret_shaped_fields_are_rejected(self, mocked_open):
        payload = topology_fixture()
        payload["api_token"] = "must-not-appear"
        mocked_open.return_value = mocked_response(payload)
        result = topology_service.get_topology_summary()
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn("must-not-appear", json.dumps(result))

    @patch("core.services.topology_service.urlopen")
    def test_raw_upstream_error_is_not_relayed(self, mocked_open):
        payload = topology_fixture()
        payload["backend"] = {"status": "ERROR", "source": "InfluxDB", "error": "internal host detail"}
        mocked_open.return_value = mocked_response(payload)
        result = topology_service.get_topology_summary()
        self.assertNotIn("internal host detail", json.dumps(result))
        self.assertEqual(result["data"]["backend"]["error"], "Monitoring evidence temporarily unavailable.")

    @override_settings(TOPOLOGY_SERVICE_URL="http://127.0.0.1:8050/not-topology")
    @patch("core.services.topology_service.urlopen")
    def test_configured_url_must_target_fixed_api_path(self, mocked_open):
        self.assertEqual(topology_service.get_topology_summary()["status"], "unavailable")
        mocked_open.assert_not_called()


class TopologyHomeAndEndpointTests(TestCase):
    @patch("core.views.topology_service.get_topology_summary", side_effect=lambda: available_summary())
    def test_home_renders_supplied_node_and_edge_data(self, mocked_summary):
        response = self.client.get(reverse("core:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "R1")
        self.assertContains(response, "R1:eth3--S1:eth1")
        self.assertContains(response, "192.168.200.1")
        self.assertContains(response, "2 nodes / 1 links")

    @patch("core.views.topology_service.get_topology_summary")
    def test_home_unavailable_state_does_not_crash(self, mocked_summary):
        mocked_summary.return_value = {"status": "unavailable", "message": topology_service.UNAVAILABLE_MESSAGE, "data": None, "node_count": 0, "edge_count": 0}
        response = self.client.get(reverse("core:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, topology_service.UNAVAILABLE_MESSAGE)
        self.assertContains(response, "Platform capabilities")

    @patch("core.views.topology_service.get_topology_summary", side_effect=lambda: available_summary())
    def test_topology_endpoint_is_get_only(self, mocked_summary):
        url = reverse("core:topology_data")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["graph"]["nodes"][0]["id"], "R1")
        for method in (self.client.post, self.client.put, self.client.patch, self.client.delete):
            with self.subTest(method=method.__name__):
                self.assertEqual(method(url).status_code, 405)

    @patch("core.views.topology_service.get_topology_summary")
    def test_proxy_failure_is_generic_and_does_not_leak_internal_error(self, mocked_summary):
        mocked_summary.return_value = {"status": "unavailable", "message": topology_service.UNAVAILABLE_MESSAGE, "data": None, "node_count": 0, "edge_count": 0}
        response = self.client.get(reverse("core:topology_data"))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"status": "unavailable", "message": topology_service.UNAVAILABLE_MESSAGE})

    @patch("core.views.topology_service.get_topology_summary", side_effect=lambda: available_summary())
    def test_no_topology_mutation_control_or_upstream_url_in_markup(self, mocked_summary):
        html = self.client.get(reverse("core:home")).content.decode()
        for forbidden in ("Create Node", "Delete Node", "Create Link", "Delete Link", settings.TOPOLOGY_SERVICE_URL):
            self.assertNotIn(forbidden, html)
        self.assertIn(reverse("core:topology_data"), html)

    @patch("core.views.topology_service.get_topology_summary", side_effect=lambda: available_summary())
    def test_all_four_themes_render_home_in_the_mapped_context(self, mocked_summary):
        expected_contexts = {"basic-minimal": "default", "dark-mode": "default", "dark-angels": "hexagrammaton", "adeptus-mechanicus": "core"}
        for theme, context in expected_contexts.items():
            with self.subTest(theme=theme):
                self.client.cookies[settings.THEME_COOKIE_NAME] = theme
                response = self.client.get(reverse("core:home"))
                self.assertContains(response, 'data-theme="' + theme + '"')
                self.assertContains(response, 'data-theme-context="' + context + '"')
                self.assertNotContains(response, "theme-watermark--fallback")


class TopologyFrontendContractTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.js_path = Path(finders.find("core/js/topology.js"))
        cls.js = cls.js_path.read_text()
        cls.template = (Path(settings.BASE_DIR) / "core/templates/core/home.html").read_text()

    def test_node_and_link_details_use_real_metadata_fields(self):
        for field in ("health_reason", "monitoring_address_v6", "management_ipv6", "endpoint_state", "admin_status", "oper_status", "status_source"):
            self.assertIn(field, self.js)

    def test_address_visibility_control_is_present(self):
        self.assertIn("topology-toggle-addresses", self.template)
        self.assertIn("showAddresses", self.js)
        self.assertIn("monitoring_address_v6", self.js)

    def test_node_drag_is_presentation_only_and_has_no_network_call(self):
        tree = ast.parse(inspect.getsource(views))
        imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertFalse({"netmiko", "pynetbox", "paramiko", "subprocess"} & imported)
        drag_source = self.js[self.js.index("function onNodePointerMove"):self.js.index("function markUnavailable")]
        self.assertIn("nodeOffsets", drag_source)
        self.assertNotIn("fetch(", drag_source)

    def test_only_get_is_used_for_topology_network_access(self):
        self.assertIn('method: "GET"', self.js)
        for mutation in ('method: "POST"', 'method: "PUT"', 'method: "PATCH"', 'method: "DELETE"'):
            self.assertNotIn(mutation, self.js)

    def test_reset_and_refresh_preserve_documented_presentation_contract(self):
        self.assertIn("function resetNodePositions()", self.js)
        self.assertIn("nodeOffsets = {};", self.js)
        self.assertIn("if (!viewInitialized || identityChanged)", self.js)
        self.assertIn("else { applyView(); }", self.js)
        self.assertIn("window.setInterval(load", self.js)

    def test_pan_zoom_and_keyboard_selection_are_wired(self):
        for marker in ("zoomBy", 'addEventListener("wheel"', 'addEventListener("pointermove"', 'event.key === "Enter"', 'setAttribute("tabindex", "0")'):
            self.assertIn(marker, self.js)

    def test_static_assets_resolve(self):
        self.assertIsNotNone(finders.find("core/css/topology.css"))
        self.assertIsNotNone(finders.find("core/js/topology.js"))
