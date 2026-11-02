from __future__ import annotations

import inspect
import json
from email.message import Message
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from core.services import monitoring_service


AVAILABLE = {"status": "available", "message": "Grafana monitoring service is available."}
UNAVAILABLE = {
    "status": "unavailable",
    "message": "Grafana monitoring service temporarily unavailable.",
}


class MonitoringServiceContractTests(SimpleTestCase):
    def test_canonical_dashboard_uids_only(self):
        self.assertEqual(
            {value["grafana_uid"] for value in monitoring_service.CANONICAL_DASHBOARDS.values()},
            {"nmas-resources", "nmas-link-events", "nmas-link-state-traffic"},
        )
        self.assertFalse(
            {
                "nmas-fleet-overview",
                "nmas-streaming-telemetry",
                "nmas-snmp-monitoring",
                "nmas-critical-syslog",
            }
            & {value["grafana_uid"] for value in monitoring_service.CANONICAL_DASHBOARDS.values()}
        )

    def test_unknown_dashboard_identifier_is_rejected(self):
        with self.assertRaises(monitoring_service.UnknownDashboardError):
            monitoring_service.build_dashboard_url("nmas-fleet-overview")

    def test_filter_to_grafana_variable_mapping(self):
        cases = (
            ("resources", {"device": "R3"}, "var-device", "R3"),
            ("resources", {"platform": "ceos"}, "var-platform", "ceos"),
            ("link_state_traffic", {"interface": "Ethernet1/1"}, "var-interface", "Ethernet1/1"),
            ("resources", {"severity": "crit"}, "var-severity", "crit"),
            ("link_events", {"event_type": "linkDown"}, "var-event_type", "linkDown"),
        )
        for page, filters, parameter, expected in cases:
            with self.subTest(page=page, parameter=parameter):
                query = parse_qs(urlsplit(monitoring_service.build_dashboard_url(page, filters)).query)
                self.assertEqual(query[parameter], [expected])

    def test_boolean_filters_map_and_defaults_are_omitted(self):
        url = monitoring_service.build_dashboard_url(
            "link_state_traffic",
            {
                "hide_zero_traffic": "true",
                "hide_down": "true",
                "active_only": "true",
                "include_mgmt": "false",
                "include_loopback": "false",
            },
        )
        query = parse_qs(urlsplit(url).query)
        for name in (
            "hide_zero_traffic",
            "hide_down",
            "active_only",
            "include_mgmt",
            "include_loopback",
        ):
            self.assertIn(f"var-{name}", query)
        reset_query = parse_qs(
            urlsplit(monitoring_service.build_dashboard_url("link_state_traffic")).query
        )
        self.assertFalse(any(key.startswith("var-") for key in reset_query))

    def test_unknown_filter_keys_and_invalid_values_are_ignored(self):
        url = monitoring_service.build_dashboard_url(
            "resources",
            {"unknown": "from=now-10y", "device": "R1&to=2099", "platform": "srlinux"},
        )
        self.assertNotIn("unknown", url)
        self.assertNotIn("var-device", url)
        self.assertNotIn("var-platform", url)

    def test_values_are_url_encoded(self):
        url = monitoring_service.build_dashboard_url(
            "link_state_traffic", {"interface": "Ethernet1/1"}
        )
        self.assertIn("var-interface=Ethernet1%2F1", url)

    @override_settings(GRAFANA_BASE_URL="http://127.0.0.1:3000")
    def test_filter_injection_cannot_change_grafana_host(self):
        url = monitoring_service.build_dashboard_url(
            "resources", {"device": "//evil.example/path", "from": "https://evil.example"}
        )
        self.assertEqual(urlsplit(url).hostname, "127.0.0.1")
        self.assertNotIn("evil.example", url)

    @override_settings(GRAFANA_BASE_URL="https://user:password@example.invalid")
    def test_credentials_are_rejected_in_configured_base_url(self):
        with self.assertRaises(ValueError):
            monitoring_service.build_dashboard_url("resources")

    def test_time_range_validation_and_defaults(self):
        url = monitoring_service.build_dashboard_url("resources", time_range="7d")
        self.assertEqual(parse_qs(urlsplit(url).query)["from"], ["now-7d"])
        invalid = monitoring_service.validate_filters("resources", {"time_range": "10 years"})
        self.assertEqual(invalid["time_range"], "6h")
        self.assertIn("time_range", invalid["invalid"])

    def test_full_url_preserves_valid_filters(self):
        url = monitoring_service.build_dashboard_url(
            "link_events",
            {"device": "R3", "event_type": "linkDown", "severity": "crit"},
            time_range="24h",
        )
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["var-device"], ["R3"])
        self.assertEqual(query["var-event_type"], ["linkDown"])
        self.assertEqual(query["var-severity"], ["crit"])
        self.assertEqual(query["from"], ["now-24h"])

    def test_embed_and_full_urls_use_distinct_presentation_for_every_dashboard(self):
        for page_key, dashboard in monitoring_service.CANONICAL_DASHBOARDS.items():
            with self.subTest(page=page_key):
                full = urlsplit(monitoring_service.build_dashboard_url(page_key))
                embedded = urlsplit(
                    monitoring_service.build_dashboard_url(page_key, embed=True)
                )
                self.assertEqual(full.path, embedded.path)
                self.assertEqual(
                    full.path,
                    f"/d/{dashboard['grafana_uid']}/{dashboard['grafana_slug']}",
                )
                full_query = parse_qs(full.query)
                embedded_query = parse_qs(embedded.query)
                self.assertNotIn("kiosk", full_query)
                self.assertEqual(embedded_query["kiosk"], ["true"])
                for name in (
                    "_dash.hideTimePicker",
                    "_dash.hideVariables",
                    "_dash.hideLinks",
                ):
                    self.assertNotIn(name, full_query)
                    self.assertEqual(embedded_query[name], ["true"])
                self.assertEqual(full_query["from"], embedded_query["from"])
                self.assertEqual(full_query["to"], embedded_query["to"])

    def test_dashboard_contract_matches_generated_json(self):
        json_dir = settings.REPO_ROOT / "monitoring/grafana/provisioning/dashboards/json"
        for dashboard in monitoring_service.CANONICAL_DASHBOARDS.values():
            source = json.loads((json_dir / dashboard["source_file"]).read_text())
            self.assertEqual(source["uid"], dashboard["grafana_uid"])
            self.assertEqual(source["title"], dashboard["grafana_title"])
            source_variables = {item["name"] for item in source["templating"]["list"]}
            mapped_variables = {
                item["grafana_variable"] for item in dashboard["filters"].values()
            }
            self.assertEqual(source_variables, mapped_variables)

    @override_settings(GRAFANA_HEALTH_TIMEOUT_SECONDS=1.25)
    def test_health_check_is_fixed_get_with_finite_timeout(self):
        response = MagicMock()
        response.read.return_value = b'{"database":"ok"}'
        response.__enter__.return_value = response
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(monitoring_service, "build_opener", return_value=opener):
            health = monitoring_service.get_grafana_health()
        self.assertEqual(health["status"], "available")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:3000/api/health")
        self.assertEqual(request.method, "GET")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 1.25)

    def test_health_failure_returns_generic_unavailable_state(self):
        opener = MagicMock()
        opener.open.side_effect = URLError("internal detail must not escape")
        with patch.object(monitoring_service, "build_opener", return_value=opener):
            health = monitoring_service.get_grafana_health()
        self.assertEqual(health, UNAVAILABLE)

    @override_settings(
        GRAFANA_EMBED_ENABLED=True,
        GRAFANA_BASE_URL="http://127.0.0.1:3000",
    )
    def test_live_frame_capability_probe_allows_header_free_dashboard(self):
        headers = Message()
        response = MagicMock(headers=headers)
        response.__enter__.return_value = response
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(monitoring_service, "build_opener", return_value=opener):
            allowed = monitoring_service.grafana_allows_embedding(
                "resources",
                embedding_origin="http://127.0.0.1:8001",
            )
        self.assertTrue(allowed)
        request = opener.open.call_args.args[0]
        self.assertIn("/d/nmas-resources/nmas-resources", request.full_url)
        self.assertEqual(parse_qs(urlsplit(request.full_url).query)["kiosk"], ["true"])
        self.assertEqual(request.method, "GET")

    @override_settings(GRAFANA_EMBED_ENABLED=True)
    def test_live_frame_capability_probe_rejects_xfo_and_csp(self):
        cases = (
            ("X-Frame-Options", "deny"),
            ("X-Frame-Options", "SAMEORIGIN"),
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("Content-Security-Policy", "frame-ancestors 'self'"),
        )
        for name, value in cases:
            with self.subTest(header=name, value=value):
                headers = Message()
                headers[name] = value
                response = MagicMock(headers=headers)
                response.__enter__.return_value = response
                opener = MagicMock()
                opener.open.return_value = response
                with patch.object(monitoring_service, "build_opener", return_value=opener):
                    self.assertFalse(
                        monitoring_service.grafana_allows_embedding(
                            "resources",
                            embedding_origin="http://127.0.0.1:8001",
                        )
                    )

    @override_settings(GRAFANA_EMBED_ENABLED=False)
    def test_embedding_operator_kill_switch_skips_live_probe(self):
        with patch.object(monitoring_service, "build_opener") as build_opener_mock:
            self.assertFalse(
                monitoring_service.grafana_allows_embedding(
                    "resources",
                    embedding_origin="http://127.0.0.1:8001",
                )
            )
        build_opener_mock.assert_not_called()


class MonitoringRouteTests(TestCase):
    def _get(self, route_name: str, params=None, health=AVAILABLE, embedding=True):
        with (
            patch.object(monitoring_service, "get_grafana_health", return_value=health),
            patch.object(
                monitoring_service,
                "grafana_allows_embedding",
                return_value=embedding,
            ),
        ):
            return self.client.get(reverse(route_name), params or {})

    def test_all_monitoring_routes_return_200(self):
        for name in (
            "core:monitoring_landing",
            "core:monitoring_resources",
            "core:monitoring_link_events",
            "core:monitoring_link_state_traffic",
        ):
            with self.subTest(name=name):
                self.assertEqual(self._get(name).status_code, 200)

    def test_each_route_uses_correct_uid(self):
        cases = (
            ("core:monitoring_resources", "nmas-resources"),
            ("core:monitoring_link_events", "nmas-link-events"),
            ("core:monitoring_link_state_traffic", "nmas-link-state-traffic"),
        )
        for route, uid in cases:
            with self.subTest(route=route):
                response = self._get(route)
                self.assertEqual(response.context["dashboard"]["grafana_uid"], uid)
                self.assertContains(response, f"/d/{uid}/{uid}")

    def test_get_filters_reach_full_grafana_link(self):
        response = self._get(
            "core:monitoring_link_state_traffic",
            {
                "device": "R3",
                "platform": "linux",
                "interface": "eth1.103",
                "active_only": "true",
                "time_range": "1h",
            },
        )
        url = response.context["full_grafana_url"]
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["var-device"], ["R3"])
        self.assertEqual(query["var-interface"], ["eth1.103"])
        self.assertEqual(query["var-active_only"], ["true"])
        self.assertEqual(query["from"], ["now-1h"])
        embed_query = parse_qs(urlsplit(response.context["embed_url"]).query)
        self.assertEqual(embed_query["var-device"], ["R3"])
        self.assertEqual(embed_query["var-interface"], ["eth1.103"])
        self.assertEqual(embed_query["var-active_only"], ["true"])
        self.assertEqual(embed_query["from"], ["now-1h"])
        self.assertEqual(embed_query["kiosk"], ["true"])
        self.assertNotIn("kiosk", query)

    def test_reset_link_has_no_query_and_default_url_has_no_variables(self):
        response = self._get("core:monitoring_resources")
        self.assertEqual(response.context["reset_url"], reverse("core:monitoring_resources"))
        query = parse_qs(urlsplit(response.context["full_grafana_url"]).query)
        self.assertFalse(any(key.startswith("var-") for key in query))
        self.assertContains(response, "Reset Filters")

    def test_unavailable_grafana_keeps_page_200_and_invents_no_data(self):
        response = self._get("core:monitoring_resources", health=UNAVAILABLE)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Grafana monitoring service temporarily unavailable.")
        self.assertContains(response, 'data-monitoring-data="none"')
        self.assertNotContains(response, "devices_up")
        self.assertNotContains(response, "cpu_percent")

    def test_reachable_frame_capable_grafana_renders_iframe(self):
        response = self._get("core:monitoring_resources", embedding=True)
        self.assertContains(response, "<iframe")
        self.assertContains(response, "/d/nmas-resources/nmas-resources")
        self.assertNotContains(response, "currently denies iframe embedding")

    def test_reachable_grafana_with_prohibited_framing_renders_secure_fallback(self):
        response = self._get("core:monitoring_resources", embedding=False)
        self.assertNotContains(response, "<iframe")
        self.assertContains(response, "Open Full Grafana Dashboard")
        self.assertContains(response, "requires its own authenticated browser session")

    def test_embed_is_sandboxed_and_credential_free(self):
        response = self._get("core:monitoring_resources", embedding=True)
        self.assertContains(response, "<iframe")
        self.assertContains(response, 'sandbox="allow-same-origin allow-scripts allow-forms')
        self.assertNotContains(response, "password=")
        self.assertNotContains(response, "token=")

    def test_no_runtime_secret_appears_in_html(self):
        marker = "PHASE6_DO_NOT_RENDER_SECRET"
        with override_settings(GRAFANA_BASE_URL="http://127.0.0.1:3000"):
            response = self._get("core:monitoring_resources")
        body = response.content.decode()
        self.assertNotIn(marker, body)
        for forbidden in ("GRAFANA_ADMIN_PASSWORD", "INFLUXDB_TOKEN", "NETBOX_TOKEN"):
            self.assertNotIn(forbidden, body)

    def test_filter_form_is_get_only(self):
        response = self._get("core:monitoring_link_events")
        self.assertContains(response, 'method="get"')
        self.assertNotContains(response, 'method="post" action="/monitoring')

    def test_all_four_themes_render_resources(self):
        for theme in ("basic-minimal", "dark-mode", "dark-angels", "adeptus-mechanicus"):
            with self.subTest(theme=theme):
                self.client.cookies[settings.THEME_COOKIE_NAME] = theme
                response = self._get("core:monitoring_resources")
                self.assertContains(response, f'data-theme="{theme}"')

    def test_dark_angels_monitoring_pages_use_ravenwing(self):
        self.client.cookies[settings.THEME_COOKIE_NAME] = "dark-angels"
        for route in (
            "core:monitoring_link_events",
            "core:monitoring_link_state_traffic",
        ):
            with self.subTest(route=route):
                self.assertContains(self._get(route), 'data-theme-context="ravenwing"')

    def test_mechanicus_monitoring_context(self):
        self.client.cookies[settings.THEME_COOKIE_NAME] = "adeptus-mechanicus"
        self.assertContains(
            self._get("core:monitoring_link_state_traffic"),
            'data-theme-context="monitoring"',
        )


class MonitoringArchitectureTests(SimpleTestCase):
    def test_monitoring_service_has_no_device_or_netbox_logic(self):
        source = inspect.getsource(monitoring_service).lower()
        for forbidden in ("netmiko", "paramiko", "pynetbox", "influxdbclient", "subprocess"):
            self.assertNotIn(forbidden, source)

    def test_monitoring_templates_have_no_state_changing_controls(self):
        template_dir = Path(__file__).resolve().parents[1] / "templates/core/monitoring"
        source = "\n".join(path.read_text() for path in template_dir.glob("*.html")).lower()
        for method in ('method="post"', 'method="put"', 'method="patch"', 'method="delete"'):
            self.assertNotIn(method, source)
