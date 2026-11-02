"""Offline contract tests for deterministic Grafana desired state."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from modules import grafana
from modules.nmas import NmasError
import monitoring.scripts.build_grafana_dashboards as builder


class GrafanaSourceTests(unittest.TestCase):
    def test_dashboard_uids_titles_panels_and_variables_are_stable(self):
        dashboards = grafana.source_dashboards()
        self.assertEqual(set(dashboards), set(grafana.EXPECTED))
        for uid, expected in grafana.EXPECTED.items():
            self.assertEqual(dashboards[uid]["title"], expected["title"])
            self.assertEqual({p["title"] for p in dashboards[uid]["panels"]}, expected["panels"])
            self.assertEqual({v["name"] for v in dashboards[uid]["templating"]["list"]}, expected["variables"])

    def test_every_panel_uses_stable_datasource_and_has_flux(self):
        for dashboard in grafana.source_dashboards().values():
            for panel in dashboard["panels"]:
                self.assertTrue(panel["targets"])
                for target in panel["targets"]:
                    self.assertEqual(target["datasource"]["uid"], grafana.DATASOURCE_UID)
                    self.assertIn("from(bucket:", target["query"])

    def test_all_substitution_leaves_no_dashboard_variable(self):
        for dashboard in grafana.source_dashboards().values():
            queries = [v["query"] for v in dashboard["templating"]["list"]]
            queries += [t["query"] for p in dashboard["panels"] for t in p["targets"]]
            for query in queries:
                self.assertNotIn("${", grafana.substitute_variables(query))


class CanonicalTaxonomyTests(unittest.TestCase):
    """Phase 2: the three canonical dashboards mapping to the future Django
    Resources / Link Events / Link State & Traffic pages exist alongside the
    four preserved legacy dashboards, with deterministic identity."""

    def test_canonical_and_legacy_partition_expected(self):
        self.assertEqual(grafana.CANONICAL | grafana.LEGACY | grafana.LIFECYCLE, set(grafana.EXPECTED))
        self.assertEqual(grafana.CANONICAL & grafana.LEGACY, set())
        self.assertEqual((grafana.CANONICAL | grafana.LEGACY) & grafana.LIFECYCLE, set())
        self.assertEqual(grafana.CANONICAL, {"nmas-resources", "nmas-link-events", "nmas-link-state-traffic"})

    def test_canonical_dashboards_exist_with_stable_uids_and_tags(self):
        dashboards = grafana.source_dashboards()
        for uid in grafana.CANONICAL:
            self.assertIn(uid, dashboards)
            self.assertIn("canonical", dashboards[uid]["tags"])
        for uid in grafana.LEGACY:
            self.assertIn("legacy", dashboards[uid]["tags"])

    def test_device_and_interface_filters_wired_into_canonical_queries(self):
        dashboards = grafana.source_dashboards()
        # Every canonical dashboard must filter by device; the one with an
        # interface template variable must use it in every panel query.
        for uid in grafana.CANONICAL:
            dash = dashboards[uid]
            var_names = {v["name"] for v in dash["templating"]["list"]}
            self.assertIn("device", var_names)
            for p in dash["panels"]:
                for t in p["targets"]:
                    self.assertIn("${device:regex}", t["query"], f"{uid}/{p['title']} does not filter by device")
            if "interface" in var_names:
                # netconf_snapshot is a device-level snapshot with no
                # per-interface tag in the stored schema (see
                # docs/GRAFANA_MONITORING_TAXONOMY.md); every other panel on
                # an interface-scoped dashboard must filter by interface.
                device_level_exceptions = {"Latest NETCONF RPC snapshots"}
                for p in dash["panels"]:
                    if p["title"] in device_level_exceptions:
                        continue
                    for t in p["targets"]:
                        self.assertIn("${interface:regex}", t["query"], f"{uid}/{p['title']} does not filter by interface")

    def test_link_state_traffic_only_uses_real_stored_measurements(self):
        allowed = {"gnmi_telemetry", "netconf_snapshot"}
        dash = grafana.source_dashboards()["nmas-link-state-traffic"]
        for p in dash["panels"]:
            for t in p["targets"]:
                found = {m for m in allowed if f'"{m}"' in t["query"]}
                self.assertTrue(found, f"{p['title']} does not reference a known real measurement")
                self.assertLessEqual(found, allowed)

    def test_collector_alert_is_never_conflated_with_snmp_trap(self):
        dashboards = grafana.source_dashboards()
        for dash in dashboards.values():
            for p in dash["panels"]:
                for t in p["targets"]:
                    query = t["query"]
                    if "collector_alert" in query:
                        self.assertNotIn("snmp_trap", query, f"{p['title']} mixes collector_alert and snmp_trap in one query")
                    if 'r._measurement == "snmp_trap"' in query:
                        self.assertNotIn("alert_type", query, f"{p['title']} filters snmp_trap by a collector_alert-only tag")

    def test_link_state_traffic_never_computes_a_fabricated_utilization_percentage(self):
        dash = grafana.source_dashboards()["nmas-link-state-traffic"]
        for p in dash["panels"]:
            self.assertNotIn("speed", p["description"].lower() + str(p["targets"]))
            for t in p["targets"]:
                self.assertNotIn("ifSpeed", t["query"])


class EventOptionalSemanticsTests(unittest.TestCase):
    """Phase 2: the CPU-alert-panel verifier fix. Event-optional status is a
    per-panel field set once by the generator (build_grafana_dashboards.py's
    panel(event_optional=...)) and read back directly by
    modules.grafana.panel_requires_data -- there is no separate hardcoded
    title allow-list."""

    def test_cpu_alerts_panel_is_event_optional(self):
        dash = grafana.source_dashboards()["nmas-snmp-monitoring"]
        panel = next(p for p in dash["panels"] if p["title"] == "NMAS Collector CPU Alerts")
        self.assertTrue(panel["eventOptional"])
        self.assertFalse(grafana.panel_requires_data(panel))

    def test_known_event_optional_panels_do_not_require_data(self):
        expected_event_optional = {
            "nmas-fleet-overview": {
                "Critical syslog events", "SNMP traps", "Current non-UP interfaces",
                "Recent linkDown notifications", "Recent critical syslog",
            },
            "nmas-streaming-telemetry": {"Current non-UP interfaces"},
            "nmas-snmp-monitoring": {
                "Traps received", "Trap volume over time", "Trap types",
                "Recent SNMP notifications", "NMAS Collector CPU Alerts",
            },
            "nmas-critical-syslog": {
                "Critical events", "Events by device", "Severity distribution",
                "Critical event volume over time", "Facilities", "Recent critical events",
            },
            "nmas-resources": {"NMAS Collector CPU Alerts (range)", "Per-device health & freshness", "Resource-related critical syslog"},
            "nmas-link-events": {
                "SNMP notifications (range)", "Critical syslog (range)", "Trap types",
                "Notification volume over time (by event type)", "Recent SNMP notifications",
                "Recent critical syslog",
            },
        }
        dashboards = grafana.source_dashboards()
        for uid, titles in expected_event_optional.items():
            for p in dashboards[uid]["panels"]:
                if p["title"] in titles:
                    self.assertFalse(grafana.panel_requires_data(p), f"{uid}/{p['title']} should be event-optional")
                else:
                    self.assertTrue(grafana.panel_requires_data(p), f"{uid}/{p['title']} should require data (metric/state panel)")

    def test_link_state_traffic_has_no_event_optional_panels(self):
        # Link State & Traffic is entirely metric/state (continuous samples
        # and counters); nothing on it should be allowed to be silently empty.
        dash = grafana.source_dashboards()["nmas-link-state-traffic"]
        for p in dash["panels"]:
            self.assertTrue(grafana.panel_requires_data(p), f"{p['title']} unexpectedly marked event-optional")

    def test_verify_loop_tolerates_empty_event_optional_panel(self):
        # Simulates the exact condition in modules.grafana.verify_grafana's
        # per-panel empty-result check without needing a live Grafana.
        event_optional_panel = {"title": "NMAS Collector CPU Alerts", "eventOptional": True}
        points = 0
        self.assertFalse(points == 0 and grafana.panel_requires_data(event_optional_panel))

    def test_verify_loop_still_fails_a_metric_panel_that_is_empty(self):
        strict_panel = {"title": "CPU utilization", "eventOptional": False}
        points = 0
        self.assertTrue(points == 0 and grafana.panel_requires_data(strict_panel))


class GrafanaLiveFailureModeTests(unittest.TestCase):
    """Verifies that execute_flux still raises on a genuinely failing/
    malformed query, regardless of event-optional status -- event-optional
    only waives the zero-rows check, never a real query/datasource failure."""

    def test_execute_flux_raises_on_flux_query_error(self):
        session = MagicMock()
        with patch.object(grafana, "api") as mock_api:
            mock_api.return_value.json.return_value = {
                "results": {"A": {"status": 400, "error": "invalid Flux syntax"}}
            }
            with self.assertRaises(NmasError):
                grafana.execute_flux(session, 'from(bucket: "network-monitoring") |> this is not valid')

    def test_execute_flux_raises_on_non_200_status_even_when_no_error_text(self):
        session = MagicMock()
        with patch.object(grafana, "api") as mock_api:
            mock_api.return_value.json.return_value = {"results": {"A": {"status": 500}}}
            with self.assertRaises(NmasError):
                grafana.execute_flux(session, 'from(bucket: "network-monitoring") |> range(start: -1h)')

    def test_api_raises_on_non_ok_http_response(self):
        session = MagicMock()
        response = MagicMock(ok=False, status_code=502, text="bad gateway")
        session.request.return_value = response
        with self.assertRaises(NmasError):
            grafana.api(session, "GET", "/api/health")


class GeneratorDeterminismTests(unittest.TestCase):
    """Phase 2 requirement: the generator stays deterministic/idempotent
    after the event-optional metadata and canonical-dashboard additions."""

    def test_definitions_are_byte_identical_across_two_generations(self):
        first = {name: builder.encoded(value) for name, value in builder.definitions().items()}
        second = {name: builder.encoded(value) for name, value in builder.definitions().items()}
        self.assertEqual(first, second)

    def test_tracked_json_matches_freshly_generated_output(self):
        for name, value in builder.definitions().items():
            path = builder.OUTPUT / name
            self.assertTrue(path.exists(), f"{name} is not generated on disk")
            self.assertEqual(path.read_text(), builder.encoded(value), f"{name} on disk differs from a fresh generation")

    def test_seven_dashboards_defined(self):
        self.assertEqual(len(builder.definitions()), 7)


if __name__ == "__main__":
    unittest.main()
