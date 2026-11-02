"""Lab 7 closure -- ``monitoring/scripts/build_grafana_dashboards.py``: every builder helper and dashboard function,
plus the generate / --check entry point, each called directly.

Pure: nothing is sent to Grafana or InfluxDB.  ``main`` writes only into a temporary directory (``OUTPUT`` patched)
or compares against the tracked JSON read-only.  POSITIVE: exact panel / variable / dashboard shapes, each dashboard
matches ``modules.grafana.EXPECTED`` and is byte-identical to the tracked JSON, generation writes every file.
NEGATIVE: blank flux and empty thresholds stay empty, unknown panel kinds and defaults never select an option, an
unserializable value is refused, and --check against a missing or stale output exits 1 naming the stale files.
"""
from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import monitoring.scripts.build_grafana_dashboards as b
from modules import grafana

DASHBOARD_FUNCTIONS = {
    "fleet-overview.json": b.fleet_dashboard, "streaming-telemetry.json": b.telemetry_dashboard, "snmp-monitoring.json": b.snmp_dashboard,
    "critical-syslog.json": b.syslog_dashboard, "resources.json": b.resources_dashboard, "link-events.json": b.link_events_dashboard,
    "link-state-traffic.json": b.link_state_traffic_dashboard,
}


class HelperTests(unittest.TestCase):
    def test_flux_and_target_return_dedented_queries(self):
        self.assertEqual(b.flux("\n    from(bucket: \"x\")\n      |> last()\n  "), 'from(bucket: "x")\n  |> last()')
        self.assertEqual(b.target("  q  ", "B"), {"datasource": b.DATASOURCE, "query": "q", "refId": "B"})

    def test_flux_and_target_of_blank_text_are_empty(self):
        self.assertEqual((b.flux("   \n  "), b.target("")["query"], b.target("")["refId"]), ("", "", "A"))

    def test_thresholds_returns_ordered_steps(self):
        self.assertEqual(b.thresholds(("green", None), ("red", 80)),
                         {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 80}]})

    def test_thresholds_without_steps_is_empty(self):
        self.assertEqual(b.thresholds(), {"mode": "absolute", "steps": []})

    def test_panel_returns_the_stat_shape_with_decimals_and_event_flag(self):
        found = b.panel(3, "CPU", "stat", 1, 2, 3, 4, "q", unit="percent", decimals=1, event_optional=True, threshold_steps=(("green", None), ("red", 90)))
        self.assertEqual((found["id"], found["gridPos"], found["eventOptional"], found["targets"], found["fieldConfig"]["defaults"]),
                         (3, {"x": 1, "y": 2, "w": 3, "h": 4}, True, [b.target("q")],
                          {"color": {"mode": "thresholds"}, "unit": "percent", "decimals": 1,
                           "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 90}]}}))
        self.assertEqual(found["options"]["reduceOptions"]["calcs"], ["lastNotNull"])
        kinds = {kind: b.panel(1, "t", kind, 0, 0, 1, 1, "q")["options"] for kind in ("bargauge", "table", "state-timeline", "piechart")}
        self.assertEqual((kinds["bargauge"]["displayMode"], kinds["table"], kinds["state-timeline"]["mergeValues"], kinds["piechart"]["pieType"]),
                         ("gradient", {"cellHeight": "sm", "showHeader": True, "sortBy": []}, True, "pie"))

    def test_panel_of_an_unknown_kind_falls_back_and_never_sets_decimals(self):
        found = b.panel(1, "t", "unknown-kind", 0, 0, 1, 1, "q")
        self.assertEqual(found["options"], {"legend": {"calcs": ["lastNotNull", "max"], "displayMode": "table", "placement": "bottom", "showLegend": True},
                                            "tooltip": {"mode": "multi", "sort": "desc"}})
        self.assertNotIn("decimals", found["fieldConfig"]["defaults"])
        self.assertEqual((found["fieldConfig"]["defaults"]["color"], found["eventOptional"]), ({"mode": "palette-classic"}, False))

    def test_query_variable_returns_a_multi_select_with_all(self):
        found = b.query_variable("device", "Device", "  q  ")
        self.assertEqual((found["query"], found["definition"], found["includeAll"], found["allValue"], found["current"]),
                         ("q", "q", True, ".*", {"selected": True, "text": "All", "value": "$__all"}))

    def test_query_variable_single_select_has_no_all_value(self):
        found = b.query_variable("device", "Device", "q", multi=False)
        self.assertEqual((found["multi"], found["includeAll"], found["allValue"], found["current"]), (False, False, None, {}))

    def test_bool_variable_returns_two_options_with_the_default_selected(self):
        found = b.bool_variable("hide_down", "Hide down", default="true")
        self.assertEqual((found["query"], [o["selected"] for o in found["options"]], found["current"]),
                         ("false,true", [False, True], {"text": "true", "value": "true", "selected": True}))

    def test_bool_variable_with_an_unknown_default_selects_no_option(self):
        self.assertEqual([o["selected"] for o in b.bool_variable("x", "X", default="maybe")["options"]], [False, False])

    def test_dashboard_returns_the_shared_envelope_with_extra_tags(self):
        found = b.dashboard("u", "T", "D", [{"name": "v"}], [{"id": 1}], start="now-1h", extra_tags=("canonical",))
        self.assertEqual((found["uid"], found["tags"], found["templating"], found["time"], found["refresh"], found["schemaVersion"]),
                         ("u", ["nmas", "network-monitoring", "iac", "canonical"], {"list": [{"name": "v"}]}, {"from": "now-1h", "to": "now"}, "20s", 40))

    def test_dashboard_without_extra_tags_is_never_editable(self):
        found = b.dashboard("u", "T", "D", [], [], start="now-1h")
        self.assertEqual((found["tags"], found["editable"], found["id"], found["panels"]), (["nmas", "network-monitoring", "iac"], False, None, []))

    def test_basic_and_link_state_filters_return_the_regex_clauses(self):
        self.assertEqual(b.basic_filters(interface=True),
                         "r.device =~ /^${device:regex}$/ and r.platform =~ /^${platform:regex}$/ and r.interface =~ /^${interface:regex}$/")
        found = b.link_state_filters()
        self.assertTrue(found.startswith(b.basic_filters(interface=True)))
        self.assertIn('("${include_mgmt}" == "true" or not (r.interface =~ /^(Management|Vlan200)/))', found)
        self.assertIn('("${include_loopback}" == "true" or not (r.interface == "lo" or r.interface =~ /^Loopback/))', found)

    def test_basic_filters_without_interface_has_no_interface_clause(self):
        self.assertNotIn("interface", b.basic_filters())

    def test_recent_critical_syslog_panel_returns_the_shared_table(self):
        found = b.recent_critical_syslog_panel(7, 0, 1, 12, 8, title="Syslog")
        self.assertEqual((found["id"], found["title"], found["type"], found["gridPos"]), (7, "Syslog", "table", {"x": 0, "y": 1, "w": 12, "h": 8}))
        self.assertIn('r._measurement == "syslog_event"', found["targets"][0]["query"])

    def test_recent_critical_syslog_panel_never_requires_rows(self):
        found = b.recent_critical_syslog_panel(1, 0, 0, 1, 1)
        self.assertEqual((found["title"], found["eventOptional"]), ("Recent critical syslog", True))

    def test_encoded_returns_sorted_indented_json(self):
        self.assertEqual(b.encoded({"b": 1, "a": [1]}), '{\n  "a": [\n    1\n  ],\n  "b": 1\n}\n')

    def test_encoded_refuses_an_unserializable_value(self):
        with self.assertRaises(TypeError):
            b.encoded({"x": object()})


class DashboardTests(unittest.TestCase):
    def test_each_dashboard_matches_the_expected_contract_and_the_tracked_json(self):
        for name, function in DASHBOARD_FUNCTIONS.items():
            with self.subTest(case=f"dashboard matches {name}"):
                found = function()
                expected = grafana.EXPECTED[found["uid"]]
                self.assertEqual((found["title"], {p["title"] for p in found["panels"]}, {v["name"] for v in found["templating"]["list"]}),
                                 (expected["title"], expected["panels"], expected["variables"]))
                self.assertEqual(b.encoded(found), (b.OUTPUT / name).read_text())
        self.assertEqual(set(b.definitions()), set(DASHBOARD_FUNCTIONS))


class MainTests(unittest.TestCase):
    def main(self, argv, output):
        out = io.StringIO()
        with mock.patch.object(b, "OUTPUT", output), mock.patch("sys.argv", ["build_grafana_dashboards.py", *argv]), contextlib.redirect_stdout(out):
            return b.main(), out.getvalue()

    def test_main_generates_every_dashboard_then_check_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "json"
            self.assertEqual(self.main([], output), (0, "Generated 7 Grafana dashboards\n"))
            self.assertEqual(sorted(p.name for p in output.iterdir()), sorted(DASHBOARD_FUNCTIONS))
            self.assertEqual(self.main(["--check"], output), (0, "Verified 7 Grafana dashboards\n"))
        self.assertEqual(self.main(["--check"], b.OUTPUT), (0, "Verified 7 Grafana dashboards\n"))

    def test_main_check_of_missing_or_stale_output_fails_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            (output / "resources.json").write_text("{}\n")
            with mock.patch.object(b, "BASE", output):
                code, printed = self.main(["--check"], output)
            self.assertEqual(code, 1)
            self.assertEqual(printed, "Dashboard JSON is stale: " + ", ".join(sorted(DASHBOARD_FUNCTIONS, key=list(b.definitions()).index)) + "\n")
            self.assertEqual([p.name for p in output.iterdir()], ["resources.json"])
            self.assertEqual((output / "resources.json").read_text(), "{}\n")


class GrafanaModuleTests(unittest.TestCase):
    """``modules.grafana`` session construction and the provision-then-verify entry point (both stages faked)."""

    def test_grafana_session_returns_an_authenticated_session_ignoring_proxy_env(self):
        session = grafana.grafana_session({"GRAFANA_ADMIN_USER": "admin", "GRAFANA_ADMIN_PASSWORD": "pw-not-real"})
        self.assertEqual((session.auth, session.trust_env), (("admin", "pw-not-real"), False))

    def test_grafana_session_without_a_password_raises(self):
        with self.assertRaises(KeyError):
            grafana.grafana_session({"GRAFANA_ADMIN_USER": "admin"})

    def test_ensure_grafana_infrastructure_returns_the_verification_after_provisioning(self):
        calls = []
        with mock.patch.object(grafana, "provision_grafana", side_effect=lambda: calls.append("provision")), \
                mock.patch.object(grafana, "verify_grafana", side_effect=lambda verbose: calls.append(("verify", verbose)) or {"ok": True}):
            self.assertEqual(grafana.ensure_grafana_infrastructure(verbose=True), {"ok": True})
        self.assertEqual(calls, ["provision", ("verify", True)])

    def test_ensure_grafana_infrastructure_with_failed_provisioning_never_verifies(self):
        verify = mock.Mock()
        with mock.patch.object(grafana, "provision_grafana", side_effect=grafana.NmasError("Grafana API POST failed")), \
                mock.patch.object(grafana, "verify_grafana", verify):
            with self.assertRaisesRegex(grafana.NmasError, "Grafana API POST failed"):
                grafana.ensure_grafana_infrastructure()
        verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
