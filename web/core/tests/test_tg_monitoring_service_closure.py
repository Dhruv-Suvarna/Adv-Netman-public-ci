"""Lab 7 closure -- ``core.services.monitoring_service`` page-level entry points, each called directly.

Hermetic: ``get_grafana_health`` and ``grafana_allows_embedding`` are patched (no HTTP request leaves the process) and
``GRAFANA_BASE_URL`` is pinned.  POSITIVE: exact metadata / validated filters / landing and page contexts with the
canonical Grafana URLs.  NEGATIVE: unknown or legacy dashboard keys raise ``UnknownDashboardError``; invalid filter
values and time ranges are dropped and reported, never forwarded to Grafana; an unavailable Grafana disables embedding.
"""
from __future__ import annotations

from unittest import mock

from django.test import SimpleTestCase, override_settings

from core.services import monitoring_service as ms

AVAILABLE = {"status": "available", "message": "Grafana monitoring service is available."}
UNAVAILABLE = {"status": "unavailable", "message": "Grafana monitoring service temporarily unavailable."}


@override_settings(GRAFANA_BASE_URL="http://grafana.test:3000/", GRAFANA_EMBED_ENABLED=True)
class MonitoringServiceClosureTests(SimpleTestCase):
    def test_get_dashboard_metadata_of_a_legacy_key_raises(self):
        for key in ("fleet_overview", "nmas-resources", ""):
            with self.subTest("unknown " + repr(key)), self.assertRaisesRegex(ms.UnknownDashboardError, "Unknown canonical dashboard"):
                ms.get_dashboard_metadata(key)

    def test_validate_filters_returns_the_selected_values_and_time_range(self):
        result = ms.validate_filters("resources", {"device": " R3 ", "platform": "ceos", "severity": "All", "unhealthy_only": "true",
                                                   "time_range": "24h", "unrelated": "x"})
        self.assertEqual(result, {"filters": {"device": "R3", "platform": "ceos", "unhealthy_only": "true"}, "time_range": "24h",
                                  "invalid": ()})

    def test_validate_filters_drops_invalid_values_and_unknown_time_ranges(self):
        result = ms.validate_filters("resources", {"device": "R3;drop", "platform": "junos", "unhealthy_only": "maybe", "time_range": "1y"})
        self.assertEqual(result, {"filters": {}, "time_range": "6h", "invalid": ("device", "platform", "unhealthy_only", "time_range")})

    def test_get_monitoring_summary_returns_the_grafana_health(self):
        with mock.patch.object(ms, "get_grafana_health", return_value=AVAILABLE) as health:
            self.assertEqual(ms.get_monitoring_summary(), AVAILABLE)
        health.assert_called_once_with()

    def test_get_monitoring_landing_context_lists_the_three_canonical_pages(self):
        with mock.patch.object(ms, "get_grafana_health", return_value=AVAILABLE):
            context = ms.get_monitoring_landing_context()
        self.assertEqual((context["page_title"], context["summary"]), ("Monitoring", AVAILABLE))
        self.assertEqual([(p["key"], p["grafana_uid"], p["route_name"], p["status"]) for p in context["pages"]],
                         [("resources", "nmas-resources", "core:monitoring_resources", "available"),
                          ("link_events", "nmas-link-events", "core:monitoring_link_events", "available"),
                          ("link_state_traffic", "nmas-link-state-traffic", "core:monitoring_link_state_traffic", "available")])

    def test_get_monitoring_page_context_returns_full_and_embed_urls(self):
        with mock.patch.object(ms, "get_grafana_health", return_value=AVAILABLE), \
                mock.patch.object(ms, "grafana_allows_embedding", return_value=True) as allows:
            context = ms.get_monitoring_page_context("resources", {"device": "R1", "time_range": "1h"}, reset_url="/monitoring/resources/",
                                                     embedding_origin="http://nmas.test")
        allows.assert_called_once_with("resources", embedding_origin="http://nmas.test")
        self.assertEqual(context["page_title"], "Monitoring · Resources")
        self.assertEqual(context["full_grafana_url"], "http://grafana.test:3000/d/nmas-resources/nmas-resources?from=now-1h&to=now&var-device=R1")
        self.assertTrue(context["embed_url"].startswith(context["full_grafana_url"] + "&kiosk=true&theme=dark"))
        self.assertEqual((context["selected_filters"], context["invalid_filters"], context["selected_time_range"], context["reset_url"]),
                         ({"device": "R1"}, (), "1h", "/monitoring/resources/"))
        self.assertEqual([c["name"] for c in context["filters"]], ["device", "platform", "severity", "unhealthy_only"])
        self.assertEqual(len(context["time_ranges"]), 6)

    def test_get_monitoring_page_context_with_grafana_unavailable_never_embeds(self):
        with mock.patch.object(ms, "get_grafana_health", return_value=UNAVAILABLE), mock.patch.object(ms, "grafana_allows_embedding") as allows:
            context = ms.get_monitoring_page_context("link_events", {"device": "bad value!"}, reset_url="/r/", embedding_origin="http://nmas.test")
        allows.assert_not_called()
        self.assertEqual((context["embed_enabled"], context["embed_url"], context["invalid_filters"]), (False, None, ("device",)))
        self.assertNotIn("bad", context["full_grafana_url"])

    def test_get_monitoring_page_context_of_an_unknown_page_raises(self):
        with mock.patch.object(ms, "get_grafana_health") as health, self.assertRaises(ms.UnknownDashboardError):
            ms.get_monitoring_page_context("snmp_monitoring", {}, reset_url="/r/", embedding_origin="http://nmas.test")
        health.assert_not_called()
