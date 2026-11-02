"""
Phase 7 NSOT tests.

Every NetBox/live-device/Git call in these tests is either mocked at the
adapter boundary (core.services.nsot_netbox / nsot_live / nsot_git) or, for
Git, exercised against this real repository (Git access has no external
dependency and is safe to call directly in tests). Nothing here reaches a
real NetBox instance or a real device.
"""

from __future__ import annotations

import ast
import inspect
import subprocess
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from core import views
from core.services import nsot_git, nsot_live, nsot_netbox, nsot_service
from core.tests.helpers.fakes import netbox_unreachable


def clear_nsot_cache():
    cache.clear()


def fixture_devices():
    return {
        "status": "available",
        "source": "NETBOX",
        "fetched_at": "2026-09-20T00:00:00+00:00",
        "data": [
            {
                "name": "R1", "role": "Router", "device_type": "cEOS 4.36.2F", "manufacturer": "Arista",
                "platform": None, "status": "Active", "site": "Lab", "primary_ipv4": "192.168.200.1",
                "primary_ipv6": "2001:db8:200::1", "managed": True, "tags": ["csci5840-iac", "managed"],
            },
            {
                "name": "R5", "role": "Router", "device_type": "cEOS 4.36.2F", "manufacturer": "Arista",
                "platform": None, "status": "Active", "site": "Lab", "primary_ipv4": None,
                "primary_ipv6": None, "managed": False, "tags": ["csci5840-iac", "unmanaged"],
            },
        ],
    }


def fixture_device_detail():
    return {
        "status": "available",
        "data": {
            "summary": {
                "name": "R1", "role": "Router", "device_type": "cEOS 4.36.2F", "manufacturer": "Arista",
                "platform": None, "status": "Active", "site": "Lab", "primary_ipv4": "192.168.200.1",
                "primary_ipv6": "2001:db8:200::1", "managed": True, "tags": ["csci5840-iac", "managed"],
            },
            "interfaces": [
                {
                    "name": "Vlan200", "type": "Virtual", "description": None, "mac_address": None,
                    "mode": "access", "untagged_vlan": 200, "enabled": True,
                    "addresses": [{"address": "192.168.200.1", "prefix_length": 24, "family": 4, "role": None}],
                },
            ],
        },
    }


def fixture_vlans():
    return {
        "status": "available",
        "data": [
            {"vid": 10, "name": "vlan10", "status": "Active", "role": None, "description": None, "static_management": False},
            {"vid": 200, "name": "management", "status": "Active", "role": None, "description": "Management VLAN", "static_management": True},
        ],
    }


class NsotRouteTests(TestCase):
    """Every NSOT route must load and degrade gracefully when NetBox is
    unavailable -- one unavailable source must not crash the page."""

    def setUp(self):
        clear_nsot_cache()

    @patch("core.services.nsot_netbox.health", return_value={"status": "available", "source": "NETBOX", "data": {}})
    @patch("core.services.nsot_netbox.list_devices", side_effect=lambda: fixture_devices())
    @patch("core.services.nsot_netbox.list_interfaces", return_value={"status": "available", "source": "NETBOX", "data": []})
    @patch("core.services.nsot_netbox.list_prefixes", return_value={"status": "available", "source": "NETBOX", "data": []})
    @patch("core.services.nsot_netbox.list_ip_addresses", return_value={"status": "available", "source": "NETBOX", "data": []})
    @patch("core.services.nsot_netbox.list_vlans", side_effect=lambda: fixture_vlans())
    def test_overview_loads_with_real_counts(self, *_mocks):
        response = self.client.get(reverse("core:nsot"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "NETBOX")

    @patch("core.services.nsot_netbox.list_devices", return_value={"status": "unavailable", "message": "boom", "data": None})
    def test_devices_page_degrades_when_netbox_unavailable(self, _mock):
        response = self.client.get(reverse("core:nsot_devices"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "NetBox unavailable")

    @patch("core.services.nsot_netbox.list_devices", side_effect=lambda: fixture_devices())
    def test_devices_page_loads_with_data(self, _mock):
        response = self.client.get(reverse("core:nsot_devices"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "R1")

    @patch("core.services.nsot_netbox.get_device_detail", side_effect=lambda name: fixture_device_detail())
    @patch("core.services.nsot_netbox.compare_device_facts", return_value={"status": "available", "data": {"equivalent": True, "differences": []}})
    @patch("core.services.nsot_git.read_catalogued_file", return_value={"status": "available", "path": "templates/R1.cfg.j2", "content": "..."})
    @patch("core.services.nsot_live.get_live_target", return_value={"platform": "ceos", "address": "192.168.200.1"})
    def test_device_detail_loads(self, *_mocks):
        response = self.client.get(reverse("core:nsot_device_detail", args=["R1"]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "R1")
        self.assertContains(response, "management · static")

    @patch("core.services.nsot_netbox.get_device_detail", return_value={"status": "not_found", "message": "nope", "data": None})
    def test_unknown_device_is_404(self, _mock):
        response = self.client.get(reverse("core:nsot_device_detail", args=["totally-fake-device"]))
        self.assertEqual(response.status_code, 404)

    def test_unknown_device_never_triggers_drift_inventory_git_or_topology_lookups(self):
        """Lab 7 O4: NetBox (the device-name authority) says not found -> 404 with no other source consulted."""
        with patch("core.services.nsot_netbox.get_device_detail", return_value={"status": "not_found", "message": "nope", "data": None}), \
             patch("core.services.nsot_netbox.compare_device_facts") as drift, patch("core.services.nsot_git.read_catalogued_file") as git, \
             patch("core.services.nsot_live.get_live_target_metadata") as live, \
             patch("core.services.topology_service.get_topology_summary") as topology:
            response = self.client.get(reverse("core:nsot_device_detail", args=["NOT-A-DEVICE-9"]))
        self.assertEqual(response.status_code, 404)
        for lookup in (drift, git, live, topology):
            lookup.assert_not_called()

    def test_netbox_unavailable_still_degrades_to_the_read_only_topology_neighbors(self):
        topology = {"status": "available", "data": {"graph": {"edges": [{"id": "e1", "source": "R1", "target": "R2", "status": "up"}]}}}
        with patch("core.services.nsot_netbox.get_device_detail", return_value={"status": "unavailable", "message": "NetBox down", "data": None}), \
             patch("core.services.nsot_netbox.compare_device_facts", return_value={"status": "unavailable", "message": "down", "data": None}), \
             patch("core.services.nsot_git.read_catalogued_file", return_value={"status": "unavailable"}), \
             patch("core.services.nsot_live.get_live_target_metadata", return_value=None), \
             patch("core.services.topology_service.get_topology_summary", return_value=topology):
            detail = nsot_service.get_device_detail("R1", force_refresh=True)
        self.assertEqual(detail["status"], "unavailable")
        self.assertEqual(detail["topology_neighbors"], {"status": "available", "source": "TOPOLOGY",
                                                        "data": [{"neighbor": "R2", "status": "up", "edge_id": "e1"}]})

    def test_invalid_device_name_shape_is_404_not_a_crash(self):
        # A single path segment that is not shaped like a real device name
        # (no traversal is even reachable here -- the URL pattern itself
        # cannot contain "/") must 404 cleanly rather than reach NetBox.
        response = self.client.get("/nsot/devices/R1%27%7C%7C1%3D%3D1/")
        self.assertEqual(response.status_code, 404)

    @patch("core.services.nsot_netbox.list_interfaces", return_value={"status": "available", "source": "NETBOX", "data": []})
    def test_interfaces_page_loads(self, _mock):
        response = self.client.get(reverse("core:nsot_interfaces"))
        self.assertEqual(response.status_code, 200)

    @patch("core.services.nsot_netbox.list_prefixes", return_value={"status": "available", "data": []})
    @patch("core.services.nsot_netbox.list_ip_addresses", return_value={"status": "available", "data": []})
    @patch("core.services.nsot_netbox.list_dhcp_ranges", return_value={"status": "available", "data": []})
    @patch("core.services.nsot_netbox.reservation_report", return_value={"status": "available", "data": {"rows_checked": 0, "overall_status": "READY", "readiness_counts": {}, "ok": True}})
    def test_ipam_page_loads(self, *_mocks):
        response = self.client.get(reverse("core:nsot_ipam"))
        self.assertEqual(response.status_code, 200)

    @patch("core.services.nsot_netbox.list_vlans", side_effect=lambda: fixture_vlans())
    def test_vlans_page_shows_vlan200_as_static_management(self, _mock):
        response = self.client.get(reverse("core:nsot_vlans"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "MANAGEMENT")
        self.assertContains(response, "STATIC")

    def test_vlans_page_has_no_dhcp_action_control(self):
        html = self.client.get(reverse("core:nsot_vlans")).content.decode()
        for forbidden in ("Enable DHCP", "Create Reservation", "reservation-action"):
            self.assertNotIn(forbidden, html)

    @patch("core.services.nsot_netbox.list_asns", return_value={"status": "available", "data": []})
    def test_routing_page_loads_and_is_honest_about_sparse_data(self, _mock):
        response = self.client.get(reverse("core:nsot_routing"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No ASN objects are currently modeled")

    @patch("core.services.nsot_netbox.get_device_types", return_value={"status": "available", "data": []})
    def test_platforms_page_loads(self, _mock):
        response = self.client.get(reverse("core:nsot_platforms"))
        self.assertEqual(response.status_code, 200)

    def test_templates_page_loads_against_real_catalogue(self):
        response = self.client.get(reverse("core:nsot_templates"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "templates/")

    @patch("core.services.nsot_netbox.list_devices", side_effect=lambda: fixture_devices())
    @patch("core.services.nsot_netbox.compare_device_facts", return_value={"status": "available", "data": {"equivalent": True, "differences": []}})
    @patch("core.services.nsot_netbox.reservation_report", return_value={"status": "available", "data": {"rows_checked": 1, "overall_status": "READY", "readiness_counts": {}, "ok": True}})
    def test_drift_page_loads(self, *_mocks):
        response = self.client.get(reverse("core:nsot_drift"))
        self.assertEqual(response.status_code, 200)

    def test_future_golden_candidate_uat_are_not_fabricated(self):
        with netbox_unreachable():
            html = self.client.get(reverse("core:nsot")).content.decode()
        # These future-state names may appear as an honest "not implemented
        # yet" disclosure, but never as populated data with no such
        # disclosure nearby.
        for mentioned in ("Golden", "Candidate", "UAT", "Probation"):
            if mentioned in html:
                self.assertIn("Not implemented yet", html)


class NsotCacheFreshnessTests(TestCase):
    """Phase 20.5: a materialized snapshot with an explicit manual refresh,
    honest freshness/staleness metadata, and a failed refresh that never
    destroys the last known good snapshot (docs/DJANGO_NSOT_INTEGRATION.md
    "Cache failure / staleness")."""

    def setUp(self):
        clear_nsot_cache()

    def _fresh_devices(self):
        fixture = fixture_devices()
        fixture["fetched_at"] = nsot_service._now_iso()
        return fixture

    def test_successful_load_is_tagged_current_with_a_fresh_age(self):
        with patch("core.services.nsot_netbox.list_devices", side_effect=self._fresh_devices):
            result = nsot_service.get_devices(force_refresh=True)
        self.assertEqual(result["freshness"]["state"], "CURRENT")
        self.assertIsNotNone(result["freshness"]["age_seconds"])
        self.assertLess(result["freshness"]["age_seconds"], 5)
        self.assertEqual(result["cache"], "miss")

    @patch("core.services.nsot_netbox.list_devices", side_effect=lambda: fixture_devices())
    def test_cache_hit_reports_growing_age_not_a_fixed_zero(self, _mock):
        first = nsot_service.get_devices(force_refresh=True)
        hit = nsot_service.get_devices(force_refresh=False)
        self.assertEqual(hit["cache"], "hit")
        self.assertEqual(hit["freshness"]["state"], "CURRENT")
        self.assertEqual(hit["data"], first["data"])

    def test_failed_forced_refresh_preserves_last_good_snapshot_and_marks_stale(self):
        with patch("core.services.nsot_netbox.list_devices", side_effect=lambda: fixture_devices()):
            first = nsot_service.get_devices(force_refresh=True)
        self.assertEqual(first["status"], "available")

        with patch(
            "core.services.nsot_netbox.list_devices",
            return_value={"status": "unavailable", "message": "NetBox down", "data": None},
        ):
            second = nsot_service.get_devices(force_refresh=True)

        # The failure never replaces good data with an empty/invalid snapshot.
        self.assertEqual(second["status"], "available")
        self.assertEqual(second["data"], first["data"])
        self.assertEqual(second["cache"], "stale")
        self.assertEqual(second["freshness"]["state"], "STALE")
        self.assertEqual(second["refresh_error"], "NetBox down")

    def test_loader_exception_also_preserves_last_good_snapshot(self):
        with patch("core.services.nsot_netbox.list_devices", side_effect=lambda: fixture_devices()):
            first = nsot_service.get_devices(force_refresh=True)

        with patch("core.services.nsot_netbox.list_devices", side_effect=RuntimeError("connection reset")):
            second = nsot_service.get_devices(force_refresh=True)

        self.assertEqual(second["status"], "available")
        self.assertEqual(second["data"], first["data"])
        self.assertIn("connection reset", second["refresh_error"])
        self.assertEqual(second["freshness"]["state"], "STALE")

    def test_failed_refresh_with_no_prior_good_snapshot_surfaces_the_failure_honestly(self):
        with patch(
            "core.services.nsot_netbox.list_devices",
            return_value={"status": "unavailable", "message": "never worked", "data": None},
        ):
            result = nsot_service.get_devices(force_refresh=True)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["freshness"]["state"], "STALE")
        self.assertIsNone(result["freshness"]["age_seconds"])
        self.assertNotIn("refresh_error", result)   # nothing to fall back to -- not a false "refresh failed" claim

    def test_manual_refresh_route_shows_stale_state_and_keeps_last_good_data_on_failure(self):
        with patch("core.services.nsot_netbox.list_devices", side_effect=lambda: fixture_devices()):
            self.client.get(reverse("core:nsot_devices"))
        with patch(
            "core.services.nsot_netbox.list_devices",
            return_value={"status": "unavailable", "message": "boom", "data": None},
        ):
            response = self.client.get(reverse("core:nsot_devices") + "?refresh=1")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "R1")
        self.assertContains(response, "STALE")
        self.assertContains(response, "Refresh failed")


class NsotDriftPerformanceTests(TestCase):
    def setUp(self):
        clear_nsot_cache()

    def test_managed_device_comparisons_use_one_materialized_fleet_read(self):
        rows = {"status": "available", "data": [
            {"name": name, "managed": True} for name in ("R1", "R2", "R3", "R4")
        ]}
        comparisons = {
            name: {"status": "available", "data": {"equivalent": True, "differences": []}}
            for name in ("R1", "R2", "R3", "R4")
        }
        with patch("core.services.nsot_netbox.list_devices", return_value=rows), \
             patch("core.services.nsot_netbox.compare_device_facts_many", return_value=comparisons) as batch, \
             patch("core.services.nsot_netbox.reservation_report", return_value={
                 "status": "available", "data": {"ok": True, "rows_checked": 0, "overall_status": "READY"}
             }), \
             patch("core.services.topology_service.get_topology_summary", return_value={
                 "status": "available", "data": {"graph": {"nodes": [
                     {"canonical_name": name} for name in ("R1", "R2", "R3", "R4")
                 ]}}
             }):
            result = nsot_service.get_drift(force_refresh=True)
        self.assertEqual(result["status"], "available")
        batch.assert_called_once_with(["R1", "R2", "R3", "R4"])


class NsotRunningConfigRouteTests(TestCase):
    def setUp(self):
        clear_nsot_cache()

    @patch("core.services.nsot_live.fetch_running_config")
    def test_running_config_route_is_get_only(self, mocked_fetch):
        mocked_fetch.return_value = {"status": "available", "source": "LIVE", "observed_at": "now", "command": "show running-config", "data": "hostname R1"}
        url = reverse("core:nsot_device_running_config", args=["R1"])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        for method in (self.client.post, self.client.put, self.client.patch, self.client.delete):
            with self.subTest(method=method.__name__):
                self.assertEqual(method(url).status_code, 405)

    @patch("core.services.nsot_live.fetch_running_config")
    def test_running_config_is_never_fetched_from_device_detail_page(self, mocked_fetch):
        with patch("core.services.nsot_netbox.get_device_detail", side_effect=lambda name: fixture_device_detail()), \
             patch("core.services.nsot_netbox.compare_device_facts", return_value={"status": "available", "data": {"equivalent": True, "differences": []}}), \
             patch("core.services.nsot_git.read_catalogued_file", return_value={"status": "unavailable"}), \
             patch("core.services.nsot_live.get_live_target", return_value={"platform": "ceos", "address": "192.168.200.1"}):
            self.client.get(reverse("core:nsot_device_detail", args=["R1"]))
        mocked_fetch.assert_not_called()

    @patch("core.services.nsot_live.fetch_running_config")
    def test_running_config_display_redacts_and_does_not_use_safe_filter(self, mocked_fetch):
        mocked_fetch.return_value = {
            "status": "available", "source": "LIVE", "observed_at": "now",
            "command": "show running-config",
            "data": 'username admin secret ******** \n<script>alert(1)</script>',
        }
        response = self.client.get(reverse("core:nsot_device_running_config", args=["R1"]))
        html = response.content.decode()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    @patch("core.services.nsot_live.fetch_running_config", return_value={"status": "unavailable", "source": "LIVE", "message": "LIVE UNAVAILABLE: NetmikoTimeoutException."})
    def test_running_config_unavailable_does_not_crash(self, _mock):
        response = self.client.get(reverse("core:nsot_device_running_config", args=["R3"]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "LIVE UNAVAILABLE")


class RedactionTests(SimpleTestCase):
    def test_known_secret_syntax_is_redacted(self):
        sample = (
            "username admin privilege 15 role network-admin secret sha512 $6$abc$def123hash\n"
            "enable secret 5 $1$somehash\n"
            "enable password 7 021508550735\n"
            "snmp-server community mySecretCommunity ro\n"
            "   password 7 070C285F4D06\n"
            "      key-string 7 13061E010803\n"
            "   neighbor 10.0.0.1 password MyBgpSecret123\n"
            "interface Vlan200\n"
            "   ip address 192.168.200.1/24\n"
        )
        redacted = nsot_live.redact_config(sample)
        for secret in ("abc", "def123hash", "somehash", "021508550735", "mySecretCommunity", "070C285F4D06", "13061E010803", "MyBgpSecret123"):
            self.assertNotIn(secret, redacted)
        self.assertIn("192.168.200.1/24", redacted)
        self.assertIn("neighbor 10.0.0.1", redacted)

    def test_non_secret_context_is_preserved(self):
        sample = "interface Ethernet1\n   description uplink-to-S1\n   no switchport"
        self.assertEqual(nsot_live.redact_config(sample), sample)

    def test_redaction_is_line_scoped_not_multiline_greedy(self):
        # A secret on one line must never be absorbed unredacted into a
        # later line's match (regression test for a real greedy-regex bug
        # found and fixed during Phase 7 development).
        sample = "enable secret 5 REALSECRETVALUE\nenable password 7 ANOTHERSECRET\n"
        redacted = nsot_live.redact_config(sample)
        self.assertNotIn("REALSECRETVALUE", redacted)
        self.assertNotIn("ANOTHERSECRET", redacted)


class GitAdapterTests(TestCase):
    """Exercised against the real repository -- git access has no external
    dependency and this is exactly what these functions are for."""

    @staticmethod
    def _real_git(*args):
        # Independent of nsot_git._run_git so the expectation is not
        # self-referential.
        return subprocess.run(
            ["git", *args],
            cwd=str(nsot_git.REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    def test_repo_state_matches_real_repository(self):
        # The branch must be whatever Git reports for the checkout under
        # test -- main, a feature branch, or "HEAD" for a detached checkout
        # (e.g. a GitHub Actions pull_request merge ref) -- never a fixed name.
        state = nsot_git.get_repo_state()
        self.assertEqual(state["status"], "available")
        self.assertEqual(state["branch"], self._real_git("rev-parse", "--abbrev-ref", "HEAD"))
        self.assertTrue(state["head_commit"])
        self.assertEqual(state["head_commit"], self._real_git("rev-parse", "--short", "HEAD"))
        self.assertEqual(state["head_commit_full"], self._real_git("rev-parse", "HEAD"))

    def test_known_runtime_logs_are_distinguished_from_project_source_drift(self):
        state = nsot_git.get_repo_state()
        for path in state["known_runtime_log_modifications"]:
            self.assertIn(path, nsot_git.KNOWN_RUNTIME_LOG_PATHS)
        self.assertTrue(set(state["project_source_drift"]).isdisjoint(nsot_git.KNOWN_RUNTIME_LOG_PATHS))

    def test_git_failure_degrades_gracefully(self):
        with patch("core.services.nsot_git._run_git", side_effect=nsot_git.GitUnavailableError("boom")):
            state = nsot_git.get_repo_state()
        self.assertEqual(state["status"], "unavailable")

    def test_catalogue_is_allowlisted_to_known_roots(self):
        catalogue = nsot_git.list_catalogued_files()
        self.assertEqual(catalogue["status"], "available")
        for row in catalogue["data"]:
            self.assertTrue(any(row["path"].startswith(root + "/") for root in nsot_git.CATALOGUE_ROOTS))

    def test_path_traversal_is_rejected(self):
        result = nsot_git.read_catalogued_file("../../../../etc/passwd")
        self.assertEqual(result["status"], "unavailable")

    def test_only_allowlisted_extensions_are_catalogued(self):
        catalogue = nsot_git.list_catalogued_files()
        for row in catalogue["data"]:
            self.assertTrue(any(row["path"].endswith(ext) for ext in nsot_git.CATALOGUE_EXTENSIONS))

    def test_env_files_are_never_catalogued(self):
        catalogue = nsot_git.list_catalogued_files()
        for row in catalogue["data"]:
            self.assertNotIn(".env", row["path"])

    def test_git_subprocess_uses_fixed_argument_array_not_shell(self):
        source = inspect.getsource(nsot_git._run_git)
        self.assertIn("shell=False", source)
        self.assertIn('["git", *args]', source)


class SecretExposureTests(TestCase):
    """Prove secret-shaped fixture values never reach the rendered page."""

    def setUp(self):
        clear_nsot_cache()

    def test_device_normalizer_only_reads_known_safe_fields(self):
        # _normalize_device must never dump a device's raw custom_fields
        # dict (which could contain anything an operator added in NetBox)
        # into the page -- only the specific known-safe fields below.
        fake_device = MagicMock()
        fake_device.name = "R1"
        fake_device.tags = []
        fake_device.custom_fields = {"iac_managed": True, "some_future_secret_field": "must-not-appear"}
        fake_device.device_type = None
        fake_device.role = None
        fake_device.platform = None
        fake_device.status = None
        fake_device.site = None
        fake_device.primary_ip4 = None
        fake_device.primary_ip6 = None
        normalized = nsot_netbox._normalize_device(fake_device)
        self.assertNotIn("must-not-appear", str(normalized))
        self.assertEqual(set(normalized), {"name", "role", "device_type", "manufacturer", "platform", "status", "site", "primary_ipv4", "primary_ipv6", "managed", "tags"})

    def test_no_settings_values_reach_markup(self):
        with netbox_unreachable():
            html = self.client.get(reverse("core:nsot")).content.decode()
        for forbidden in ("NETBOX_TOKEN", "SLACK_WEBHOOK_URL", "TEST_ONLY_ROTATION_SECRET_NEVER_REAL", "ceos_password"):
            self.assertNotIn(forbidden, html)


class ArchitectureBoundaryTests(SimpleTestCase):
    FORBIDDEN_MODULES = ("netmiko", "pynetbox", "paramiko", "subprocess", "influxdb")

    def test_views_module_still_imports_no_automation_modules(self):
        tree = ast.parse(inspect.getsource(views))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(imported.isdisjoint(self.FORBIDDEN_MODULES))

    def test_only_nsot_git_module_shells_out_to_subprocess(self):
        for module in (nsot_netbox, nsot_live, nsot_service):
            with self.subTest(module=module.__name__):
                self.assertNotIn("subprocess", inspect.getsource(module))

    def test_netbox_adapter_never_raises_on_unexpected_exception(self):
        # Every public nsot_netbox function wraps its body in a broad
        # try/except and returns an "unavailable" envelope -- this is what
        # lets a NetBox outage degrade a page instead of crashing it.
        with patch("core.services.nsot_netbox._client", side_effect=RuntimeError("boom")):
            result = nsot_netbox.list_devices()
        self.assertEqual(result["status"], "unavailable")


class InvalidFilterTests(TestCase):
    def setUp(self):
        clear_nsot_cache()

    @patch("core.services.nsot_netbox.list_devices", side_effect=lambda: fixture_devices())
    def test_garbage_query_params_do_not_crash_devices_page(self, _mock):
        response = self.client.get(reverse("core:nsot_devices") + "?device=" + ("x" * 5000) + "&page=notanumber")
        self.assertEqual(response.status_code, 200)

    @patch("core.services.nsot_netbox.list_interfaces", return_value={"status": "available", "data": []})
    def test_garbage_device_filter_on_interfaces_page_is_safe(self, _mock):
        response = self.client.get(reverse("core:nsot_interfaces") + "?device=<script>alert(1)</script>")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("<script>alert(1)</script>", response.content.decode())


class PaginationTests(TestCase):
    def setUp(self):
        clear_nsot_cache()

    @patch("core.services.nsot_netbox.list_devices")
    def test_devices_page_paginates(self, mocked_devices):
        many = {
            "status": "available", "source": "NETBOX", "data": [
                {
                    "name": f"D{i}", "role": "Router", "device_type": "x", "manufacturer": "x",
                    "platform": None, "status": "Active", "site": "Lab", "primary_ipv4": None,
                    "primary_ipv6": None, "managed": True, "tags": [],
                }
                for i in range(40)
            ],
        }
        mocked_devices.return_value = many
        response = self.client.get(reverse("core:nsot_devices"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Page 1 of 2")


class MonitoringAndTopologyLinkTests(TestCase):
    def setUp(self):
        clear_nsot_cache()

    @patch("core.services.nsot_netbox.get_device_detail", side_effect=lambda name: fixture_device_detail())
    @patch("core.services.nsot_netbox.compare_device_facts", return_value={"status": "available", "data": {"equivalent": True, "differences": []}})
    @patch("core.services.nsot_git.read_catalogued_file", return_value={"status": "unavailable"})
    @patch("core.services.nsot_live.get_live_target", return_value=None)
    def test_device_detail_monitoring_links_use_validated_get_params(self, *_mocks):
        response = self.client.get(reverse("core:nsot_device_detail", args=["R1"]))
        html = response.content.decode()
        self.assertIn(f"{reverse('core:monitoring_resources')}?device=R1", html)
        self.assertIn(f"{reverse('core:monitoring_link_events')}?device=R1", html)

    def test_overview_links_back_to_home_for_topology(self):
        with netbox_unreachable():
            html = self.client.get(reverse("core:nsot")).content.decode()
        self.assertIn(reverse("core:home"), html)


class NoNetworkMutationTests(SimpleTestCase):
    def test_nsot_netbox_module_never_calls_reconcile_object(self):
        source = inspect.getsource(nsot_netbox)
        self.assertNotIn("reconcile_object(", source)
        self.assertNotIn(".save()", source)
        self.assertNotIn(".update(", source)
        self.assertNotIn(".delete(", source)

    def test_nsot_live_module_never_enters_config_mode(self):
        source = inspect.getsource(nsot_live.fetch_running_config)
        # conn.enable() IS called (mirrors master.py::verify_eos()'s own
        # established read-only pattern -- required for EOS to return
        # "show running-config" at all) but only raises CLI privilege
        # level; config_mode()/send_config_set() must never appear.
        self.assertIn("conn.enable(", source)
        for forbidden in ("config_mode", "send_config_set", "write memory", "copy running"):
            self.assertNotIn(forbidden, source)

    def test_running_config_is_the_only_route_requiring_get(self):
        source = inspect.getsource(views)
        # nsot_device_running_config is the one route that performs a
        # (bounded, read-only) live network call; it must be GET-only.
        marker = source.index("def nsot_device_running_config")
        preceding = source[:marker]
        self.assertIn("@require_GET", preceding[-80:])
