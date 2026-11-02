"""Lab 7 closure -- Fleet Quick, the Deep-Health device checks, the telemetry adapters and the managed inventory,
each called directly.

Telemetry is a synthetic topology summary (``helpers.health``), NetBox / Grafana / the provisioning registry are
patched, and the DHCP state is injected -- no device, InfluxDB, NetBox, Grafana or Docker is contacted.  POSITIVE:
exact per-device rows, fleet conditions, reachability, fact summaries and inventory lookups.  NEGATIVE: an unavailable
topology yields UNKNOWN (never UNHEALTHY) with no metric invented, an unknown device is None, a failed live query is
UNKNOWN unless telemetry is also expired, unavailable groups are left out of the fact summary, and an unreadable
registry admits nothing.
"""

from __future__ import annotations

from unittest import mock

from django.test import SimpleTestCase

from core.services.health import device as dm
from core.services.health import fleet, inventory, telemetry
from core.services.health.codes import CheckStatus as S, Freshness, Health, Role
from core.services.health.evidence import DeviceEvidence
from core.tests.helpers import health as h

OSPF = [{"neighbor_id": "1.1.1.1", "interface": "Ethernet1", "state": "FULL"}]


class QuickCheckTests(SimpleTestCase):
    def evidence(self, snap, name="R1"):
        return telemetry.device_evidence(snap, name, "ceos")

    def test_quick_checks_and_device_row_of_fresh_normal_telemetry(self):
        snap = h.snapshot(links=[h.edge("R1", "R2")])
        results = fleet.quick_checks("R1", self.evidence(snap), snap, now=h.NOW)
        self.assertEqual([(r.check_code, r.status) for r in results], [("DEVICE_TELEMETRY_FRESH", S.PASS), ("CPU_HIGH", S.PASS), ("MEMORY_HIGH", S.PASS),
                                                                       ("CRITICAL_EVENTS_RECENT", S.PASS), ("LINK_HEALTH_DEGRADED", S.PASS)])
        row = fleet.device_row({"name": "R1", "platform": "ceos"}, self.evidence(snap), snap, results, h.NOW)
        self.assertEqual({k: row[k] for k in ("device", "health", "freshness", "age_seconds", "cpu_percent", "memory_percent", "link_issues", "routing_issues", "issues")},
                         {"device": "R1", "health": Health.HEALTHY, "freshness": Freshness.FRESH, "age_seconds": 5.0, "cpu_percent": 20.0,
                          "memory_percent": 30.0, "link_issues": 0, "routing_issues": None, "issues": []})
        self.assertEqual([link["status"] for link in telemetry.link_states(snap, "R1")], ["UP"])

    def test_quick_checks_and_device_row_of_an_unavailable_topology_invent_no_metric(self):
        snap = h.snapshot(summary=h.unavailable_topology())
        evidence = self.evidence(snap)
        results = fleet.quick_checks("R1", evidence, snap, now=h.NOW)
        self.assertEqual([(r.check_code, r.status) for r in results], [("DEVICE_TELEMETRY_UNAVAILABLE", S.UNKNOWN)])
        row = fleet.device_row({"name": "R1", "platform": "ceos"}, evidence, snap, results, h.NOW)
        self.assertEqual((row["health"], row["cpu_percent"], row["memory_percent"], row["link_issues"], row["age_seconds"]), (Health.UNKNOWN, None, None, None, None))
        self.assertEqual((telemetry.link_states(snap, "R1"), evidence.group("telemetry").error), ([], "TOPOLOGY_UNAVAILABLE"))

    def test_device_evidence_returns_telemetry_for_a_topology_node(self):
        group = self.evidence(h.snapshot(cpu={"R1": 55}), "R1").group("telemetry")
        self.assertEqual((group.available, group.data["cpu_percent"], group.data["monitored"]), (True, 55.0, True))

    def test_device_evidence_of_a_device_missing_from_topology_is_unavailable(self):
        self.assertEqual(self.evidence(h.snapshot(), "R99").group("telemetry").error, "NOT_IN_TOPOLOGY")

    def test_fleet_conditions_of_healthy_sources_all_pass(self):
        snap = h.snapshot()
        found = fleet.fleet_conditions(snap, [{"freshness": Freshness.FRESH}], netbox=True, grafana=True)
        self.assertEqual([(c.check_code, c.status) for c in found], [("TOPOLOGY_SERVICE_UNAVAILABLE", S.PASS), ("MONITORING_PIPELINE_UNHEALTHY", S.PASS),
                                                                     ("TELEMETRY_COLLECTOR_SILENT", S.PASS), ("NETBOX_SOURCE_UNAVAILABLE", S.PASS),
                                                                     ("GRAFANA_UNAVAILABLE", S.PASS)])

    def test_fleet_conditions_of_unavailable_sources_are_never_green(self):
        found = fleet.fleet_conditions(h.snapshot(summary=h.unavailable_topology()), [], netbox=False, grafana=None)
        self.assertEqual([(c.check_code, c.status) for c in found], [("TOPOLOGY_SERVICE_UNAVAILABLE", S.FAIL), ("MONITORING_PIPELINE_UNHEALTHY", S.UNKNOWN),
                                                                     ("NETBOX_SOURCE_UNAVAILABLE", S.WARN)])
        silent = fleet.fleet_conditions(h.snapshot(), [{"freshness": Freshness.STALE}], netbox=None, grafana=False)
        self.assertEqual([(c.check_code, c.status) for c in silent][-2:], [("TELEMETRY_COLLECTOR_SILENT", S.WARN), ("GRAFANA_UNAVAILABLE", S.WARN)])

    def test_get_device_quick_returns_the_row_of_a_managed_device(self):
        row = fleet.get_device_quick("R1", snapshot=h.snapshot(), now=h.NOW)
        self.assertEqual((row["device"], row["health"]), ("R1", Health.HEALTHY))

    def test_get_device_quick_of_an_unknown_device_is_none(self):
        with mock.patch.object(telemetry, "collect", side_effect=AssertionError("no telemetry read")):
            self.assertIsNone(fleet.get_device_quick("NOPE", now=h.NOW))

    def test_netbox_and_grafana_probes_return_their_availability(self):
        with mock.patch("core.services.nsot_netbox.health", return_value={"status": "available"}), \
                mock.patch("core.services.monitoring_service.get_grafana_health", return_value={"status": "available"}):
            self.assertEqual((telemetry.netbox_reachable(), telemetry.grafana_available()), (True, True))


class DeepCheckTests(SimpleTestCase):
    def test_reachability_check_passes_after_a_completed_live_query(self):
        found = dm.reachability_check("R1", h.device_evidence("R1"), Freshness.FRESH, role=Role.TARGET)
        self.assertEqual((found.check_code, found.status, found.freshness, found.observed), ("DEVICE_REACHABLE", S.PASS, Freshness.FRESH, {"reachable": True}))

    def test_reachability_check_of_a_failed_or_absent_query_is_never_green(self):
        failed = DeviceEvidence("R1", platform="ceos", live_attempted=True, live_error="TIMEOUT")
        self.assertEqual([(r.check_code, r.status) for r in (dm.reachability_check("R1", failed, Freshness.FRESH, role=Role.TARGET),
                                                            dm.reachability_check("R1", failed, Freshness.EXPIRED, role=Role.TARGET))],
                         [("DEVICE_UNREACHABLE", S.UNKNOWN), ("DEVICE_UNREACHABLE", S.FAIL)])
        absent = dm.reachability_check("R1", DeviceEvidence("R1", platform="ceos"), Freshness.FRESH, role=Role.FLEET)
        self.assertEqual((absent.status, absent.observed["reason_code"]), (S.NOT_APPLICABLE, "NOT_ATTEMPTED"))

    def test_facts_summary_returns_bounded_normalized_groups(self):
        evidence = h.device_evidence("R1", interfaces={"Ethernet1": {"admin": "UP", "oper": "UP"}}, addresses={"Ethernet1": ["10.0.0.1/31"]},
                                     routes=[{"prefix": "0.0.0.0/0"}], ospf=OSPF, bgp=[])
        found = dm.facts_summary(evidence)
        self.assertEqual((found["interfaces"], found["routes"], found["ospf"], found["bgp"], found["live"]),
                         ([{"name": "Ethernet1", "admin": "UP", "oper": "UP", "addresses": ["10.0.0.1/31"]}], {"count": 1, "sample": ["0.0.0.0/0"]},
                          OSPF, [], {"attempted": True, "error": ""}))
        self.assertEqual(sorted(found["groups"]), ["addresses", "bgp", "interfaces", "ospf", "routes"])

    def test_facts_summary_leaves_out_unavailable_groups(self):
        found = dm.facts_summary(h.device_evidence("R1", live_ok=False, interfaces=None, routes=None))
        self.assertEqual((sorted(found), found["groups"]["interfaces"]["available"], found["live"]), (["groups", "live"], False, {"attempted": False, "error": "TIMEOUT"}))

    def test_deep_checks_pass_for_up_interfaces_and_full_adjacencies(self):
        evidence = h.device_evidence("R1", interfaces={"Ethernet1": {"admin": "UP", "oper": "UP"}}, addresses={"Ethernet1": ["10.0.0.1/31"]}, ospf=OSPF)
        evidence.groups["telemetry"] = telemetry.device_evidence(h.snapshot(), "R1", "ceos").group("telemetry")
        found = {(r.check_code, r.status) for r in dm.deep_checks("R1", evidence, h.snapshot(), h.NOW, role=Role.TARGET, dhcp_state={})}
        self.assertTrue({("DEVICE_REACHABLE", S.PASS), ("DEVICE_TELEMETRY_FRESH", S.PASS), ("INTERFACE_EXPECTED_UP", S.PASS), ("OSPF_EXPECTED_FULL", S.PASS)} <= found)

    def test_deep_checks_fail_down_interfaces_adjacencies_and_record_conflicts(self):
        evidence = h.device_evidence("R1", interfaces={"Ethernet1": {"admin": "UP", "oper": "DOWN"}, "Ethernet2": {"admin": "DOWN", "oper": "DOWN"}},
                                     addresses={"Ethernet1": ["10.0.0.1/31"], "Ethernet2": ["10.0.0.3/31"]},
                                     ospf=[{**OSPF[0], "state": "INIT"}], bgp=[{"peer": "10.0.0.2", "state": ""}])
        evidence.conflicts.append({"key": "Ethernet1", "live": "DOWN", "telemetry": "UP"})
        found = {(r.check_code, r.status, r.subject) for r in dm.deep_checks("R1", evidence, h.snapshot(), h.NOW, role=Role.TARGET, dhcp_state={})}
        self.assertTrue({("INTERFACE_OPER_DOWN", S.FAIL, "Ethernet1"), ("INTERFACE_ADMIN_DOWN", S.WARN, "Ethernet2"), ("OSPF_ADJACENCY_DOWN", S.FAIL, "Ethernet1/1.1.1.1"),
                         ("BGP_SESSION_DOWN", S.FAIL, "10.0.0.2"), ("EVIDENCE_CONFLICT", S.WARN, "Ethernet1")} <= found)


class InventoryTests(SimpleTestCase):
    def test_inventory_lookups_return_the_tracked_devices(self):
        self.assertIn("network_devices", inventory.load_inventory())
        self.assertEqual((inventory.health_platform("arista_ceos"), inventory.health_platform("ubuntu_frr")), ("ceos", "linux"))
        self.assertEqual(inventory.get_managed_device("R1")["platform"], "ceos")
        hosts = inventory.dhcp_hosts()
        self.assertEqual(set(hosts), {"primary", "secondary", "secondary_device"})
        self.assertEqual(inventory.managed_devices()[hosts["secondary_device"]]["address"], hosts["secondary"])

    def test_inventory_lookups_of_unknown_names_or_platforms_are_none_or_unknown(self):
        self.assertEqual((inventory.get_managed_device("NOPE"), inventory.health_platform(None), inventory.health_platform("vyos")), (None, "unknown", "vyos"))

    def test_provisioned_devices_returns_registry_entries_without_overriding_inventory(self):
        entries = {"P9": {"name": "P9", "platform": "ceos", "address": "192.0.2.9"}, "R1": {"name": "R1", "platform": "linux"}}
        with mock.patch("core.services.provisioning.registry.devices", return_value=entries):
            self.assertEqual(inventory.provisioned_devices(), entries)
            managed = inventory.managed_devices()
        self.assertEqual((managed["P9"]["address"], managed["R1"]["platform"]), ("192.0.2.9", "ceos"))

    def test_provisioned_devices_of_an_unreadable_registry_admit_none(self):
        with mock.patch("core.services.provisioning.registry.devices", side_effect=RuntimeError("no table")):
            self.assertEqual(inventory.provisioned_devices(), {})
            self.assertIsNone(inventory.get_managed_device("P9"))
