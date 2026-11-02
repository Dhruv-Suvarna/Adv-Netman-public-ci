"""Lab 7 closure -- the read-only NetBox adapter (``nsot_netbox``) and the NSOT aggregation layer (``nsot_service``).

A fake pynetbox client answers only ``filter()`` / ``all()`` and fails the test on any other attribute, so a NetBox
write is impossible by construction; the Git, topology and live sources are patched.  POSITIVE: every adapter
function returns the exact normalized ``available`` envelope, and every aggregate page combines its sources with a
CURRENT freshness.  NEGATIVE: a NetBox failure becomes an ``unavailable`` envelope naming only the exception class
(never a URL or token), an unknown or malformed device name is ``not_found`` without reading other sources, one
malformed device never hides the rest of the fleet, and a failed refresh serves the last good snapshot as STALE.
"""

from __future__ import annotations

from types import SimpleNamespace as NS
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase

from core.services import nsot_netbox, nsot_service
from modules import ipam_context as ic

SECRET_URL = "https://netbox.invalid/api/?token=fake-token-value"


class Endpoint:
    """Read-only fake pynetbox endpoint: ``filter`` matches simple keyword predicates; anything else fails."""

    def __init__(self, rows, log, name, keys=None):
        self._rows, self._log, self._name, self._keys = rows, log, name, keys or {}

    def filter(self, **kwargs):
        self._log.append(f"{self._name}.filter")
        return [row for row in self._rows if all(k not in self._keys or self._keys[k](row) == v for k, v in kwargs.items())]

    def all(self):
        self._log.append(f"{self._name}.all")
        return list(self._rows)

    def __getattr__(self, item):
        raise AssertionError(f"unexpected NetBox call {self._name}.{item}")


def label(value):
    return NS(label=value)


R1 = NS(name="R1")


def fake_client(log, *, extra_v4=False):
    eth1 = NS(id=1, name="Ethernet1", device=R1, type=label("1000BASE-T"), description="uplink", mac_address="aa:bb:cc:00:00:01",
              mode=None, untagged_vlan=None, enabled=True, custom_fields={"ipv4_assignment_mode": "static", "ipv6_assignment_mode": "static"},
              primary_mac_address=NS(id=7))
    vlan10 = NS(id=2, name="Vlan10", device=R1, type=label("Virtual"), description="", mac_address=None, mode=label("Access"),
                untagged_vlan=NS(vid=10), enabled=False, custom_fields={}, primary_mac_address=None)
    addresses = [
        NS(address="10.0.0.1/31", family=NS(value=4), role=None, status=label("Active"), description="p2p", assigned_object=NS(id=1, name="Ethernet1", device=R1)),
        NS(address="2001:db8::1/64", family=NS(value=6), role=None, status=label("Active"), description="", assigned_object=NS(id=1, name="Ethernet1", device=R1)),
        NS(address="10.0.0.0/31", family=NS(value=4), role=None, status=label("Active"), description="", assigned_object=None),
        NS(address="192.0.2.1/24", family=NS(value=4), role=NS(value="vrrp", label=None, name=None), status=label("Active"), description="",
           assigned_object=None),
    ]
    if extra_v4:
        addresses.append(NS(address="10.0.0.5/31", family=NS(value=4), role=None, status=label("Active"), description="",
                            assigned_object=NS(id=1, name="Ethernet1", device=R1)))
    device = NS(id=1, name="R1", tags=[NS(name="managed"), NS(name="csci5840-iac")], custom_fields={"iac_managed": True},
                role=label("Router"), device_type=NS(id=3, model=label("cEOS-lab"), manufacturer=label("Arista")), platform=label("EOS"),
                status=label("Active"), site=label("Lab"), primary_ip4="192.168.200.1/24", primary_ip6=None)
    web = NS(id=2, name="WebServer", tags=[], custom_fields={}, role=None, device_type=None, platform=None, status=label("Active"), site=None,
             primary_ip4=None, primary_ip6=None)
    return NS(
        dcim=NS(devices=Endpoint([web, device], log, "devices", {"device_type_id": lambda r: r.device_type.id if r.device_type else None}),
                interfaces=Endpoint([vlan10, eth1], log, "interfaces", {"device": lambda r: r.device.name}),
                device_types=Endpoint([NS(id=3, model="cEOS-lab", manufacturer=label("Arista"))], log, "device_types"),
                mac_addresses=Endpoint([NS(id=7, mac_address="aa:bb:cc:00:00:01", custom_fields={"identity_status": "VERIFIED"})], log, "mac_addresses")),
        ipam=NS(ip_addresses=Endpoint(addresses, log, "ip_addresses",
                                      {"interface_id": lambda r: getattr(r.assigned_object, "id", None)}),
                prefixes=Endpoint([NS(prefix="10.0.0.0/31", family=NS(value=4), status=label("Active"), role=None, vlan=None, description=""),
                                   NS(prefix="192.0.2.0/24", family=NS(value=4), status=label("Active"), role=label("Users"), vlan=NS(vid=10),
                                      description="users")], log, "prefixes"),
                vlans=Endpoint([NS(vid=200, name="MGMT", status=label("Active"), role=None, description=""),
                                NS(vid=10, name="USERS", status=label("Active"), role=label("Users"), description="users")], log, "vlans"),
                asns=Endpoint([NS(asn=65001, description="", sites=[NS(name="Lab")])], log, "asns")),
    )


def broken_client():
    raise ConnectionError(SECRET_URL)


class AdapterTests(SimpleTestCase):
    def call(self, function, *args, **client_kwargs):
        log = []
        with mock.patch.object(nsot_netbox, "_client", return_value=fake_client(log, **client_kwargs)), \
                mock.patch.object(nsot_netbox.nb, "get_managed_devices", return_value=["R1"]):
            found = function(*args)
        self.assertTrue(all(entry.endswith((".filter", ".all")) for entry in log), log)
        return found

    def assert_available(self, envelope):
        self.assertEqual((envelope["status"], envelope["source"]), ("available", "NETBOX"))
        self.assertTrue(envelope["fetched_at"])
        return envelope["data"]

    def test_device_listings_return_normalized_rows(self):
        devices = self.assert_available(self.call(nsot_netbox.list_devices))
        self.assertEqual(devices[0], {"name": "R1", "role": "Router", "device_type": "cEOS-lab", "manufacturer": "Arista", "platform": "EOS",
                                      "status": "Active", "site": "Lab", "primary_ipv4": "192.168.200.1", "primary_ipv6": None, "managed": True,
                                      "tags": ["csci5840-iac", "managed"]})
        self.assertEqual((devices[1]["name"], devices[1]["managed"], devices[1]["device_type"]), ("WebServer", False, None))
        self.assertEqual(self.assert_available(self.call(nsot_netbox.managed_device_names)), ["R1"])
        self.assertEqual(self.assert_available(self.call(nsot_netbox.get_device_types)), [{"model": "cEOS-lab", "manufacturer": "Arista", "device_count": 1}])
        self.assertEqual(self.assert_available(self.call(nsot_netbox.list_asns)), [{"asn": 65001, "description": None, "sites": ["Lab"]}])

    def test_get_device_detail_returns_summary_and_sorted_interfaces(self):
        data = self.assert_available(self.call(nsot_netbox.get_device_detail, "R1"))
        self.assertEqual(data["summary"]["name"], "R1")
        self.assertEqual([i["name"] for i in data["interfaces"]], ["Ethernet1", "Vlan10"])
        self.assertEqual(data["interfaces"][0]["addresses"], [{"address": "10.0.0.1", "prefix_length": 31, "family": 4, "role": None},
                                                              {"address": "2001:db8::1", "prefix_length": 64, "family": 6, "role": None}])
        self.assertEqual({k: data["interfaces"][1][k] for k in ("mode", "untagged_vlan", "enabled", "description", "mac_address")},
                         {"mode": "Access", "untagged_vlan": 10, "enabled": False, "description": None, "mac_address": None})

    def test_get_device_detail_of_an_unknown_device_is_not_found(self):
        self.assertEqual(self.call(nsot_netbox.get_device_detail, "R9"),
                         {"status": "not_found", "source": "NETBOX", "message": "'R9' is not a known NetBox device.", "data": None})

    def test_ipam_listings_return_sorted_rows(self):
        interfaces = self.assert_available(self.call(nsot_netbox.list_interfaces, "R1"))
        self.assertEqual([(r["device"], r["name"], r["address_count"], r["addresses"]) for r in interfaces],
                         [("R1", "Ethernet1", 2, ["10.0.0.1/31", "2001:db8::1/64"]), ("R1", "Vlan10", 0, [])])
        self.assertEqual(self.assert_available(self.call(nsot_netbox.list_prefixes)),
                         [{"prefix": "10.0.0.0/31", "family": 4, "status": "Active", "role": None, "vlan": None, "description": None},
                          {"prefix": "192.0.2.0/24", "family": 4, "status": "Active", "role": "Users", "vlan": 10, "description": "users"}])
        filtered = self.assert_available(self.call(nsot_netbox.list_ip_addresses, "10.0.0.0/24"))
        self.assertEqual([(r["address"], r["device"], r["interface"]) for r in filtered], [("10.0.0.0/31", None, None), ("10.0.0.1/31", "R1", "Ethernet1")])
        self.assertEqual([(v["vid"], v["static_management"]) for v in self.assert_available(self.call(nsot_netbox.list_vlans))], [(10, False), (200, True)])

    def test_list_ip_addresses_filters_by_network_containment(self):
        # Regression: the filter once compared string prefixes, so 10.0.0.1/31 was dropped from 10.0.0.0/24.
        inside = self.assert_available(self.call(nsot_netbox.list_ip_addresses, "10.0.0.0/30"))
        self.assertEqual([r["address"] for r in inside], ["10.0.0.0/31", "10.0.0.1/31"])
        self.assertEqual([r["address"] for r in self.assert_available(self.call(nsot_netbox.list_ip_addresses, "2001:db8::/32"))], ["2001:db8::1/64"])

    def test_list_ip_addresses_with_an_invalid_prefix_is_unavailable(self):
        self.assertEqual(self.call(nsot_netbox.list_ip_addresses, "10.0.0.0/99"),
                         {"status": "unavailable", "source": "NETBOX", "message": "NetBox temporarily unavailable (ValueError).", "data": []})

    def test_reservation_report_returns_the_validated_readiness(self):
        data = self.assert_available(self.call(nsot_netbox.reservation_report))
        self.assertEqual(data, {"rows_checked": 2, "overall_status": "READY", "readiness_counts": {"READY": 0, "BLOCKED": 0, "FAIL": 0}, "ok": True})

    def test_health_and_dhcp_ranges_return_the_module_results(self):
        with mock.patch.object(nsot_netbox.nb, "check_status", return_value={"netbox-version": "4.2"}):
            self.assertEqual(self.assert_available(nsot_netbox.health()), {"netbox-version": "4.2"})
        with mock.patch.object(nsot_netbox, "_client", return_value=object()), \
                mock.patch.object(nsot_netbox.nb, "get_dhcp_ranges", return_value=[{"start": "192.0.2.100"}]) as ranges:
            self.assertEqual(self.assert_available(nsot_netbox.list_dhcp_ranges()), [{"start": "192.0.2.100"}])
        self.assertEqual(list(ranges.call_args.kwargs), ["client"])

    def test_every_adapter_returns_unavailable_without_leaking_the_url_when_netbox_fails(self):
        calls = {"list_devices": [], "managed_device_names": [], "list_interfaces": [], "list_prefixes": [], "list_ip_addresses": [],
                 "list_vlans": [], "list_dhcp_ranges": [], "list_asns": [], "get_device_types": [], "get_device_detail": None,
                 "reservation_report": None, "compare_device_facts": None}
        with mock.patch.object(nsot_netbox, "_client", side_effect=broken_client), \
                mock.patch.object(nsot_netbox.nb, "check_status", side_effect=TimeoutError(SECRET_URL)):
            for name, empty in calls.items():
                with self.subTest(case=f"unavailable {name}"):
                    args = ("R1",) if name in ("get_device_detail", "compare_device_facts") else ()
                    found = getattr(nsot_netbox, name)(*args)
                    self.assertEqual(found, {"status": "unavailable", "source": "NETBOX",
                                             "message": "NetBox temporarily unavailable (ConnectionError).", "data": empty})
            with self.subTest(case="unavailable health"):
                self.assertEqual(nsot_netbox.health()["message"], "NetBox temporarily unavailable (TimeoutError).")


class CompareFactsTests(SimpleTestCase):
    LEGACY = ic.DeviceFacts(interfaces={"Ethernet1": {"ipv4": "10.0.0.1/31", "ipv6": "2001:db8::1/64"}}, peer_candidates={"10.0.0.0"},
                            vrrp_gateways={"Vlan10": {"ipv4": "192.0.2.1", "ipv6": None}}, referenced_prefixes={"192.0.2.0/24"})

    def many(self, names, **client_kwargs):
        with mock.patch.object(nsot_netbox, "_client", return_value=fake_client([], **client_kwargs)), \
                mock.patch.object(ic, "extract_legacy_facts", return_value=self.LEGACY):
            return nsot_netbox.compare_device_facts_many(names)

    def test_compare_device_facts_many_returns_equivalent_for_matching_netbox_facts(self):
        found = self.many(["R1", "R1"])
        self.assertEqual(list(found), ["R1"])
        self.assertEqual((found["R1"]["status"], found["R1"]["data"]), ("available", {"equivalent": True, "differences": []}))
        self.assertEqual(nsot_netbox.compare_device_facts_many([]), {})

    def test_compare_device_facts_many_isolates_a_malformed_device_and_degrades_a_fleet_failure(self):
        found = self.many(["R1"], extra_v4=True)
        self.assertEqual(found["R1"]["message"], "NetBox temporarily unavailable (ValueError).")
        with mock.patch.object(nsot_netbox, "_client", side_effect=broken_client):
            self.assertEqual({k: v["status"] for k, v in nsot_netbox.compare_device_facts_many(["R1", "R2"]).items()},
                             {"R1": "unavailable", "R2": "unavailable"})

    def test_compare_device_facts_returns_the_field_differences(self):
        netbox = ic.DeviceFacts(interfaces={"Ethernet1": {"ipv4": "10.0.0.3/31", "ipv6": "2001:db8::1/64"}})
        with mock.patch.object(nsot_netbox, "_client", return_value=object()), \
                mock.patch.object(ic, "extract_legacy_facts", return_value=ic.DeviceFacts(interfaces={"Ethernet1": {"ipv4": "10.0.0.1/31", "ipv6": "2001:db8::1/64"}})), \
                mock.patch.object(ic, "build_netbox_facts", return_value=netbox):
            data = nsot_netbox.compare_device_facts("R1")["data"]
        self.assertFalse(data["equivalent"])
        self.assertEqual(len(data["differences"]), 1)
        self.assertIn("10.0.0.3/31", str(data["differences"][0]))


def envelope(data):
    return {"status": "available", "source": "NETBOX", "fetched_at": "2026-10-19T00:00:00+00:00", "data": data}


TOPOLOGY = {"status": "available", "node_count": 2, "edge_count": 1, "message": "",
            "data": {"graph": {"nodes": [{"canonical_name": "R1"}, {"canonical_name": "WebServer"}],
                               "edges": [{"id": "e1", "source": "R1", "target": "R2", "status": "up"}, {"id": "e2", "source": "S1", "target": "R1", "status": "down"}]}}}
DEVICES = envelope([{"name": "R1", "managed": True}, {"name": "WebServer", "managed": False}])
READ_CATALOGUED_FILE = nsot_service.nsot_git.read_catalogued_file   # the real allowlist reader (captured before any patch)


class AggregationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def sources(self):
        patches = [mock.patch.object(nsot_netbox, name, return_value=value) for name, value in (
            ("health", envelope({})), ("list_devices", DEVICES), ("list_interfaces", envelope([1, 2, 3])), ("list_prefixes", envelope([1])),
            ("list_ip_addresses", envelope([1, 2])), ("list_vlans", envelope([10, 200])), ("list_dhcp_ranges", envelope([])),
            ("list_asns", envelope([])), ("get_device_types", envelope([])),
            ("reservation_report", envelope({"ok": True, "rows_checked": 4, "overall_status": "READY", "readiness_counts": {}})),
            ("get_device_detail", envelope({"summary": {"name": "R1"}})),
            ("compare_device_facts", envelope({"equivalent": True, "differences": []})),
            ("compare_device_facts_many", {"R1": envelope({"equivalent": False, "differences": [{}, {}]})}))]
        patches += [mock.patch.object(nsot_service.nsot_git, "get_repo_state", return_value={"status": "available", "head": "abc"}),
                    mock.patch.object(nsot_service.nsot_git, "read_catalogued_file", return_value={"status": "available", "path": "templates/R1.cfg.j2"}),
                    mock.patch.object(nsot_service.nsot_git, "list_catalogued_files", return_value={"status": "available", "data": ["a"]}),
                    mock.patch.object(nsot_service.nsot_live, "get_live_target_metadata", return_value={"platform": "ceos", "address": "192.168.200.1"}),
                    mock.patch.object(nsot_service.nsot_live, "fetch_running_config", return_value={"status": "available", "data": "hostname R1"}),
                    mock.patch.object(nsot_service.topology_service, "get_topology_summary", return_value=TOPOLOGY)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_overview_and_summary_return_counts_from_every_source(self):
        self.sources()
        found = nsot_service.get_nsot_summary()
        self.assertEqual(found["netbox"], {"status": "available", "device_count": 2, "interface_count": 3, "prefix_count": 1, "address_count": 2,
                                           "vlan_count": 2, "source": "NETBOX"})
        self.assertEqual((found["git"]["head"], found["topology"]["node_count"], found["cache"], found["freshness"]["state"], found["page_title"]),
                         ("abc", 2, "miss", "CURRENT", "NSOT"))
        self.assertEqual(nsot_service.get_overview()["cache"], "hit")

    def test_device_detail_returns_drift_template_live_and_neighbors(self):
        self.sources()
        found = nsot_service.get_device_detail("R1")
        self.assertEqual((found["status"], found["device"], found["git_template"], found["live"]),
                         ("available", {"summary": {"name": "R1"}}, {"status": "available", "path": "templates/R1.cfg.j2", "available": True},
                          {"supported": True, "address": "192.168.200.1"}))
        self.assertEqual(found["topology_neighbors"]["data"], [{"neighbor": "R2", "status": "up", "edge_id": "e1"}, {"neighbor": "S1", "status": "down", "edge_id": "e2"}])
        self.assertTrue(found["monitoring_links"]["resources"].endswith("?device=R1"))
        self.assertEqual(nsot_service.fetch_device_running_config("R1"), {"status": "available", "data": "hostname R1"})

    def test_device_detail_and_running_config_refuse_unknown_or_malformed_names(self):
        self.sources()
        for name in ("../etc", "R1;rm", "", "x" * 65):
            with self.subTest(case=f"refused {name[:8]}"):
                self.assertEqual(nsot_service.get_device_detail(name), {"status": "not_found", "message": "Unknown device.", "data": None})
                self.assertEqual(nsot_service.fetch_device_running_config(name), {"status": "not_found", "message": "Unknown device.", "data": None})
        nsot_service.nsot_live.fetch_running_config.assert_not_called()
        with mock.patch.object(nsot_netbox, "get_device_detail", return_value={"status": "not_found", "message": "nope"}):
            found = nsot_service.get_device_detail("R9")
        self.assertEqual((found["status"], found["device"]), ("not_found", None))
        nsot_netbox.compare_device_facts.assert_not_called()
        nsot_service.nsot_git.read_catalogued_file.assert_not_called()

    def test_ipam_vlans_routing_platforms_templates_and_git_return_their_sources(self):
        self.sources()
        self.assertEqual(nsot_service.get_ipam()["reservations"]["data"]["overall_status"], "READY")
        self.assertEqual(nsot_service.get_vlans()["data"], [10, 200])
        self.assertEqual(nsot_service.get_interfaces("R1")["data"], [1, 2, 3])
        nsot_netbox.list_interfaces.assert_called_once_with("R1")
        self.assertEqual(nsot_service.get_routing()["git_routing_summary"]["source"], "GIT")
        self.assertEqual([r["platform"] for r in nsot_service.get_platforms()["known_images"]["rows"]], ["Arista cEOS", "Ubuntu + FRRouting"])
        self.assertEqual(nsot_service.get_templates_catalogue()["data"], ["a"])
        self.assertEqual(nsot_service.get_template_file("templates/R1.cfg.j2")["path"], "templates/R1.cfg.j2")
        self.assertEqual(nsot_service.get_git_state()["head"], "abc")
        self.assertEqual(nsot_service.get_devices()["data"], DEVICES["data"])

    def test_getters_with_a_failing_source_and_no_snapshot_are_unavailable_never_fabricated(self):
        self.sources()
        for name, target, call in (
            ("overview", (nsot_netbox, "health"), lambda: nsot_service.get_overview(force_refresh=True)),
            ("ipam", (nsot_netbox, "reservation_report"), lambda: nsot_service.get_ipam(force_refresh=True)),
            ("routing", (nsot_netbox, "list_asns"), lambda: nsot_service.get_routing(force_refresh=True)),
            ("templates", (nsot_service.nsot_git, "list_catalogued_files"), lambda: nsot_service.get_templates_catalogue(force_refresh=True)),
            ("git", (nsot_service.nsot_git, "get_repo_state"), lambda: nsot_service.get_git_state(force_refresh=True)),
        ):
            with self.subTest(case=f"unavailable {name}"), mock.patch.object(*target, side_effect=RuntimeError("source down")):
                found = call()
                self.assertEqual((found["status"], found["message"], found["data"], found["cache"]), ("unavailable", "source down", None, "miss"))
        with self.subTest(case="refused template outside the allowlist"), \
                mock.patch.object(nsot_service.nsot_git, "read_catalogued_file", wraps=READ_CATALOGUED_FILE), \
                mock.patch.object(nsot_service.nsot_git, "list_catalogued_files", return_value={"status": "available", "data": [{"path": "templates/R1.cfg.j2"}]}):
            self.assertEqual(nsot_service.get_template_file("../../etc/passwd"),
                             {"status": "unavailable", "message": "File is not in the allowlisted catalogue.", "source": "GIT"})

    def test_interfaces_ignore_a_malformed_device_filter(self):
        self.sources()
        nsot_service.get_interfaces("R1 OR 1=1")
        nsot_netbox.list_interfaces.assert_called_once_with(None)

    def test_drift_returns_one_check_per_domain(self):
        self.sources()
        checks = {c["domain"]: (c["status"], c["detail"]) for c in nsot_service.get_drift()["checks"]}
        self.assertEqual(checks["netbox_vs_git:R1"], ("DRIFT", "2 field difference(s)."))
        self.assertEqual(checks["netbox_vs_git:WebServer"][0], "UNMANAGED")
        self.assertEqual(checks["reservation_readiness"], ("IN_SYNC", "4 rows checked, overall READY."))
        self.assertEqual(checks["topology_vs_netbox"], ("IN_SYNC", "Device sets match."))
        self.assertEqual(checks["netbox_vs_live"][0], "NOT_COMPARABLE")

    def test_drift_reports_unavailable_sources_without_fabricating_results(self):
        self.sources()
        down = {"status": "unavailable", "source": "NETBOX", "message": "NetBox temporarily unavailable (ConnectionError).", "data": []}
        with mock.patch.object(nsot_netbox, "list_devices", return_value=down), \
                mock.patch.object(nsot_netbox, "reservation_report", return_value={**down, "data": None}):
            checks = {c["domain"]: c["status"] for c in nsot_service.get_drift(force_refresh=True)["checks"]}
        self.assertEqual(checks, {"netbox_vs_git": "UNAVAILABLE", "reservation_readiness": "UNAVAILABLE", "topology_vs_netbox": "UNAVAILABLE",
                                  "netbox_vs_live": "NOT_COMPARABLE"})
        nsot_netbox.compare_device_facts_many.assert_not_called()

    def test_a_failed_refresh_serves_the_last_good_snapshot_as_stale(self):
        self.sources()
        self.assertEqual(nsot_service.get_vlans()["freshness"]["state"], "CURRENT")
        with mock.patch.object(nsot_netbox, "list_vlans", return_value={"status": "unavailable", "message": "NetBox down", "data": []}):
            stale = nsot_service.get_vlans(force_refresh=True)
        self.assertEqual((stale["data"], stale["cache"], stale["refresh_error"], stale["freshness"]["state"]), ([10, 200], "stale", "NetBox down", "STALE"))
        cache.clear()
        with mock.patch.object(nsot_netbox, "get_device_types", side_effect=RuntimeError("boom")):
            failed = nsot_service.get_platforms(force_refresh=True)
        self.assertEqual((failed["status"], failed["message"], failed["data"], failed["freshness"]), ("unavailable", "boom", None, {"state": "STALE", "age_seconds": None}))
