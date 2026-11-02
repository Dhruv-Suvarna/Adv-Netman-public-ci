"""NSOT: device / interface / address parsing, empty and unavailable NetBox, stale reads, search and filters.  Read-only throughout."""

from __future__ import annotations

from challenge_console import filters
from challenge_console import models as m
from challenge_console.adapters import netbox
from challenge_console.adapters.http import HttpResult
from challenge_console.adapters.process import CommandResult
from challenge_console.collectors import NsotCollector
from challenge_console.supervisor import CollectorError

from .helpers import INVENTORY, ConsoleTestCase, FakeGetter, FakeRunner, ok_json

BASE = "http://netbox.test"


def tag(slug):
    return {"slug": slug, "name": slug}


DEVICES = [
    {"id": 1, "name": "R1", "role": {"name": "Router"}, "platform": None, "device_type": {"display": "cEOS-lab"}, "site": {"name": "Lab"},
     "status": {"value": "active", "label": "Active"}, "primary_ip4": {"address": "192.0.2.1/24"}, "primary_ip6": {"address": "2001:db8::1/64"},
     "tags": [tag("csci5840-iac"), tag("managed")]},
    {"id": 3, "name": "R3", "role": {"name": "Router"}, "platform": {"name": "Ubuntu FRR"}, "device_type": {"display": "ubuntu-24-04"},
     "status": {"label": "Active"}, "primary_ip4": {"address": "192.0.2.33/24"}, "primary_ip6": None, "tags": [tag("managed")]},
    {"id": 5, "name": "R5", "role": {"name": "External / Unmanaged"}, "status": {"label": "Active"},
     "primary_ip4": {"address": "192.168.255.5/32"}, "primary_ip6": None, "tags": [tag("unmanaged")]},
]
INTERFACES = [
    {"id": 10, "device": {"name": "R1"}, "name": "Vlan200", "type": {"label": "Virtual"}, "enabled": True, "mgmt_only": True, "description": "mgmt"},
    {"id": 11, "device": {"name": "R1"}, "name": "Ethernet2", "type": {"label": "Virtual"}, "enabled": True, "mgmt_only": False, "description": ""},
    {"id": 30, "device": {"name": "R3"}, "name": "eth3", "type": {"label": "Virtual"}, "enabled": True, "mgmt_only": True, "description": ""},
    {"id": 50, "device": {"name": "R5"}, "name": "Loopback0", "type": {"label": "Virtual"}, "enabled": True, "mgmt_only": False, "description": ""},
]
ADDRESSES = [
    {"address": "192.0.2.1/24", "family": {"label": "IPv4"}, "status": {"label": "Active"}, "assigned_object_type": "dcim.interface", "assigned_object_id": 10},
    {"address": "2001:db8::1/64", "family": {"label": "IPv6"}, "status": {"label": "Active"}, "assigned_object_type": "dcim.interface", "assigned_object_id": 10},
    {"address": "198.51.100.0/31", "family": {"label": "IPv4"}, "status": {"label": "Active"}, "assigned_object_type": "dcim.interface", "assigned_object_id": 11},
    {"address": "192.0.2.33/24", "family": {"label": "IPv4"}, "status": {"label": "Active"}, "assigned_object_type": "dcim.interface", "assigned_object_id": 30},
    {"address": "192.168.10.1/24", "family": {"label": "IPv4"}, "status": {"label": "Active"}, "role": {"label": "VRRP"}, "assigned_object_type": None},
]
PREFIXES = [{"prefix": "192.0.2.0/24", "status": {"label": "Active"}, "role": {"name": "Management"}, "vlan": {"display": "MGMT (200)"}}]
VLANS = [{"vid": 200, "name": "MGMT", "status": {"label": "Active"}}, {"vid": 10, "name": "USERS10", "status": {"label": "Active"}}]


def page(rows, following=None):
    return ok_json({"count": len(rows), "next": following, "results": rows})


def routes(devices=DEVICES, interfaces=INTERFACES, addresses=ADDRESSES, prefixes=PREFIXES, vlans=VLANS):
    return {f"{BASE}/api/dcim/devices/": page(devices), f"{BASE}/api/dcim/interfaces/": page(interfaces),
            f"{BASE}/api/ipam/ip-addresses/": page(addresses), f"{BASE}/api/ipam/prefixes/": page(prefixes), f"{BASE}/api/ipam/vlans/": page(vlans)}


class AdapterTests(ConsoleTestCase):
    def reader(self, getter, token="tok-123"):
        return netbox.NetboxReader(BASE, token, getter=getter)

    def test_device_enumeration_and_address_interface_parsing(self):
        snapshot = self.reader(FakeGetter(routes())).snapshot()
        self.assertEqual([d["name"] for d in snapshot["devices"]], ["R1", "R3", "R5"])
        r1 = snapshot["devices"][0]
        self.assertEqual((r1["role"], r1["device_type"], r1["status"], r1["primary_ip4"], r1["primary_ip6"]),
                         ("Router", "cEOS-lab", "Active", "192.0.2.1/24", "2001:db8::1/64"))
        self.assertEqual([d["managed"] for d in snapshot["devices"]], [True, True, False])
        self.assertEqual([i["name"] for i in r1["interfaces"]], ["Ethernet2", "Vlan200"])
        vlan200 = r1["interfaces"][1]
        self.assertEqual([a["address"] for a in vlan200["addresses"]], ["192.0.2.1/24", "2001:db8::1/64"])
        self.assertEqual((vlan200["mgmt_only"], r1["address_count"]), (True, 3))
        self.assertEqual([a["address"] for a in snapshot["unassigned_addresses"]], ["192.168.10.1/24"])
        self.assertEqual([v["vid"] for v in snapshot["vlans"]], [10, 200])
        self.assertEqual(snapshot["prefixes"][0]["vlan"], "MGMT (200)")
        self.assertEqual(snapshot["counts"], {"devices": 3, "interfaces": 4, "addresses": 5, "prefixes": 1, "vlans": 2})

    def test_pagination_is_followed_on_the_configured_origin_only(self):
        table = routes()
        table[f"{BASE}/api/dcim/devices/"] = lambda url, headers: page(DEVICES[1:]) if "offset=1" in url else page(
            DEVICES[:1], f"{BASE}/api/dcim/devices/?limit=250&offset=1")
        self.assertEqual(len(self.reader(FakeGetter(table)).snapshot()["devices"]), 3)
        table[f"{BASE}/api/dcim/devices/"] = page(DEVICES[:1], "http://evil.test/api/dcim/devices/?offset=1")
        getter = FakeGetter(table)
        with self.assertRaises(netbox.NetboxUnavailable):
            self.reader(getter).snapshot()
        self.assertFalse([url for url, _ in getter.requests if "evil.test" in url])                  # the token never leaves the NetBox origin

    def test_empty_response(self):
        snapshot = self.reader(FakeGetter(routes([], [], [], [], []))).snapshot()
        self.assertEqual((snapshot["devices"], snapshot["prefixes"], snapshot["vlans"]), ([], [], []))
        self.assertEqual(set(snapshot["counts"].values()), {0})

    def test_netbox_unavailable_and_auth_failures_are_fixed_codes(self):
        cases = {"CONNECTION_REFUSED": FakeGetter({}), "TIMEOUT": FakeGetter({BASE: HttpResult(None, error="TIMEOUT")}),
                 "AUTHENTICATION_FAILED": FakeGetter({BASE: HttpResult(403)}), "HTTP_500": FakeGetter({BASE: HttpResult(500)}),
                 "PARSE_ERROR": FakeGetter({BASE: HttpResult(200, body=b"<html>")})}
        for code, getter in cases.items():
            with self.assertRaises(netbox.NetboxUnavailable) as caught:
                self.reader(getter).snapshot()
            self.assertEqual(caught.exception.code, code)
            self.assertNotIn("tok-123", str(caught.exception))
        with self.assertRaises(netbox.NetboxUnavailable) as caught:
            self.reader(FakeGetter({BASE: HttpResult(403)}), token="").snapshot()
        self.assertEqual(caught.exception.code, "TOKEN_NOT_CONFIGURED")

    def test_token_handling(self):
        self.assertEqual(netbox.auth_header("abc"), {"Authorization": "Token abc"})
        self.assertEqual(netbox.auth_header("nbt_key.secret"), {"Authorization": "Bearer nbt_key.secret"})   # the project's v2 rule
        reader = self.reader(FakeGetter(routes()))
        self.assertNotIn("tok-123", repr(reader))
        env = self.tmp / ".env"
        env.write_text('# comment\nNETBOX_URL=http://netbox.test/\nNETBOX_TOKEN="tok-123"\nSUPERUSER_PASSWORD=x\n')
        configured = netbox.NetboxReader.from_config(self.config.with_overrides(netbox_env_file=env, netbox_url=""), getter=FakeGetter(routes()))
        self.assertEqual((configured.url, configured.authenticated), ("http://netbox.test", True))
        self.assertEqual(netbox.parse_env_file(self.tmp / "missing"), {})

    def test_only_get_requests_can_be_made(self):
        from challenge_console.adapters import http
        import inspect
        self.assertNotIn("method", inspect.signature(http.get).parameters)
        source = inspect.getsource(http)
        self.assertEqual(source.count('method="GET"'), 1)
        for verb in ("POST", "PUT", "PATCH", "DELETE"):
            self.assertNotIn(f'"{verb}"', source + inspect.getsource(netbox))

    def test_search_and_filters(self):
        devices = self.reader(FakeGetter(routes())).snapshot()["devices"]
        names = lambda **kw: [d["name"] for d in filters.filter_devices(devices, **kw)]  # noqa: E731
        self.assertEqual(names(), ["R1", "R3", "R5"])
        self.assertEqual(names(text="r3"), ["R3"])
        self.assertEqual(names(text="198.51.100"), ["R1"])                                           # an interface address
        self.assertEqual(names(text="vlan200"), ["R1"])                                              # an interface name
        self.assertEqual(names(text="ubuntu"), ["R3"])
        self.assertEqual(names(role="External / Unmanaged"), ["R5"])
        self.assertEqual(names(scope="Managed"), ["R1", "R3"])
        self.assertEqual(names(scope="Unmanaged"), ["R5"])
        self.assertEqual(names(scope="Managed", text="192.168.255"), [])
        self.assertEqual(names(text="nothing-matches"), [])


class CollectorTests(ConsoleTestCase):
    def collector(self, getter):
        self.runner = FakeRunner()
        self.runner.outputs[("docker", "ps", "--filter")] = CommandResult(0, stdout="clab-lab-R1\nclab-lab-R5\n")
        collector = NsotCollector(self.config, self.store, self.bus, reader=netbox.NetboxReader(BASE, "tok-123", getter=getter),
                                  runner=self.runner, inventory_document=INVENTORY)
        collector.setup()
        return collector

    def test_snapshot_with_consistency_against_inventory_and_runtime(self):
        collector = self.collector(FakeGetter(routes()))
        collector.collect()
        document = self.store.document(m.NSOT)
        self.assertTrue(document["available"] and not document["stale"])
        checks = {row["device"]: row for row in document["data"]["consistency"]}
        self.assertEqual(checks["R1"], {"device": "R1", "management_address": "MATCH", "managed_scope": "MATCH", "runtime": "RUNNING"})
        self.assertEqual((checks["R3"]["management_address"], checks["R3"]["runtime"]), ("MISMATCH", "NOT_RUNNING"))   # NSOT .33 vs inventory .3
        self.assertEqual((checks["R5"]["management_address"], checks["R5"]["managed_scope"]), ("NO_INVENTORY_ADDRESS", "MATCH"))
        event = self.kinds("nsot.snapshot")[0]
        self.assertEqual(event.outcome, m.FAIL)
        self.assertEqual([row["device"] for row in event.data["inconsistent"]], ["R3"])
        self.assertEqual(document["data"]["lab"], {"running": 2, "expected": 15})

    def test_runtime_unknown_is_not_guessed(self):
        collector = self.collector(FakeGetter(routes()))
        self.runner.outputs[("docker", "ps", "--filter")] = CommandResult(None, error="RUNTIME_UNAVAILABLE")
        collector.collect()
        self.assertEqual({row["runtime"] for row in self.store.document(m.NSOT)["data"]["consistency"]}, {"UNKNOWN"})

    def test_netbox_unavailable_keeps_the_last_snapshot_marked_stale(self):
        getter = FakeGetter(routes())
        collector = self.collector(getter)
        collector.collect()
        good = self.store.document(m.NSOT)
        getter.routes = {}
        with self.assertRaises(CollectorError) as caught:
            collector.collect()
        self.assertEqual((caught.exception.code, caught.exception.target), ("CONNECTION_REFUSED", "netbox"))
        stale = self.store.document(m.NSOT)
        self.assertEqual((stale["available"], stale["stale"], stale["reason"]), (False, True, "CONNECTION_REFUSED"))
        self.assertEqual(stale["data"], good["data"])                                                # still inspectable
        self.assertEqual(stale["last_ok"], good["ts"])
        self.assertGreater(stale["ts"], good["ts"])
        getter.routes = routes()
        collector.collect()
        self.assertTrue(self.store.document(m.NSOT)["available"])

    def test_unavailable_before_any_read_shows_no_data_and_is_not_stale(self):
        collector = self.collector(FakeGetter({}))
        with self.assertRaises(CollectorError):
            collector.collect()
        document = self.store.document(m.NSOT)
        self.assertEqual((document["available"], document["stale"], document["data"]), (False, False, {}))
