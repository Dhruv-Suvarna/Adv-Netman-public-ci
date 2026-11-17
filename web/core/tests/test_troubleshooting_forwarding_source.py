"""Forwarding source (RB02 host connectivity: HC10 / HC15 / HC24) -- parser -> collector -> runtime -> runbook.  Stable IDs FWSRC-001 .. FWSRC-020.

PROVENANCE: every device document below is SIMULATED (hand-written to the cEOS ``show ip[v6] route | json`` / ``show ip arp | json`` / ``show ipv6 neighbors | json`` and
iproute2 ``ip -j route|neigh`` schemas).  No gateway-recorded output is pinned by this file, so nothing here claims live verification; the injected gateway dictionary
(``live=false``) only proves that transport provenance is carried verbatim into the evidence rows.  FIB is never produced by any fixture: it is asserted to be an explicit gap.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import forwarding as fw

_p = Path(__file__).parent / "fixtures" / "troubleshooting_runbooks" / "scenarios.py"
_spec = importlib.util.spec_from_file_location("ts_scenarios_fw", _p)
S = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(S)

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
ACTOR = repo.Actor("alice", "user", tenant="acme")
GW = {"live": False, "fixture_id": "simulated-forwarding", "note": "SIMULATED: not gateway-recorded"}
EV = {"evidence_id": "ev-1", "source_type": "CLI", "transport": "t", "adapter": "a", "command_or_api": "show ip route | json", "collected_at": T0.isoformat(), "raw_ref": {"hash": "h"}}
MAC = {"gw": "00:1c:73:00:00:01", "gw2": "00:1c:73:00:00:99", "h1": "00:1c:73:00:01:10"}

PLATFORM = {"h1": "linux", "h2": "linux", "sw1": "ceos", "r1": "ceos", "r2": "ceos", "r3": "ceos"}
V4_ROUTE, V6_ROUTE = "show ip route | json", "show ipv6 route | json"
V4_ARP, V6_ND = "show ip arp | json", "show ipv6 neighbors | json"
L_ROUTE4, L_ROUTE6 = ("ip", "-j", "-4", "route", "show"), ("ip", "-j", "-6", "route", "show")
L_NEIGH = ("ip", "-j", "neigh", "show")

OWNERS_V4 = {"10.1.1.1": "r1", "10.0.12.1": "r1", "10.0.12.2": "r2", "10.0.13.1": "r1", "10.0.13.3": "r3", "10.2.2.1": "r2"}
OWNERS_V6 = {"fd00:1::1": "r1", "fd00:12::1": "r1", "fd00:12::2": "r2", "fd00:2::1": "r2"}


# ------------------------------------------------------------------------------------------------------------ document builders
def eos_routes(routes, vrf="default", **extra):
    """routes: {prefix: (type, [(nexthop|None, iface)])}"""
    body = {}
    for prefix, (kind, vias) in routes.items():
        body[prefix] = {"routeType": kind, "directlyConnected": kind == "connected", "metric": 20, "preference": 110 if kind == "OSPF" else 0,
                        "vias": [({"nexthopAddr": nh} if nh else {}) | {"interface": ifn} for nh, ifn in vias]}
    return json.dumps({"vrfs": {vrf: {"routingDisabled": False, "allRoutesProgrammedHardware": True, "routes": body, **extra}}})


def linux_routes(*rows):
    return json.dumps(list(rows))


def eos_arp(*entries):
    return json.dumps({"dynamicEntries": len(entries), "ipV4Neighbors": [{"address": a, "hwAddress": mac, "interface": "Vlan10, Ethernet1", "age": 5} for a, mac in entries],
                       "notLearnedEntries": 0, "totalEntries": len(entries), "staticEntries": 0})


def eos_nd(*entries):
    return json.dumps({"ipV6Neighbors": [{"address": a, "hwAddress": mac, "interface": "Ethernet1", "state": st, "age": 5} for a, mac, st in entries]})


def linux_neigh(*entries):
    return json.dumps([({"dst": a, "dev": "eth0", "state": [st]} | ({"lladdr": mac} if mac else {})) for a, mac, st in entries])


# --------------------------------------------------------------------------------------------------------------- IPv4 lab
def v4_lab():
    out = {
        "r1": {V4_ROUTE: eos_routes({"10.1.1.0/24": ("connected", [(None, "Ethernet1")]), "10.2.2.0/24": ("OSPF", [("10.0.12.2", "Ethernet2")])}), V4_ARP: eos_arp()},
        "r2": {V4_ROUTE: eos_routes({"10.2.2.0/24": ("connected", [(None, "Ethernet2")]), "10.1.1.0/24": ("OSPF", [("10.0.12.1", "Ethernet1")])}), V4_ARP: eos_arp()},
        "r3": {V4_ROUTE: eos_routes({"10.0.13.0/24": ("connected", [(None, "Ethernet1")])})},
        "sw1": {},
        "h1": {L_ROUTE4: linux_routes({"dst": "default", "gateway": "10.1.1.1", "dev": "eth0", "protocol": "dhcp", "metric": 100},
                                      {"dst": "10.1.1.0/24", "dev": "eth0", "protocol": "kernel", "scope": "link"}),
               L_NEIGH: linux_neigh(("10.1.1.1", MAC["gw"], "REACHABLE"))},
        "h2": {L_ROUTE4: linux_routes({"dst": "default", "gateway": "10.2.2.1", "dev": "eth0", "protocol": "static"}), L_NEIGH: linux_neigh(("10.2.2.1", MAC["gw"], "STALE"))},
    }
    return out


def v6_lab():
    return {
        "r1": {V6_ROUTE: eos_routes({"fd00:1::/64": ("connected", [(None, "Ethernet1")]), "fd00:2::/64": ("OSPF", [("fe80::2" and "fd00:12::2", "Ethernet2")])}), V6_ND: eos_nd()},
        "r2": {V6_ROUTE: eos_routes({"fd00:2::/64": ("connected", [(None, "Ethernet2")]), "fd00:1::/64": ("OSPF", [("fd00:12::1", "Ethernet1")])}), V6_ND: eos_nd()},
        "r3": {V6_ROUTE: eos_routes({"fd00:13::/64": ("connected", [(None, "Ethernet1")])})},
        "sw1": {},
        "h1": {L_ROUTE6: linux_routes({"dst": "default", "gateway": "fd00:1::1", "dev": "eth0", "protocol": "ra", "metric": 1024}), L_NEIGH: linux_neigh(("fd00:1::1", MAC["gw"], "REACHABLE"))},
        "h2": {L_ROUTE6: linux_routes({"dst": "default", "gateway": "fd00:2::1", "dev": "eth0", "protocol": "ra"}), L_NEIGH: linux_neigh(("fd00:2::1", MAC["gw"], "STALE"))},
    }


class Transport:
    def __init__(self, table, provenance=GW):
        self.table = table
        self.calls = []
        self.provenance = lambda: provenance

    def execute(self, rendered):
        self.calls.append(rendered)
        return self.table.get(rendered if isinstance(rendered, str) else tuple(rendered), "")


def intent(v6=False):
    i = copy.deepcopy(S.intent())
    if v6:
        i["hosts"]["h1"].update({"gateway": "fd00:1::1", "prefix": "fd00:1::/64"})
    return i


def flow(v6=False):
    f = dict(S.FLOW)
    if v6:
        f.update({"af": "ipv6", "src_ip": "fd00:1::10", "dst_ip": "fd00:2::20", "src_prefix": "fd00:1::/64", "dst_prefix": "fd00:2::/64"})
    return f


def fctx(v6=False):
    return fw.ForwardingContext(address_owners=OWNERS_V6 if v6 else OWNERS_V4, gateways={"h1": ["fd00:1::1" if v6 else "10.1.1.1"]})


def make_case(key, v6=False):
    return repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "web"}, flow_scope=flow(v6),
                          affected_scope={"devices": S.DEVICES}, target_states={d: "VERIFIED" for d in S.DEVICES}, severity="HIGH", runbook="RB02", worked_before=True,
                          first_detected_at=T0 - timedelta(minutes=10), last_known_good_at=T0 - timedelta(hours=3), now=T0 - timedelta(minutes=5))


def run(key, tables, *, v6=False, version="4.36.2F", context="default", transports=None, at=T0):
    case = make_case(key, v6)
    ctx = fctx(v6) if context == "default" else context
    transports = transports if transports is not None else {d: Transport(t) for d, t in tables.items()}
    d = rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=lambda: {dev: {"platform": PLATFORM[dev], "os_version": "8.4.4" if PLATFORM[dev] == "linux" else version} for dev in S.DEVICES}),
        cli_transport=lambda info: transports[info.device], sources=bl.StaticSources({**S.static_data(), "intent": intent(v6)}), forwarding_context=ctx,
        clock=lambda: 0.0, sleep=lambda s: None, now=lambda: at, capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})
    res = rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=at, engine_config=eng.EngineConfig(exhaustive=True))
    return case, res, transports


def verdicts(case):
    return {t.test_id: t.verdict for t in m.TsDiagnosticTest.objects.filter(case=case)}


def summary(case, tid):
    return m.TsDiagnosticTest.objects.get(case=case, test_id=tid).summary if hasattr(m.TsDiagnosticTest, "summary") else ""


def norm_routes(raw, platform="ceos", version="4.36.2F", family=None):
    return nz.normalize_routes(raw, platform=platform, os_version=version, device="r1", evidence=EV, family=family, now=T0, observed_at=T0)


def norm_nbrs(raw, platform="ceos", version="4.36.2F", family=None):
    return nz.normalize_neighbor_table(raw, platform=platform, os_version=version, device="r1", evidence=EV, family=family, now=T0, observed_at=T0)


# ------------------------------------------------------------------------------------------------------------------ unit
class UnitParserTests(SimpleTestCase):
    def test_FWSRC_001_eos_rib_vrf_af_nexthops_and_provenance(self):
        res = norm_routes(eos_routes({"10.2.2.0/24": ("OSPF", [("10.0.12.2", "Et2"), ("10.0.13.3", "Ethernet3")]), "10.1.1.0/24": ("connected", [(None, "Ethernet1")])}), family="ipv4")
        (o,) = res["observations"]
        self.assertEqual((o["key"], o["target"]["vrf"], o["target"]["family"]), ("route.table", "default", "ipv4"))
        self.assertEqual((res["parser"]["id"], res["parser"]["version"]), ("route.table", "eos-json-1.0"))
        v = o["value"]
        routes = {r["prefix"]: r for r in v["routes"]}
        self.assertEqual([(h["address"], h["interface"]) for h in routes["10.2.2.0/24"]["next_hops"]], [("10.0.12.2", "Ethernet2"), ("10.0.13.3", "Ethernet3")])
        self.assertTrue(routes["10.1.1.0/24"]["connected"])
        self.assertEqual((v["complete"], v["table_kind"], v["fib_evidence"]), (True, "rib", False))
        self.assertEqual(o["quality"], "OK")
        self.assertEqual(o["raw_hash"], "h")

    def test_FWSRC_002_eos_ipv6_and_linux_tables(self):
        res = norm_routes(eos_routes({"fd00:2::/64": ("OSPF", [("fd00:12::2", "Ethernet2")])}), family="ipv6")
        self.assertEqual(res["observations"][0]["target"]["family"], "ipv6")
        lin = norm_routes(linux_routes({"dst": "default", "gateway": "10.1.1.1", "dev": "eth0", "protocol": "dhcp"}, {"dst": "10.9.9.9", "dev": "eth1", "scope": "link"},
                                       {"dst": "10.5.0.0/16", "nexthops": [{"gateway": "10.0.0.1", "dev": "eth1", "weight": 1}, {"gateway": "10.0.1.1", "dev": "eth2", "weight": 1}], "protocol": "bgp"},
                                       {"type": "blackhole", "dst": "10.6.0.0/16"}), platform="linux", version="8.4.4", family="ipv4")
        v = lin["observations"][0]["value"]
        by = {r["prefix"]: r for r in v["routes"]}
        self.assertEqual(set(by), {"0.0.0.0/0", "10.9.9.9/32", "10.5.0.0/16", "10.6.0.0/16"})
        self.assertEqual(len(by["10.5.0.0/16"]["next_hops"]), 2)
        self.assertEqual((by["10.6.0.0/16"]["discard"], by["10.6.0.0/16"]["next_hops"]), ("blackhole", []))
        self.assertEqual(v["table_kind"], "kernel-routing-table")      # a RIB view of the kernel, never presented as FIB
        v6 = norm_routes(linux_routes({"dst": "default", "gateway": "fd00:1::1", "dev": "eth0"}), platform="linux", version="8.4.4", family="ipv6")
        self.assertEqual(v6["observations"][0]["value"]["routes"][0]["prefix"], "::/0")
        wrong = norm_routes(linux_routes({"dst": "fd00::/64", "dev": "eth0"}), platform="linux", version="8.4.4", family="ipv4")
        self.assertEqual(wrong["observations"], [])
        self.assertEqual(wrong["missing"][0]["reason"], "PARSE_FAILED")

    def test_FWSRC_003_neighbor_tables_states_and_ipv6(self):
        a = norm_nbrs(eos_arp(("10.1.1.1", MAC["gw"])), family="ipv4")["observations"][0]
        self.assertEqual((a["key"], a["target"]["neighbor"], a["value"]["state"], a["value"]["state_reported"]), ("neighbor.entry", "10.1.1.1", None, False))
        nd = norm_nbrs(eos_nd(("fd00:1::1", MAC["gw"], "REACHABLE"), ("fd00:1::2", None, "INCOMPLETE")), family="ipv6")["observations"]
        self.assertEqual([(o["target"]["neighbor"], o["value"]["state"], o["value"]["mac"]) for o in nd], [("fd00:1::1", "REACHABLE", MAC["gw"]), ("fd00:1::2", "INCOMPLETE", None)])
        lin = norm_nbrs(linux_neigh(("10.1.1.1", None, "FAILED"), ("fd00:1::1", MAC["gw"], "STALE")), platform="linux", version="8.4.4")["observations"]
        self.assertEqual([(o["value"]["family"], o["value"]["state"]) for o in lin], [("ipv4", "FAILED"), ("ipv6", "STALE")])

    def test_FWSRC_004_version_gate_malformed_empty_partial_truncated(self):
        for version, code in (("4.20.1F", "VERSION_UNSUPPORTED"), ("5.1.0F", "VERSION_UNSUPPORTED"), ("", "VERSION_UNKNOWN")):
            res = norm_routes(eos_routes({"10.0.0.0/8": ("static", [("1.1.1.1", "Ethernet1")])}), version=version)
            self.assertEqual((res["observations"], res["missing"][0]["reason"], res["missing"][0]["extra"]["selection_error"]), ([], "PARSER_UNAVAILABLE", code))
        self.assertEqual(norm_routes("{}", platform="iosxe", version="17.06.01a")["missing"][0]["extra"]["selection_error"], "WRONG_PLATFORM")
        for raw in ("{not json", json.dumps({"other": 1}), json.dumps({"vrfs": {"default": {}}})):
            self.assertEqual(norm_routes(raw)["missing"][0]["reason"], "PARSE_FAILED", raw)
        self.assertEqual(norm_routes(json.dumps({"vrfs": {"default": {"routes": {}}}}))["missing"][0]["reason"], "EMPTY")
        part = norm_routes(json.dumps({"vrfs": {"default": {"routes": {"10.0.0.0/8": {"routeType": "static", "vias": [{"nexthopAddr": "1.1.1.1", "interface": "Ethernet1"}]},
                                                                      "bogus": {"vias": []}, "10.1.0.0/16": {"vias": [{"nexthopAddr": "notip"}]}}}}}))
        o = part["observations"][0]
        self.assertEqual((o["quality"], o["value"]["complete"], len(o["value"]["routes"])), ("PARTIAL", False, 1))
        self.assertIn("PARTIAL_PARSE", o["flags"])
        old = nz.FWD_MAX_ROUTES
        try:
            nz.FWD_MAX_ROUTES = 2
            t = norm_routes(eos_routes({f"10.{i}.0.0/16": ("static", [("1.1.1.1", "Ethernet1")]) for i in range(5)}))["observations"][0]
        finally:
            nz.FWD_MAX_ROUTES = old
        self.assertEqual((t["value"]["complete"], t["value"]["route_count"], t["quality"]), (False, 2, "PARTIAL"))
        self.assertIn("TRUNCATED", t["flags"])
        short = norm_nbrs(json.dumps({"ipV4Neighbors": [{"address": "10.1.1.1", "hwAddress": MAC["gw"], "interface": "Ethernet1"}], "totalEntries": 3}))["observations"][0]
        self.assertEqual(short["quality"], "PARTIAL")

    def test_FWSRC_005_unsupported_version_does_not_contact_transport(self):
        class NoContact:
            def execute(self, command):
                raise AssertionError("unsupported forwarding command contacted a device")
        collector = col.CliCollector(capability_probe=lambda *a: {"status": "SUPPORTED"})
        bundle = collector.collect(col.Target(device="r1", platform="ceos", os_version="5.1.0", verified=True, lifecycle_state="VERIFIED"), ["ip_route", "arp"], NoContact())
        self.assertEqual(bundle["observations"], [])
        self.assertEqual({r["reason"] for r in bundle["missing"]}, {"PARSER_UNAVAILABLE"})


class LookupTests(SimpleTestCase):
    def table(self, routes, family="ipv4", complete=True, platform="ceos"):
        raw = eos_routes(routes) if platform == "ceos" else routes
        obs = norm_routes(raw, platform=platform, version="4.36.2F" if platform == "ceos" else "8.4.4", family=family)["observations"][0]
        obs["value"]["complete"] = complete
        return [obs]

    def test_FWSRC_006_longest_prefix_exact_and_covering_default(self):
        t = self.table({"0.0.0.0/0": ("static", [("10.0.0.1", "Ethernet1")]), "10.2.0.0/16": ("OSPF", [("10.0.12.2", "Ethernet2")])})
        ctx = fw.ForwardingContext(address_owners=OWNERS_V4)
        v, _ = fw.rib_lookup(t, fw.RouteQuery("10.2.2.0/24", "default", "ipv4"), device="r1", ctx=ctx)
        self.assertEqual((v["present"], v["matched_prefix"], v["exact"], v["next_hop"], v["next_hop_device"]), (True, "10.2.0.0/16", False, "10.0.12.2", "r2"))
        v, _ = fw.rib_lookup(t, fw.RouteQuery("192.0.2.0/24", "default", "ipv4"), device="r1", ctx=ctx)
        self.assertEqual((v["matched_prefix"], v["next_hop_device"]), ("0.0.0.0/0", None))      # unknown owner => unresolved, never guessed
        self.assertFalse(v["fib_evidence"])

    def test_FWSRC_007_absence_only_from_complete_table_of_the_right_vrf_and_family(self):
        t = self.table({"10.1.1.0/24": ("connected", [(None, "Ethernet1")])})
        v, _ = fw.rib_lookup(t, fw.RouteQuery("10.2.2.0/24", "default", "ipv4"), device="r1")
        self.assertEqual((v["present"], v["reason"]), (False, "NO_COVERING_ROUTE"))
        for bad in (fw.RouteQuery("10.2.2.0/24", "blue", "ipv4"), fw.RouteQuery("fd00:2::/64", "default", "ipv6")):
            self.assertEqual(fw.rib_lookup(t, bad, device="r1")[0], None)
        inc = self.table({"10.1.1.0/24": ("connected", [(None, "Ethernet1")])}, complete=False)
        value, why = fw.rib_lookup(inc, fw.RouteQuery("10.2.2.0/24", "default", "ipv4"), device="r1")
        self.assertIsNone(value)
        self.assertIn("incomplete", why)

    def test_FWSRC_008_discard_ecmp_and_interface_peer_resolution(self):
        raw = linux_routes({"dst": "10.6.0.0/16", "type": "blackhole"}, {"dst": "10.5.0.0/16", "nexthops": [{"gateway": "10.0.12.2", "dev": "e2"}, {"gateway": "10.0.13.3", "dev": "e3"}]},
                           {"dst": "10.7.0.0/16", "dev": "e9", "scope": "link"}, {"dst": "10.8.0.0/16", "gateway": "10.0.12.2", "dev": "e2"}, {"dst": "10.6.1.0/24", "gateway": "10.0.12.2", "dev": "e2"})
        t = self.table(raw, platform="linux")
        ctx = fw.ForwardingContext(address_owners=OWNERS_V4, link_peers={("r1", "e9"): "r2"})
        look = lambda p: fw.rib_lookup(t, fw.RouteQuery(p, "default", "ipv4"), device="r1", ctx=ctx)[0]   # noqa: E731
        self.assertEqual((look("10.6.0.0/16")["present"], look("10.6.0.0/16")["discard"]), (False, "blackhole"))
        ecmp = look("10.5.0.0/16")
        self.assertEqual((ecmp["ecmp"], ecmp["next_hop_devices"], ecmp["next_hop_device"]), (True, ["r2", "r3"], None))
        self.assertEqual(look("10.7.0.0/16")["next_hop_device"], "r2")           # directly attached hop resolved through the intended link, not an address
        self.assertEqual(look("10.8.0.0/16")["next_hop_device"], "r2")

    def test_FWSRC_009_neighbor_values_duplicates_and_judgeability(self):
        ents = norm_nbrs(linux_neigh(("10.1.1.1", MAC["gw"], "REACHABLE"), ("10.1.1.5", MAC["gw"], "PERMANENT"), ("10.1.1.6", None, "REACHABLE"), ("10.1.1.7", None, "INCOMPLETE")),
                         platform="linux", version="8.4.4")["observations"]
        dup = copy.deepcopy(ents[0])
        dup["value"].update({"mac": MAC["gw2"], "state": "STALE", "interface": "eth1"})
        vals = fw.neighbor_values(ents + [dup])
        v, q, _ = vals["10.1.1.1"]
        self.assertEqual((v["state"], v["mac"], v["dup_macs"], q), ("REACHABLE", MAC["gw"], [MAC["gw2"]], None))
        self.assertEqual(vals["10.1.1.5"][1], "UNTRUSTED")
        self.assertEqual(vals["10.1.1.6"][1], "UNTRUSTED")
        self.assertEqual((vals["10.1.1.7"][0]["state"], vals["10.1.1.7"][0]["mac"]), ("INCOMPLETE", None))
        a = norm_nbrs(eos_arp(("10.1.1.1", MAC["gw"])), family="ipv4")["observations"]
        v, q, flags = fw.neighbor_values(a)["10.1.1.1"]
        self.assertEqual((v["state"], v["state_reported"], flags), ("STALE", False, ["ARP_STATE_NOT_REPORTED"]))

    def test_FWSRC_010_fib_is_never_available_and_source_labels_are_honest(self):
        self.assertTrue(all("route.fib" not in v for v in rt.CLI_KEY_CANON.values()))
        d = fw.describe_source()
        self.assertEqual((d["label"], d["live"], d["fib"]["available"]), ("SIMULATED", False, False))
        self.assertEqual(fw.describe_source(recorded=True)["label"], "RECORDED")
        self.assertEqual(fw.describe_source(gateway={"live": "true"})["label"], "SIMULATED")      # only boolean live=true from the trusted boundary counts
        self.assertEqual(fw.describe_source(gateway={"live": True})["label"], "LIVE_GATEWAY_PINNED")
        self.assertTrue(fw.is_supported("ceos", "4.36.2F") and fw.is_supported("linux", "8.4.4", "neighbor.table"))
        self.assertFalse(fw.is_supported("iosxe", "17.06.01a"))
        self.assertFalse(fw.is_supported("ceos", "4.20.0F"))


# ------------------------------------------------------------------------------------------------------- runtime + runbook
class RuntimeToRb02Tests(TestCase):
    def test_FWSRC_011_healthy_v4_pass_with_provenance_and_explicit_fib_gap(self):
        case, res, tr = run("fw11", v4_lab())
        v = verdicts(case)
        self.assertEqual((v["HC10"], v["HC15"], v["HC24"]), ("PASS", "PASS", "PASS"), v)
        self.assertNotEqual(v.get("HC16"), "PASS")                       # RIB passing must not become FIB passing
        rib = m.TsObservation.objects.get(case=case, target="r1", key="route.rib@10.2.2.0/24", is_missing_data=False)
        self.assertEqual((rib.value["present"], rib.value["next_hop"], rib.value["next_hop_device"], rib.value["fib_evidence"]), (True, "10.0.12.2", "r2", False))
        self.assertFalse(m.TsObservation.objects.filter(case=case, key__startswith="route.fib", is_missing_data=False).exists())
        gap = m.TsObservation.objects.get(case=case, target="r1", key="route.fib@10.2.2.0/24")
        self.assertTrue(gap.is_missing_data and gap.missing_reason.startswith("UNSUPPORTED_OPERATION"))
        self.assertIn("never derived from the RIB", gap.missing_reason)
        arp = m.TsObservation.objects.get(case=case, target="h1", key="arp.entry@10.1.1.1", is_missing_data=False)
        self.assertEqual((arp.value["state"], arp.value["mac"], arp.value["dup_macs"]), ("REACHABLE", MAC["gw"], []))
        ev = m.TsEvidenceRef.objects.get(case=case, device="r1", command_or_api=V4_ROUTE)
        self.assertEqual((ev.parser, ev.parser_version, ev.scope["gateway"], ev.scope["live"]), ("route.table", "eos-json-1.0", GW, False))
        self.assertRegex(ev.scope["raw_hash_as_received"], r"^(sha256:)?[0-9a-f]{64}$")
        self.assertNotIn(V6_ROUTE, [c for c in tr["r1"].calls if isinstance(c, str)])        # IPv4 flow reads no IPv6 table

    def test_FWSRC_012_missing_route_fails_hc15_then_recovers(self):
        lab = v4_lab()
        lab["r1"][V4_ROUTE] = eos_routes({"10.1.1.0/24": ("connected", [(None, "Ethernet1")])})
        case, res, _ = run("fw12a", lab)
        v = verdicts(case)
        self.assertEqual(v["HC15"], "FAIL", v)
        self.assertIn("F-rib", json.dumps(res["diagnosis"]))
        self.assertIn("no RIB route to 10.2.2.0/24", json.dumps(res["diagnosis"]) + str(m.TsDiagnosticTest.objects.get(case=case, test_id="HC15").__dict__))
        self.assertNotEqual(v["HC16"], "FAIL")
        rec, _, _ = run("fw12b", v4_lab())
        self.assertEqual(verdicts(rec)["HC15"], "PASS")

    def test_FWSRC_013_wrong_next_hop_and_incomplete_table_semantics(self):
        lab = v4_lab()
        lab["r1"][V4_ROUTE] = eos_routes({"10.1.1.0/24": ("connected", [(None, "Ethernet1")]), "10.2.2.0/24": ("OSPF", [("10.0.13.3", "Ethernet3")])})
        case, _, _ = run("fw13a", lab)
        self.assertEqual(verdicts(case)["HC15"], "FAIL")
        self.assertEqual(m.TsObservation.objects.get(case=case, target="r1", key="route.rib@10.2.2.0/24").value["next_hop_device"], "r3")
        # without intent-owned addresses the next-hop device is UNKNOWN: HC15 must not invent a divergence
        case2, _, _ = run("fw13b", lab, context=fw.ForwardingContext(gateways={"h1": ["10.1.1.1"]}))
        self.assertIsNone(m.TsObservation.objects.get(case=case2, target="r1", key="route.rib@10.2.2.0/24").value["next_hop_device"])
        self.assertNotEqual(verdicts(case2)["HC15"], "FAIL")

    def test_FWSRC_014_unresolved_neighbor_fails_hc10_absent_entry_is_unknown_and_recovers(self):
        lab = v4_lab()
        lab["h1"][L_NEIGH] = linux_neigh(("10.1.1.1", None, "INCOMPLETE"))
        case, _, _ = run("fw14a", lab)
        self.assertEqual(verdicts(case)["HC10"], "FAIL")
        lab["h1"][L_NEIGH] = linux_neigh(("10.1.1.99", MAC["h1"], "REACHABLE"))            # gateway simply not in the cache
        case, _, _ = run("fw14b", lab)
        self.assertNotIn(verdicts(case)["HC10"], ("PASS", "FAIL"))
        gap = m.TsObservation.objects.get(case=case, target="h1", key="arp.entry@10.1.1.1")
        self.assertTrue(gap.is_missing_data and "not proof" in gap.missing_reason)
        lab["h1"][L_NEIGH] = linux_neigh(("10.1.1.1", MAC["gw"], "STALE"))
        case, _, _ = run("fw14c", lab)
        self.assertEqual(verdicts(case)["HC10"], "PASS")

    def test_FWSRC_015_duplicate_address_and_ambiguous_states(self):
        lab = v4_lab()
        lab["h1"][L_NEIGH] = json.dumps([{"dst": "10.1.1.1", "dev": "eth0", "lladdr": MAC["gw"], "state": ["REACHABLE"]}, {"dst": "10.1.1.1", "dev": "eth1", "lladdr": MAC["gw2"], "state": ["STALE"]}])
        case, _, _ = run("fw15a", lab)
        self.assertEqual(verdicts(case)["HC10"], "FAIL")
        self.assertEqual(m.TsObservation.objects.get(case=case, target="h1", key="arp.entry@10.1.1.1").value["dup_macs"], [MAC["gw2"]])
        lab["h1"][L_NEIGH] = linux_neigh(("10.1.1.1", MAC["gw"], "PERMANENT"))
        case, _, _ = run("fw15b", lab)
        self.assertNotIn(verdicts(case)["HC10"], ("PASS", "FAIL"))
        self.assertEqual(m.TsObservation.objects.get(case=case, target="h1", key="arp.entry@10.1.1.1").quality, "UNTRUSTED")

    def test_FWSRC_016_ipv6_healthy_missing_route_and_unresolved_nd(self):
        case, _, tr = run("fw16a", v6_lab(), v6=True)
        v = verdicts(case)
        self.assertEqual((v["HC10"], v["HC15"], v["HC24"]), ("PASS", "PASS", "PASS"), v)
        row = m.TsObservation.objects.get(case=case, target="r1", key="route.rib@fd00:2::/64")
        self.assertEqual((row.value["family"], row.value["next_hop_device"]), ("ipv6", "r2"))
        self.assertIn(V6_ROUTE, tr["r1"].calls)
        self.assertNotIn(V4_ROUTE, tr["r1"].calls)
        lab = v6_lab()
        lab["r1"][V6_ROUTE] = eos_routes({"fd00:1::/64": ("connected", [(None, "Ethernet1")])})
        lab["h1"][L_NEIGH] = linux_neigh(("fd00:1::1", None, "FAILED"))
        case, _, _ = run("fw16b", lab, v6=True)
        v = verdicts(case)
        self.assertEqual((v["HC10"], v["HC15"]), ("FAIL", "FAIL"), v)

    def test_FWSRC_017_return_path_fault_isolated_to_hc24_and_multihop_next_hops(self):
        lab = v4_lab()
        lab["r2"][V4_ROUTE] = eos_routes({"10.2.2.0/24": ("connected", [(None, "Ethernet2")])})        # no route back to 10.1.1.0/24
        case, _, _ = run("fw17a", lab)
        v = verdicts(case)
        self.assertEqual((v["HC15"], v["HC24"]), ("PASS", "FAIL"), v)
        lab = v4_lab()
        lab["r2"][V4_ROUTE] = eos_routes({"10.2.2.0/24": ("connected", [(None, "Ethernet2")]), "10.1.1.0/24": ("OSPF", [("10.0.13.3", "Ethernet3")])})   # asymmetric: back via r3
        case, _, _ = run("fw17b", lab)
        self.assertEqual((verdicts(case)["HC15"], verdicts(case)["HC24"]), ("PASS", "FAIL"))
        case, _, _ = run("fw17c", v4_lab())
        v = verdicts(case)
        self.assertEqual((v["HC15"], v["HC24"]), ("PASS", "PASS"))
        self.assertEqual(m.TsObservation.objects.get(case=case, target="r2", key="route.rib@10.1.1.0/24").value["next_hop_device"], "r1")

    def test_FWSRC_018_unsupported_version_and_parse_failure_are_gaps_not_verdicts(self):
        case, _, tr = run("fw18a", v4_lab(), version="4.20.1F")
        v = verdicts(case)
        self.assertNotIn("PASS", (v["HC15"], v["HC24"]))
        self.assertNotIn("FAIL", (v["HC15"], v["HC24"]))
        gap = m.TsObservation.objects.get(case=case, target="r1", key="route.rib@10.2.2.0/24")
        self.assertTrue(gap.is_missing_data and gap.missing_reason.startswith("PARSER_UNAVAILABLE"))
        self.assertEqual([c for c in tr["r1"].calls if c in (V4_ROUTE, V4_ARP)], [])             # unsupported version: nothing was sent
        lab = v4_lab()
        lab["r1"][V4_ROUTE] = "{not json"
        case, _, _ = run("fw18b", lab)
        self.assertNotIn(verdicts(case)["HC15"], ("PASS", "FAIL"))
        self.assertTrue(m.TsObservation.objects.filter(case=case, target="r1", key="route.rib@10.2.2.0/24", is_missing_data=True, missing_reason__startswith="PARSE_FAILED").exists())

    def test_FWSRC_019_vrf_not_collected_is_unknown(self):
        case = make_case("fw19")
        case.flow_scope = {**case.flow_scope, "vrf": "blue"}
        case.save()
        d = rt.RuntimeDeps(
            admission=rt.InventoryAdmission(inventory=lambda: {dev: {"platform": PLATFORM[dev], "os_version": "8.4.4" if PLATFORM[dev] == "linux" else "4.36.2F"} for dev in S.DEVICES}),
            cli_transport=lambda info: Transport(v4_lab()[info.device]), sources=bl.StaticSources({**S.static_data(), "intent": intent()}), forwarding_context=fctx(),
            clock=lambda: 0.0, sleep=lambda s: None, now=lambda: T0, capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})
        rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=T0, engine_config=eng.EngineConfig(exhaustive=True))
        self.assertNotIn(verdicts(case)["HC15"], ("PASS", "FAIL"))
        gap = m.TsObservation.objects.get(case=case, target="r1", key="route.rib@10.2.2.0/24")
        self.assertIn("VRF blue", gap.missing_reason)

    def test_FWSRC_020_bounds_are_enforced_on_the_wire_path(self):
        old = nz.FWD_MAX_ROUTES
        try:
            nz.FWD_MAX_ROUTES = 1
            lab = v4_lab()
            lab["r1"][V4_ROUTE] = eos_routes({"10.1.1.0/24": ("connected", [(None, "Ethernet1")]), "10.9.0.0/16": ("static", [("10.0.12.2", "Ethernet2")])})
            case, _, _ = run("fw20", lab)
        finally:
            nz.FWD_MAX_ROUTES = old
        self.assertNotIn(verdicts(case)["HC15"], ("PASS", "FAIL"))         # truncated table: absence cannot be asserted
        gap = m.TsObservation.objects.get(case=case, target="r1", key="route.rib@10.2.2.0/24")
        self.assertTrue(gap.is_missing_data and "incomplete" in gap.missing_reason)
