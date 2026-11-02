"""Postchecks the access-routing redesign needs: IS-IS route presence / absence with its paths, and cEOS RIP peers.

Device output shapes are the ones cEOS 4.36.2F returned in the disposable sandbox.  The RIP cases separate two things
that are easy to confuse: a client prefix being ADVERTISED, and RIP having a PEER on the client VLAN.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from django.test import SimpleTestCase

from core.services.health import live
from core.services.health.evaluators import EVALUATORS, EvalContext
from core.services.health.evidence import DeviceEvidence, EvidenceSet, FactGroup
from core.services.health.requirements import REQUIREMENT_MAP, Requirement
from core.services.health.thresholds import load_thresholds

NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
V4 = json.dumps({"interfaces": {
    name: {"interfaceAddress": {"primaryIp": {"address": cidr.split("/")[0], "maskLen": int(cidr.split("/")[1])},
                                "secondaryIpsOrderedList": [], "virtualIp": {"address": "0.0.0.0", "maskLen": 0},
                                "virtualSecondaryIpsOrderedList": []}}
    for name, cidr in {"Ethernet1": "192.168.110.3/31", "Vlan10": "192.168.10.3/24", "Vlan20": "192.168.20.3/24", "Vlan99": "192.168.110.5/31"}.items()}})
V6 = json.dumps({"interfaces": {}})
# S2 today: peers over the uplink, the transit AND both client VLANs.
RIP_BEFORE = """RIP Router (VRF default)
RIP Gateway Summary
Address         Last-Heard Bad-Packets Num-Routes  Bad-Routes  Flags
192.168.110.2   00:00:10   0           4           0           ACCEPTED QUERY 
192.168.10.2    00:00:07   0           7           0           ACCEPTED 
192.168.110.4   00:00:07   0           1           0           ACCEPTED 
192.168.20.2    00:00:07   0           2           0           ACCEPTED 
"""
RIP_AFTER = """RIP Router (VRF default)
RIP Gateway Summary
Address         Last-Heard Bad-Packets Num-Routes  Bad-Routes  Flags
192.168.110.2   00:00:02   0           3           0           ACCEPTED 
192.168.110.4   00:00:12   0           6           0           ACCEPTED 
"""


def routes(*rows):
    return [{"prefix": prefix, "type": kind, "next_hops": [], "interfaces": sorted(interfaces)} for prefix, kind, interfaces in rows]


def check(check_type, expected, *, device="S1", **groups):
    evidence = DeviceEvidence(device=device, platform="ceos", groups={name: FactGroup(data, "LIVE", NOW) for name, data in groups.items()})
    context = EvalContext(evidence=EvidenceSet(devices={device: evidence}, now=NOW, thresholds=load_thresholds()))
    requirement = Requirement(cfg_id="STAGE", device=device, kind="X", expected=expected, check_types=(check_type,))
    return EVALUATORS[check_type][0](requirement, context)


class IsisRoutePostcheckTests(SimpleTestCase):
    AGG = "2001:db8::/32"

    def test_presence_requires_the_exact_paths_not_merely_the_prefix(self):
        normal = routes((self.AGG, "isisL2", ["Ethernet1"]))
        outcome = check("ISIS_ROUTE_EXPECTED", {"prefix": self.AGG, "interfaces": ["Ethernet1"]}, routes=normal)
        self.assertEqual((outcome.status, outcome.code, outcome.observed["paths"]), ("PASS", "ISIS_ROUTE_PRESENT", ["Ethernet1"]))
        drained = routes((self.AGG, "isisL2", ["Vlan99"]))
        outcome = check("ISIS_ROUTE_EXPECTED", {"prefix": self.AGG, "interfaces": ["Ethernet1"]}, routes=drained)
        self.assertEqual((outcome.status, outcome.code, outcome.observed["paths"]), ("FAIL", "ISIS_ROUTE_PATH_MISMATCH", ["Vlan99"]))

    def test_several_expected_next_hops_must_all_be_there(self):
        both = routes((self.AGG, "isisL2", ["Ethernet1", "Vlan99"]))
        want = {"prefix": self.AGG, "interfaces": ["Vlan99", "Ethernet1"]}
        self.assertEqual(check("ISIS_ROUTE_EXPECTED", want, routes=both).code, "ISIS_ROUTE_PRESENT")
        one = routes((self.AGG, "isisL2", ["Ethernet1"]))
        outcome = check("ISIS_ROUTE_EXPECTED", want, routes=one)
        self.assertEqual((outcome.code, outcome.expected["paths"], outcome.observed["paths"]),
                         ("ISIS_ROUTE_PATH_MISMATCH", ["Ethernet1", "Vlan99"], ["Ethernet1"]))

    def test_a_static_or_ospf_route_for_the_prefix_is_not_an_isis_route(self):
        outcome = check("ISIS_ROUTE_EXPECTED", {"prefix": self.AGG}, routes=routes((self.AGG, "static", ["Ethernet1"])))
        self.assertEqual((outcome.code, outcome.observed["other_sources"]), ("ISIS_ROUTE_MISSING", ["static"]))

    def test_absence_is_asserted_and_reappearance_is_seen(self):
        gone = check("ISIS_ROUTE_EXPECTED", {"prefix": self.AGG, "present": False}, routes=routes(("2001:db8:10::/64", "connected", ["Vlan10"])))
        self.assertEqual((gone.status, gone.code), ("PASS", "ISIS_ROUTE_ABSENT"))
        back = check("ISIS_ROUTE_EXPECTED", {"prefix": self.AGG, "present": False}, routes=routes((self.AGG, "isisL2", ["Ethernet1"])))
        self.assertEqual((back.status, back.code), ("FAIL", "ISIS_ROUTE_UNEXPECTED"))

    def test_real_route_json_carries_the_isis_type(self):
        text = json.dumps({"vrfs": {"default": {"routes": {"2001:db8:255::2/128": {
            "routeType": "isisL2", "preference": 115, "metric": 20, "vias": [{"nexthopAddr": "fe80::42:aff:fefb:903", "interface": "Ethernet1"}]}}}}})
        (row,) = live.parse_eos_routes(json.dumps({"vrfs": {"default": {"routes": {}}}}), text)
        self.assertEqual((row["type"], row["interfaces"]), ("isisL2", ["Ethernet1"]))

    def test_missing_evidence_is_unknown_never_a_pass(self):
        self.assertEqual(check("ISIS_ROUTE_EXPECTED", {"prefix": self.AGG, "present": False}).status, "UNKNOWN")


class RipNeighborTests(SimpleTestCase):
    def test_peers_are_placed_on_the_interface_whose_subnet_holds_them(self):
        rows = live.parse_eos_rip_neighbors(RIP_BEFORE, V4, V6)
        self.assertEqual([(r["peer"], r["interface"]) for r in rows], [
            ("192.168.110.2", "Ethernet1"), ("192.168.10.2", "Vlan10"), ("192.168.20.2", "Vlan20"), ("192.168.110.4", "Vlan99")])
        self.assertEqual(live.parse_eos_rip_neighbors("", V4, V6), [])
        self.assertEqual(live.CEOS_COMMANDS["rip_neighbors"], "show ip rip neighbors")

    def test_the_current_design_fails_the_final_state_and_the_cleaned_one_passes(self):
        final = [("Vlan99", {"interface": "Vlan99", "peer": "192.168.110.4"}, "RIP_NEIGHBOR_PRESENT", "RIP_NEIGHBOR_PRESENT"),
                 ("Vlan10", {"interface": "Vlan10", "present": False}, "RIP_NEIGHBOR_UNEXPECTED", "RIP_NEIGHBOR_ABSENT"),
                 ("Vlan20", {"interface": "Vlan20", "present": False}, "RIP_NEIGHBOR_UNEXPECTED", "RIP_NEIGHBOR_ABSENT"),
                 ("Vlan30", {"interface": "Vlan30", "present": False}, "RIP_NEIGHBOR_ABSENT", "RIP_NEIGHBOR_ABSENT")]
        before, after = (live.parse_eos_rip_neighbors(text, V4, V6) for text in (RIP_BEFORE, RIP_AFTER))
        for label, expected, code_before, code_after in final:
            with self.subTest(interface=label):
                self.assertEqual(check("RIP_NEIGHBOR_EXPECTED", expected, device="S2", rip_neighbors=before).code, code_before)
                self.assertEqual(check("RIP_NEIGHBOR_EXPECTED", expected, device="S2", rip_neighbors=after).code, code_after)

    def test_an_advertised_client_prefix_is_not_a_client_vlan_peer(self):
        """After the cleanup R2 still learns the client prefix by RIP while S2 has no peer on the client VLAN."""
        upstream = routes(("192.168.10.0/24", "rip", ["Ethernet3"]))
        self.assertTrue(any(r["prefix"] == "192.168.10.0/24" and r["type"] == "rip" for r in upstream))
        after = live.parse_eos_rip_neighbors(RIP_AFTER, V4, V6)
        self.assertEqual(check("RIP_NEIGHBOR_EXPECTED", {"interface": "Vlan10", "present": False}, device="S2", rip_neighbors=after).status, "PASS")

    def test_a_named_peer_must_be_that_peer(self):
        after = live.parse_eos_rip_neighbors(RIP_AFTER, V4, V6)
        outcome = check("RIP_NEIGHBOR_EXPECTED", {"interface": "Vlan99", "peer": "192.168.110.9"}, device="S2", rip_neighbors=after)
        self.assertEqual((outcome.status, outcome.code), ("FAIL", "RIP_NEIGHBOR_MISSING"))


class WiringTests(SimpleTestCase):
    def test_stage_requirements_map_to_the_new_checks(self):
        self.assertEqual(REQUIREMENT_MAP["ISIS_ROUTE_INTENDED"], (({}, "ISIS_ROUTE_EXPECTED"),))
        self.assertEqual(REQUIREMENT_MAP["RIP_PEERING_INTENDED"], (({}, "RIP_NEIGHBOR_EXPECTED"),))


class RipRouteAndMetricTests(SimpleTestCase):
    def test_a_rip_route_is_checked_by_its_path(self):
        far = "192.168.255.1/32"
        via_client = routes((far, "rip", ["Vlan10"]))
        outcome = check("RIP_ROUTE_EXPECTED", {"prefix": far, "interfaces": ["Vlan99"]}, device="S2", routes=via_client)
        self.assertEqual((outcome.status, outcome.code, outcome.observed["paths"]), ("FAIL", "RIP_ROUTE_PATH_MISMATCH", ["Vlan10"]))
        via_transit = routes((far, "rip", ["Vlan99"]))
        self.assertEqual(check("RIP_ROUTE_EXPECTED", {"prefix": far, "interfaces": ["Vlan99"]}, device="S2", routes=via_transit).code, "RIP_ROUTE_PRESENT")
        self.assertEqual(check("RIP_ROUTE_EXPECTED", {"prefix": far}, device="S2", routes=routes((far, "static", ["Vlan99"]))).code, "RIP_ROUTE_MISSING")
        self.assertEqual(REQUIREMENT_MAP["RIP_ROUTE_INTENDED"], (({}, "RIP_ROUTE_EXPECTED"),))

    def test_an_intended_isis_metric_must_be_the_configured_metric(self):
        from core.services.health import routing_config

        rows = routing_config.eos("interface Ethernet1\n   isis enable NMAS\n   isis metric 1000\nrouter isis NMAS\n   net 49.0110.1921.6825.5011.00\n")
        base = {"protocol": "isis", "interface": "Ethernet1", "passive": False}
        self.assertEqual(check("ROUTING_BINDING_CONFIG", {**base, "metric": 1000}, routing_config=rows).status, "PASS")
        self.assertEqual(check("ROUTING_BINDING_CONFIG", {**base, "metric": 10}, routing_config=rows).status, "FAIL")
        self.assertEqual(check("ROUTING_BINDING_CONFIG", base, routing_config=rows).status, "PASS")       # no metric stated: not checked
