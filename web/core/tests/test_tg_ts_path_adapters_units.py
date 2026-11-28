"""Direct tests for the forwarding, active-probe and routing-protocol request/answer helpers
(troubleshooting/adapters/forwarding.py, probes.py, protocol.py).

Each helper either answers from complete evidence of the asked scope or returns an explicit UNKNOWN/gap: an incomplete
table never asserts absence, a probe answer from the wrong vantage is refused, and a protocol read without an explicit
scope is never issued.
"""

from __future__ import annotations

import json

from django.test import SimpleTestCase

from core.services.troubleshooting.adapters import forwarding as fw
from core.services.troubleshooting.adapters import probes as pr
from core.services.troubleshooting.adapters import protocol as proto
from core.tests import test_troubleshooting_probe_source as P

FLOW = {"src": "h1", "dst": "h2", "protocol": "tcp", "port": 443, "dst_prefix": "10.2.2.0/24", "src_prefix": "10.1.1.0/24"}
Q = fw.RouteQuery("10.2.2.0/24", "default", "ipv4")


def rib(routes, complete=True, vrf="default", family="ipv4"):
    return [{"value": {"vrf": vrf, "family": family, "routes": routes, "complete": complete, "table_kind": "rib"}}]


def fib(entries, complete=True, coverage="FULL_TABLE", queried=()):
    return [{"value": {"vrf": "default", "family": "ipv4", "entries": entries, "complete": complete, "coverage": coverage, "queried": queried,
                       "source": {"id": "fib-1"}, "provenance": "SIMULATED"}}]


def arp(address, state, mac, *, reported=True):
    return {"value": {"vrf": "default", "address": address, "state": state, "state_reported": reported, "mac": mac, "interface": "Ethernet1",
                      "family": "ipv4"}}


# ================================================================================================== forwarding
class ForwardingTests(SimpleTestCase):
    def test_route_queries_and_wanted_families_return_each_flow_prefix(self):
        ctx = fw.ForwardingContext(gateways={"r1": ["2001:db8::1"]})
        self.assertEqual([q.prefix for q in fw.route_queries(FLOW)], ["10.2.2.0/24", "10.1.1.0/24"])
        self.assertEqual(fw.wanted_families(FLOW, ctx), {"ipv4", "ipv6"})

    def test_route_queries_of_malformed_or_missing_prefixes_is_empty(self):
        self.assertEqual(fw.route_queries({"dst_prefix": "not-a-prefix"}), [])
        self.assertEqual(fw.route_queries(None), [])

    def test_wanted_families_without_a_prefix_never_reads_ipv6(self):
        self.assertEqual(fw.wanted_families({}, fw.ForwardingContext(gateways={"r1": ["bad"]})), {"ipv4"})

    def test_fib_requests_of_a_flow_without_prefixes_is_empty(self):
        self.assertEqual(fw.fib_requests({"src": "h1"}), [])

    def test_fib_lookup_returns_the_installed_covering_entry(self):
        entry = {"prefix": "10.2.0.0/16", "next_hops": [{"address": "10.0.12.2", "resolved": True}], "programmed": True, "action": "forward"}
        value, reason = fw.fib_lookup(fib([entry]), Q)
        self.assertEqual((value["installed"], value["next_hop"], value["resolved"], reason), (True, "10.0.12.2", True, None))

    def test_rib_lookup_of_an_incomplete_or_absent_table_is_unknown(self):
        with self.subTest("an incomplete table cannot assert absence"):
            value, reason = fw.rib_lookup(rib([], complete=False), Q, device="r1")
            self.assertIsNone(value)
            self.assertIn("incomplete", reason)
        with self.subTest("a missing VRF table is unknown"):
            self.assertIsNone(fw.rib_lookup(rib([], vrf="blue"), Q, device="r1")[0])

    def test_neighbor_values_marks_unjudgeable_or_duplicate_entries(self):
        out = fw.neighbor_values([arp("10.0.12.2", "PERMANENT", "aa:aa"), arp("10.0.12.2", "FAILED", "bb:bb"),
                                  arp("10.0.12.9", "REACHABLE", "", reported=False)])
        value, quality, flags = out["10.0.12.2"]
        self.assertEqual((quality, value["dup_macs"], "NEIGHBOR_STATE_NOT_JUDGEABLE" in flags), ("UNTRUSTED", ["bb:bb"], True))
        self.assertIn("ARP_STATE_NOT_REPORTED", out["10.0.12.9"][2])

    def test_is_supported_returns_true_for_a_parsed_platform(self):
        self.assertTrue(fw.is_supported("ceos", "4.36.2F"))


# ======================================================================================================= probes
class ProbeTests(SimpleTestCase):
    def ctx(self, **kw):
        return pr.ProbeContext(**{**P.CTX_KW, **kw})

    def tcp(self):
        return pr.requests_for_device(P.FLOW, "h1", ["service.probe"], self.ctx())[0]

    def test_family_of_returns_the_address_family(self):
        self.assertEqual((pr.family_of("10.1.1.1"), pr.family_of("2001:db8::1")), ("ipv4", "ipv6"))

    def test_family_of_an_invalid_or_multicast_address_is_empty(self):
        self.assertEqual((pr.family_of("h2"), pr.family_of("224.0.0.5")), ("", ""))

    def test_served_keys_returns_each_request_engine_key(self):
        reqs = pr.requests_for_device(P.FLOW, "h1", ["service.probe", "path.trace"], self.ctx())
        self.assertEqual(pr.served_keys(reqs), {"service.probe@tcp", "path.trace@h2"})

    def test_served_keys_of_no_request_is_empty(self):
        self.assertEqual(pr.served_keys(pr.requests_for_device(P.FLOW, "h2", ["service.probe"], self.ctx())), set())

    def test_pmtu_request_builds_a_bounded_ladder_up_to_the_payload(self):
        req = pr.pmtu_request({**P.FLOW, "payload_bytes": 1400}, "h1", "10.1.1.10", "h2", "10.2.2.20", self.ctx(pmtu_protocols=("icmp",)))
        self.assertEqual((req.sizes, req.family, req.df, req.required_payload), ((548, 1000, 1200, 1400), "ipv4", True, 1400))

    def test_pmtu_request_with_an_invalid_payload_falls_back_to_the_default(self):
        req = pr.pmtu_request({**P.FLOW, "payload_bytes": True}, "h1", "10.1.1.10", "h2", "", self.ctx(pmtu_protocols=("icmp",)))
        self.assertEqual((req.required_payload, req.family), (1472, ""))

    def test_parse_response_returns_the_tcp_measurement(self):
        out = pr.parse_response(P.tcp_doc(), self.tcp(), timeout_s=2.0)
        self.assertEqual((out["key"], out["value"]["ok"], out["value"]["l7_verified"]), ("service.probe", 3, False))

    def test_parse_response_refuses_malformed_json_or_another_vantage(self):
        doc = json.loads(P.tcp_doc())
        doc["vantage"]["device"] = "h9"
        for label, raw in (("malformed JSON", "{"), ("another vantage", json.dumps(doc))):
            with self.subTest(f"{label} is refused"), self.assertRaises(pr.ProbeBad):
                pr.parse_response(raw, self.tcp(), timeout_s=2.0)


# ===================================================================================================== protocol
TARGET = {"device": "R1", "neighbor_device": "R2", "protocol": "ospf", "af": "ipv4", "interface": "Ethernet1", "neighbor_interface": "Ethernet1"}
WANTED = list(proto.PROTOCOL_KEYS)


class ProtocolTests(SimpleTestCase):
    def test_wanted_here_returns_true_for_a_protocol_key(self):
        self.assertTrue(proto.wanted_here(["protocol.config"]))

    def test_wanted_here_without_a_protocol_key_is_false(self):
        self.assertFalse(proto.wanted_here(["interfaces"]))

    def test_scope_of_returns_the_explicit_scope(self):
        self.assertEqual(proto.scope_of(TARGET), {"protocol": "ospf", "af": "ipv4", "vrf": "default"})

    def test_scope_of_an_unsupported_or_incomplete_target_is_none(self):
        for label, target in (("an unsupported protocol", {**TARGET, "protocol": "eigrp"}), ("no interface", {**TARGET, "interface": ""}),
                              ("no target", None)):
            with self.subTest(f"{label} has no scope"):
                self.assertIsNone(proto.scope_of(target))

    def test_served_keys_returns_each_included_read(self):
        reqs = proto.requests_for_device(TARGET, "R1", WANTED)
        self.assertEqual(proto.served_keys(reqs), set(WANTED))

    def test_served_keys_of_no_request_is_empty(self):
        self.assertEqual(proto.served_keys([]), set())

    def test_requests_for_device_refuses_a_device_that_is_neither_end_or_outside_scope(self):
        self.assertEqual(proto.requests_for_device(TARGET, "R9", WANTED), [])
        self.assertEqual(proto.requests_for_device(TARGET, "R2", WANTED, scope_devices=("R1",)), [])

    def test_gap_reason_names_each_unknown_cause(self):
        self.assertTrue(proto.gap_reason({**TARGET, "protocol": "eigrp"}, True, False).startswith("UNSUPPORTED_OPERATION"))
        self.assertTrue(proto.gap_reason({}, True, False).startswith("SCOPE_MISMATCH"))
        self.assertEqual(proto.gap_reason(TARGET, False, False), proto.PROTO_GAP_REASON)
        self.assertTrue(proto.gap_reason(TARGET, True, False).startswith("SCOPE_MISMATCH"))
        self.assertTrue(proto.gap_reason(TARGET, True, True).startswith("UNKNOWN"))
