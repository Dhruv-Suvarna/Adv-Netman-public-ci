"""Direct tests for the deterministic multi-fault observation / classification helpers (troubleshooting/faults.py).

Every helper is a pure function over time-stamped evidence: counter discontinuities are never read as health, a flap
needs repeated transitions inside a bounded window, and a proposal the case's own evidence contradicts is refused.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core.services.troubleshooting import faults as f
from core.services.troubleshooting import repository as repo
from core.tests.test_tg_ts_engine_units import open_case
from core.tests.test_troubleshooting_engine import ACTOR

NOW = datetime(2026, 11, 27, 6, 0, tzinfo=timezone.utc)


def sample(at=NOW, *, admin="up", oper="up", changes=0, counters=None, **kw):
    return f.InterfaceSample("r1", "Ethernet1", at, admin, oper, "connected" if oper == "up" else "notconnect",
                             "up" if oper == "up" else "down", link_status_changes=changes,
                             counters=counters if counters is not None else {"totalInErrors": 0, "inTotalPkts": 1000}, **kw)


class ObservationTests(SimpleTestCase):
    def test_interface_sample_as_dict_returns_iso_times(self):
        d = sample(last_change=NOW - timedelta(seconds=5)).as_dict()
        self.assertEqual((d["at"], d["last_change"], d["interface"]), ("2026-11-27T06:00:00Z", "2026-11-27T05:59:55Z", "Ethernet1"))

    def test_interface_samples_of_a_document_without_interfaces_is_empty(self):
        for label, doc in (("no document", None), ("no interfaces", {}), ("management only", {"interfaces": {"Management0": {}}})):
            with self.subTest(f"{label} gives no sample"):
                self.assertEqual(f.interface_samples("r1", doc, NOW), [])

    def test_linux_interface_samples_never_include_the_management_veth_or_non_ports(self):
        links = [{"ifname": "eth0", "flags": ["UP", "LOWER_UP"]}, {"ifname": "lo", "flags": ["UP"]}, {"ifname": "eth01"},
                 {"ifname": "eth1@if9", "flags": ["UP"]}]
        out = f.linux_interface_samples("r3", links, NOW)
        self.assertEqual([(s.interface, s.admin, s.oper) for s in out], [("eth1", "up", "down")])
        self.assertEqual(f.linux_interface_samples("r3", None, NOW), [])

    def test_adjacency_sample_key_identifies_device_protocol_and_neighbor(self):
        s = f.AdjacencySample("r1", "ospf", "10.0.0.2", "Ethernet2", "full", NOW)
        self.assertEqual(s.key, ("r1", "ospf", "10.0.0.2"))

    def test_adjacency_samples_of_no_routing_documents_is_empty(self):
        self.assertEqual(f.adjacency_samples("r1", None, None, NOW), [])
        self.assertEqual(f.adjacency_samples("r1", {"vrfs": {}}, {"vrfs": {"default": {"peers": {}}}}, NOW), [])


class CounterAndHistoryTests(SimpleTestCase):
    def test_counter_delta_and_degraded_return_each_reason_above_threshold(self):
        prev = sample(counters={"totalInErrors": 0, "inDiscards": 0, "inTotalPkts": 1000})
        cur = sample(NOW + timedelta(seconds=60), counters={"totalInErrors": 30, "inDiscards": 200, "inTotalPkts": 3000})
        delta = f.counter_delta(prev, cur)
        self.assertEqual((delta.reset, delta.deltas["totalInErrors"], delta.interval_s), (False, 30, 60.0))
        self.assertEqual(len(delta.degraded()), 2)

    def test_counter_delta_of_a_reset_counter_is_never_degraded(self):
        prev = sample(counters={"totalInErrors": 500, "inTotalPkts": 9000}, changes=7)
        cur = sample(NOW + timedelta(seconds=60), counters={"totalInErrors": 0, "inTotalPkts": 10}, changes=0)
        delta = f.counter_delta(prev, cur)
        self.assertTrue(delta.reset)
        self.assertEqual(delta.degraded(), [])

    def test_link_history_window_counts_device_and_poll_transitions(self):
        history = f.LinkHistory()
        for i, (oper, changes) in enumerate((("up", 0), ("down", 3), ("up", 6))):
            history.update(sample(NOW + timedelta(seconds=10 * i), oper=oper, changes=changes))
        win = history.window(NOW + timedelta(seconds=30))
        self.assertEqual((win["transitions"], win["device_counter_transitions"], len(win["poll_edges"]), win["severity"]),
                         (6, 6, 2, "MODERATE"))

    def test_link_history_window_outside_the_window_has_no_transition(self):
        history = f.LinkHistory()
        history.update(sample(NOW, oper="up"))
        history.update(sample(NOW + timedelta(seconds=10), oper="down", changes=1))
        win = history.window(NOW + timedelta(hours=1))
        self.assertEqual((win["transitions"], win["severity"], win["stable_for_s"]), (0, "NONE", None))

    def test_flap_severity_returns_each_band(self):
        self.assertEqual([f.flap_severity(n) for n in (4, 8, 16)], ["MODERATE", "HIGH", "SEVERE"])

    def test_flap_severity_below_the_minimum_is_none(self):
        self.assertEqual(f.flap_severity(f.FLAP_MIN_TRANSITIONS - 1), "NONE")


class ClassificationTests(SimpleTestCase):
    def test_classification_as_dict_carries_the_schema(self):
        c = f.Classification(f.NO_FAULT, {"device": "r1"}, False, f.CAUSE_CONFIRMED, "ok")
        self.assertEqual((c.as_dict()["schema"], c.as_dict()["category"]), (f.SCHEMA, f.NO_FAULT))

    def test_classify_adjacency_never_reports_a_healthy_expected_neighbor(self):
        exp = f.AdjacencySample("r1", "ospf", "10.0.0.2", "Ethernet2", "full", NOW)
        self.assertEqual(f.classify_adjacency([exp], [exp], now=NOW, expectation_source="golden"), [])
        out = f.classify_adjacency([exp], [], now=NOW, expectation_source="golden", link_incidents={"r1": "Ethernet2 down"})
        self.assertEqual((out[0].category, out[0].evidence["possibly_secondary_to"]), (f.ROUTING_ADJACENCY_FAILURE, "Ethernet2 down"))

    def test_classify_route_returns_no_fault_via_the_expected_next_hop(self):
        c = f.classify_route("r1", "10.9.0.0/24", ["10.0.0.2"], ["10.0.0.2", "10.0.0.6"], now=NOW)
        self.assertEqual((c.category, c.cause_status), (f.NO_FAULT, f.CAUSE_CONFIRMED))

    def test_classify_reachability_returns_a_confirmed_route_domain_for_sustained_loss(self):
        route = f.classify_route("r1", "10.9.0.0/24", ["10.0.0.2"], [], now=NOW)
        samples = [{"at": "t1", "loss_pct": 100.0, "measured": True}, {"at": "t2", "loss_pct": 100.0, "measured": True}]
        c = f.classify_reachability({"source": "h1", "destination": "h2", "af": "ipv4"}, samples, baseline_loss_pct=0.0, routes=[route], now=NOW)
        self.assertEqual((c.category, c.cause_status, c.cause), (f.ROUTE_OR_REACHABILITY_FAILURE, f.CAUSE_CONFIRMED, route.summary))
        healthy = f.classify_reachability({"source": "h1"}, [{"loss_pct": 0.0, "measured": True}] * 2, baseline_loss_pct=0.0, now=NOW)
        self.assertEqual(healthy.category, f.NO_FAULT)


class ProposalProblemTests(TestCase):
    def setUp(self):
        self.case = open_case(key="tg-faults")

    def observe(self, value, at):
        ref = repo.store_evidence(ACTOR, self.case, source_type="cli", device="r1", command_or_api="show interfaces | json",
                                  adapter="unit", adapter_version="1", collected_at=at, raw="{}")
        repo.record_observation(ACTOR, self.case, key=f"{f.EVIDENCE_KEY}@Ethernet1", target="r1", observed_at=at, value=value,
                                evidence=ref)

    def test_proposal_problem_accepts_an_enable_of_an_interface_observed_admin_down(self):
        self.observe({"admin": "down", "oper": "down"}, NOW - timedelta(seconds=30))
        self.assertEqual(f.proposal_problem(self.case, {"kind": "interface_enable", "device": "r1", "interface": "Ethernet1"}, now=NOW), "")
        self.assertEqual(f.proposal_problem(self.case, {"kind": "neighbor_reset"}, now=NOW), "")

    def test_proposal_problem_refuses_an_enable_of_an_interface_observed_admin_up(self):
        self.observe({"admin": "up", "oper": "down"}, NOW - timedelta(seconds=30))
        reason = f.proposal_problem(self.case, {"kind": "interface_enable", "device": "r1", "interface": "Ethernet1"}, now=NOW)
        self.assertTrue(reason.startswith("INEFFECTIVE_OPERATION: r1 Ethernet1 was observed administratively UP"))
