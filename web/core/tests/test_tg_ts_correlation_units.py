"""Direct tests for the topology / path / exception / change correlation helpers (troubleshooting/correlation.py).

Intent is never proof of state, a missing RIB/FIB is UNKNOWN, a test exception never suppresses production loss, and
change proximity never blames.  The topology is a small synthetic square with one stub.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase

from core.services.troubleshooting import correlation as corr

NOW = datetime(2026, 11, 27, 6, 0, tzinfo=timezone.utc)
LINKS = [{"a": "h1", "a_if": "eth1", "b": "r1", "b_if": "Ethernet1"}, {"a": "r1", "a_if": "Ethernet2", "b": "r2", "b_if": "Ethernet1"},
         {"a": "r1", "a_if": "Ethernet3", "b": "r3", "b_if": "Ethernet1"}, {"a": "r2", "a_if": "Ethernet2", "b": "h2", "b_if": "eth1"},
         {"a": "r3", "a_if": "Ethernet2", "b": "h2", "b_if": "eth2"}]


def iso(t):
    return t.isoformat().replace("+00:00", "Z")


class TopologyTests(SimpleTestCase):
    def test_build_graph_preserves_parallel_links(self):
        g = corr.build_graph(LINKS + [{"a": "r1", "a_if": "Ethernet9", "b": "r2", "b_if": "Ethernet9"}])
        self.assertEqual(len(g["r1"]["r2"]), 2)
        self.assertEqual(sorted(g["r1"]), ["h1", "r2", "r3"])

    def test_build_graph_of_no_links_is_empty(self):
        self.assertEqual(dict(corr.build_graph([])), {})

    def test_find_link_returns_the_link_at_either_end(self):
        self.assertIs(corr.find_link(LINKS, "r2", "Ethernet1"), LINKS[1])
        self.assertIs(corr.find_link(LINKS, "r1", "Ethernet2"), LINKS[1])

    def test_find_link_of_an_unknown_port_is_none(self):
        self.assertIsNone(corr.find_link(LINKS, "r1", "Ethernet7"))

    def test_compare_topology_reports_missing_unexpected_and_miscabled_links(self):
        observed = LINKS[:3] + [{"a": "r2", "a_if": "Ethernet2", "b": "r3", "b_if": "Ethernet2"}]
        out = corr.compare_topology(LINKS, observed)
        self.assertFalse(out["conforms"])
        self.assertEqual(len(out["missing_in_observed"]), 2)
        self.assertEqual(sorted(m["port"] for m in out["miscabled"]), ["r2:Ethernet2", "r3:Ethernet2"])

    def test_intended_paths_returns_shortest_first_hops(self):
        paths = corr.intended_paths(LINKS, "h1", "h2")
        self.assertEqual([[h["device"] for h in p] for p in paths], [["h1", "r1", "r2", "h2"], ["h1", "r1", "r3", "h2"]])
        self.assertEqual(paths[0][1], {"device": "r1", "in_if": "Ethernet1", "out_if": "Ethernet2"})

    def test_intended_paths_to_an_unconnected_device_is_empty(self):
        self.assertEqual(corr.intended_paths(LINKS, "h1", "nowhere"), [])

    def test_l3_view_returns_routed_hops_only(self):
        path = corr.intended_paths(LINKS, "h1", "h2")[0]
        self.assertEqual([h["device"] for h in corr.l3_view(path, {"r2": "switch"}, "h1")], ["r1", "h2"])

    def test_l3_view_of_a_switch_only_path_is_empty(self):
        self.assertEqual(corr.l3_view([{"device": "h1"}, {"device": "sw1"}], {"sw1": "switch"}, "h1"), [])

    def test_diff_path_conforms_to_a_matching_traceroute(self):
        out = corr.diff_path(corr.intended_paths(LINKS, "h1", "h2")[0], ["h1", "r1", "r2", "h2"])
        self.assertEqual((out["conforms"], out["first_divergence_index"]), (True, None))

    def test_diff_path_of_a_divergent_traceroute_is_not_conformant(self):
        out = corr.diff_path(corr.intended_paths(LINKS, "h1", "h2")[0], ["h1", "r1", "r3", "h2"])
        self.assertEqual((out["conforms"], out["first_divergence"]), (False, {"expected": "r2", "observed": "r3"}))


class ForwardingAndProtocolTests(SimpleTestCase):
    def test_rib_fib_gap_returns_consistent_when_both_agree(self):
        self.assertEqual(corr.rib_fib_gap({"present": True, "next_hop": "x"}, {"installed": True, "next_hop": "x"})["verdict"], "CONSISTENT")

    def test_rib_fib_gap_flags_missing_or_mismatched_forwarding(self):
        cases = (("a missing fib observation", {"present": True}, None, "UNKNOWN"),
                 ("an uninstalled route", {"present": True, "next_hop": "x"}, {"installed": False}, "FIB_INSTALL_DISCREPANCY"),
                 ("a different next hop", {"present": True, "next_hop": "x"}, {"installed": True, "next_hop": "y"}, "NEXT_HOP_MISMATCH"),
                 ("an unresolved adjacency", {"present": True, "next_hop": "x"}, {"installed": True, "next_hop": "x", "resolved": False},
                  "UNRESOLVED_ADJACENCY"),
                 ("no rib route", {"present": False}, {"installed": False}, "NO_ROUTE"))
        for label, rib, fib, verdict in cases:
            with self.subTest(f"{label} is {verdict}"):
                self.assertEqual(corr.rib_fib_gap(rib, fib)["verdict"], verdict)

    def test_protocol_distinction_accepts_an_intentional_diagnostic_block(self):
        probes = {"tcp": {"sent": 20, "ok": 20}, "icmp": {"sent": 20, "ok": 0}}
        out = corr.protocol_distinction(probes, {"protocol": "tcp"}, intentionally_blocked=["ICMP"])
        self.assertEqual((out["classification"], out["expected_protocol_distinction"]), ("NO_PRODUCTION_IMPACT", True))
        self.assertEqual(corr.protocol_distinction({"tcp": {"sent": 5, "ok": 5}}, {"protocol": "tcp"})["classification"], "HEALTHY")

    def test_protocol_distinction_never_lets_diagnostics_mask_production(self):
        cases = (("a lossy production protocol", {"tcp": {"sent": 20, "ok": 10}, "icmp": {"sent": 20, "ok": 20}}, "PRODUCTION_IMPACT"),
                 ("no production probe", {"icmp": {"sent": 20, "ok": 20}}, "UNKNOWN"),
                 ("an unexplained diagnostic failure", {"tcp": {"sent": 20, "ok": 20}, "icmp": {"sent": 20, "ok": 0}},
                  "NO_PRODUCTION_IMPACT_UNEXPLAINED_DIAGNOSTIC_FAILURE"))
        for label, probes, cls in cases:
            with self.subTest(f"{label} is {cls}"):
                self.assertEqual(corr.protocol_distinction(probes, {"protocol": "tcp"})["classification"], cls)


POLICY = {"id": "EXC-1", "status": "ACTIVE", "expires_at": iso(NOW + timedelta(hours=1)), "bound_revisions": {"golden": "g7"},
          "scope": {"src": "h1", "dst": "h2", "vrf": "", "protocols": ["icmp"]}}
SIGNAL = {"src": "h1", "dst": "h2", "vrf": "", "protocol": "ICMP", "kind": "TEST_FAILURE", "production": False}


class ExceptionAndCounterTests(SimpleTestCase):
    def test_exception_matches_suppresses_an_in_scope_test_failure(self):
        out = corr.exception_matches(POLICY, SIGNAL, current_revisions={"golden": "g7"}, now=NOW)
        self.assertEqual((out["suppressed"], out["policy"]), (True, "EXC-1"))

    def test_exception_matches_refuses_production_expired_invalidated_or_out_of_scope_signals(self):
        cases = (("production loss", POLICY, {**SIGNAL, "production": True}, {"golden": "g7"}),
                 ("an expired policy", {**POLICY, "expires_at": iso(NOW - timedelta(seconds=1))}, SIGNAL, {"golden": "g7"}),
                 ("a revoked policy", {**POLICY, "status": "REVOKED"}, SIGNAL, {"golden": "g7"}),
                 ("a changed bound revision", POLICY, SIGNAL, {"golden": "g8"}),
                 ("an empty scope", {**POLICY, "scope": {}}, SIGNAL, {"golden": "g7"}),
                 ("another destination", POLICY, {**SIGNAL, "dst": "h3"}, {"golden": "g7"}),
                 ("an unlisted protocol", POLICY, {**SIGNAL, "protocol": "tcp"}, {"golden": "g7"}))
        for label, policy, signal, revisions in cases:
            with self.subTest(f"{label} is never suppressed"):
                self.assertFalse(corr.exception_matches(policy, signal, current_revisions=revisions, now=NOW)["suppressed"])

    def test_counter_flow_correlation_refuses_unusable_or_uncorrelated_counters(self):
        t = [iso(NOW + timedelta(seconds=s)) for s in (0, 30, 60, 600)]
        lossy = [{"at": t[1], "loss_pct": 40.0}]
        cases = (("a single sample", [{"at": t[0], "hits": 1}], lossy, None),
                 ("an opposite-direction sample", [{"at": t[0], "hits": 1, "direction": "out"}, {"at": t[1], "hits": 9, "direction": "out"}], lossy, None),
                 ("a reset counter", [{"at": t[0], "hits": 9}, {"at": t[1], "hits": 1}], lossy, None),
                 ("a flat counter", [{"at": t[0], "hits": 5}, {"at": t[1], "hits": 5}], lossy, False),
                 ("no flow impairment", [{"at": t[0], "hits": 5}, {"at": t[1], "hits": 9}], [], False),
                 ("a distant onset", [{"at": t[0], "hits": 5}, {"at": t[1], "hits": 9}], [{"at": t[3], "loss_pct": 40.0}], False))
        for label, counters, flows, expected in cases:
            with self.subTest(f"{label} is not correlated"):
                self.assertIs(corr.counter_flow_correlation(counters, flows, direction="in")["correlated"], expected)
        with self.subTest("a matching increase at the onset is correlated"):
            out = corr.counter_flow_correlation([{"at": t[0], "hits": 5}, {"at": t[1], "hits": 9}], lossy, direction="in")
            self.assertEqual((out["correlated"], out["delta"]), (True, 4))


class ChangeCorrelationTests(SimpleTestCase):
    def test_change_correlation_returns_scored_rows_that_never_blame(self):
        changes = [{"change_id": "CHG-ON-PATH", "at": iso(NOW - timedelta(minutes=10)), "devices": ["r2"], "approved": True},
                   {"change_id": "CHG-OFF-PATH", "at": iso(NOW - timedelta(minutes=10)), "devices": ["r3"]}]
        rows = corr.change_correlation(changes, onset=NOW, path_devices=["r1", "r2"], links=LINKS)
        self.assertEqual([r["change_id"] for r in rows], ["CHG-ON-PATH", "CHG-OFF-PATH"])
        self.assertEqual((rows[0]["relation"], rows[0]["on_affected_path"], rows[1]["topology_distance"]), ("BEFORE_ONSET", True, 1))
        self.assertTrue(all(r["blame"] is False for r in rows))

    def test_change_correlation_of_undated_late_or_old_changes_never_scores(self):
        changes = [{"change_id": "CHG-UNDATED"}, {"change_id": "CHG-LATE", "at": iso(NOW + timedelta(minutes=1)), "devices": ["r1"]},
                   {"change_id": "CHG-OLD", "at": iso(NOW - timedelta(days=30)), "devices": ["r1"]}]
        rows = {r["change_id"]: r for r in corr.change_correlation(changes, onset=NOW, path_devices=["r1"], links=LINKS)}
        self.assertEqual({k: r["relation"] for k, r in rows.items()},
                         {"CHG-UNDATED": "UNKNOWN_TIME", "CHG-LATE": "AFTER_ONSET", "CHG-OLD": "OUTSIDE_LOOKBACK"})
        self.assertEqual((rows["CHG-LATE"]["score"], rows["CHG-OLD"]["score"]), (0.0, 0.0))
