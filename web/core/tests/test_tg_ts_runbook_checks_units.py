"""Direct tests for the specialist runbook checks RB01 (link flap), RB03 (neighbor), RB04 (STP), RB05 (DNS), RB06 (MTU), RB07 (layer 1).

Each runbook's healthy scenario (the one its scenario tests already accept end to end) supplies the evidence context the engine
builds.  Positive: every check called on it returns PASS and every applicability predicate whose feature the scenario has returns
True.  Negative: with the evidence withheld the check refuses with a ``Gap`` or an INCONCLUSIVE / NOT_APPLICABLE answer, a fault
injected into the evidence is reported as FAIL, and an applicability predicate whose feature is absent from intent refuses to apply.
Feature-specific checks (LAG, MST, EVPN, split-horizon, DNSSEC, subinterfaces) get the feature added to intent and evidence.
"""

from __future__ import annotations

import copy

from django.test import TestCase

from core.services.troubleshooting.runbooks import base, rb01_link_flap as rb01, rb03_neighbor as rb03, rb04_stp as rb04
from core.services.troubleshooting.runbooks import rb05_dns as rb05, rb06_mtu as rb06, rb07_layer1 as rb07
from core.tests import test_troubleshooting_runbooks as R
from core.tests.test_troubleshooting_engine import S


def context_of(run):
    engine, _stages = run
    return engine._context()


def derive(h, *extra, view=None, **over):
    """A copy of ``h`` with ``extra`` observations added (or ``view`` replacing the evidence) and the given parts overridden."""
    kw = dict(now=h.now, case=copy.deepcopy(h.case), flow=dict(h.flow), intent=copy.deepcopy(h.intent), baselines=h.baselines, changes=h.changes,
              path_fwd=h.path_fwd, path_ret=h.path_ret, results=h.results, intent_evidence_ids=h.intent_evidence_ids, alarms=h.alarms,
              correlation=h.correlation)
    kw.update(over)
    return base.Ctx(view=view if view is not None else base.EvidenceView([*h.view.all(), *extra], h.now), **kw)


def withheld(h):
    return derive(h, view=base.EvidenceView([], h.now))


def ob(h, key, device, subject, value):
    return base.Obs(key=key, device=device, subject=subject, value=value, observed_at=h.now, evidence_ids=(f"ev-{key}-{device}",))


class RunbookCheckCase(TestCase):
    module = None
    checks: tuple[str, ...] = ()
    # checks that answer without device evidence; their negative is exercised by a dedicated test
    evidence_free: tuple[str, ...] = ()
    # checks that answer INCONCLUSIVE / NOT_APPLICABLE themselves when their evidence is absent
    self_refusing: tuple[str, ...] = ()

    def healthy(self):
        raise NotImplementedError

    def run_checks_on_healthy(self):
        h = self.healthy()
        for name in self.checks:
            with self.subTest(check=name):
                result = getattr(self.module, name)(derive(h))
                self.assertEqual(result.verdict, "PASS", f"{name}: {result.summary or result.reason}")

    def run_checks_without_evidence(self):
        empty = withheld(self.healthy())
        for name in self.checks:
            if name in self.evidence_free:
                continue
            check = getattr(self.module, name)
            if name in self.self_refusing:
                with self.subTest(f"{name} refuses a verdict without evidence"):
                    self.assertIn(check(empty).verdict, ("INCONCLUSIVE", "SKIPPED"))
                continue
            with self.subTest(f"{name} refuses missing evidence"):
                with self.assertRaises(base.Gap) as caught:
                    check(empty)
                self.assertIn(caught.exception.status, ("INCONCLUSIVE", "UNAVAILABLE"))


class LinkFlapChecksTests(RunbookCheckCase):
    module = rb01
    checks = ("lf01", "lf02", "lf03", "lf04", "lf05", "lf07", "lf08", "lf09")
    evidence_free = ("lf09",)

    def healthy(self):
        return context_of(R.rb01())

    def lag(self, h, state="bundled", churn=0):
        return derive(h, ob(h, "lacp.member", "r1", "Eth2", {"state": state, "churn_1h": churn}), intent={**h.intent, "lag": {"r1:Eth2": "Po1"}})

    def test_every_link_flap_check_returns_pass_on_a_stable_link(self):
        self.run_checks_on_healthy()

    def test_link_flap_checks_refuse_withheld_evidence(self):
        self.run_checks_without_evidence()

    def test_lf06_lacp_member_returns_pass_when_bundled(self):
        h = self.healthy()
        ctx = self.lag(h)
        self.assertIs(rb01.lf06_applies(ctx)[0], True)
        self.assertEqual(rb01.lf06(ctx).verdict, "PASS")

    def test_lf06_refuses_churn_and_an_interface_outside_any_lag(self):
        h = self.healthy()
        with self.subTest("a detached member is refused as a fault"):
            r = rb01.lf06(self.lag(h, state="detached", churn=5))
            self.assertEqual((r.verdict, r.finding.id), ("FAIL", "F-lacp"))
        with self.subTest("an interface not in a lag is refused applicability"):
            self.assertIs(rb01.lf06_applies(derive(h))[0], False)
        with self.subTest("a lag member with no lacp evidence is refused"):
            with self.assertRaises(base.Gap):
                rb01.lf06(derive(withheld(h), intent={**h.intent, "lag": {"r1:Eth2": "Po1"}}))

    def test_lf09_without_flow_or_alternate_path_is_inconclusive(self):
        h = self.healthy()
        ctx = derive(withheld(h), intent={**h.intent, "links": []}, flow={})
        with self.subTest("no flow health and no alternate path cannot judge impact"):
            self.assertEqual(rb01.lf09(ctx).verdict, "INCONCLUSIVE")


class NeighborChecksTests(RunbookCheckCase):
    module = rb03
    checks = ("nb01", "nb02", "nb03", "nb04", "nb05", "nb06", "nb07", "nb08", "nb09", "nb10")

    def healthy(self):
        return context_of(R.RB03Tests.run_nb(None, S.rb03_obs()))

    def proto(self, h, protocol):
        return derive(h, case={**h.case, "target": {**h.case["target"], "protocol": protocol}})

    def test_every_neighbor_check_returns_pass_on_a_full_adjacency(self):
        self.run_checks_on_healthy()

    def test_neighbor_checks_refuse_withheld_evidence(self):
        self.run_checks_without_evidence()

    def test_applicability_follows_the_protocol_and_adjacency(self):
        h = self.healthy()
        self.assertIs(rb03.nb03_applies(self.proto(h, "bgp"))[0], True)
        self.assertIs(rb03.nb07_applies(derive(h))[0], True)
        self.assertIs(rb03.nb10_applies(derive(h))[0], True)

    def test_applicability_refuses_protocols_and_states_it_does_not_cover(self):
        h = self.healthy()
        with self.subTest("ospf has no tcp session, so nb03 does not apply"):
            self.assertIs(rb03.nb03_applies(derive(h))[0], False)
        with self.subTest("bgp exchanges no mtu, so nb07 does not apply"):
            self.assertIs(rb03.nb07_applies(self.proto(h, "bgp"))[0], False)
        with self.subTest("a neighbor not established is refused route checks"):
            self.assertIs(rb03.nb10_applies(withheld(h))[0], False)


class StpChecksTests(RunbookCheckCase):
    module = rb04
    checks = ("st01", "st02", "st03", "st04", "st06", "st08", "st09")
    evidence_free = ("st01",)
    self_refusing = ("st08",)
    DEVS = ("sw1", "sw2", "sw3")

    def healthy(self):
        return context_of(R.RB04Tests.run_st(None, S.rb04_obs(), R.RB04Tests.MODES))

    def modes(self, h, mode, *extra):
        intent = copy.deepcopy(h.intent)
        intent.setdefault("l2", {})["stp"] = {d: mode for d in self.DEVS}
        return derive(h, *extra, intent=intent)

    def test_every_stp_check_returns_pass_on_a_stable_rstp_domain(self):
        self.run_checks_on_healthy()
        self.assertIs(rb04.st_applies(derive(self.healthy()))[0], True)

    def test_stp_checks_refuse_withheld_evidence(self):
        self.run_checks_without_evidence()

    def test_st01_refuses_an_unknown_or_stp_free_domain(self):
        h = self.healthy()
        with self.subTest("a domain with no stp mode in intent is inconclusive"):
            self.assertEqual(rb04.st01(derive(h, intent={**h.intent, "l2": {}})).verdict, "INCONCLUSIVE")
        with self.subTest("an evpn domain is not applicable"):
            ctx = self.modes(h, "evpn-vxlan")
            self.assertEqual(rb04.st01(ctx).status, "NOT_APPLICABLE")
            self.assertIs(rb04.st_applies(ctx)[0], False)

    def test_st05_mst_region_returns_pass_when_digests_agree(self):
        h = self.healthy()
        cfg = {"name": "R1", "revision": 3, "digest": "abc"}
        ctx = self.modes(h, "mst", *(ob(h, "stp.mst_config", d, "", cfg) for d in self.DEVS))
        self.assertEqual(rb04.st05(ctx).verdict, "PASS")

    def test_st05_refuses_a_split_region_and_a_non_mst_domain(self):
        h = self.healthy()
        with self.subTest("differing mst digests are refused as a fault"):
            cfgs = [ob(h, "stp.mst_config", d, "", {"name": "R1", "revision": 3, "digest": "abc" if d != "sw3" else "zzz"}) for d in self.DEVS]
            self.assertEqual(rb04.st05(self.modes(h, "mst", *cfgs)).verdict, "FAIL")
        with self.subTest("an rstp domain is not applicable"):
            self.assertEqual(rb04.st05(derive(h)).status, "NOT_APPLICABLE")

    def test_st07_port_channel_returns_pass_when_members_are_bundled(self):
        h = self.healthy()
        ctx = derive(h, ob(h, "lacp.member", "sw1", "Eth5", {"state": "bundled"}), intent={**h.intent, "lag": {"sw1:Eth5": "Po5"}})
        self.assertIs(rb04.st07_applies(ctx)[0], True)
        self.assertEqual(rb04.st07(ctx).verdict, "PASS")

    def test_st07_refuses_a_mismatched_partner_and_a_domain_without_lag(self):
        h = self.healthy()
        with self.subTest("a partner mismatch is refused as a fault"):
            ctx = derive(h, ob(h, "lacp.member", "sw1", "Eth5", {"state": "bundled", "partner_mismatch": True}), intent={**h.intent, "lag": {"sw1:Eth5": "Po5"}})
            self.assertEqual(rb04.st07(ctx).verdict, "FAIL")
        with self.subTest("no port-channel in intent is refused applicability"):
            self.assertIs(rb04.st07_applies(derive(h))[0], False)

    def test_st10_evpn_mobility_returns_pass_when_normal(self):
        h = self.healthy()
        ctx = self.modes(h, "evpn-vxlan", *(ob(h, "evpn.state", d, "", {"duplicate_mac_detected": False, "mac_mobility_events_1h": 1}) for d in self.DEVS))
        self.assertIs(rb04.st10_applies(ctx)[0], True)
        result = rb04.st10(ctx)
        self.assertEqual((result.verdict, result.observed["checked"]), ("PASS", 3))

    def test_st10_refuses_duplicate_macs_and_a_domain_without_evpn(self):
        h = self.healthy()
        with self.subTest("a duplicate mac is refused as a fault"):
            ctx = self.modes(h, "evpn-vxlan", *(ob(h, "evpn.state", d, "", {"duplicate_mac_detected": d == "sw2"}) for d in self.DEVS))
            self.assertEqual(rb04.st10(ctx).finding.id, "F-evpn-dup")
        with self.subTest("an rstp domain is refused evpn applicability"):
            self.assertIs(rb04.st10_applies(derive(h))[0], False)
        with self.subTest("an evpn vtep without evidence is refused"):
            with self.assertRaises(base.Gap):
                rb04.st10(self.modes(withheld(h), "evpn-vxlan"))


class DnsChecksTests(RunbookCheckCase):
    module = rb05
    checks = ("dn01", "dn02", "dn03", "dn04", "dn05", "dn06", "dn07", "dn10")
    evidence_free = ("dn10",)

    def healthy(self):
        return context_of(R.RB05Tests.run_dn(None, S.rb05_obs()))

    def split(self, h, answers):
        target = h.case["target"]
        views = {"inside": {"vantage": target["client"], "resolver": target["resolvers"][0], "expected": ["10.2.2.20"]}}
        intent = copy.deepcopy(h.intent)
        intent.setdefault("services", {})["split_horizon"] = views
        return derive(h, ob(h, "dns.query", target["client"], f"{target['name']}/{target['resolvers'][0]}", {"answers": answers}), intent=intent)

    def signed(self, h, value):
        target = {**h.case["target"], "dnssec": True}
        return derive(h, ob(h, "dns.dnssec", target["client"], target["zone"], value), case={**h.case, "target": target})

    def test_every_dns_check_returns_pass_on_a_healthy_resolution_chain(self):
        self.run_checks_on_healthy()

    def test_dns_checks_refuse_withheld_evidence(self):
        self.run_checks_without_evidence()

    def test_serial_helpers_accept_32_bit_serials_in_rfc1982_order(self):
        self.assertTrue(rb05.serial_valid(2026110901))
        self.assertEqual(rb05.serial_compare(5, 5), 0)
        self.assertEqual(rb05.serial_compare(rb05.SERIAL_MOD - 1, 1), -1)        # wraparound: the smaller number is newer
        self.assertEqual(rb05.serial_compare(10, 2), 1)

    def test_serial_helpers_refuse_non_serials_and_undefined_order(self):
        for bad in (-1, rb05.SERIAL_MOD, True, "2026110901", None):
            with self.subTest(f"{bad!r} is refused as a serial"):
                self.assertFalse(rb05.serial_valid(bad))
        with self.subTest("a non-serial cannot be compared"):
            with self.assertRaises(ValueError):
                rb05.serial_compare(-1, 1)
        with self.subTest("a distance of exactly half the space has no order"):
            self.assertIsNone(rb05.serial_compare(0, rb05.SERIAL_HALF))

    def test_dn08_split_horizon_returns_pass_when_views_answer_as_intended(self):
        ctx = self.split(self.healthy(), ["10.2.2.20"])
        self.assertIs(rb05.dn08_applies(ctx)[0], True)
        self.assertEqual(rb05.dn08(ctx).verdict, "PASS")

    def test_dn08_refuses_a_wrong_view_answer_and_an_unsplit_zone(self):
        h = self.healthy()
        with self.subTest("a view with the wrong answer is refused as a fault"):
            self.assertEqual(rb05.dn08(self.split(h, ["192.0.2.1"])).finding.id, "F-split-horizon")
        with self.subTest("a zone without views is refused applicability"):
            self.assertIs(rb05.dn08_applies(derive(h))[0], False)

    def test_dn09_dnssec_returns_pass_when_validated(self):
        ctx = self.signed(self.healthy(), {"ad": True, "rrsig_days_left": 12, "ds_match": True})
        self.assertIs(rb05.dn09_applies(ctx)[0], True)
        self.assertEqual(rb05.dn09(ctx).verdict, "PASS")

    def test_dn09_refuses_failed_validation_and_an_unsigned_zone(self):
        h = self.healthy()
        with self.subTest("an expired signature is refused as a fault"):
            self.assertEqual(rb05.dn09(self.signed(h, {"ad": False, "rrsig_days_left": 0})).finding.id, "F-dnssec")
        with self.subTest("an unsigned zone is refused applicability"):
            self.assertIs(rb05.dn09_applies(derive(h))[0], False)
        with self.subTest("a signed zone without dnssec evidence is refused"):
            with self.assertRaises(base.Gap):
                rb05.dn09(derive(withheld(h), case={**h.case, "target": {**h.case["target"], "dnssec": True}}))

    def test_dn10_refuses_clock_drift_and_unapproved_changes(self):
        h = self.healthy()
        client = h.case["target"]["client"]
        with self.subTest("a drifted client clock is refused as a fault"):
            self.assertEqual(rb05.dn10(derive(h, ob(h, "time.sync", client, "", {"offset_ms": 9000}))).finding.id, "F-time")
        with self.subTest("an unapproved zone change before onset is refused as a fault"):
            corr = {"changes": [{"change_id": "CHG-9", "relation": "BEFORE_ONSET", "kind": "zone", "authorized": False}]}
            self.assertEqual(rb05.dn10(derive(h, correlation=corr)).finding.id, "F-dns-change")


class MtuChecksTests(RunbookCheckCase):
    module = rb06
    checks = ("mt01", "mt02", "mt03", "mt04", "mt05", "mt07", "mt08")

    def healthy(self):
        return context_of(R.rb06())

    def subif(self, h, sub_mtu):
        dev, ifn = rb06._links(h)[0]
        intent = {**h.intent, "subinterfaces": {f"{dev}:{ifn}": [f"{ifn}.10"]}}
        return derive(h, ob(h, "interface.mtu", dev, ifn, 1500), ob(h, "interface.mtu", dev, f"{ifn}.10", sub_mtu), intent=intent)

    def test_every_mtu_check_returns_pass_on_a_consistent_path(self):
        self.run_checks_on_healthy()

    def test_mtu_checks_refuse_withheld_evidence(self):
        self.run_checks_without_evidence()

    def test_mt06_subinterface_returns_pass_when_within_the_parent(self):
        result = rb06.mt06(self.subif(self.healthy(), 1500))
        self.assertEqual((result.verdict, result.summary), ("PASS", "1 parent/child MTU relationships consistent"))

    def test_mt06_refuses_a_larger_child_and_a_path_without_subinterfaces(self):
        h = self.healthy()
        with self.subTest("a child mtu above its parent is refused as a fault"):
            self.assertEqual(rb06.mt06(self.subif(h, 9000)).finding.id, "F-sub-mtu")
        with self.subTest("no subinterface or lag on the path is not applicable"):
            self.assertEqual(rb06.mt06(derive(h)).status, "NOT_APPLICABLE")


class Layer1ChecksTests(RunbookCheckCase):
    module = rb07
    checks = ("ph01", "ph02", "ph03", "ph04", "ph05", "ph06", "ph07", "ph08", "ph09")
    evidence_free = ("ph08",)
    self_refusing = ("ph09",)

    def healthy(self):
        case = R.RB07Tests("run")
        return context_of(case.run_ph(case.obs(fec_b="rs")))

    def test_every_layer1_check_returns_pass_on_a_clean_link(self):
        self.run_checks_on_healthy()
        self.assertIs(rb07.ph05_applies(derive(self.healthy()))[0], True)

    def test_layer1_checks_refuse_withheld_evidence(self):
        self.run_checks_without_evidence()

    def test_absent_cable_record_or_link_intent_is_refused(self):
        h = self.healthy()
        with self.subTest("no cable record is refused applicability"):
            self.assertIs(rb07.ph05_applies(derive(h, intent={**h.intent, "cables": {}}))[0], False)
        with self.subTest("a link absent from intent reports no alternate path and no downstream impact"):
            result = rb07.ph08(derive(h, intent={**h.intent, "links": [], "lag": {}}))
            self.assertIn("alternate path none", result.summary)
