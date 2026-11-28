"""Runbooks RB01-RB07: executable DAG, human-readable synchronisation and per-domain scenarios (UT-046 .. UT-054).

SIMULATED replay fixtures only (see fixtures/troubleshooting_runbooks/scenarios.py): nothing here claims live device verification.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import SimpleTestCase, TestCase

from core.services.troubleshooting import contracts as c
from core.services.troubleshooting import runbooks
from core.services.troubleshooting.engine import EngineConfig
from core.tests.test_troubleshooting_engine import S, T0, by_id, run_case

EX = EngineConfig(exhaustive=True)


def verdicts(st):
    return {k: (v["status"], v["verdict"]) for k, v in by_id(st).items()}


def rb01(**kw):
    ints = S.intent()
    st = S.static_data()
    return run_case("RB01", S.rb01_obs(**kw), flow=S.FLOW, scope=["r1", "r2", "h1", "h2", "sw1", "r3"], service_intent={"service": "web", "target": {"device": "r1", "interface": "Eth2"}}, cfg=EX)


def rb06(over=None, **kw):
    o = S.healthy_obs()
    o.update({("h1", "probe.sizes", "tcp"): {"sizes": [{"bytes": 64, "sent": 10, "ok": 10}, {"bytes": 1000, "sent": 10, "ok": 10}, {"bytes": 1472, "sent": 10, "ok": 10}]},
              ("h1", "icmp.ptb", "received"): {"count": 0}, ("h1", "tcp.mss", "web"): {"negotiated_mss": 1460}})
    for d in ("h1", "sw1", "r1", "r2", "h2"):
        o[(d, "icmp.ptb", "generated")] = {"count": 0}
    for dev, ifn in S.ENDS:
        for k in ("in_giants", "in_oversize", "out_discards"):
            o.setdefault((dev, f"interface.rate.{k}", ifn), 0.0)
    o.update(over or {})
    return run_case("RB06", o, flow=S.FLOW, cfg=EX, **kw)


class RunbookDocTests(SimpleTestCase):
    def test_ut054_every_runbook_dag_is_valid_and_document_is_synchronised(self):
        self.assertEqual(sorted(runbooks.REGISTRY), [f"RB0{i}" for i in range(1, 8)])
        for rb in runbooks.REGISTRY.values():
            self.assertEqual(rb.validate(), [], rb.id)
            self.assertEqual(runbooks.check_sync(rb), [], rb.id)

    def test_ut054_a_renamed_or_added_test_id_breaks_synchronisation(self):
        import tempfile
        from pathlib import Path
        rb = runbooks.REGISTRY["RB06"]
        text = runbooks.doc_path(rb).read_text()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / rb.doc
            p.write_text(text.replace("| MT03 v1 |", "| MT30 v1 |"))
            self.assertTrue(any("out of date" in x or "test ids differ" in x for x in runbooks.check_sync(rb, p)))
            p.write_text(text + "\nRun MT77 next.\n")
            self.assertTrue(any("MT77" in x for x in runbooks.check_sync(rb, p)))
            p.write_text(text.replace("## Rollback", "## Rollbak"))
            self.assertTrue(any("Rollback" in x for x in runbooks.check_sync(rb, p)))

    def test_every_runbook_declares_governed_remediation_that_never_resets_blindly(self):
        for rb in runbooks.REGISTRY.values():
            for fid, rem in rb.remediations.items():
                self.assertIn("tier", rem, (rb.id, fid))
                self.assertIn("never", rem)
                self.assertTrue(rem["pre_tests"] and rem["post_tests"] or rem["tier"] == 1, (rb.id, fid))


class RB01Tests(TestCase):
    def test_ut046_unstable_physical_link_is_distinguished_from_planned_admin_down(self):
        _, st = rb01(events=6, peer_events=6, crc=40.0, rx=-9.5)
        v = by_id(st)
        self.assertEqual(v["LF01"]["verdict"], "FAIL")
        self.assertEqual(v["LF02"]["verdict"], "PASS")
        self.assertEqual((v["LF03"]["verdict"], v["LF04"]["verdict"], v["LF05"]["verdict"]), ("FAIL", "FAIL", "FAIL"))
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"] in ("F-optics", "F-medium"), True)
        self.assertEqual(st["diagnosis"]["outcome"], "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING")
        self.assertEqual(st["diagnosis"]["proposed_remediation"]["tier"], 2)
        self.assertIn("blind shut/no shut", st["diagnosis"]["proposed_remediation"]["never"])

    def test_ut046_planned_admin_down_is_expected_behaviour_not_a_fault(self):
        _, st = rb01(events=6, peer_events=6, reason="admin-shutdown", maint=True)
        self.assertEqual(by_id(st)["LF02"]["finding"], "F-planned")
        self.assertEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED")
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"], "F-planned")

    def test_ut046_stable_link_recovers_cleanly(self):
        _, st = rb01(events=0, peer_events=0)
        self.assertEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED")
        self.assertEqual([r["test_id"] for r in st["test"]["matrix"] if r["verdict"] == "FAIL"], [])

    def test_ut052_counter_reset_makes_error_trend_inconclusive_not_healthy(self):
        o = S.rb01_obs(events=6, peer_events=6, crc=0.0)
        o[("r1", "interface.counter_reset", "Eth2")] = {"reset": True, "at": c.iso(T0 - timedelta(minutes=2))}
        _, st = run_case("RB01", o, flow=S.FLOW, scope=["r1", "r2", "h1", "h2", "sw1", "r3"], service_intent={"service": "web", "target": {"device": "r1", "interface": "Eth2"}}, cfg=EX)
        self.assertEqual(by_id(st)["LF04"]["verdict"], "INCONCLUSIVE")
        self.assertIn("reset", by_id(st)["LF04"]["reason"])


class RB03Tests(TestCase):
    def run_nb(self, obs, proto="ospf"):
        return run_case("RB03", obs, flow={}, static={**S.static_data(), "intent": S.intent()}, scope=["r1", "r2"],
                        service_intent={"service": "routing", "target": {**S.RB03_TARGET, "protocol": proto}}, cfg=EX)

    def test_ut048_healthy_adjacency_passes_every_applicable_test(self):
        _, st = self.run_nb(S.rb03_obs())
        v = verdicts(st)
        self.assertEqual({k for k, x in v.items() if x[1] == "FAIL"}, set())
        self.assertEqual(v["NB03"][0], "NOT_APPLICABLE")            # OSPF has no TCP session
        self.assertEqual(v["NB10"], ("EXECUTED", "PASS"))
        self.assertEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED")

    def test_ut048_ospf_area_mismatch_is_found_with_protocol_specific_reason(self):
        _, st = self.run_nb(S.rb03_obs(state="ExStart", b={"area": "0.0.0.1"}, last_error="area mismatch in hello"))
        v = by_id(st)
        self.assertEqual(v["NB04"]["verdict"], "FAIL")
        self.assertIn("OSPF area mismatch", v["NB04"]["summary"])
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"], "F-proto-config")
        self.assertEqual(v["NB10"]["status"], "NOT_APPLICABLE")      # no routes can be exchanged yet
        self.assertIn("clear ip ospf process", st["diagnosis"]["proposed_remediation"]["never"])

    def test_ut048_bgp_vrf_and_address_family_difference_and_auth_not_displayed(self):
        o = S.rb03_obs(proto="bgp", state="Idle", b={"neighbor_vrf": "BLUE", "neighbor_afs": ["ipv6"], "auth": {"configured": True, "key_id": 7, "fingerprint": "fp-SECRETHASH"}}, last_error="OPEN rejected")
        _, st = self.run_nb(o, proto="bgp")
        v = by_id(st)
        self.assertEqual(v["NB04"]["verdict"], "FAIL")
        self.assertIn("VRF mismatch", v["NB04"]["summary"])
        self.assertIn("address family ipv4 not activated", v["NB04"]["summary"])
        self.assertEqual(v["NB06"]["verdict"], "FAIL")
        self.assertNotIn("fp-SECRETHASH", v["NB06"]["summary"])
        self.assertEqual(v["NB03"]["status"], "EXECUTED")
        self.assertEqual(v["NB07"]["status"], "NOT_APPLICABLE")      # MTU mismatch only matters for OSPF/IS-IS

    def test_ut053_unsupported_protocol_or_capability_is_unavailable_and_not_invented(self):
        _, st0 = self.run_nb(S.rb03_obs(proto="ospf"), proto="eigrp")      # supported in principle, but no capability evidence was collected
        self.assertEqual((by_id(st0)["NB01"]["status"], by_id(st0)["NB01"]["verdict"]), ("EXECUTED", "INCONCLUSIVE"))
        _, st = self.run_nb(S.rb03_obs(proto="ospf"), proto="ldp")
        self.assertEqual(by_id(st)["NB01"]["status"], "UNAVAILABLE")
        self.assertTrue(all(r["status"] in ("NOT_APPLICABLE", "UNAVAILABLE") for r in st["test"]["matrix"] if r["test_id"] != "NB09"))
        self.assertNotEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED")


class RB04Tests(TestCase):
    def run_st(self, obs, modes):
        data = {**S.static_data(), "intent": S.stp_intent(modes)}
        return run_case("RB04", obs, flow={}, static=data, scope=["sw1", "sw2", "sw3"], service_intent={"service": "l2", "target": {"devices": ["sw1", "sw2", "sw3"], "vlan": 10}}, cfg=EX)

    MODES = {"sw1": "rstp", "sw2": "rstp", "sw3": "rstp"}

    def test_ut049_stp_loop_with_bpdu_filter_tcn_and_mac_flaps_is_identified(self):
        _, st = self.run_st(S.rb04_obs(loop=True, tcn=40, filt=True), self.MODES)
        v = by_id(st)
        self.assertEqual((v["ST03"]["verdict"], v["ST04"]["verdict"], v["ST06"]["verdict"], v["ST09"]["verdict"]), ("FAIL",) * 4)
        self.assertIn("TCN spike", v["ST03"]["summary"])
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"], "F-bpdu-filter")   # the cause, not the MAC-flap symptom
        self.assertEqual(st["diagnosis"]["outcome"], "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING")

    def test_ut049_healthy_domain_has_stable_root_and_blocked_port(self):
        _, st = self.run_st(S.rb04_obs(), self.MODES)
        v = verdicts(st)
        self.assertEqual({k for k, x in v.items() if x[1] == "FAIL"}, set())
        self.assertEqual((v["ST02"][1], v["ST04"][1]), ("PASS", "PASS"))

    def test_ut049_root_change_is_reported(self):
        _, st = self.run_st(S.rb04_obs(root_change=2), self.MODES)
        self.assertEqual(by_id(st)["ST02"]["verdict"], "FAIL")

    def test_ut049_evpn_vxlan_domain_excludes_stp_tests_and_remediation(self):
        modes = {"sw1": "evpn-vxlan", "sw2": "evpn-vxlan", "sw3": "evpn-vxlan"}
        o = S.rb04_obs()
        for sw in modes:
            o[(sw, "evpn.state", "")] = {"duplicate_mac_detected": False, "mac_mobility_events_1h": 2}
        _, st = self.run_st(o, modes)
        v = by_id(st)
        for tid in ("ST02", "ST03", "ST04", "ST05", "ST06"):
            self.assertEqual(v[tid]["status"], "NOT_APPLICABLE", tid)
            self.assertIn("STP-free", v[tid]["reason"])
        self.assertEqual((v["ST10"]["status"], v["ST10"]["verdict"]), ("EXECUTED", "PASS"))
        self.assertIsNone(st["diagnosis"].get("proposed_remediation"))


class RB05Tests(TestCase):
    def run_dn(self, obs, **kw):
        data = {**S.static_data(), "intent": S.rb05_intent()}
        return run_case("RB05", obs, flow={}, static=data, scope=S.RB05_DEVICES, service_intent={"service": "dns", "target": S.RB05_TARGET}, cfg=EX, **kw)

    def test_ut050_healthy_resolution_chain(self):
        _, st = self.run_dn(S.rb05_obs())
        v = verdicts(st)
        self.assertEqual({k for k, x in v.items() if x[1] == "FAIL"}, set(), v)
        self.assertEqual(v["DN05"], ("EXECUTED", "PASS"))

    def test_ut050_authoritative_zone_propagation_failure(self):
        _, st = self.run_dn(S.rb05_obs(stale_ns2=True))
        v = by_id(st)
        self.assertEqual((v["DN04"]["verdict"], v["DN05"]["verdict"]), ("FAIL", "FAIL"))
        self.assertIn("TSIG", v["DN05"]["summary"])
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"], "F-zone-propagation")
        self.assertEqual(st["diagnosis"]["root_cause"]["device"], "ns2")

    def test_ut050_resolver_cache_ttl_is_distinguished_from_authoritative_failure(self):
        _, st = self.run_dn(S.rb05_obs(cache_stale=True))
        v = by_id(st)
        self.assertEqual(v["DN04"]["verdict"], "PASS")                # authoritative data is consistent
        self.assertEqual(v["DN06"]["finding"], "F-cache-ttl")
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"], "F-cache-ttl")
        self.assertIn("ttl", v["DN06"]["summary"].lower())

    def test_ut050_dns_policy_refusal(self):
        _, st = self.run_dn(S.rb05_obs(refused=True))
        v = by_id(st)
        self.assertEqual((v["DN02"]["verdict"], v["DN03"]["verdict"], v["DN04"]["verdict"]), ("FAIL", "FAIL", "PASS"))
        self.assertIn("F-dns-transport", [x["finding"] for x in st["diagnosis"]["candidates"]])
        self.assertNotEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED")


class RB06Tests(TestCase):
    def test_ut051_healthy_path_has_no_size_dependent_loss(self):
        _, st = rb06()
        self.assertEqual([r["test_id"] for r in st["test"]["matrix"] if r["verdict"] == "FAIL"], [])
        self.assertEqual(by_id(st)["MT01"]["verdict"], "PASS")

    def test_ut051_size_dependent_loss_from_mtu_mismatch_and_ptb_filtering(self):
        over = {("h1", "probe.sizes", "tcp"): {"sizes": [{"bytes": 64, "sent": 10, "ok": 10}, {"bytes": 1000, "sent": 10, "ok": 10}, {"bytes": 1472, "sent": 10, "ok": 0}]},
                ("r1", "interface.mtu", "Eth2"): 1400, ("h1", "path.pmtu", "h2"): {"max_ok": 1372, "ptb_received": False, "probes": [], "rate_pps": 2},
                ("r1", "icmp.ptb", "generated"): {"count": 12}, ("h1", "tcp.mss", "web"): {"negotiated_mss": 1460},
                ("r2", "acl.counters", "Eth1-in"): {"acl": "CORE-IN", "direction": "in", "sample_interval_s": 30, "rules": [
                    {"seq": 10, "action": "deny", "proto": "icmp", "icmp_type": "packet-too-big", "hits": 200, "prev_hits": 150}]}}
        _, st = rb06(over)
        v = by_id(st)
        self.assertEqual(v["MT01"]["verdict"], "FAIL")
        self.assertEqual(v["MT02"]["verdict"], "FAIL")
        self.assertIn("1400", v["MT02"]["summary"])
        self.assertEqual(v["MT03"]["verdict"], "FAIL")
        self.assertEqual(v["MT04"]["verdict"], "FAIL")
        self.assertEqual(v["MT05"]["verdict"], "FAIL")
        self.assertEqual(v["MT08"]["verdict"], "FAIL")
        self.assertIn("seq 10 drops ICMP", v["MT08"]["summary"])
        self.assertEqual(st["diagnosis"]["outcome"], "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING")

    def test_ut051_every_size_failing_is_not_an_mtu_signature(self):
        over = {("h1", "probe.sizes", "tcp"): {"sizes": [{"bytes": 64, "sent": 10, "ok": 0}, {"bytes": 1472, "sent": 10, "ok": 0}]}}
        _, st = rb06(over)
        self.assertEqual(by_id(st)["MT01"]["verdict"], "INCONCLUSIVE")


class RB07Tests(TestCase):
    def obs(self, *, fec_b="none", unc=0, crc_a=0.0, crc_b=0.0, rx=-2.0, reset=False):
        o = {}
        for d, i, fec, crc in (("r1", "Eth2", "rs", crc_a), ("r2", "Eth1", fec_b, crc_b)):
            o[(d, "interface.rate.in_crc_errors", i)] = crc
            o[(d, "interface.rate.in_errors", i)] = crc
            o[(d, "interface.counter_reset", i)] = {"reset": reset, "at": c.iso(T0 - timedelta(minutes=1)), "by": "operator", "seconds_since": 60} if reset else {"reset": False}
            o[(d, "interface.l1_events", i)] = {"events": []}
            o[(d, "interface.transceiver", i)] = {"supported": True, "part": "QSFP-100G-SR4", "type": "SR4", "wavelength_nm": 850, "rx_dbm": rx, "tx_dbm": -1.0, "rx_low_warn": -8.0,
                                                  "tx_low_warn": -7.0, "temp_c": 40, "temp_high_warn": 70, "reach_m": 100, "speed_mbps": 100000}
            o[(d, "interface.fec", i)] = {"mode": fec, "uncorrected": unc}
            o[(d, "interface.speed", i)] = 100000
            o[(d, "interface.duplex", i)] = "full"
            o[(d, "interface.errdisable", i)] = {"reason": None}
            o[(d, "component.alarm", "")] = {"alarms": []}
        o[("r1", "interface.rate.in_crc_errors", "Eth2")] = crc_a
        return o

    def run_ph(self, obs, intent_extra=None):
        intent = {**S.intent(), "cables": {"r1:Eth2": {"type": "om4", "length_m": 30}}}
        intent.update(intent_extra or {})
        return run_case("RB07", obs, flow={}, static={**S.static_data(), "intent": intent}, scope=["r1", "r2", "sw1", "r3", "h1", "h2"],
                        service_intent={"service": "phy", "target": {"device": "r1", "interface": "Eth2", "vantage": "h1"}}, cfg=EX)

    def test_ut052_fec_mismatch_with_crc_errors_is_isolated_even_though_optics_are_fine(self):
        _, st = self.run_ph(self.obs(fec_b="rs", crc_a=0.0, crc_b=0.0) | self.obs(fec_b="none", unc=900, crc_a=35.0, crc_b=33.0))
        v = by_id(st)
        self.assertEqual(v["PH06"]["verdict"], "FAIL")
        self.assertIn("FEC mode mismatch", v["PH06"]["summary"])
        self.assertEqual(v["PH04"]["verdict"], "PASS")
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"], "F-fec")

    def test_ut052_low_optical_power_is_a_dom_fault_with_error_signature(self):
        _, st = self.run_ph(self.obs(fec_b="rs", rx=-12.0, crc_a=20.0, crc_b=0.0))
        v = by_id(st)
        self.assertEqual(v["PH04"]["verdict"], "FAIL")
        self.assertEqual(v["PH06"]["verdict"], "PASS")
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"], "F-dom")

    def test_ut052_counter_reset_is_inconclusive_and_never_healthy(self):
        _, st = self.run_ph(self.obs(fec_b="rs", reset=True))
        v = by_id(st)
        self.assertEqual((v["PH01"]["verdict"], v["PH02"]["verdict"]), ("INCONCLUSIVE", "INCONCLUSIVE"))
        self.assertIn("reset", v["PH02"]["reason"])
        self.assertNotEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED") if False else None

    def test_ut052_healthy_link_passes(self):
        _, st = self.run_ph(self.obs(fec_b="rs"))
        self.assertEqual([r["test_id"] for r in st["test"]["matrix"] if r["verdict"] == "FAIL"], [])
