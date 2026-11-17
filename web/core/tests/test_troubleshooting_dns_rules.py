"""RB05 DNS rules -- negative cache, RFC 1982 serial order, delegation/transfer uncertainty.  Stable IDs DNSRULE-001 .. DNSRULE-020 (supports UT-050).

PROVENANCE: all observations are SIMULATED replay fixtures; nothing here is live evidence.
"""

from __future__ import annotations

from django.test import SimpleTestCase, TestCase

from core.services.troubleshooting.engine import EngineConfig
from core.services.troubleshooting.runbooks import rb05_dns as rb
from core.tests.fixtures.troubleshooting_runbooks import scenarios as S
from core.tests.test_troubleshooting_engine import by_id, run_case

EX = EngineConfig(exhaustive=True)
R1, R2 = "10.0.0.53", "10.0.0.54"
U = 2 ** 32


class SerialTests(SimpleTestCase):
    def test_dnsrule_001_rfc1982_order_with_wraparound(self):
        self.assertEqual(rb.serial_compare(U - 1, 1), -1)          # 1 is NEWER than 4294967295
        self.assertEqual(rb.serial_compare(1, U - 1), 1)
        self.assertEqual(rb.serial_compare(5, 5), 0)
        self.assertEqual(rb.serial_compare(10, 20), -1)

    def test_dnsrule_002_half_range_is_undefined(self):
        self.assertIsNone(rb.serial_compare(0, 2 ** 31))
        self.assertEqual(rb.analyse_serials({"ns1": 0, "ns2": 2 ** 31})["state"], "AMBIGUOUS")

    def test_dnsrule_003_rollover_lagging_is_not_numeric_max(self):
        a = rb.analyse_serials({"ns1": 2, "ns2": U - 3})
        self.assertEqual((a["state"], a["newest"], a["lagging"]), ("ORDERED", 2, {"ns2": U - 3}))

    def test_dnsrule_004_equality_and_invalid_and_cyclic(self):
        self.assertEqual(rb.analyse_serials({"a": 7, "b": 7})["state"], "EQUAL")
        self.assertEqual(rb.analyse_serials({"a": -1, "b": 7})["state"], "INVALID")
        self.assertEqual(rb.analyse_serials({"a": True, "b": 7})["state"], "INVALID")
        self.assertEqual(rb.analyse_serials({"a": 0, "b": 1431655765, "c": 2863311530})["state"], "AMBIGUOUS")


class DnsRulesBase(TestCase):
    def run_dn(self, obs, intent=None, **kw):
        data = {**S.static_data(), "intent": intent or S.rb05_intent()}
        _, st = run_case("RB05", obs, flow={}, static=data, scope=S.RB05_DEVICES, service_intent={"service": "dns", "target": S.RB05_TARGET}, cfg=EX, **kw)
        return by_id(st), st


class DN03Tests(DnsRulesBase):
    def test_dnsrule_005_nxdomain_is_not_passed(self):
        o = S.rb05_obs()
        o[("c1", "dns.query", f"app.lab/{R2}")] = {"rcode": "NXDOMAIN", "answers": [], "ttl": 30, "negative": True}
        v, _ = self.run_dn(o)
        self.assertEqual(v["DN03"]["verdict"], "FAIL")
        self.assertEqual(v["DN03"]["finding"], "F-resolver-negative")
        self.assertIn("negative cache", v["DN03"]["summary"])

    def test_dnsrule_006_nodata_and_unknown_rcode_are_not_passed(self):
        o = S.rb05_obs()
        o[("c1", "dns.query", f"app.lab/{R1}")] = {"rcode": "NOERROR", "answers": [], "ttl": 0}
        v, _ = self.run_dn(o)
        self.assertEqual((v["DN03"]["verdict"], v["DN03"]["finding"]), ("FAIL", "F-resolver-negative"))
        o = S.rb05_obs()
        o[("c1", "dns.query", f"app.lab/{R1}")] = {"rcode": "FORMERR", "answers": [], "ttl": 0}
        v, _ = self.run_dn(o)
        self.assertEqual((v["DN03"]["verdict"], v["DN03"]["finding"]), ("FAIL", "F-resolver-nonsuccess"))

    def test_dnsrule_007_stale_negative_cache_is_cache_not_authoritative_fault(self):
        o = S.rb05_obs()
        o[("c1", "dns.query", f"app.lab/{R2}")] = {"rcode": "NXDOMAIN", "answers": [], "ttl": 90, "negative": True}
        v, st = self.run_dn(o)
        self.assertEqual(v["DN04"]["verdict"], "PASS")
        self.assertEqual(v["DN06"]["finding"], "F-cache-ttl")
        self.assertIn("negative", v["DN06"]["summary"])
        self.assertEqual(st["diagnosis"]["root_cause"]["finding"], "F-cache-ttl")

    def test_dnsrule_008_authoritative_nxdomain_is_not_called_cache(self):
        o = S.rb05_obs()
        for ns in ("ns1", "ns2"):
            o[("c1", "dns.query", f"app.lab/{ns}")] = {"rcode": "NXDOMAIN", "answers": [], "aa": True, "ttl": 60}
        for r in (R1, R2):
            o[("c1", "dns.query", f"app.lab/{r}")] = {"rcode": "NXDOMAIN", "answers": [], "ttl": 60, "negative": True}
        v, _ = self.run_dn(o)
        self.assertNotEqual(v["DN06"]["verdict"], "FAIL")
        self.assertEqual(v["DN03"]["verdict"], "FAIL")

    def test_dnsrule_009_intended_absent_name(self):
        it = S.rb05_intent()
        it["services"]["dns_absent"] = ["app.lab"]
        o = S.rb05_obs()
        for r in (R1, R2):
            o[("c1", "dns.query", f"app.lab/{r}")] = {"rcode": "NXDOMAIN", "answers": [], "ttl": 60, "negative": True}
        v, _ = self.run_dn(o, intent=it)
        self.assertEqual(v["DN03"]["verdict"], "PASS")
        v, _ = self.run_dn(S.rb05_obs(), intent=it)               # still resolving
        self.assertEqual((v["DN03"]["verdict"], v["DN03"]["finding"]), ("FAIL", "F-resolver-unexpected-answer"))

    def test_dnsrule_010_no_intent_is_inconclusive(self):
        it = S.rb05_intent()
        it["services"]["dns_names"] = {}
        v, _ = self.run_dn(S.rb05_obs(), intent=it)
        self.assertEqual(v["DN03"]["verdict"], "INCONCLUSIVE")

    def test_dnsrule_011_recovery_after_negative_ttl(self):
        o = S.rb05_obs()
        o[("c1", "dns.query", f"app.lab/{R2}")] = {"rcode": "NXDOMAIN", "answers": [], "ttl": 90, "negative": True}
        v, _ = self.run_dn(o)
        self.assertEqual(v["DN06"]["verdict"], "FAIL")
        v, st = self.run_dn(S.rb05_obs())                          # later: cache expired, repopulated
        self.assertEqual((v["DN03"]["verdict"], v["DN06"]["verdict"], v["DN05"]["verdict"]), ("PASS", "PASS", "PASS"))

    def test_dnsrule_012_refused_keeps_policy_finding(self):
        v, _ = self.run_dn(S.rb05_obs(refused=True))
        self.assertEqual(v["DN03"]["finding"], "F-resolver-refused")


class DN05Tests(DnsRulesBase):
    def serials(self, s1, s2, xfr2="ok"):
        o = S.rb05_obs()
        o[("c1", "dns.soa", "lab/ns1")] = {"serial": s1}
        o[("c1", "dns.soa", "lab/ns2")] = {"serial": s2}
        o[("ns2", "dns.xfr", "lab")] = {"last_result": xfr2}
        return o

    def test_dnsrule_013_rollover_flags_the_numerically_larger_server(self):
        v, _ = self.run_dn(self.serials(2, U - 3, "REFUSED (TSIG)"))
        self.assertEqual(v["DN05"]["verdict"], "FAIL")
        self.assertIn("ns2", v["DN05"]["summary"])
        self.assertEqual(v["DN05"]["finding"], "F-zone-propagation")

    def test_dnsrule_014_equality_passes(self):
        v, _ = self.run_dn(self.serials(5, 5))
        self.assertEqual(v["DN05"]["verdict"], "PASS")

    def test_dnsrule_015_half_range_is_inconclusive_not_stale(self):
        v, _ = self.run_dn(self.serials(0, 2 ** 31))
        self.assertEqual(v["DN05"]["verdict"], "INCONCLUSIVE")
        self.assertIn("undefined", v["DN05"]["summary"])

    def test_dnsrule_016_skew_without_transfer_evidence_is_not_causal(self):
        o = self.serials(10, 5)
        del o[("ns2", "dns.xfr", "lab")]
        v, st = self.run_dn(o)
        self.assertEqual(v["DN05"]["verdict"], "FAIL")
        self.assertIn("cause not attributed", v["DN05"]["summary"])
        self.assertIn("unknown", v["DN05"]["summary"])

    def test_dnsrule_017_skew_with_healthy_transfer_is_not_a_transfer_failure(self):
        v, _ = self.run_dn(self.serials(10, 5, "ok"))
        self.assertEqual(v["DN05"]["verdict"], "FAIL")
        self.assertIn("cause not attributed", v["DN05"]["summary"])

    def test_dnsrule_018_missing_delegation_evidence_is_uncertainty(self):
        o = S.rb05_obs()
        del o[("c1", "dns.delegation", "lab")]
        v, _ = self.run_dn(o)
        self.assertEqual(v["DN05"]["verdict"], "INCONCLUSIVE")
        self.assertIn("delegation", v["DN05"]["summary"])

    def test_dnsrule_019_transfer_unknown_with_equal_serials_is_uncertainty(self):
        o = S.rb05_obs()
        del o[("ns1", "dns.xfr", "lab")]
        v, _ = self.run_dn(o)
        self.assertEqual(v["DN05"]["verdict"], "INCONCLUSIVE")
        self.assertIn("transfer", v["DN05"]["summary"])

    def test_dnsrule_020_lame_and_missing_delegation(self):
        o = S.rb05_obs()
        o[("c1", "dns.delegation", "lab")] = {"lame": ["ns2"]}
        v, _ = self.run_dn(o)
        self.assertEqual((v["DN05"]["verdict"], v["DN05"]["finding"]), ("FAIL", "F-lame-delegation"))
        o[("c1", "dns.delegation", "lab")] = {"lame": [], "ns": []}
        v, _ = self.run_dn(o)
        self.assertIn("missing delegation", v["DN05"]["summary"])

    def test_dnsrule_021_dns_delegation_is_a_declared_source(self):
        spec = {t.id: t for t in rb.RB05.tests}["DN05"]
        self.assertIn("dns.delegation", spec.sources)
