"""ACL source (HC18 scoped ACL evidence + safe causality) -- parser -> collector -> runtime -> RB02/HC18.  Stable IDs ACLSRC-001 .. ACLSRC-016.

PROVENANCE: every document below is SIMULATED (hand-written to the EOS ``show ip access-lists | json`` and ``... summary | json`` shape).  No
gateway-recorded cEOS ACL output is pinned, so nothing here claims live verification; the injected gateway dict (live=False) only proves provenance is
carried verbatim.  Supported grammar / unsupported features: docs/troubleshooting/acl-source.md.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import acl as acl_ad
from core.tests.fixtures.troubleshooting_runbooks import scenarios as S

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
ACTOR = repo.Actor("alice", "user", tenant="acme")
R_CMD, A_CMD = "show ip access-lists | json", "show ip access-lists summary | json"
GW = {"live": False, "fixture_id": "simulated-acl", "note": "SIMULATED: not gateway-recorded"}
EV = {"evidence_id": "ev-1", "source_type": "CLI", "transport": "t", "adapter": "a", "command_or_api": R_CMD, "collected_at": T0.isoformat(), "raw_ref": {"hash": "h"}}
PERMIT_WEB = "permit tcp 10.1.1.0/24 10.2.2.0/24 eq 443"
DENY_WEB = "deny tcp 10.1.1.0/24 10.2.2.0/24 eq 443"


def acl(name="EDGE-IN", rules=(), **kw):
    return {"name": name, "sequence": [{"sequenceNumber": q, "text": t, **({"counterData": {"matchedPackets": h}} if h is not None else {})} for q, t, h in rules], **kw}


def rdoc(*acls):
    return json.dumps({"aclList": list(acls)})


def adoc(name="EDGE-IN", ingress=(), egress=(), **kw):
    row = {"name": name, **kw}
    if ingress is not None:
        row["configuredIngressIntfs"] = list(ingress)
    if egress:
        row["configuredEgressIntfs"] = list(egress)
    return json.dumps({"aclList": [row]})


def nr(raw, at=T0, version="4.36.2F", device="r1", **kw):
    return nz.normalize_acl_rules(raw, platform="ceos", os_version=version, device=device, evidence=EV, now=at, observed_at=at, **kw)


def na(raw, at=T0, version="4.36.2F", device="r1"):
    return nz.normalize_acl_attachment(raw, platform="ceos", os_version=version, device=device, evidence=EV, now=at, observed_at=at)


class GrammarTests(SimpleTestCase):
    def test_ACLSRC_001_supported_and_unsupported_rule_syntax(self):
        p = nz.parse_acl_rule_text
        self.assertEqual(p(DENY_WEB), {"action": "deny", "proto": "tcp", "port": 443, "src": "10.1.1.0/24", "dst": "10.2.2.0/24"})
        self.assertEqual(p("permit ip any any log"), {"action": "permit", "proto": "ip", "port": None, "src": "any", "dst": "any"})
        self.assertEqual(p("deny icmp host 10.1.1.10 any")["src"], "10.1.1.10/32")
        for text in ("permit tcp any eq 80 any", "permit tcp any any range 1 5", "permit tcp any any eq https", "permit tcp any any established", "permit ipv6 any any",
                     "permit ip 10.0.0.0 0.0.0.255 any", "permit icmp any any echo", "permit ip any any fragments", "permit ip any any tracked", "permit ip addrgroup A any",
                     "permit udp any any gt 1023", "garbage", ""):
            self.assertIn("unsupported", p(text), text)


class RulesParserTests(SimpleTestCase):
    def test_ACLSRC_002_order_remarks_counters_and_defects(self):
        res = nr(rdoc(acl(rules=[(20, "permit ip any any", 7), (5, "remark why", None), (10, DENY_WEB, 3), (30, "permit tcp any eq 80 any", None)])))
        (o,) = res["observations"]
        v = o["value"]
        self.assertEqual([r["seq"] for r in v["rules"]], [10, 20, 30])             # device order by sequence; remark dropped
        self.assertEqual(v["rules"][0]["hits"], 3)
        self.assertIsNone(v["rules"][2]["hits"])
        self.assertEqual(v["unsupported_rules"], [30])
        self.assertTrue(v["complete"])
        self.assertEqual(o["key"], "acl.rules")
        self.assertEqual(res["parser"]["id"], "acl.rules")
        dup = nr(rdoc(acl(rules=[(10, DENY_WEB, 1), (10, PERMIT_WEB, 2)])))["observations"][0]
        self.assertEqual((dup["quality"], dup["value"]["complete"]), ("PARTIAL", False))
        std = nr(rdoc(acl(rules=[(10, "permit 10.0.0.0/8", 1)], standard=True)))["observations"][0]
        self.assertFalse(std["value"]["complete"])
        part = nr(rdoc(acl(rules=[(10, DENY_WEB, 1)]), {"name": ""}))["observations"][0]
        self.assertEqual(part["quality"], "PARTIAL")
        self.assertIn("PARTIAL_PARSE", part["flags"])
        self.assertEqual(nr("{bad")["missing"][0]["reason"], nz.Missing.PARSE_FAILED)
        self.assertEqual(nr(rdoc())["missing"][0]["reason"], nz.Missing.EMPTY)
        self.assertEqual(nr(json.dumps({"x": 1}))["missing"][0]["reason"], nz.Missing.PARSE_FAILED)

    def test_ACLSRC_003_attachment_is_explicit_never_inferred(self):
        res = na(adoc(ingress=["Et1"], egress=["Ethernet2"], activeIngressIntfs=["Et1"]))
        got = {(o["value"]["interface"], o["value"]["direction"]): o for o in res["observations"]}
        self.assertEqual(set(got), {("Ethernet1", "in"), ("Ethernet2", "out")})
        self.assertEqual(got[("Ethernet1", "in")]["quality"], "OK")
        self.assertIsNone(got[("Ethernet1", "in")]["value"]["vrf"])
        inactive = na(adoc(ingress=["Ethernet1"], activeIngressIntfs=[]))["observations"][0]
        self.assertEqual((inactive["quality"], inactive["value"]["uncertain"]), ("PARTIAL", ["configured_not_active"]))
        self.assertEqual(na(adoc(ingress=[]))["missing"][0]["reason"], nz.Missing.EMPTY)
        self.assertEqual(na(adoc(ingress=None))["missing"][0]["reason"], nz.Missing.EMPTY)
        self.assertEqual(na(json.dumps({"aclList": [{"name": "X", "configuredIngressIntfs": "Et1"}]}))["missing"][0]["reason"], nz.Missing.PARSE_FAILED)

    def test_ACLSRC_004_counter_history_ok_reset_stale_short_changed_partial(self):
        h = nz.AclHistory()
        doc = lambda hits, text=DENY_WEB: rdoc(acl(rules=[(10, text, hits)]))
        rule = lambda res: res["observations"][0]["value"]["rules"][0]
        first = rule(nr(doc(100), T0 - timedelta(seconds=120), history=h))
        self.assertEqual((first["prev_hits"], first["history"]), (None, "no_history"))
        ok = nr(doc(160), T0 - timedelta(seconds=60), history=h)["observations"][0]
        self.assertEqual((ok["value"]["rules"][0]["prev_hits"], ok["value"]["rules"][0]["history"], ok["value"]["sample_interval_s"]), (100 + 0, "ok", 60.0))
        reset = rule(nr(doc(5), T0, history=h))
        self.assertEqual((reset["prev_hits"], reset["history"]), (None, "counter_reset"))
        short = rule(nr(doc(9), T0 + timedelta(seconds=3), history=h))
        self.assertEqual(short["history"], "short_history")
        stale = rule(nr(doc(20), T0 + timedelta(hours=2), history=h))
        self.assertEqual(stale["history"], "stale_history")
        changed = rule(nr(doc(30, "deny tcp any any eq 443"), T0 + timedelta(hours=2, seconds=60), history=h))
        self.assertEqual(changed["history"], "rule_changed")
        nocnt = rule(nr(rdoc(acl(rules=[(10, DENY_WEB, None)])), T0 + timedelta(hours=2, seconds=120), history=h))
        self.assertEqual(nocnt["history"], "no_counter")
        before = h.previous("r1", "EDGE-IN")["at"]
        nr(rdoc(acl(rules=[(10, DENY_WEB, 99), (10, DENY_WEB, 99)])), T0 + timedelta(hours=3), history=h)       # partial: must not advance history
        self.assertEqual(h.previous("r1", "EDGE-IN")["at"], before)
        nr(doc(1), T0 - timedelta(days=1), history=h)                                                         # non-monotonic: ignored
        self.assertEqual(h.previous("r1", "EDGE-IN")["at"], before)
        self.assertIsNone(rule(nr(doc(100)))["prev_hits"])                                                     # no history object at all

    def test_ACLSRC_005_version_gate_fails_closed(self):
        for v in ("4.20.1F", "5.0.0", "", "garbage"):
            self.assertEqual(nr(rdoc(acl(rules=[(10, DENY_WEB, 1)])), version=v)["missing"][0]["reason"], nz.Missing.PARSER_UNAVAILABLE, v)
            self.assertEqual(na(adoc(ingress=["Et1"]), version=v)["missing"][0]["reason"], nz.Missing.PARSER_UNAVAILABLE, v)
        self.assertEqual(nz.normalize_acl_rules(rdoc(), platform="iosxe", os_version="17.6", device="x", evidence=EV, now=T0)["missing"][0]["reason"], nz.Missing.PARSER_UNAVAILABLE)


class Transport:
    def __init__(self, outputs, provenance=None):
        self.outputs, self.calls = outputs, []
        if provenance:
            self.provenance = lambda: provenance

    def execute(self, rendered):
        self.calls.append(rendered)
        return self.outputs.get(rendered, "{}")


class CollectorTests(SimpleTestCase):
    def target(self, version="4.36.2F", platform="ceos"):
        return col.Target(device="r1", platform=platform, os_version=version, lifecycle_state="VERIFIED", verified=True, capabilities={col.SourceType.CLI: "SUPPORTED"})

    def test_ACLSRC_006_catalogue_read_only_labels_and_no_contact_when_unsupported(self):
        for key, parser in (("acl_rules", "acl.rules"), ("acl_attach", "acl.attachment")):
            spec = col.COMMAND_CATALOG["ceos"][key]
            col.validate_read_only("ceos", spec.command)
            self.assertEqual(spec.parser_id, parser)
        self.assertNotIn("acl_rules", col.COMMAND_CATALOG["iosxe"])
        self.assertEqual(acl_ad.describe_source()["label"], "SIMULATED")
        self.assertEqual(acl_ad.describe_source(recorded=True)["label"], "RECORDED")
        self.assertFalse(acl_ad.describe_source(gateway={"live": False})["live"])
        self.assertEqual(acl_ad.describe_source(gateway={"live": True})["label"], "LIVE_GATEWAY_PINNED")
        self.assertIn("IPv6 ACLs", acl_ad.describe_source()["unsupported"])
        self.assertTrue(acl_ad.is_supported("ceos", "4.36.2F"))
        self.assertFalse(acl_ad.is_supported("ceos", "4.20.1F"))
        self.assertFalse(acl_ad.is_supported("iosxe", "17.6"))
        tr = Transport({R_CMD: rdoc(acl(rules=[(10, DENY_WEB, 1)])), A_CMD: adoc(ingress=["Ethernet1"])})
        bundle = col.CliCollector().collect(self.target("4.20.1F"), ["acl_rules", "acl_attach"], tr)
        self.assertEqual(tr.calls, [])
        self.assertEqual({r["reason"] for r in bundle["missing"]}, {nz.Missing.PARSER_UNAVAILABLE})
        tr2 = Transport({})
        b2 = col.CliCollector().collect(self.target(platform="iosxe", version="17.6.1"), ["acl_rules"], tr2)
        self.assertEqual(tr2.calls, [])
        self.assertTrue(b2["missing"])
        for bad in ("clear ip access-lists counters", "show ip access-lists | json ; clear counters", "configure terminal"):
            with self.assertRaises(col.CommandNotAllowed):
                col.validate_read_only("ceos", bad)

    def test_ACLSRC_007_collector_preserves_raw_hash_source_and_history(self):
        ctx = acl_ad.AclContext()
        c = col.CliCollector()
        c.acl_context = ctx
        tr = Transport({R_CMD: rdoc(acl(rules=[(10, DENY_WEB, 5)])), A_CMD: adoc(ingress=["Ethernet1"])}, provenance=GW)
        b = c.collect(self.target(), ["acl_rules", "acl_attach"], tr)
        self.assertEqual(sorted(tr.calls), sorted([R_CMD, A_CMD]))
        self.assertEqual({o["key"] for o in b["observations"]}, {"acl.rules", "acl.attachment"})
        for o in b["observations"]:
            self.assertRegex(o["raw_hash"], r"^(sha256:)?[0-9a-f]{64}$")
            self.assertEqual(o["source"]["command_or_api"], R_CMD if o["key"] == "acl.rules" else A_CMD)
        self.assertEqual(b["run"]["gateway"], GW)
        self.assertIsNotNone(ctx.history.previous("r1", "EDGE-IN"))


class JoinTests(SimpleTestCase):
    def test_ACLSRC_008_join_uses_only_collected_attachment(self):
        c = col.CliCollector()
        tr = Transport({R_CMD: rdoc(acl("A", [(10, DENY_WEB, 5)]), acl("B", [(10, PERMIT_WEB, 1)])), A_CMD: adoc("A", ingress=["Ethernet1"], egress=["Ethernet2"])})
        tgt = col.Target(device="r1", platform="ceos", os_version="4.36.2F", lifecycle_state="VERIFIED", verified=True, capabilities={col.SourceType.CLI: "SUPPORTED"})
        b = c.collect(tgt, ["acl_rules", "acl_attach"], tr)
        joined = [o for v in rt.join_acl_observations(b["observations"], device="r1", run_key="k").values() for o in v]
        self.assertEqual(sorted(o["key"] for o in joined), ["acl.counters@Ethernet1-in", "acl.counters@Ethernet2-out"])   # ACL B has no attachment: nothing
        self.assertEqual({o["quality"] for o in joined}, {"GOOD"})
        self.assertEqual(joined[0]["value"]["attachment_source"], "acl.attachment")
        # attached ACL whose rules are absent -> explicit gap, never a value
        tr = Transport({R_CMD: rdoc(acl("B", [(10, PERMIT_WEB, 1)])), A_CMD: adoc("A", ingress=["Ethernet1"])})
        b = c.collect(tgt, ["acl_rules", "acl_attach"], tr)
        (g,) = [o for v in rt.join_acl_observations(b["observations"], device="r1", run_key="k").values() for o in v]
        self.assertTrue(g["is_missing_data"])
        # incomplete rules -> UNTRUSTED
        tr = Transport({R_CMD: rdoc(acl("A", [(10, DENY_WEB, 1), (10, DENY_WEB, 1)])), A_CMD: adoc("A", ingress=["Ethernet1"])})
        b = c.collect(tgt, ["acl_rules", "acl_attach"], tr)
        (u,) = [o for v in rt.join_acl_observations(b["observations"], device="r1", run_key="k").values() for o in v]
        self.assertEqual(u["quality"], "UNTRUSTED")


def verdicts(case):
    return {t.test_id: t.verdict for t in m.TsDiagnosticTest.objects.filter(case=case)}


def intent():
    i = S.intent()
    for l in i["links"]:
        l["a_if"], l["b_if"] = (x.replace("Eth", "Ethernet") for x in (l["a_if"], l["b_if"]))
    return i


def make_case(key):
    devs = ["h1", "sw1", "r1", "r2", "h2"]
    target = {"device": "r1", "devices": devs, "links": [], "cables": [], "lag": None}
    return repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "web", "target": target},
                          flow_scope=dict(S.FLOW), affected_scope={"devices": devs}, target_states={d: "VERIFIED" for d in devs}, severity="HIGH", runbook="RB02",
                          worked_before=True, first_detected_at=T0 - timedelta(minutes=10), last_known_good_at=T0 - timedelta(hours=3), now=T0 - timedelta(minutes=5))


def seeded(rules_before, *, seconds=60, name="EDGE-IN"):
    """AclContext whose history for r1 holds the previous sample ``rules_before`` [(seq, text, hits)]."""
    ctx = acl_ad.AclContext()
    nr(rdoc(acl(name, rules_before)), T0 - timedelta(seconds=seconds), history=ctx.history)
    return ctx


def run(key, rules, *, ingress=("Ethernet1",), egress=(), before=None, version="4.36.2F", unattached=False, **adoc_kw):
    case = make_case(key)
    tr = Transport({R_CMD: rdoc(acl(rules=rules)), A_CMD: adoc(ingress=() if unattached else ingress, egress=() if unattached else egress, **adoc_kw)}, GW)
    ctx = seeded(before) if before is not None else None
    d = rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=lambda: {x: {"platform": "ceos", "os_version": version} for x in ("h1", "sw1", "r1", "r2", "h2")}),
        cli_transport=lambda info: tr if info.device == "r1" else Transport({}), sources=bl.StaticSources({**S.static_data(), "intent": intent()}),
        clock=lambda: 0.0, sleep=lambda s: None, now=lambda: T0, acl_context=ctx,
        capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})
    res = rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=T0, engine_config=eng.EngineConfig(exhaustive=True))
    return case, res, tr


def hc18(case):
    return m.TsDiagnosticTest.objects.get(case=case, test_id="HC18")


DENY_NOW = [(10, DENY_WEB, 460), (20, "permit ip any any", 50)]
DENY_BEFORE = [(10, DENY_WEB, 400), (20, "permit ip any any", 40)]


class RuntimeToHc18Tests(TestCase):
    def test_ACLSRC_017_no_explicit_match_cannot_exclude_implicit_deny(self):
        rules = [(10, "permit udp any any eq 53", 30)]
        case, _, _ = run("acl-implicit-deny", rules, before=[(10, "permit udp any any eq 53", 20)])
        self.assertNotConclusive(case)
        self.assertIn("implicit/default action", json.dumps(hc18(case).observed))

    def assertNotConclusive(self, case):
        v = verdicts(case)["HC18"]
        self.assertNotIn(v, ("PASS", "FAIL"), v)
        self.assertNotIn("F-acl-deny", json.dumps([t.observed_summary for t in m.TsDiagnosticTest.objects.filter(case=case, test_id="HC18")]))

    def test_ACLSRC_009_ingress_deny_with_incrementing_counter_is_causal(self):
        case, res, tr = run("acl-a", DENY_NOW, before=DENY_BEFORE)
        self.assertIn(R_CMD, tr.calls)
        self.assertIn(A_CMD, tr.calls)
        self.assertEqual(verdicts(case)["HC18"], "FAIL", verdicts(case))
        self.assertIn("F-acl-deny", json.dumps(res["diagnosis"]))
        row = m.TsObservation.objects.get(case=case, target="r1", key="acl.counters@Ethernet1-in", is_missing_data=False)
        self.assertEqual((row.value["acl"], row.value["direction"], row.value["attachment_source"]), ("EDGE-IN", "in", "acl.attachment"))
        self.assertEqual(row.value["rules"][0]["prev_hits"], 400)

    def test_ACLSRC_010_tcp_healthy_with_icmp_denied_passes_and_records_icmp(self):
        rules = [(5, "deny icmp any any", 90), (10, PERMIT_WEB, 5000), (20, "permit ip any any", 3)]
        case, _, _ = run("acl-b", rules, before=[(5, "deny icmp any any", 80), (10, PERMIT_WEB, 4000), (20, "permit ip any any", 2)])
        self.assertEqual(verdicts(case)["HC18"], "PASS", verdicts(case))
        self.assertIn("denies icmp", json.dumps(hc18(case).observed))

    def test_ACLSRC_011_shadowed_deny_does_not_block(self):
        rules = [(10, PERMIT_WEB, 900), (20, DENY_WEB, 77), (30, "permit ip any any", 3)]
        case, _, _ = run("acl-c", rules, before=[(10, PERMIT_WEB, 800), (20, DENY_WEB, 10), (30, "permit ip any any", 2)])
        self.assertEqual(verdicts(case)["HC18"], "PASS", verdicts(case))

    def test_ACLSRC_012_wrong_direction_denial_is_never_causal(self):
        # r1: flow enters via Ethernet1 and leaves via Ethernet2.  Deny attached OUTBOUND on the ingress interface, or INBOUND on the egress interface.
        for i, kw in enumerate(({"ingress": (), "egress": ("Ethernet1",)}, {"ingress": ("Ethernet2",), "egress": ()})):
            case, _, _ = run(f"acl-d{i}", DENY_NOW, before=DENY_BEFORE, **kw)
            self.assertNotConclusive(case)
        # the same deny on the correct side of the flow IS causal (control)
        case, _, _ = run("acl-d2", DENY_NOW, before=DENY_BEFORE, ingress=(), egress=("Ethernet2",))
        self.assertEqual(verdicts(case)["HC18"], "FAIL")
        # unrelated interface
        case, _, _ = run("acl-d3", DENY_NOW, before=DENY_BEFORE, ingress=("Ethernet9",))
        self.assertNotConclusive(case)

    def test_ACLSRC_013_unknown_or_inactive_attachment_stays_inconclusive(self):
        case, _, _ = run("acl-e", DENY_NOW, before=DENY_BEFORE, unattached=True)
        self.assertNotConclusive(case)
        self.assertFalse(m.TsObservation.objects.filter(case=case, key__startswith="acl.counters@", is_missing_data=False).exists())
        case, _, _ = run("acl-e2", DENY_NOW, before=DENY_BEFORE, activeIngressIntfs=[])        # configured but not active
        self.assertNotConclusive(case)

    def test_ACLSRC_014_stale_reset_missing_and_flat_counters_never_causal(self):
        case, _, _ = run("acl-f1", DENY_NOW)                                                    # no history at all
        self.assertNotConclusive(case)
        case, _, _ = run("acl-f2", DENY_NOW, before=[(10, DENY_WEB, 9000), (20, "permit ip any any", 40)])      # counters went down: reset
        self.assertNotConclusive(case)
        case, _, _ = run("acl-f3", DENY_NOW, before=DENY_BEFORE, )
        self.assertEqual(verdicts(case)["HC18"], "FAIL")
        stale_ctx = seeded(DENY_BEFORE, seconds=7200)
        self.assertEqual(nr(rdoc(acl(rules=DENY_NOW)), history=stale_ctx.history)["observations"][0]["value"]["rules"][0]["history"], "stale_history")
        case, _, _ = run("acl-f4", [(10, DENY_WEB, 400), (20, "permit ip any any", 50)], before=DENY_BEFORE)   # deny matches but not incrementing
        self.assertNotConclusive(case)
        case, _, _ = run("acl-f5", [(10, DENY_WEB, None), (20, "permit ip any any", 50)], before=DENY_BEFORE)   # counters not enabled
        self.assertNotConclusive(case)

    def test_ACLSRC_015_unsupported_rule_before_match_is_inconclusive(self):
        rules = [(5, "deny tcp any eq 5555 any", 12), (10, PERMIT_WEB, 900), (20, "permit ip any any", 3)]
        case, _, _ = run("acl-g1", rules, before=[(5, "deny tcp any eq 5555 any", 1), (10, PERMIT_WEB, 800), (20, "permit ip any any", 2)])
        self.assertNotConclusive(case)
        # an unsupported rule AFTER the proven first match cannot change the verdict
        rules = [(10, PERMIT_WEB, 900), (20, "permit tcp any any established", 12)]
        case, _, _ = run("acl-g2", rules, before=[(10, PERMIT_WEB, 800), (20, "permit tcp any any established", 1)])
        self.assertEqual(verdicts(case)["HC18"], "PASS", verdicts(case))

    def test_ACLSRC_016_unsupported_version_no_contact_and_provenance(self):
        case, _, tr = run("acl-h", DENY_NOW, before=DENY_BEFORE, version="4.20.1F")
        self.assertNotIn(R_CMD, tr.calls)
        self.assertNotIn(A_CMD, tr.calls)
        self.assertNotIn(verdicts(case).get("HC18"), ("PASS", "FAIL"))
        self.assertTrue(m.TsObservation.objects.filter(case=case, target="r1", is_missing_data=True, missing_reason__startswith="PARSER_UNAVAILABLE").exists())
        case, _, _ = run("acl-i", DENY_NOW, before=DENY_BEFORE)
        ev = m.TsEvidenceRef.objects.get(case=case, device="r1", command_or_api=R_CMD)
        self.assertEqual((ev.parser, ev.parser_version), ("acl.rules", "eos-json-1.0"))
        self.assertEqual(ev.scope["gateway"], GW)
        self.assertFalse(ev.scope["live"])
