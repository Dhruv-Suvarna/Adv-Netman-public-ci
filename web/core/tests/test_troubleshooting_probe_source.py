"""Active-probe source (HC22 service.probe / HC17 path.trace) -- contract -> collector -> runtime -> runbook.  Stable IDs PRBSRC-001 .. PRBSRC-020.

PROVENANCE: every runner response below is SIMULATED (hand-written ``nmas.probe.response/1``).  No gateway-recorded probe output is pinned and no socket is
opened; nothing here claims live verification.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import deployment as dep
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import probes as pr
from core.tests.fixtures.troubleshooting_runbooks import scenarios as S

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
ACTOR = repo.Actor("alice", "user", tenant="acme")
GW = {"live": False, "fixture_id": "simulated-probe", "note": "SIMULATED: not gateway-recorded"}
ADDR = {"h1": "10.1.1.10", "h2": "10.2.2.20", "r1": "10.1.1.1", "r2": "10.0.12.2"}
HOPS = ["10.1.1.1", "10.0.12.2", "10.2.2.20"]
CTX_KW = dict(admitted_sources=("h1",), destinations=("h2",), ports=(443,), addresses=ADDR)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def auth(case_id, expires=T0 + timedelta(hours=1)):
    return {"id": "AP-1", "case_id": case_id, "expires_at": iso(expires), "approved_by": "bob"}


def tcp_doc(outcomes=("connected",) * 3, **kw):
    rows = [{"seq": i, "outcome": o, "rtt_ms": 2.0 + i if o == "connected" else None} for i, o in enumerate(outcomes, 1)]
    d = {"schema": pr.RESPONSE_SCHEMA, "op": "tcp_connect", "status": "response", "vantage": {"device": "h1", "address": ADDR["h1"], "kind": "host-namespace"},
         "destination": {"address": ADDR["h2"], "port": 443}, "protocol": "tcp", "started_at": iso(T0), "finished_at": iso(T0 + timedelta(seconds=1)), "attempts": rows}
    d.update(kw)
    return json.dumps(d)


def trace_doc(addrs=HOPS, method="tcp", **kw):
    hops = [{"ttl": i, "address": a, "rtt_ms": 1.0 + i, "status": "reached" if i == len(addrs) and a == ADDR["h2"] else "ttl_exceeded"} if a else
            {"ttl": i, "address": None, "rtt_ms": None, "status": "timeout"} for i, a in enumerate(addrs, 1)]
    d = {"schema": pr.RESPONSE_SCHEMA, "op": "path_trace", "status": "response", "method": method, "vantage": {"device": "h1", "address": ADDR["h1"]},
         "destination": {"address": ADDR["h2"]}, "reached": bool(addrs and addrs[-1] == ADDR["h2"]), "started_at": iso(T0), "finished_at": iso(T0 + timedelta(seconds=1)), "hops": hops}
    d.update(kw)
    return json.dumps(d)


class Runner:
    """Scriptable injected runner; ``calls`` is every request that reached it (it is the only thing that could touch a network)."""

    def __init__(self, tcp=None, trace=None, caps=("tcp_connect", "path_trace"), raises=None, provenance=None):
        self.tcp, self.trace, self.caps, self.raises, self.calls = tcp or tcp_doc(), trace or trace_doc(), caps, raises, []
        if provenance:
            self.provenance = lambda: provenance

    def capabilities(self):
        return self.caps

    def execute(self, req):
        self.calls.append(req)
        assert req["schema"] == "nmas.probe.request/1" and req["active_probe"] is True and req["mutating"] is False
        if self.raises:
            raise self.raises
        return self.tcp if req["op"] == "tcp_connect" else self.trace


FLOW = {"name": "web", "src": "h1", "dst": "h2", "protocol": "tcp", "port": 443}


def policy(**kw):
    ctx = pr.ProbeContext(authorization={"id": "AP-1", "case_id": "C1", "expires_at": iso(T0 + timedelta(hours=1))}, **{**CTX_KW, **kw})
    return pr.policy_for(FLOW, "C1", ctx), ctx


def collector(ctx=None, **bk):
    c = col.ProbeCollector(budget=col.Budget(**bk), now=lambda: T0, clock=lambda: 0.0, sleep=lambda s: None, adapter="test",
                           capability_probe=lambda p, s: {"status": "SUPPORTED"})
    c.context = ctx
    return c


TARGET = col.Target(device="h1", platform="linux", os_version="24.04", lifecycle_state="VERIFIED", verified=True)


def run(runner, reqs=None, pol=None, ctx=None, **bk):
    p, c = policy()
    reqs = reqs if reqs is not None else pr.requests_for_device(FLOW, "h1", ["service.probe", "path.trace"], c)
    return collector(ctx or c, **bk).collect(TARGET, reqs, runner, p if pol is None else pol)


def reasons(b):
    return [x["reason"] for x in b["missing"]]


class ContractTests(SimpleTestCase):
    def test_PRBSRC_001_requests_derive_only_from_the_flow_tuple_and_flow_source(self):
        _, c = policy()
        r = pr.requests_for_device(FLOW, "h1", ["service.probe", "path.trace"], c)
        self.assertEqual([(x.op, x.dst_address, x.port) for x in r], [("tcp_connect", ADDR["h2"], 443), ("path_trace", ADDR["h2"], 443)])
        self.assertEqual(pr.requests_for_device(FLOW, "r1", ["service.probe"], c), [])           # only the flow source originates probes
        self.assertEqual(pr.requests_for_device({**FLOW, "protocol": "udp"}, "h1", ["service.probe"], c), [])
        self.assertEqual(pr.requests_for_device({}, "h1", ["service.probe"], c), [])

    def test_PRBSRC_002_good_tcp_and_trace_preserve_vantage_provenance_and_limits(self):
        r = Runner(provenance=GW)
        b = run(r)
        self.assertEqual(reasons(b), [])
        tcp, tr = b["observations"]
        v = tcp["value"]
        self.assertEqual((tcp["key"], tcp["target"]["probe"], v["sent"], v["ok"], v["rtt_ms_p50"], v["vantage"]["device"], v["l7_verified"], v["production_flow_equivalent"]),
                         ("service.probe", "tcp", 3, 3, 4.0, "h1", False, False))
        self.assertTrue(any("L7" in x for x in v["limitations"]))
        self.assertEqual((tr["key"], tr["target"]["probe"], tr["value"]["hop_devices"], tr["value"]["reached"], tr["value"]["method"]), ("path.trace", "h2", ["r1", "r2", "h2"], True, "tcp"))
        self.assertEqual(tcp["observed_at"], iso(T0 + timedelta(seconds=1)))
        self.assertEqual(b["run"]["gateway"], GW)
        self.assertEqual(b["evidence"][0]["gateway"], GW)
        self.assertEqual(b["evidence"][0]["parser"]["id"], "probe.tcp")
        self.assertTrue(b["evidence"][0]["raw_ref"]["hash"])

    def test_PRBSRC_003_refusals_never_reach_the_runner(self):
        p, c = policy()
        cases = {
            "no policy": dict(pol=None, expect="NOT_CONFIGURED", policy_none=True),
            "no authorization": dict(pol=col.ProbePolicy(**{**p.__dict__, "deny_reason": "no active-probe authorization is recorded for this case"}), expect="PERMISSION_DENIED"),
            "expired": dict(pol=col.ProbePolicy(**{**p.__dict__, "expires_at": T0}), expect="PERMISSION_DENIED"),
            "source not admitted": dict(pol=col.ProbePolicy(**{**p.__dict__, "admitted_sources": ("x",)}), expect="COMMAND_NOT_ALLOWED"),
            "destination not authorized": dict(pol=col.ProbePolicy(**{**p.__dict__, "destinations": ("other",)}), expect="COMMAND_NOT_ALLOWED"),
            "port not authorized": dict(pol=col.ProbePolicy(**{**p.__dict__, "ports": (80,)}), expect="COMMAND_NOT_ALLOWED"),
            "flow differs": dict(pol=col.ProbePolicy(**{**p.__dict__, "flow": {**FLOW, "port": 8443}}), expect="COMMAND_NOT_ALLOWED"),
        }
        for name, spec in cases.items():
            r = Runner()
            if spec.get("policy_none"):
                b = collector(c).collect(TARGET, pr.requests_for_device(FLOW, "h1", ["service.probe"], c), r, None)
            else:
                b = run(r, pol=spec["pol"])
            self.assertEqual(r.calls, [], name)
            self.assertEqual(b["observations"], [], name)
            self.assertEqual(set(reasons(b)), {spec["expect"]}, name)

    def test_PRBSRC_004_authorization_bound_to_another_case_or_missing_expiry(self):
        _, c = policy()
        for a in ({"id": "AP-1", "case_id": "OTHER", "expires_at": iso(T0 + timedelta(hours=1))}, {"id": "AP-1", "case_id": "C1"}, None):
            c.authorization = a
            p = pr.policy_for(FLOW, "C1", c)
            r = Runner()
            b = collector(c).collect(TARGET, pr.requests_for_device(FLOW, "h1", ["service.probe"], c), r, p)
            self.assertEqual((r.calls, reasons(b)), ([], ["PERMISSION_DENIED"]))

    def test_PRBSRC_005_missing_runner_capability_and_bad_request_fields(self):
        for caps in ((), ("path_trace",)):
            r = Runner(caps=caps)
            b = run(r)
            self.assertNotIn("tcp_connect", [c["op"] for c in r.calls])
            self.assertIn("UNSUPPORTED_OPERATION", reasons(b))
        p, c = policy()
        r = Runner()
        bad = [col.ProbeRequest("tcp_connect", "h1", "", "h2", ADDR["h2"], "tcp", 443, 99), col.ProbeRequest("tcp_connect", "h1", "", "h2", "", "tcp", 443, 3),
               col.ProbeRequest("tcp_connect", "h1", "", "h2", "224.0.0.1", "tcp", 443, 3), col.ProbeRequest("tcp_connect", "h1", "", "h2", ADDR["h2"], "udp", 443, 3),
               col.ProbeRequest("tcp_connect", "h1", "", "h2", ADDR["h2"], "tcp", True, 3), col.ProbeRequest("exec", "h1", "", "h2", ADDR["h2"]),
               col.ProbeRequest("path_trace", "h1", "", "h2", ADDR["h2"], "tcp", 443, 0, "tcp", 99)]
        b = collector(c).collect(TARGET, bad, r, p)
        self.assertEqual((r.calls, reasons(b)), ([], ["COMMAND_NOT_ALLOWED"] * 5 + ["UNSUPPORTED_OPERATION", "COMMAND_NOT_ALLOWED"]))   # unknown op: not a declared capability

    def test_PRBSRC_006_attempt_budget_and_command_budget(self):
        p, c = policy()
        r = Runner()
        two = [col.ProbeRequest("tcp_connect", "h1", "", "h2", ADDR["h2"], "tcp", 443, 5)] * 3
        b = collector(c).collect(TARGET, two, r, p)               # max_probes 10 => two of three
        self.assertEqual((len(r.calls), reasons(b)), (2, ["BUDGET_EXCEEDED"]))
        r = Runner()
        b = run(r, max_commands=1)
        self.assertEqual((len(r.calls), reasons(b)), (1, ["BUDGET_EXCEEDED"]))
        self.assertEqual(len(b["observations"]), 1)

    def test_PRBSRC_007_timeout_transport_permission_and_unexpected_errors_are_gaps_without_retry(self):
        for exc, want in ((TimeoutError("x"), "TIMEOUT"), (col.TransportError("conn", True), "TRANSPORT_ERROR"), (col.PermissionDenied(), "PERMISSION_DENIED"),
                          (RuntimeError("secret-token"), "TRANSPORT_ERROR")):
            r = Runner(raises=exc)
            b = run(r, max_retries=3)
            self.assertEqual(len(r.calls), 2, want)                # one attempt per request, never retried
            self.assertEqual(set(reasons(b)), {want})
            self.assertEqual(b["observations"], [])
            self.assertNotIn("secret-token", json.dumps(b["missing"]))

    def test_PRBSRC_008_malformed_responses_yield_parse_failed_with_raw_evidence_kept(self):
        bad_tcp = ["{nope", tcp_doc(schema="x"), tcp_doc(op="path_trace"), tcp_doc(status="error"), tcp_doc(attempts=[]), tcp_doc(attempts=[{"seq": 1, "outcome": "weird"}]),
                   tcp_doc(outcomes=("connected",) * 4), tcp_doc(destination={"address": "10.9.9.9", "port": 443}), tcp_doc(destination={"address": ADDR["h2"], "port": 80}),
                   tcp_doc(started_at="yesterday"), tcp_doc(finished_at=iso(T0 - timedelta(hours=1))), tcp_doc(outcomes=("error", "error")),
                   json.dumps({"schema": pr.RESPONSE_SCHEMA, "op": "tcp_connect", "status": "response", "vantage": {"device": "h1"}, "destination": {"address": ADDR["h2"], "port": 443},
                               "protocol": "tcp", "started_at": iso(T0), "finished_at": iso(T0), "attempts": [{"seq": 1, "outcome": "connected", "rtt_ms": -3}]})]
        for raw in bad_tcp:
            _, c = policy()
            b = collector(c).collect(TARGET, pr.requests_for_device(FLOW, "h1", ["service.probe"], c), Runner(tcp=raw), policy()[0])
            self.assertEqual((b["observations"], reasons(b)), ([], ["PARSE_FAILED"]), raw[:60])
            self.assertEqual(len(b["evidence"]), 1)
        for raw in ("[]", trace_doc(method="icmp"), trace_doc(reached=False), trace_doc(hops=[]), trace_doc(hops=[{"ttl": 2, "address": "10.0.0.1", "status": "ttl_exceeded"}]),
                    trace_doc(hops=[{"ttl": 1, "address": "nonsense", "status": "ttl_exceeded"}])):
            _, c = policy()
            b = collector(c).collect(TARGET, pr.requests_for_device(FLOW, "h1", ["path.trace"], c), Runner(trace=raw), policy()[0])
            self.assertEqual((b["observations"], reasons(b)), ([], ["PARSE_FAILED"]), raw[:60])

    def test_PRBSRC_009_oversize_response_is_discarded(self):
        b = run(Runner(tcp=tcp_doc() + " " * (col.PROBE_MAX_RESPONSE_BYTES + 1)))
        self.assertIn("OUTPUT_TOO_LARGE", reasons(b))

    def test_PRBSRC_010_vantage_mismatch_is_not_accepted_as_the_requested_source(self):
        doc = json.loads(tcp_doc())
        doc["vantage"]["device"] = "jump-host"
        b = run(Runner(tcp=json.dumps(doc)))
        self.assertEqual([o["key"] for o in b["observations"]], ["path.trace"])
        miss = [x for x in b["missing"]]
        self.assertEqual((reasons(b), "VANTAGE_MISMATCH" in miss[0]["detail"]), (["PARSE_FAILED"], True))
        self.assertEqual(miss[0]["extra"]["engine_key"], "service.probe@tcp")

    def test_PRBSRC_011_loss_refusal_and_partial_samples_are_reported_not_hidden(self):
        b = run(Runner(tcp=tcp_doc(("connected", "refused", "timeout"))))
        v = b["observations"][0]["value"]
        self.assertEqual((v["sent"], v["ok"], v["refused"], v["timeouts"], v["outcomes"]), (3, 1, 1, 1, ["connected", "refused", "timeout"]))
        b = run(Runner(tcp=tcp_doc(("connected", "error", "connected"))))
        o = b["observations"][0]
        self.assertEqual((o["value"]["sent"], o["value"]["local_errors"], o["quality"]), (2, 1, "PARTIAL"))
        b = run(Runner(tcp=tcp_doc(("connected",))))
        self.assertIn("SHORT_SAMPLE", b["observations"][0]["flags"])

    def test_PRBSRC_012_unresolved_or_gapped_trace_is_untrusted_not_a_path_verdict(self):
        b = run(Runner(trace=trace_doc(["10.1.1.1", "192.0.2.77", ADDR["h2"]])))
        o = b["observations"][1]
        self.assertEqual((o["quality"], "UNRESOLVED_HOP_ADDRESS" in o["flags"]), ("UNTRUSTED_PARSE", True))
        b = run(Runner(trace=trace_doc(["10.1.1.1", None, ADDR["h2"]])))
        self.assertIn("TRACE_GAP_BEFORE_RESPONDING_HOP", b["observations"][1]["flags"])
        b = run(Runner(trace=trace_doc(["10.1.1.1", "10.0.12.2", None, None])))            # trailing silence: honest unreached trace
        v = b["observations"][1]["value"]
        self.assertEqual((v["reached"], v["last_hop"], b["observations"][1]["quality"]), (False, "r2", "OK"))

    def test_PRBSRC_013_non_tcp_trace_carries_a_limitation(self):
        _, c = policy()
        c.trace_method = "icmp"
        b = collector(c).collect(TARGET, pr.requests_for_device(FLOW, "h1", ["path.trace"], c), Runner(trace=trace_doc(method="icmp")), policy()[0])
        self.assertTrue(any("not proof of the path taken by the TCP" in x for x in b["observations"][0]["value"]["limitations"]))

    def test_PRBSRC_014_unverified_device_never_reaches_the_runner(self):
        r = Runner()
        p, c = policy()
        b = collector(c).collect(col.Target(device="h1", platform="linux", verified=False, lifecycle_state="UNVERIFIED"), pr.requests_for_device(FLOW, "h1", ["service.probe"], c), r, p)
        self.assertEqual((r.calls, b["run"]["status"], reasons(b)), ([], "REFUSED", ["NOT_ADMITTED"]))

    def test_PRBSRC_015_deployment_wrapper_requires_capabilities_and_factory_is_fail_closed(self):
        class NoCaps:
            def execute(self, r):
                return "{}"
        d = dep.build_runtime_deps(probe_runner_factory=lambda info: NoCaps(), problems=(pb := []))
        self.assertIsNone(d.probe_runner(type("I", (), {"device": "h1"})()))
        self.assertTrue(pb)
        self.assertIsNone(dep.build_runtime_deps().probe_runner)
        self.assertIsNone(dep.runtime_deps({}).probe_runner)
        d = dep.runtime_deps({"probe_runner_factory": lambda info: Runner(provenance=GW), "probe_context_provider": lambda: pr.ProbeContext(**CTX_KW)})
        w = d.probe_runner(type("I", (), {"device": "h1"})())
        self.assertEqual((w.capabilities(), w.provenance()), (("tcp_connect", "path_trace"), GW))
        self.assertFalse(hasattr(w, "calls"))
        bad = dep.runtime_deps({"probe_context_provider": lambda: "garbage"})
        self.assertEqual(bad.probe_context.authorization, None)          # invalid context degrades to an empty (authorizing nothing) context

    def test_PRBSRC_016_source_label_never_claims_live_without_gateway(self):
        self.assertEqual(pr.describe_source()["label"], "SIMULATED")
        self.assertEqual(pr.describe_source(gateway={"live": True})["label"], "LIVE_GATEWAY_PINNED")


# ------------------------------------------------------------------------------------------------------------------ runtime -> RB02
def make_case(key, flow=None):
    devs = ["h1", "h2"]
    return repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "web"}, flow_scope=flow or S.FLOW,
                          affected_scope={"devices": devs}, target_states={d: "VERIFIED" for d in devs}, severity="HIGH", runbook="RB02", worked_before=True,
                          first_detected_at=T0 - timedelta(minutes=10), last_known_good_at=T0 - timedelta(hours=3), now=T0 - timedelta(minutes=5))


def deps(runner, case, *, ctx=True, **kw):
    context = pr.ProbeContext(authorization=auth(case.case_id), **CTX_KW) if ctx is True else ctx
    return rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=lambda: {d: {"platform": "linux", "os_version": "24.04"} for d in ("h1", "h2")}),
        probe_runner=(lambda info: runner) if runner else None, probe_context=context, sources=bl.StaticSources(S.static_data()),
        clock=lambda: 0.0, sleep=lambda s: None, now=lambda: T0, capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"}, **kw)


def go(case, d, key="r1"):
    return rt.run_case(ACTOR, case.case_id, d, run_key=key, now=T0, engine_config=eng.EngineConfig(exhaustive=True))


def tests_of(case):
    return {t.test_id: t for t in m.TsDiagnosticTest.objects.filter(case=case)}


class RuntimeTests(TestCase):
    def test_PRBSRC_017_runtime_maps_probes_to_engine_keys_and_hc22_hc17_consume_them(self):
        case = make_case("p17")
        r = Runner(provenance=GW)
        go(case, deps(r, case))
        o = m.TsObservation.objects.get(case=case, target="h1", key="service.probe@tcp")
        self.assertEqual((o.value["ok"], o.value["vantage"]["device"], o.is_missing_data), (3, "h1", False))
        self.assertTrue(m.TsObservation.objects.filter(case=case, target="h1", key="path.trace@h2", is_missing_data=False).exists())
        ev = m.TsEvidenceRef.objects.get(case=case, device="h1", command_or_api__startswith="probe:tcp_connect")
        self.assertEqual((ev.scope["gateway"], ev.scope["live"], ev.parser), (GW, False, "probe.tcp"))
        t = tests_of(case)
        self.assertEqual(t["HC22"].verdict, "PASS")
        self.assertIn(t["HC17"].verdict, ("PASS", "FAIL"))             # consumed (not an evidence gap)
        self.assertNotIn("not collected", json.dumps(t["HC17"].gaps if hasattr(t["HC17"], "gaps") else ""))

    def test_PRBSRC_018_failing_handshakes_become_an_hc22_fault_and_unresolved_trace_is_inconclusive(self):
        case = make_case("p18")
        go(case, deps(Runner(tcp=tcp_doc(("timeout",) * 3), trace=trace_doc(["10.1.1.1", "192.0.2.77"])), case))
        t = tests_of(case)
        self.assertEqual(t["HC22"].verdict, "FAIL")
        self.assertEqual(t["HC17"].verdict, "INCONCLUSIVE")

    def test_PRBSRC_019_absent_runner_or_authorization_is_an_unknown_gap_and_nothing_is_sent(self):
        case = make_case("p19a")
        go(case, deps(None, case))
        gaps = m.TsObservation.objects.filter(case=case, target="h1", key__in=("service.probe@tcp", "path.trace@h2"), is_missing_data=True)
        self.assertEqual(gaps.count(), 2)
        self.assertTrue(all(g.missing_reason.startswith("NOT_CONFIGURED") for g in gaps))
        self.assertNotEqual(tests_of(case)["HC22"].verdict, "PASS")
        for key, ctx, want in (("p19b", None, "NOT_CONFIGURED"), ("p19c", pr.ProbeContext(**CTX_KW), "PERMISSION_DENIED")):
            c2 = make_case(key)
            r = Runner()
            go(c2, deps(r, c2, ctx=ctx))
            self.assertEqual(r.calls, [], key)
            self.assertTrue(m.TsObservation.objects.filter(case=c2, key="service.probe@tcp", is_missing_data=True, missing_reason__startswith=want).exists(), key)
            self.assertNotEqual(tests_of(c2)["HC22"].verdict, "PASS")

    def test_PRBSRC_020_restart_with_same_run_key_does_not_resend_probes(self):
        case = make_case("p20")
        r = Runner()
        go(case, deps(r, case))
        n, rows = len(r.calls), m.TsObservation.objects.filter(case=case).count()
        res = go(case, deps(r, case))
        self.assertEqual((len(r.calls), m.TsObservation.objects.filter(case=case).count()), (n, rows))
        self.assertIn("h1", res["collection"]["resumed"])

    def test_PRBSRC_021_non_source_device_and_non_tcp_flow_send_nothing(self):
        case = make_case("p21", flow={**S.FLOW, "protocol": "udp"})
        r = Runner()
        go(case, deps(r, case))
        self.assertNotIn("tcp_connect", [c["op"] for c in r.calls])
        self.assertTrue(all(c["source"]["device"] == "h1" for c in r.calls))
