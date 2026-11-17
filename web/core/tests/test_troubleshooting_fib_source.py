"""Independent forwarding-table (FIB) source -> HC16.  Stable IDs FIBSRC-001 .. FIBSRC-014.

PROVENANCE: every FIB document below is SIMULATED (hand-written to the ``nmas.troubleshooting.fib-source/1`` contract); the RIB documents come from the SIMULATED
cEOS ``show ip route | json`` fixtures of test_troubleshooting_forwarding_source.  Nothing here is gateway-recorded, so no live verification is claimed: the injected gateway
dictionary (``live=false``) only proves provenance is carried verbatim.  External qualification against real cEOS / IOS-XE / FRR forwarding APIs is documented in
docs/troubleshooting/fib-source.md and NOT performed by this file.
"""

from __future__ import annotations

import copy
import json

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import forwarding as fw
from core.tests import test_troubleshooting_forwarding_source as FS

T0 = FS.T0
GW = {"live": False, "fixture_id": "simulated-fib", "note": "SIMULATED: not gateway-recorded"}
EV = {"evidence_id": "ev-fib", "source_type": "STATE_SNAPSHOT", "command_or_api": "fib-state read", "collected_at": T0.isoformat()}
SRC = {"id": "sim-fib-agent", "kind": "fib-agent", "authoritative": True, "derived_from_rib": False}


def entry(prefix, hops=(), programmed=True, action="forward"):
    return {"prefix": prefix, "programmed": programmed, "action": action,
            "next_hops": [{"address": a, "interface": i, "resolved": r, "adjacency": "arp" if r else None} for a, i, r in hops]}


def fib_doc(device, entries, *, vrf="default", family="ipv4", coverage="FULL_TABLE", complete=True, queried=(), converging=False, platform="ceos", version="4.36.2F",
            source=None, capability=None, provenance=None, restart="default", **over):
    doc = {"schema": nz.FIB_SCHEMA, "device": device, "platform": platform, "os_version": version, "source_identity": dict(SRC, **(source or {})),
           "capability": capability if capability is not None else {"status": "SUPPORTED", "api": "simulated forwarding-agent read"},
           "scope": {"vrf": vrf, "family": family, "coverage": coverage, "queried": list(queried)}, "complete": complete,
           "restart": {"converging": converging, "boot_id": "boot-1"} if restart == "default" else restart, "entries": list(entries),
           "provenance": provenance if provenance is not None else {"label": "SIMULATED", "collected_at": T0.isoformat()}}
    doc.update(over)
    return doc


HEALTHY = {"r1": [entry("10.1.1.0/24", [(None, "Ethernet1", True)]), entry("10.2.2.0/24", [("10.0.12.2", "Ethernet2", True)])],
           "r2": [entry("10.2.2.0/24", [(None, "Ethernet2", True)]), entry("10.1.1.0/24", [("10.0.12.1", "Ethernet1", True)])]}


class Reader:
    def __init__(self, docs):
        self.docs, self.calls = docs, []

    def read(self, request):
        self.calls.append(request)
        d = self.docs.get(request["device"])
        if isinstance(d, Exception):
            raise d
        return d(request) if callable(d) else d

    def provenance(self):
        return GW


def docs_for(table, **kw):
    return {d: fib_doc(d, es, **kw) for d, es in table.items()}


def run(key, docs=None, *, reader=None, fib=True, tables=None, devices=None):
    reader = reader if reader is not None else Reader(docs or {})
    case = FS.make_case(key)
    if devices is not None:
        case.affected_scope = {**case.affected_scope, "devices": list(devices)}
        case.save()
    transports = {d: FS.Transport(t) for d, t in (tables or FS.v4_lab()).items()}
    d = rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=lambda: {dev: {"platform": FS.PLATFORM[dev], "os_version": "8.4.4" if FS.PLATFORM[dev] == "linux" else "4.36.2F"} for dev in FS.S.DEVICES}),
        cli_transport=lambda info: transports[info.device], fib_source=(lambda info: reader) if fib else None,
        sources=bl.StaticSources({**FS.S.static_data(), "intent": FS.intent()}), forwarding_context=FS.fctx(), clock=lambda: 0.0, sleep=lambda s: None, now=lambda: T0,
        capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})
    res = rt.run_case(FS.ACTOR, case.case_id, d, run_key="r1", now=T0, engine_config=eng.EngineConfig(exhaustive=True))
    return case, res, reader


class _T:
    def __init__(self, t):
        self.verdict, self.summary = t.verdict, f"{t.observed_summary} | {t.reason}"


def hc16(case):
    return _T(m.TsDiagnosticTest.objects.filter(case=case, test_id="HC16").order_by("-seq", "-attempt").first())


def fib_gap(case, dev="r1"):
    return m.TsObservation.objects.get(case=case, target=dev, key="route.fib@10.2.2.0/24")


def norm(doc, *, platform="ceos", version="4.36.2F", vrf="default", family="ipv4", prefixes=("10.2.2.0/24",)):
    return nz.normalize_fib_state(doc, platform=platform, os_version=version, device="r1", evidence=EV, request={"vrf": vrf, "family": family, "prefixes": list(prefixes)}, now=T0)


class UnitTests(SimpleTestCase):
    def test_FIBSRC_001_valid_document_normalizes_with_identity_scope_provenance(self):
        res = norm(fib_doc("r1", HEALTHY["r1"]))
        (o,) = res["observations"]
        v = o["value"]
        self.assertEqual((o["key"], o["quality"], res["missing"]), ("route.fib.table", "OK", []))
        self.assertEqual((v["vrf"], v["family"], v["coverage"], v["complete"], v["fib_evidence"], v["table_kind"]), ("default", "ipv4", "FULL_TABLE", True, True, "fib"))
        self.assertEqual((v["source"]["id"], v["source"]["derived_from_rib"], v["provenance"]["label"]), ("sim-fib-agent", False, "SIMULATED"))

    def test_FIBSRC_002_rib_or_kernel_tables_are_never_accepted_as_fib(self):
        for kind in ("rib", "kernel-routing-table", "ip-route", "routing-table"):
            res = norm(fib_doc("r1", HEALTHY["r1"], source={"kind": kind}))
            self.assertEqual(res["observations"], [], kind)
            self.assertEqual(res["missing"][0]["reason"], nz.Missing.UNSUPPORTED_OPERATION, kind)
        for patch in ({"derived_from_rib": True}, {"authoritative": False}, {"authoritative": "yes"}, {"id": ""}):
            res = norm(fib_doc("r1", HEALTHY["r1"], source=patch))
            self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], nz.Missing.UNSUPPORTED_OPERATION), patch)
        rib_text = FS.eos_routes({"10.2.2.0/24": ("OSPF", [("10.0.12.2", "Ethernet2")])})        # a RIB document is not a fib-source document
        self.assertEqual(norm(json.loads(rib_text))["missing"][0]["reason"], nz.Missing.PARSE_FAILED)
        self.assertEqual(norm(rib_text)["missing"][0]["reason"], nz.Missing.PARSE_FAILED)

    def test_FIBSRC_003_identity_platform_capability_scope_provenance_gates(self):
        cases = [(dict(platform="iosxe"), nz.Missing.UNSUPPORTED_PLATFORM), (dict(version="4.30.0F"), nz.Missing.UNSUPPORTED_PLATFORM), (dict(device="r9"), nz.Missing.UNSUPPORTED_PLATFORM),
                 (dict(capability={"status": "UNSUPPORTED", "api": "x"}), nz.Missing.UNSUPPORTED_OPERATION), (dict(capability={"status": "SUPPORTED"}), nz.Missing.UNSUPPORTED_OPERATION),
                 (dict(capability={}), nz.Missing.UNSUPPORTED_OPERATION), (dict(vrf="mgmt"), nz.Missing.SCOPE_MISMATCH), (dict(family="ipv6"), nz.Missing.SCOPE_MISMATCH),
                 (dict(provenance={}), nz.Missing.PARSE_FAILED), (dict(provenance={"label": "TRUSTME", "collected_at": T0.isoformat()}), nz.Missing.PARSE_FAILED),
                 (dict(entries="nope"), nz.Missing.PARSE_FAILED)]
        for patch, reason in cases:
            doc = fib_doc("r1", HEALTHY["r1"])
            if "platform" in patch or "device" in patch:
                doc.update(patch)
            elif "version" in patch:
                doc["os_version"] = patch["version"]
            elif "vrf" in patch or "family" in patch:
                doc["scope"].update(patch)
            else:
                doc.update(patch)
            res = norm(doc)
            self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], reason), patch)
            self.assertEqual(res["missing"][0]["extra"]["engine_key"], "route.fib@10.2.2.0/24")

    def test_FIBSRC_004_completeness_restart_and_truncation_downgrade_to_partial(self):
        for label, doc in (("incomplete", fib_doc("r1", HEALTHY["r1"], complete=False)), ("converging", fib_doc("r1", HEALTHY["r1"], converging=True)),
                           ("restart-unreported", fib_doc("r1", HEALTHY["r1"], restart={})), ("bad-entry", fib_doc("r1", HEALTHY["r1"] + [{"prefix": "zzz"}])),
                           ("lookup-without-queried", fib_doc("r1", HEALTHY["r1"], coverage="PREFIX_LOOKUP"))):
            (o,) = norm(doc)["observations"]
            self.assertEqual((o["quality"], o["value"]["complete"]), ("PARTIAL", False), label)

    def test_FIBSRC_005_lookup_semantics_installed_absent_partial_wrong_scope(self):
        def lookup(doc, prefix="10.2.2.0/24", vrf="default", family="ipv4"):
            return fw.fib_lookup(norm(doc, prefixes=(prefix,))["observations"], fw.RouteQuery(prefix, vrf, family))
        v, _ = lookup(fib_doc("r1", HEALTHY["r1"]))
        self.assertEqual((v["installed"], v["next_hop"], v["resolved"], v["fib_evidence"]), (True, "10.0.12.2", True, True))
        v, _ = lookup(fib_doc("r1", HEALTHY["r1"][:1]))                                   # complete full table without the prefix => genuinely absent
        self.assertEqual((v["installed"], v["reason"]), (False, "NO_FIB_ENTRY"))
        v, _ = lookup(fib_doc("r1", [entry("10.2.2.0/24", [("10.0.12.2", "Ethernet2", True)], programmed=False)]))
        self.assertFalse(v["installed"])
        v, reason = lookup(fib_doc("r1", HEALTHY["r1"][:1], complete=False))               # partial table: absence is UNKNOWN
        self.assertIsNone(v)
        self.assertIn("incomplete", reason)
        v, _ = lookup(fib_doc("r1", [entry("10.0.0.0/8", [("10.0.12.9", "Ethernet2", True)])], complete=False))     # partial: a covering non-exact entry is not trusted
        self.assertIsNone(v)
        v, _ = lookup(fib_doc("r1", HEALTHY["r1"], complete=False))                       # partial but exact entry is positive evidence
        self.assertTrue(v["installed"] and not v["table_complete"])
        v, reason = lookup(fib_doc("r1", HEALTHY["r1"]), vrf="blue")                      # asked VRF differs from the collected table
        self.assertIsNone(v)
        self.assertIn("wrong scope", reason)
        lk = fib_doc("r1", HEALTHY["r1"], coverage="PREFIX_LOOKUP", queried=["10.2.2.0/24"])
        self.assertTrue(lookup(lk)[0]["installed"])
        v, reason = fw.fib_lookup(norm(lk)["observations"], fw.RouteQuery("10.9.9.0/24", "default", "ipv4"))
        self.assertIsNone(v)
        self.assertIn("did not look up", reason)
        v, _ = lookup(fib_doc("r1", [entry("10.2.2.0/24", [("10.0.12.2", "Ethernet2", False)])]))
        self.assertIs(v["resolved"], False)

    def test_FIBSRC_006_describe_source_labels_and_qualification(self):
        d = fw.describe_source()
        self.assertEqual((d["label"], d["fib"]["available"]), ("SIMULATED", False))
        self.assertTrue(any("external qualification" in x for x in d["fib"]["qualification"]))
        self.assertTrue(fw.describe_source(fib_source={"id": "x"})["fib"]["available"])
        self.assertEqual(fw.fib_requests(FS.flow(), FS.fctx()), [{"vrf": "default", "family": "ipv4", "prefixes": ["10.2.2.0/24", "10.1.1.0/24"]}])


class CollectorTests(SimpleTestCase):
    def collect(self, reader, **tk):
        target = col.Target(device="r1", platform="ceos", os_version="4.36.2F", **tk)
        probe = lambda plat, src: {"status": "SUPPORTED"}                               # noqa: E731
        c = col.FibCollector(capability_probe=probe, now=lambda: T0, clock=lambda: 0.0, sleep=lambda s: None)
        return c.collect(target, [{"vrf": "default", "family": "ipv4", "prefixes": ["10.2.2.0/24"]}], reader)

    def test_FIBSRC_007_collector_bounds_failures_and_admission(self):
        ok = self.collect(Reader({"r1": fib_doc("r1", HEALTHY["r1"])}))
        self.assertEqual((ok["run"]["status"], ok["run"]["privileges"], len(ok["observations"]), ok["run"]["gateway"]), ("COMPLETE", "read-only", 1, GW))
        self.assertEqual(ok["evidence"][0]["parser"]["id"], "route.fib")
        for exc, reason in ((col.TransportError(), nz.Missing.TRANSPORT_ERROR), (col.PermissionDenied(), nz.Missing.PERMISSION_DENIED), (TimeoutError(), nz.Missing.TRANSPORT_ERROR)):
            b = self.collect(Reader({"r1": exc}))
            self.assertEqual((b["observations"], b["missing"][0]["reason"]), ([], reason))
        b = self.collect(Reader({"r1": fib_doc("r1", HEALTHY["r1"])}), lifecycle_state="DECOMMISSIONED")      # not admitted: the reader is never called
        self.assertEqual(b["run"]["status"], "REFUSED")
        r = Reader({"r1": fib_doc("r1", HEALTHY["r1"])})
        self.collect(r, lifecycle_state="QUARANTINED")
        self.assertEqual(r.calls, [])


class RuntimeToHc16Tests(TestCase):
    def test_FIBSRC_008_installed_passes_hc16_with_provenance(self):
        case, res, reader = run("fib08", docs_for(HEALTHY))
        t = hc16(case)
        self.assertEqual(t.verdict, "PASS", t.summary)
        o = m.TsObservation.objects.get(case=case, target="r1", key="route.fib@10.2.2.0/24", is_missing_data=False)
        self.assertEqual((o.value["installed"], o.value["next_hop"], o.value["fib_evidence"], o.value["source"]["id"]), (True, "10.0.12.2", True, "sim-fib-agent"))
        self.assertEqual(o.value["provenance"]["label"], "SIMULATED")
        rib = m.TsObservation.objects.get(case=case, target="r1", key="route.rib@10.2.2.0/24", is_missing_data=False)
        self.assertEqual(rib.value["fib_evidence"], False)                                # RIB stays a RIB
        ev = m.TsEvidenceRef.objects.get(case=case, device="r1", source_type="state_snapshot")
        self.assertEqual((ev.scope["gateway"], ev.scope["live"], ev.parser), (GW, False, "route.fib"))
        self.assertTrue({"r1", "r2"} <= {r["device"] for r in reader.calls})               # read-only, bounded: one read per (vrf, family) per device pass
        self.assertTrue(all(len(r["prefixes"]) == 2 for r in reader.calls))
        self.assertTrue(all(set(r) == {"vrf", "family", "prefixes", "device", "platform", "os_version"} for r in reader.calls))

    def test_FIBSRC_009_missing_with_complete_coverage_fails_hc16(self):
        table = {**HEALTHY, "r1": HEALTHY["r1"][:1]}
        case, res, _ = run("fib09", docs_for(table))
        t = hc16(case)
        self.assertEqual(t.verdict, "FAIL", t.summary)
        self.assertIn("FIB_INSTALL_DISCREPANCY", t.summary)
        o = m.TsObservation.objects.get(case=case, target="r1", key="route.fib@10.2.2.0/24", is_missing_data=False)
        self.assertEqual((o.value["installed"], o.value["reason"]), (False, "NO_FIB_ENTRY"))
        self.assertEqual(FS.verdicts(case)["HC15"], "PASS")                                # RIB good / FIB missing is a forwarding discrepancy, not a routing one
        # next-hop disagreement and unresolved adjacency are also discrepancies
        bad = {**HEALTHY, "r1": [HEALTHY["r1"][0], entry("10.2.2.0/24", [("10.0.99.9", "Ethernet2", True)])]}
        self.assertIn("NEXT_HOP_MISMATCH", hc16(run("fib09b", docs_for(bad))[0]).summary)
        unres = {**HEALTHY, "r1": [HEALTHY["r1"][0], entry("10.2.2.0/24", [("10.0.12.2", "Ethernet2", False)])]}
        self.assertIn("UNRESOLVED_ADJACENCY", hc16(run("fib09c", docs_for(unres))[0]).summary)

    def test_FIBSRC_010_partial_table_is_unknown_never_pass_or_fail(self):
        table = {**HEALTHY, "r1": HEALTHY["r1"][:1]}
        case, _, _ = run("fib10", docs_for(table, complete=False))
        t = hc16(case)
        self.assertNotIn(t.verdict, ("PASS", "FAIL"), t.summary)
        gap = fib_gap(case)
        self.assertTrue(gap.is_missing_data)
        self.assertIn("incomplete", gap.missing_reason)
        self.assertFalse(m.TsObservation.objects.filter(case=case, target="r1", key="route.fib@10.2.2.0/24", is_missing_data=False).exists())

    def test_FIBSRC_011_unsupported_capability_or_rib_derived_source_stays_unavailable(self):
        for tag, patch in (("cap", dict(capability={"status": "UNSUPPORTED", "api": "none"})), ("rib", dict(source={"kind": "kernel-routing-table", "derived_from_rib": True}))):
            case, _, _ = run("fib11" + tag, docs_for(HEALTHY, **patch))
            t = hc16(case)
            self.assertEqual(t.verdict, "UNAVAILABLE", (tag, t.summary))
            gap = fib_gap(case)
            self.assertTrue(gap.is_missing_data and gap.missing_reason.startswith("UNSUPPORTED_OPERATION"), gap.missing_reason)
        case, _, _ = run("fib11none", fib=False)                                        # no source configured: the pre-existing explicit gap
        self.assertTrue(fib_gap(case).missing_reason.startswith("UNSUPPORTED_OPERATION"))
        self.assertNotIn(hc16(case).verdict, ("PASS", "FAIL"))

    def test_FIBSRC_012_wrong_scope_vrf_family_or_device_is_unknown(self):
        for tag, docs in (("vrf", docs_for(HEALTHY, vrf="mgmt")), ("fam", docs_for(HEALTHY, family="ipv6")),
                          ("dev", {"r1": fib_doc("r2", HEALTHY["r2"]), "r2": fib_doc("r1", HEALTHY["r1"])}), ("ver", docs_for(HEALTHY, version="4.20.0F"))):
            case, _, _ = run("fib12" + tag, docs)
            t = hc16(case)
            self.assertNotIn(t.verdict, ("PASS", "FAIL"), (tag, t.summary))
            self.assertTrue(fib_gap(case).is_missing_data, tag)
            self.assertFalse(m.TsObservation.objects.filter(case=case, key__startswith="route.fib@", is_missing_data=False).exists(), tag)

    def test_FIBSRC_013_restart_in_progress_is_unknown_then_converged_passes(self):
        case, _, _ = run("fib13a", docs_for({**HEALTHY, "r1": HEALTHY["r1"][:1]}, converging=True))       # empty-looking FIB while the device re-converges
        self.assertNotIn(hc16(case).verdict, ("PASS", "FAIL"), hc16(case).summary)
        self.assertIn("incomplete", fib_gap(case).missing_reason)
        self.assertFalse(m.TsObservation.objects.filter(case=case, target="r1", key="route.fib@10.2.2.0/24", is_missing_data=False).exists())
        case2, _, _ = run("fib13b", docs_for(HEALTHY))
        self.assertEqual(hc16(case2).verdict, "PASS")

    def test_FIBSRC_014_source_failure_and_restarted_run_are_bounded_and_idempotent(self):
        case, _, _ = run("fib14a", {"r1": col.TransportError(), "r2": col.PermissionDenied()})
        self.assertNotIn(hc16(case).verdict, ("PASS", "FAIL"))
        self.assertTrue(fib_gap(case).is_missing_data)
        docs = docs_for(HEALTHY)
        case, res, reader = run("fib14b", docs, devices=("r1", "r2"))
        n = len(reader.calls)
        d = rt.RuntimeDeps(admission=rt.InventoryAdmission(inventory=lambda: {dev: {"platform": FS.PLATFORM[dev], "os_version": "8.4.4" if FS.PLATFORM[dev] == "linux" else "4.36.2F"} for dev in FS.S.DEVICES}),
                           cli_transport=lambda info: FS.Transport(FS.v4_lab()[info.device]), fib_source=lambda info: reader, sources=bl.StaticSources({**FS.S.static_data(), "intent": FS.intent()}),
                           forwarding_context=FS.fctx(), clock=lambda: 0.0, sleep=lambda s: None, now=lambda: T0,
                           capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})
        again = rt.run_case(FS.ACTOR, case.case_id, d, run_key="r1", now=T0, engine_config=eng.EngineConfig(exhaustive=True))       # restart with the same run key
        self.assertTrue({"r1", "r2"}.isdisjoint(again["collection"]["contacted"]) and {"r1", "r2"} <= set(again["collection"]["resumed"]), again["collection"])
        self.assertEqual(len([r for r in reader.calls[n:] if r["device"] in ("r1", "r2")]), 0)
        self.assertEqual(len(reader.calls) - n, len(again["collection"]["contacted"]))   # only unfinished off-path devices may be re-read, one bounded read each
        self.assertEqual(m.TsObservation.objects.filter(case=case, target="r1", key="route.fib@10.2.2.0/24", is_missing_data=False).count(), 1)
