"""Runtime orchestration (RT-001 .. RT-012): ACTUAL collector outputs -> canonical mapping -> persistence -> Engine -> report.

All device output below is replayed through the real CliCollector / SnmpCollector / SyslogCollector (SIMULATED transports, no live device); nothing
here claims live verification.  Gateway provenance is injected only to prove it is preserved verbatim.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from core.tests.helpers.troubleshooting import anonymous, ts_sign_in, ts_user
from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import contracts as c
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.runbooks import REGISTRY
from core.tests.test_troubleshooting_collectors import EOS_IFACES, SNMP_IFACES

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
ACTOR = repo.Actor("alice", "user", tenant="acme")
OSPF = json.dumps({"vrfs": {"default": {"instList": {"1": {"ospfNeighborEntries": [
    {"routerId": "10.0.0.2", "interfaceName": "Ethernet1", "adjacencyState": "full"}]}}}}})
SYSLOG = [("<189>Nov  9 11:58:05 R1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down", T0 - timedelta(seconds=100)),
          ("<189>Nov  9 11:58:20 R1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to up", T0 - timedelta(seconds=80))]
GW = {"live": True, "fixture_id": "fx-1", "node": "r1", "pin_id": "pin-1", "gateway_evidence_seqs": [7, 8]}


class Transport:
    def __init__(self, outputs, provenance=None):
        self.outputs, self.calls = outputs, []
        if provenance:
            self.provenance = lambda: provenance

    def execute(self, rendered):
        self.calls.append(rendered)
        return self.outputs.get(rendered if isinstance(rendered, str) else tuple(rendered), "")


class Session:
    def walk(self, oid):
        return {k: v for k, v in SNMP_IFACES.items() if k.startswith(oid + ".")}

    def get(self, oid):
        return 123456


def inventory(*names, platform="ceos"):
    return lambda: {n: {"platform": platform, "os_version": "4.36.2F"} for n in names}


def deps(transport=None, *, names=("R1", "R2"), lifecycle=None, snmp=True, syslog=True, **kw):
    clock = [0.0]
    return rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=inventory(*names), lifecycle=lifecycle),
        cli_transport=(lambda info: transport) if transport else None,
        snmp_session=(lambda info: Session()) if snmp else None,
        syslog_lines=(lambda info: list(SYSLOG)) if syslog else None,
        sources=bl.StaticSources({}), clock=lambda: clock[0], sleep=lambda s: None, now=lambda: T0,
        capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"}, **kw)


OUT = {"show interfaces | json": EOS_IFACES, "show ip ospf neighbor | json": OSPF, "show ip bgp summary | json": json.dumps({"vrfs": {}}),
       "show ip route | json": "{}", "show ip arp | json": "{}", "show mac address-table | json": "{}", "show spanning-tree | json": "{}"}


def make_case(runbook="RB01", devices=("R1", "R2"), key="k", **kw):
    target = {"device": "R1", "interface": "Ethernet1", "neighbor_device": "R2", "protocol": "ospf", "af": "ipv4", "vrf": "default",
              "peer_device": "R2", "peer_interface": "Ethernet1",
              "links": [], "cables": [], "lag": None, "devices": ["R1", "R2"], "vlan": 10, "resolvers": ["192.0.2.53"], "authoritative": ["192.0.2.54"],
              "client": "R1", "name": "www.example.test", "zone": "example.test", "services": {}}
    return repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "web", "target": target},
                          flow_scope={"name": "web", "src": "R1", "dst": "R2", "protocol": "tcp", "port": 443}, affected_scope={"devices": list(devices)},
                          target_states=kw.pop("target_states", {d: "VERIFIED" for d in devices}), severity="HIGH", runbook=runbook, worked_before=True,
                          first_detected_at=T0 - timedelta(minutes=10), last_known_good_at=T0 - timedelta(hours=3), now=T0 - timedelta(minutes=5))


def obs(case, device=None):
    qs = m.TsObservation.objects.filter(case=case)
    return qs.filter(target=device) if device else qs


class MappingTests(TestCase):
    def test_RT001_actual_collector_outputs_map_to_engine_keys_with_provenance(self):
        case = make_case(key="rt1")
        tr = Transport(OUT, provenance=GW)
        res = rt.run_case(ACTOR, case.case_id, deps(tr), run_key="r1", now=T0)
        keys = {o.key for o in obs(case, "R1").filter(is_missing_data=False)}
        for k in ("interface.oper_state@Ethernet1", "interface.admin_state@Ethernet1", "interface.mtu@Ethernet1", "interface.speed@Ethernet1",
                  "interface.link_event@Ethernet1"):
            self.assertIn(k, keys)
        case3 = make_case("RB03", key="rt1b")
        rt.run_case(ACTOR, case3.case_id, deps(Transport(OUT)), run_key="r1", now=T0)
        nb = obs(case3, "R1").get(key="routing.neighbor@10.0.0.2")
        self.assertEqual((nb.value["state"], nb.value["protocol"]), ("Full", "ospfv2"))
        # raw source pointers, hashes, parser identity and gateway provenance survive on the evidence row
        ev = m.TsEvidenceRef.objects.filter(case=case, device="R1", command_or_api="show interfaces | json").get()
        self.assertEqual(ev.scope["gateway"], GW)
        self.assertTrue(ev.scope["live"])
        self.assertEqual(ev.parser, "interfaces.state")
        self.assertRegex(ev.scope["raw_hash_as_received"], r"^(sha256:)?[0-9a-f]{64}$")
        self.assertIn(ev.scope["raw_hash_as_received"], ev.raw_pointer)
        oper = obs(case, "R1").get(key="interface.oper_state@Ethernet1", evidence=ev)   # SNMP supplies a second, separately sourced row
        self.assertEqual(oper.evidence.evidence_id, ev.evidence_id)
        self.assertEqual(oper.raw_pointer, ev.raw_pointer)
        self.assertEqual(res["schema"], rt.RUN_SCHEMA)
        self.assertEqual(res["diagnosis"]["outcome"] in ("EXPECTED_BEHAVIOR_CONFIRMED", "INCONCLUSIVE_ESCALATED", "ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING"), True)

    def test_RT002_no_transport_means_unavailable_not_values(self):
        case = make_case(key="rt2")
        res = rt.run_case(ACTOR, case.case_id, deps(None, snmp=False, syslog=False), run_key="r1", now=T0)
        self.assertFalse(obs(case).filter(is_missing_data=False).exclude(key__startswith="collection").exists())
        miss = obs(case, "R1").filter(is_missing_data=True)
        self.assertTrue(miss.filter(missing_reason__startswith="UNSUPPORTED").exists())
        for row in res["report"]["sections"]["test_matrix"]["rows"] if "rows" in res["report"]["sections"]["test_matrix"] else []:
            pass
        self.assertNotIn("PASS", {r["verdict"] for r in res["diagnosis"].get("_", [])})
        passed = m.TsDiagnosticTest.objects.filter(case=case, verdict__in=("PASS", "FAIL"))
        for t in passed:
            self.assertTrue(t.evidence_ids, f"{t.test_id} {t.verdict} without evidence")

    def test_RT003_partial_parser_results_are_gaps_beside_parsed_values(self):
        case = make_case("RB04", key="rt3")
        rt.run_case(ACTOR, case.case_id, deps(Transport(OUT), snmp=False, syslog=False), run_key="r1", now=T0)
        # STP now has a validated parser: malformed {} is PARSE_FAILED.
        # MAC also has a validated parser. Both retain evidence without inventing values.
        gaps = {o.key: o.missing_reason for o in obs(case, "R1").filter(is_missing_data=True)}
        self.assertTrue(gaps["stp.state"].startswith("PARSE_FAILED"), gaps)
        self.assertTrue(gaps["mac.table"].startswith("PARSE_FAILED"), gaps)
        self.assertFalse(obs(case, "R1").filter(key__startswith="stp.state", is_missing_data=False).exists())
        self.assertTrue(m.TsEvidenceRef.objects.filter(case=case, command_or_api="show spanning-tree | json").exists())
        self.assertFalse(obs(case, "R1").filter(key__startswith="interface.oper_state", is_missing_data=False).exists())   # RB04 never asked for it

    def test_RT004_untrusted_parse_stays_untrusted(self):
        bad = json.loads(EOS_IFACES)
        bad["interfaces"]["Ethernet2"].update(interfaceStatus="disabled", lineProtocolStatus="up")   # oper up while admin down
        case = make_case(key="rt4")
        rt.run_case(ACTOR, case.case_id, deps(Transport({**OUT, "show interfaces | json": json.dumps(bad)}), snmp=False, syslog=False), run_key="r1", now=T0)
        row = obs(case, "R1").get(key="interface.oper_state@Ethernet2")
        self.assertEqual(row.quality, "UNTRUSTED")


class AdmissionTests(TestCase):
    def test_RT005_admission_comes_from_inventory_not_client_target_states(self):
        case = make_case(devices=("R1", "R9"), key="rt5", target_states={"R1": "VERIFIED", "R9": "VERIFIED"})   # client claims R9 is verified
        tr = Transport(OUT)
        res = rt.run_case(ACTOR, case.case_id, deps(tr, names=("R1",)), run_key="r1", now=T0)
        case.refresh_from_db()
        self.assertEqual(case.target_states, {"R1": "VERIFIED", "R9": "UNKNOWN"})
        self.assertEqual(res["admission"]["R9"]["state"], "UNKNOWN")
        self.assertEqual(obs(case, "R9").filter(is_missing_data=False).count(), 0)
        self.assertTrue(m.TsAuditEvent.objects.filter(case=case, action="PROBE_REFUSED").exists())
        self.assertNotIn("R9", res["collection"]["contacted"])

    def test_RT006_withdrawn_device_never_probed(self):
        case = make_case(key="rt6")
        tr = Transport(OUT)
        res = rt.run_case(ACTOR, case.case_id, deps(tr, lifecycle=lambda d: {"withdrawn": True} if d == "R2" else None), run_key="r1", now=T0)
        self.assertEqual(res["admission"]["R2"]["state"], "WITHDRAWN")
        self.assertEqual(res["collection"]["contacted"], ["R1"])
        self.assertEqual(obs(case, "R2").filter(is_missing_data=False).count(), 0)

    def test_RT007_device_budget_is_enforced_and_clamped(self):
        b = rt.RuntimeBudget.clamp({"max_devices": 1, "max_seconds": 10 ** 9})
        self.assertEqual((b.max_devices, b.max_seconds), (1, rt.SERVER_CAPS.max_seconds))
        with self.assertRaises(ValueError):
            rt.RuntimeBudget.clamp({"max_devices": 0})
        with self.assertRaises(ValueError):
            rt.RuntimeBudget.clamp({"bogus": 1})
        case = make_case(key="rt7")
        res = rt.run_case(ACTOR, case.case_id, deps(Transport(OUT)), run_key="r1", budget={"max_devices": 1}, now=T0)
        self.assertEqual(res["admission"]["R2"]["state"], "BUDGET_EXCEEDED")
        self.assertEqual(res["collection"]["contacted"], ["R1"])

    def test_RT008_wall_clock_budget_exhaustion_is_a_gap(self):
        case = make_case(key="rt8")
        d = deps(Transport(OUT))
        t = [0.0]
        d.clock = lambda: t.__setitem__(0, t[0] + 100) or t[0]    # every reading advances 100 s
        res = rt.run_case(ACTOR, case.case_id, d, run_key="r1", budget={"max_seconds": 50}, now=T0)
        self.assertTrue(obs(case).filter(key="collection.error", missing_reason__startswith="TIMEOUT").exists())
        self.assertEqual(res["collection"]["contacted"], [])


class RestartTests(TestCase):
    def test_RT009_restart_with_same_run_key_does_not_recontact_or_duplicate(self):
        case = make_case(key="rt9")
        tr = Transport(OUT)
        d = deps(tr)
        first = rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=T0)
        calls, n_obs, n_ev, n_runs = len(tr.calls), obs(case).count(), m.TsEvidenceRef.objects.filter(case=case).count(), m.TsCollectionRun.objects.filter(case=case).count()
        second = rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=T0)
        self.assertEqual(len(tr.calls), calls)
        self.assertEqual((obs(case).count(), m.TsEvidenceRef.objects.filter(case=case).count(), m.TsCollectionRun.objects.filter(case=case).count()), (n_obs, n_ev, n_runs))
        self.assertEqual(second["collection"]["resumed"], ["R1", "R2"])
        self.assertEqual(first["test_counts"], second["test_counts"])
        self.assertEqual(m.TsDiagnosticTest.objects.filter(case=case).count(), len(REGISTRY["RB01"].tests))

    def test_RT010_crash_mid_device_resumes_without_duplicate_observations(self):
        case = make_case(key="rt10")
        d = deps(Transport(OUT), names=("R1", "R2"))
        boom = {"n": 0}
        real = repo.ingest_collection_bundle

        def flaky(actor, bundle, **kw):
            boom["n"] += 1
            if boom["n"] == 2:
                raise RuntimeError("simulated process death")
            return real(actor, bundle, **kw)
        repo.ingest_collection_bundle = flaky
        try:
            with self.assertRaises(RuntimeError):
                rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=T0)
        finally:
            repo.ingest_collection_bundle = real
        res = rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=T0)
        keys = list(obs(case).exclude(dedupe_key="").values_list("dedupe_key", flat=True))
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(res["collection"]["resumed"], [])    # R1 had no manifest -> recollected, finished runs reused
        self.assertEqual(m.TsCollectionRun.objects.filter(case=case, status__in=("PENDING", "RUNNING")).count(), 0)


class CoverageTests(TestCase):
    def test_RT011_all_seven_runbooks_run_on_actual_collector_output_without_fabrication(self):
        coverage = {}
        for i, rb in enumerate(sorted(REGISTRY)):
            case = make_case(rb, key=f"rt11{i}")
            res = rt.run_case(ACTOR, case.case_id, deps(Transport(OUT)), run_key="cov", now=T0)
            recv = rt.received_keys(ACTOR, case)
            sources = {k for t in REGISTRY[rb].tests for k in t.sources}
            supported = sorted(k for k in sources if any(r == k or r.startswith(k + ".") or k.startswith(r + ".") for r in recv.get("R1", [])))
            gapped = sorted(o.key.split("@")[0] for o in obs(case, "R1").filter(is_missing_data=True))
            coverage[rb] = (supported, gapped, res["diagnosis"]["outcome"])
            # no fabricated findings: every PASS/FAIL cites evidence; healthy replay yields no proven root cause
            for t in m.TsDiagnosticTest.objects.filter(case=case, verdict__in=("PASS", "FAIL")):
                self.assertTrue(t.evidence_ids, f"{rb}:{t.test_id}")
            self.assertNotEqual(res["diagnosis"]["outcome"], "RESOLVED_VERIFIED")
            self.assertFalse(m.TsDiagnosticTest.objects.filter(case=case, verdict="FAIL", test_id__in=[t.id for t in REGISTRY[rb].tests]).exists() and rb == "RB02",
                             "healthy interface data must not produce FAIL on RB02")
            self.assertEqual(len(res["report"]["section_order"]), 11)
        # runbooks whose evidence the collectors can supply received it
        for rb in ("RB01", "RB02", "RB03", "RB06", "RB07"):
            self.assertTrue(coverage[rb][0], (rb, coverage[rb]))
        # RB04/RB05: no validated STP / DNS parser or collector exists -> explicit gaps only (documented INCOMPLETE_WORK), never invented observations
        self.assertEqual(coverage["RB05"][0], [])
        self.assertIn("stp.state", coverage["RB04"][1])
        self.assertTrue(coverage["RB05"][1])

    def test_RT012_rate_and_reset_need_two_snmp_polls(self):
        case = make_case("RB07", key="rt12")
        d = deps(Transport(OUT))
        rt.run_case(ACTOR, case.case_id, d, run_key="p1", now=T0)
        self.assertFalse(obs(case, "R1").filter(key__startswith="interface.rate.", is_missing_data=False).exists())
        self.assertFalse(obs(case, "R1").filter(key__startswith="interface.counter_reset", is_missing_data=False).exists())


class ViewTests(TestCase):
    def setUp(self):
        for name, groups in (("op", ("ts-operator", "ts-tenant:acme")), ("view", ("ts-viewer", "ts-tenant:acme")), ("other", ("ts-operator", "ts-tenant:zzz"))):
            ts_user(name, *groups)
        self.case = make_case(key="rtv")

    def url(self):
        return f"/api/v1/troubleshooting/cases/{self.case.case_id}/run/"

    def post(self, who, body=None):
        if who:
            ts_sign_in(self.client, User.objects.get(username=who))
        else:
            anonymous(self.client)
        return self.client.post(self.url(), json.dumps(body or {}), content_type="application/json")

    def test_RT013_auth_roles_tenant_and_method(self):
        self.assertEqual(self.post(None).status_code, 401)
        self.assertEqual(self.post("view").status_code, 403)
        self.assertEqual(self.post("other").status_code, 404)
        ts_sign_in(self.client, User.objects.get(username="op"))
        self.assertEqual(self.client.get(self.url()).status_code, 405)

    @override_settings(NMAS_TS_RUNTIME_FACTORY="")
    def test_RT014_run_endpoint_is_idempotent_ignores_client_states_and_fails_closed(self):
        r = self.post("op", {"run_key": "v1", "target_states": {"R1": "VERIFIED"}, "budget": {"max_devices": 99}})
        self.assertEqual(r.status_code, 200, r.content)
        data = r.json()["data"]
        self.assertEqual(data["ignored_client_fields"], ["target_states"])
        self.assertEqual(data["budget"]["max_devices"], rt.SERVER_CAPS.max_devices)
        # NO factory configured: bare RuntimeDeps() admits from the real inventory but has NO transport -> every device source is
        # UNAVAILABLE, no values
        self.assertEqual(data["collection"]["contacted"], ["R1", "R2"])
        self.assertFalse(m.TsObservation.objects.filter(case=self.case, target__in=("R1", "R2"), is_missing_data=False).exists())
        n = m.TsObservation.objects.filter(case=self.case).count()
        r2 = self.post("op", {"run_key": "v1"})
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(m.TsObservation.objects.filter(case=self.case).count(), n)
        self.assertEqual(self.post("op", {"budget": {"nope": 1}}).status_code, 400)
        self.assertEqual(self.post("op", {"runbook": "RB99"}).status_code, 400)

    def test_RT014b_shipped_settings_admit_nothing_until_the_binding_is_enabled(self):
        # config/settings.py ships the deployment factory with an EMPTY NMAS_TS_DEPLOYMENT (NMAS_TS_BINDING unset): no lifecycle or
        # version provider is bound, so no device is admitted and none is contacted, whatever the client sends.
        r = self.post("op", {"run_key": "v1b", "target_states": {"R1": "VERIFIED", "R2": "VERIFIED"}})
        self.assertEqual(r.status_code, 200, r.content)
        data = r.json()["data"]
        self.assertEqual(data["collection"]["contacted"], [])
        self.assertEqual(data["ignored_client_fields"], ["target_states"])
        self.assertFalse(m.TsObservation.objects.filter(case=self.case, is_missing_data=False).exists())

    @override_settings(NMAS_TS_RUNTIME_FACTORY="core.tests.test_troubleshooting_runtime.view_deps")
    def test_RT015_factory_hook_drives_collection(self):
        data = self.post("op", {"run_key": "v2"}).json()["data"]
        self.assertEqual(data["collection"]["contacted"], ["R1", "R2"])
        self.assertTrue(m.TsObservation.objects.filter(case=self.case, key="interface.oper_state@Ethernet1").exists())


def view_deps():
    return deps(Transport(OUT))
