"""Direct tests for the unattended incident intake (troubleshooting/intake.py).

The intake only ever READS devices through the trusted Containerlab console (``docker exec ... show ... | json``).  Here
that console is replaced by a fake ``subprocess.run`` that answers per command, so the readers' parsing and their
fail-closed behaviour (an unreadable device is ``None``, never an empty healthy reading) are tested without any container.
Case admission (dedup, maintenance, cooldown, budget) and the case/handoff/dispatch path run against the test database
with injected dependencies; nothing starts a real dispatcher.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase, override_settings

from core import models
from core.services.troubleshooting import faults, intake, route_intent

T0 = datetime(2026, 11, 17, 9, 4, 14, tzinfo=timezone.utc)
CFG = intake.IntakeConfig(devices=("R2", "S4"), confirm_seconds=30, cooldown_seconds=900, max_cases_per_hour=2)
IFACES = {"interfaces": {"Ethernet1": {"interfaceStatus": "disabled", "lineProtocolStatus": "down"},
                         "Management0": {"interfaceStatus": "connected", "lineProtocolStatus": "up"}}}
OSPF = {"vrfs": {"default": {"instList": {"1": {"ospfNeighborEntries": [{"routerId": "10.0.0.4", "interfaceName": "Ethernet2",
                                                                         "adjacencyState": "full"}]}}}}}
SUMMARY = {"vrfs": {"default": {"ospfCounts": {"ospfTotal": 4}, "connected": 3, "static": 1}}}


def console(answers: dict | None = None, *, rc: int = 0, raises: Exception | None = None):
    """A fake ``subprocess.run``: the stdout of the first answer whose key occurs in the joined argv."""
    calls = []

    def run(argv, **_kw):
        calls.append(argv)
        if raises is not None:
            raise raises
        joined = " ".join(argv)
        out = next((v for k, v in (answers or {}).items() if k in joined), "")
        return subprocess.CompletedProcess(argv, rc, out if isinstance(out, str) else json.dumps(out), "")
    run.calls = calls
    return run


def sample(device="R2", iface="Ethernet1", admin="down", oper="down", link="disabled"):
    return faults.InterfaceSample(device=device, interface=iface, at=T0, admin=admin, oper=oper, link_status=link, protocol="down")


def incident(fp="LINK:R2:Ethernet1|S4:Ethernet3", devices=("R2",)):
    return intake.Incident(fp, list(devices), [sample()], T0)


class IntakeConfigTests(TestCase):
    @override_settings(NMAS_TS_INTAKE_DEVICES="R1, R2", NMAS_TS_INTAKE_CONFIRM_SECONDS=45, NMAS_TS_ROUTE_INTENT_FILE="/srv/intent.json")
    def test_from_settings_builds_the_configured_intake(self):
        cfg = intake.IntakeConfig.from_settings()
        self.assertEqual((cfg.devices, cfg.confirm_seconds, cfg.route_intent_path), (("R1", "R2"), 45, "/srv/intent.json"))
        self.assertEqual(cfg.routing_devices, intake.DEFAULT_ROUTING_DEVICES)


class ConsoleReaderTests(TestCase):
    def test_readers_return_parsed_state_from_the_console(self):
        with mock.patch.object(intake.subprocess, "run", console({"show interfaces": IFACES, "ip ospf neighbor": OSPF, "route summary": SUMMARY})):
            samples = intake.read_device("R2", CFG)
            adjacencies = intake.read_adjacencies("R2", CFG)
            sources = intake.read_route_sources("R2", CFG)
        self.assertEqual([(s.interface, s.admin) for s in samples], [("Ethernet1", "down")])          # Management is skipped
        self.assertEqual([(a.protocol, a.neighbor) for a in adjacencies], [("ospf", "10.0.0.4")])
        self.assertEqual(sources["ipv4"]["ospf"], 4)
        with mock.patch.object(intake.subprocess, "run", console({"link show": [{"ifname": "eth1", "flags": ["UP", "LOWER_UP"]}]})):
            self.assertEqual([s.interface for s in intake.read_device("R3", CFG)], ["eth1"])

    def test_unreadable_console_yields_none_never_a_healthy_reading(self):
        for label, run in (("a failing command", console(rc=1)), ("an unavailable docker", console(raises=OSError("no docker"))),
                           ("a non-object document", console({"show interfaces": []}))):
            with mock.patch.object(intake.subprocess, "run", run):
                with self.subTest(f"{label} is unreadable for interfaces"):
                    self.assertIsNone(intake.read_device("R2", CFG))
                with self.subTest(f"{label} is unreadable for adjacencies"):
                    if label != "a non-object document":
                        self.assertIsNone(intake.read_adjacencies("R2", CFG))
                with self.subTest(f"{label} is unreadable for route sources"):
                    self.assertIsNone(intake.read_route_sources("R2", CFG))
        with mock.patch.object(intake.subprocess, "run", console(rc=1)):
            with self.subTest("an unreadable frr device is none"):
                self.assertIsNone(intake.read_device("R3", CFG))

    def test_read_config_admin_returns_the_configured_state(self):
        with mock.patch.object(intake.subprocess, "run", console({"running-config": "interface Ethernet1\n   shutdown\n"})):
            self.assertEqual(intake.read_config_admin("R2", "Ethernet1", CFG), "down")
        with mock.patch.object(intake.subprocess, "run", console({"running-config": "interface Ethernet1\n   description x\n"})):
            self.assertEqual(intake.read_config_admin("R2", "Ethernet1", CFG), "up")

    def test_read_config_admin_refuses_unsafe_names_and_unreadable_config(self):
        run = console({"running-config": "interface Ethernet1\n"})
        with mock.patch.object(intake.subprocess, "run", run):
            with self.subTest("a shell-unsafe interface name is refused before any command"):
                self.assertIsNone(intake.read_config_admin("R2", "Ethernet1; reload", CFG))
                self.assertEqual(run.calls, [])
        for label, failing in (("a failed command", console(rc=1)), ("no docker", console(raises=OSError())),
                               ("output without the interface", console({"running-config": "% Invalid input"}))):
            with mock.patch.object(intake.subprocess, "run", failing):
                with self.subTest(f"{label} is none"):
                    self.assertIsNone(intake.read_config_admin("R2", "Ethernet1", CFG))


class TopologyEvidenceTests(TestCase):
    def test_topology_snapshot_returns_ribs_addresses_and_links(self):
        with mock.patch.object(intake.subprocess, "run", console(rc=1)):
            snap = intake.topology_snapshot(CFG)
        self.assertTrue(snap["links"])
        self.assertEqual(set(snap["addresses"]), set(intake.ADDRESS_DEVICES))
        self.assertIn("collected_at", snap)

    def test_topology_snapshot_marks_unreadable_devices(self):
        with mock.patch.object(intake.subprocess, "run", console(raises=OSError("no docker"))), \
                self.subTest("every device is unreadable without a console"):
            snap = intake.topology_snapshot(CFG)
            self.assertEqual(snap["unreadable"], sorted(intake.ADDRESS_DEVICES))

    def intent(self):
        exp = route_intent.PrefixExpectation("T1", "forward", "10.2.2.0/24", "R1", "ipv4", "10.2.2.0/24", "ospf", ("10.0.12.2",))
        return route_intent.RouteIntent("rev1", "topo1", ("review",), (exp, route_intent.PrefixExpectation(**{**exp.__dict__, "device": "H1"})))

    def test_read_route_intent_ribs_returns_only_the_intended_devices(self):
        with mock.patch.object(intake.subprocess, "run", console({"show ip route": {"vrfs": {"default": {"routes": {}}}}, "-4 route": []})):
            doc = intake.read_route_intent_ribs(self.intent(), CFG)
        self.assertEqual(sorted(doc["device_observed_at"]), ["H1", "R1"])
        self.assertEqual(doc["collector"], "nmas-intake trusted-console-read-only")

    def test_unreadable_route_intent_ribs_stay_none_not_missing(self):
        with mock.patch.object(intake.subprocess, "run", console(rc=1)):
            doc = intake.read_route_intent_ribs(self.intent(), CFG)
        with self.subTest("a failed read is none (indeterminate), not an empty table"):
            self.assertIsNone(doc["ribs"]["ipv4"]["R1"])
            self.assertIsNone(doc["ribs"]["ipv6"]["H1"])

    def snapshot(self):
        return {"ribs4": {}, "ribs6": {}, "addresses": {}, "links": [], "unreadable": ["R1"], "collected_at": T0.isoformat()}

    def test_flow_paths_returns_a_row_per_flow_branch(self):
        rows = intake.flow_paths(self.snapshot(), {("R2", "eth1")})
        self.assertEqual({r["flow"] for r in rows}, {f[0] for f in intake.TOPOLOGY_FLOWS})
        self.assertTrue(all("verdict" in r for r in rows))

    def test_flow_paths_without_evidence_traverse_no_incident(self):
        with self.subTest("no RIB evidence marks no flow as traversing the incident"):
            self.assertTrue(all(r["traverses_incident"] == [] for r in intake.flow_paths(self.snapshot(), {("R2", "eth1")})))


class CorrelationTests(TestCase):
    INTENT = {"R2": {"Ethernet1": "up"}, "S4": {"Ethernet3": "up"}}

    def test_violations_peers_and_correlate_build_one_link_incident(self):
        down_r2, down_s4 = intake.Observation("R2", "Ethernet1", "disabled", "down"), intake.Observation("S4", "Ethernet3", "notconnect", "down")
        current = intake.violations([down_r2, down_s4, intake.Observation("R2", "Management0", "disabled", "down")], self.INTENT.get)
        self.assertEqual(sorted(current), [("R2", "Ethernet1"), ("S4", "Ethernet3")])
        link_peers = intake.peers({"R2", "S4"})
        self.assertTrue(link_peers)
        pairs = {("R2", "Ethernet1"): ("S4", "Ethernet3"), ("S4", "Ethernet3"): ("R2", "Ethernet1")}
        found = intake.correlate(current, pairs, {k: T0 for k in current})
        self.assertEqual([(i.fingerprint, i.devices) for i in found], [("LINK:R2:Ethernet1|S4:Ethernet3", ["R2"])])
        self.assertEqual(found[0].category, faults.ADMIN_STATE_MISMATCH)
        self.assertIn("R2 Ethernet1 link=disabled", found[0].symptom())

    def test_healthy_or_unknown_inputs_correlate_to_no_incident(self):
        with self.subTest("an interface not intended up is no violation"):
            self.assertEqual(intake.violations([intake.Observation("R2", "Ethernet9", "disabled", "down")], self.INTENT.get), {})
        with self.subTest("no devices have no peers"):
            self.assertEqual(intake.peers(set()), {})
        with self.subTest("no abnormal ends open no incident"):
            self.assertEqual(intake.correlate({}, {}, {}), [])

    def test_fingerprint_ends_returns_link_and_interface_ends(self):
        self.assertEqual(intake.fingerprint_ends("LINK:R2:Ethernet1|S4:Ethernet3"), [("R2", "Ethernet1"), ("S4", "Ethernet3")])
        self.assertEqual(intake.fingerprint_ends("REPLAY:IFACE:R2:Ethernet1", "REPLAY:"), [("R2", "Ethernet1")])

    def test_fingerprint_ends_of_unknown_kinds_are_empty(self):
        for fp in ("ROUTE:R2", "IFACE:", "LINK:R2"):
            with self.subTest(f"{fp} has no ends"):
                self.assertEqual(intake.fingerprint_ends(fp), [])


class RouteIntentRecordTests(TestCase):
    def result(self, category, device="R1"):
        return SimpleNamespace(category=category, scope={"target_id": "T1", "direction": "forward", "device": device, "af": "ipv4"},
                               evidence={"route_prefix": "10.2.2.0/24"})

    def test_route_intent_pass_record_builds_a_journal_safe_summary(self):
        rec = intake.route_intent_pass_record({"route_intent": "DEGRADED", "intent_revision": "rev1"}, pass_id="P1", at=T0,
                                              results=[self.result(faults.NO_FAULT), self.result("MISSING_ROUTE", "R2")], expectations=2,
                                              confirmed=frozenset({"RINT:rev1:T1:R2"}))
        self.assertEqual((rec["severity"], rec["routes"]["evaluated"], rec["items_truncated"]), ("warning", 2, 0))
        self.assertEqual([(i["device"], i["status"]) for i in rec["items"]], [("R2", "CONFIRMED")])

    def test_route_intent_pass_record_of_a_failed_pass_is_an_error(self):
        with self.subTest("a record with no state is an error"):
            rec = intake.route_intent_pass_record({}, pass_id="P2", at=T0)
            self.assertEqual((rec["state"], rec["severity"]), ("ERROR", "error"))
        with self.subTest("an indeterminate evaluation without a reason carries a stable code"):
            self.assertEqual(intake.route_intent_pass_record({"route_intent": "INDETERMINATE"}, pass_id="P3", at=T0)["error_code"],
                             "RIB_ENTRIES_INDETERMINATE")

    def test_unit_route_intent_binding_returns_the_running_unit_environment(self):
        binding = intake.unit_route_intent_binding(lambda: "NMAS_TS_ROUTE_INTENT_FILE=/srv/i.json NMAS_TS_TOPOLOGY_REVISION=t1 OTHER=x")
        self.assertEqual((binding["bound"], binding["intent_file"], binding["topology_revision"]), (True, "/srv/i.json", "t1"))

    def test_unit_route_intent_binding_refuses_an_unreadable_unit(self):
        def unavailable():
            raise OSError("no systemd")
        with self.subTest("an unreadable unit environment is not bound"):
            self.assertEqual(intake.unit_route_intent_binding(unavailable), {"bound": False, "error_code": "UNIT_ENVIRONMENT_UNAVAILABLE"})
        with self.subTest("a unit without the intent file is not bound"):
            self.assertIs(intake.unit_route_intent_binding(lambda: "OTHER=x")["bound"], False)

    def test_route_intent_case_record_correlates_the_case(self):
        inc = incident("RINT:rev1:T1:R1", ("R1",))
        inc.route_evidence = {"pass_id": "P1", "intent_revision": "rev1", "topology_revision": "t1"}
        rec = intake.route_intent_case_record(inc, {"case": "TSC-1", "handoff": "AIH-0123456789ab", "dispatch_started": True}, T0)
        self.assertEqual((rec["pass_id"], rec["case_id"], rec["severity"], rec["error_code"]), ("P1", "TSC-1", "warning", None))

    def test_route_intent_case_record_of_a_failed_open_is_an_error(self):
        rec = intake.route_intent_case_record(incident(), None, T0, error="DatabaseError: locked")
        with self.subTest("a failed open carries the error code and no case"):
            self.assertEqual((rec["error_code"], rec["case_id"], rec["severity"]), ("ROUTE_INTENT_CASE_OPEN_FAILED", None, "error"))


class DispatchUnitTests(TestCase):
    def test_dispatch_active_returns_true_for_a_running_unit(self):
        with mock.patch.object(intake.subprocess, "run", console({"is-active": "active\n"})):
            self.assertIs(intake.dispatch_active("AIH-0123456789ab"), True)

    def test_dispatch_units_refuse_malformed_ids_and_read_failures_as_running(self):
        run = console({"is-active": "active\n"})
        with mock.patch.object(intake.subprocess, "run", run):
            with self.subTest("a malformed handoff id is refused without systemctl"):
                self.assertIs(intake.start_dispatch("AIH-../../etc"), False)
                self.assertIs(intake.dispatch_active("not-a-handoff"), False)
                self.assertEqual(run.calls, [])
        with mock.patch.object(intake.subprocess, "run", console({"is-active": "inactive\n"})):
            with self.subTest("an inactive unit is not running"):
                self.assertIs(intake.dispatch_active("AIH-0123456789ab"), False)
        with mock.patch.object(intake.subprocess, "run", console(raises=OSError())):
            with self.subTest("an unknown unit state never starts a second dispatcher"):
                self.assertIs(intake.dispatch_active("AIH-0123456789ab"), True)
        with mock.patch.object(intake.subprocess, "run", console(rc=5)):
            with self.subTest("a failed start is not started"):
                self.assertIs(intake.start_dispatch("AIH-0123456789ab"), False)


class CaseIntakeTests(TestCase):
    def setUp(self):
        self.mail, self.dispatched = [], []
        self.deps = intake.IntakeDeps(run_case=lambda actor, cid, deps: None,
                                      open_handoff=lambda actor, case, **kw: SimpleNamespace(record_id="AIH-0123456789ab"),
                                      dispatch=lambda hid: self.dispatched.append(hid) or True, notify=lambda s, b: self.mail.append(s),
                                      maintenance=None, policy_lookup=lambda op: None)

    def opened(self, inc=None, **dep):
        deps = intake.IntakeDeps(**{**self.deps.__dict__, **dep})
        return intake.open_incident(inc or incident(), deps, now=T0)

    def test_open_incident_creates_the_case_and_dispatches(self):
        out = self.opened()
        case = models.TsCase.objects.get(case_id=out["case"])
        self.assertEqual((case.trigger_ref, out["dispatch_started"], self.dispatched), ("LINK:R2:Ethernet1|S4:Ethernet3", True, ["AIH-0123456789ab"]))
        self.assertTrue(models.TsAuditEvent.objects.filter(case=case, action="INTAKE_DISPATCH", result="OK").exists())

    def test_open_incident_with_a_dispatcher_that_fails_is_not_started(self):
        out = self.opened(dispatch=lambda hid: False)
        with self.subTest("a dispatcher that fails is not reported as started and a human is told"):
            self.assertIs(out["dispatch_started"], False)
            self.assertTrue(any("could not start" in m for m in self.mail))

    def test_admission_accepts_a_new_fingerprint(self):
        self.assertEqual(intake.admission(incident(), CFG, T0), (True, ""))

    def test_admission_refuses_duplicates_maintenance_cooldown_and_budget(self):
        out = self.opened()
        with self.subTest("an open case for the fingerprint is refused"):
            self.assertEqual(intake.admission(incident(), CFG, T0), (False, "OPEN_CASE_EXISTS"))
        with self.subTest("an active maintenance is refused"):
            ok, why = intake.admission(incident("IFACE:R2:Ethernet2"), CFG, T0, maintenance=lambda devices: "R2: maintenance M-1")
            self.assertEqual((ok, why), (False, "MAINTENANCE_ACTIVE (R2: maintenance M-1)"))
        models.TsCase.objects.filter(case_id=out["case"]).update(state=models.TsCaseState.NO_FAULT_FOUND)    # terminal, still in cooldown
        with self.subTest("a fingerprint inside its cooldown is refused"):
            self.assertEqual(intake.admission(incident(), CFG, T0 + timedelta(seconds=60)), (False, "COOLDOWN_ACTIVE"))
        self.opened(incident("IFACE:R2:Ethernet2"))
        with self.subTest("an exhausted hourly budget is refused"):
            self.assertEqual(intake.admission(incident("IFACE:S4:Ethernet3", ("S4",)), CFG, T0 + timedelta(seconds=60)),
                             (False, "HOURLY_CASE_BUDGET_EXHAUSTED"))

    def test_maintenance_reason_returns_the_conflicts(self):
        with mock.patch("core.services.execution.eligibility._maintenance_conflicts", return_value={"R2": "maintenance M-1 active"}):
            self.assertEqual(intake.maintenance_reason(["R2"]), "R2: maintenance M-1 active")

    def test_maintenance_reason_of_an_unreadable_state_suppresses_nothing(self):
        with mock.patch("core.services.execution.eligibility._maintenance_conflicts", side_effect=RuntimeError("db locked")):
            with self.subTest("an unreadable maintenance state is no reason to suppress"):
                self.assertEqual(intake.maintenance_reason(["R2"]), "")

    def test_idle_reason_reports_an_idle_open_case(self):
        out = self.opened()
        later = datetime.now(timezone.utc) + timedelta(seconds=intake.IDLE_AFTER_SECONDS + 1)     # audit events are append-only
        self.assertTrue(intake.idle_reason(incident().fingerprint, later).startswith(f"OPEN_CASE_IDLE {out['case']}"))

    def test_idle_reason_without_an_open_or_idle_case_is_empty(self):
        with self.subTest("no open case is no idle reason"):
            self.assertEqual(intake.idle_reason("IFACE:R9:Ethernet1", T0), "")
        self.opened()
        with self.subTest("a case with recent activity is not idle"):
            self.assertEqual(intake.idle_reason(incident().fingerprint, datetime.now(timezone.utc)), "")

    def test_record_decision_and_topology_paths_are_audited(self):
        case = models.TsCase.objects.get(case_id=self.opened()["case"])
        actor = intake.repo.Actor(intake.ACTOR_NAME, "system", tenant="default", devices=frozenset({"R2"}))
        intake.record_decision(actor, case, {"outcome": faults.DIAGNOSE_AND_ESCALATE, "category": faults.ADMIN_STATE_MISMATCH}, evidence_ids=[], now=T0)
        self.assertTrue(models.TsAuditEvent.objects.filter(case=case, action="REMEDIATION_DECISION", result=faults.DIAGNOSE_AND_ESCALATE).exists())
        snap = {"ribs4": {}, "ribs6": {}, "addresses": {}, "links": [], "unreadable": [], "collected_at": T0.isoformat()}
        ids = intake.record_topology_paths(actor, case, incident(), CFG, T0, snapshot=snap)
        self.assertEqual(len(ids), len(intake.flow_paths(snap, set())))

    def test_decisions_without_outcome_and_paths_without_evidence_are_refused_or_unaffected(self):
        case = models.TsCase.objects.get(case_id=self.opened()["case"])
        actor = intake.repo.Actor(intake.ACTOR_NAME, "system", tenant="default", devices=frozenset({"R2"}))
        with self.subTest("a decision without an outcome is refused"):
            with self.assertRaises(KeyError):
                intake.record_decision(actor, case, {"category": "x"}, evidence_ids=[], now=T0)
        with self.subTest("paths without RIB evidence are not affected"):
            snap = {"ribs4": {}, "ribs6": {}, "addresses": {}, "links": [], "unreadable": ["R1"], "collected_at": T0.isoformat()}
            intake.record_topology_paths(actor, case, incident(), CFG, T0, snapshot=snap)
            self.assertEqual(models.TsAuditEvent.objects.get(case=case, action="TOPOLOGY_PATHS").result, "UNAFFECTED")
