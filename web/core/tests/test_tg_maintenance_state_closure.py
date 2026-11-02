"""Lab 7 closure -- Maintenance Mode record lifecycle, stored records, the evidence chain and the read-only collector
helpers, each public function called directly (test database, injected host commands; no device, no docker).

POSITIVE: the exact transition, stored row, chained evidence entry, journal and parsed host facts.  NEGATIVE: a step
from the wrong state is refused and leaves the record unchanged; a record that is not due starts no restore; unreadable
or missing evidence is never FRESH, never "active" and never a digest.
"""

from __future__ import annotations

import json
from datetime import timedelta

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.services.maintenance_mode import collector, evidence, lifecycle, model, store, topology
from core.services.maintenance_mode.model import ACTIVE, NORTHBOUND, SOUTHBOUND
from core.tests import test_maintenance_mode as mm
from core.tests.test_maintenance_mode import CYCLE, HOUR, T0


def ready(device="S1"):
    record = lifecycle.request(device, "operator", "replace a line card", 4 * HOUR, at=T0)
    record.evaluate(mm.flows(), at=T0)
    return record


class RecordTransitionTests(SimpleTestCase):
    def test_deadline_due_once_the_cycle_has_elapsed_on_an_active_record(self):
        record = mm.LifecycleTests().active()
        self.assertEqual((record.deadline_due(T0 + CYCLE - timedelta(seconds=1)), record.deadline_due(T0 + CYCLE)), (False, True))

    def test_deadline_due_never_for_a_record_that_is_not_active(self):
        self.assertFalse(ready().deadline_due(T0 + 30 * CYCLE))

    def test_on_deadline_starts_the_restore_when_due(self):
        record = mm.LifecycleTests().active()
        self.assertTrue(record.on_deadline(now=T0 + CYCLE))
        self.assertEqual((record.state, record.restore_trigger), (lifecycle.RESTORING, lifecycle.DEADLINE))

    def test_on_deadline_not_due_starts_no_restore(self):
        record = mm.LifecycleTests().active()
        self.assertFalse(record.on_deadline(now=T0 + CYCLE - timedelta(minutes=1)))
        self.assertEqual((record.state, record.restore_trigger), (lifecycle.ACTIVE, ""))

    def test_ready_record_with_an_unexecutable_plan_moves_to_the_held_state(self):
        record = ready()
        self.assertEqual(record.state, lifecycle.READY)
        record.refuse_plan([model.Finding("PRE_STATE_NOT_BASELINE", detail="metric 1000")], at=T0)
        self.assertEqual((record.state, record.steps, record.plan), (lifecycle.BLOCKED, (), {}))
        self.assertEqual(record.history[-1]["note"], "no executable plan: PRE_STATE_NOT_BASELINE: metric 1000")
        self.assertEqual([f.code for f in record.report.blockers][-1], "PRE_STATE_NOT_BASELINE")

    def test_refuse_plan_and_interrupt_from_the_wrong_state_are_refused_unchanged(self):
        for label, call in (("refuse_plan", lambda r: r.refuse_plan([], at=T0)), ("interrupt", lambda r: r.interrupt(at=T0, detail="x"))):
            record = mm.LifecycleTests().active()
            with self.subTest(case=f"refused {label}"), self.assertRaises(model.MaintenanceError) as caught:
                call(record)
            self.assertEqual((caught.exception.code, record.state), ("STATE_NOT_ALLOWED", lifecycle.ACTIVE))

    def test_interrupt_of_an_entry_owes_a_restore(self):
        record = mm.LifecycleTests().approved()
        record.begin_enter(mm.GOOD, at=T0, actor="operator")
        record.interrupt(at=T0 + HOUR, detail="worker stopped")
        self.assertEqual((record.state, record.restore_trigger, [f.text() for f in record.findings]),
                         (lifecycle.RESTORING, lifecycle.ENTRY_ABORT, ["ENTRY_INTERRUPTED: worker stopped"]))

    def test_unresolved_counts_own_and_related_escalations_only(self):
        own, related, unrelated, untrusted = (ready(name) for name in ("R1", "R2", "S2", "S1"))
        own.state, related.state, unrelated.state, untrusted.state = lifecycle.ACTIVE, lifecycle.RESTORE_FAILED, lifecycle.RESTORE_FAILED, lifecycle.RESTORED
        self.assertEqual(lifecycle.unresolved([own, related, unrelated, untrusted], device="R1"), ("R1", "R2"))
        unrelated.baseline_untrusted = True
        self.assertEqual(lifecycle.unresolved([unrelated], device="R1", intersects=()), ("S2",))


class StoredRecordTests(TestCase):
    def test_snapshot_serialises_report_steps_history_and_plan(self):
        record = mm.LifecycleTests().active(device="R1", v6_north=ACTIVE, v6_south=ACTIVE)
        found = store.snapshot(record)
        self.assertEqual([s["direction"] for s in found["steps"]], [NORTHBOUND, SOUTHBOUND])
        self.assertEqual(found["history"][0]["at"], T0.isoformat())
        self.assertEqual(found["maintenance_only_state"], ["isis metric 9999"])
        self.assertEqual(set(found["report"]["cells"]), {"IPV4/NORTHBOUND", "IPV4/SOUTHBOUND", "IPV6/NORTHBOUND", "IPV6/SOUTHBOUND"})
        json.dumps(found)                                             # storable as JSON

    def test_snapshot_of_an_unevaluated_record_has_no_report(self):
        found = store.snapshot(lifecycle.request("S1", "operator", "r", HOUR, at=T0))
        self.assertEqual((found["report"], found["steps"], found["findings"], found["plan"]), (None, [], [], {}))

    def test_under_maintenance_prior_unresolved_and_due_restores(self):
        store.save(ready("S1"))
        active_row = store.save(mm.LifecycleTests().active(device="S2"))
        self.assertEqual([r.request.device for r in store.under_maintenance()], ["S2"])
        self.assertEqual(store.prior_unresolved("S2"), ("S2",))
        self.assertEqual(store.start_due_restores(T0 + HOUR), [])                       # not due yet
        moved = store.start_due_restores(T0 + CYCLE)
        self.assertEqual([row.pk for row in moved], [active_row.pk])
        self.assertEqual(models.MaintenanceRecord.objects.get(pk=active_row.pk).state, lifecycle.RESTORING)


class EvidenceChainTests(TestCase):
    def row(self):
        return store.save(ready("S1"))

    def test_append_chains_entries_and_audits_a_refusal(self):
        row = self.row()
        first = evidence.append(row, kind=evidence.REQUESTED, actor="operator", at=T0, payload={"at": T0})
        second = evidence.append(row, kind=evidence.REFUSED, actor="nmas", at=T0, payload={"findings": [{"code": "PLAN_STALE"}]}, summary="refused")
        self.assertEqual((first.sequence, second.sequence, first.previous_digest, second.previous_digest), (1, 2, "", first.entry_digest))
        self.assertEqual(first.payload, {"at": T0.isoformat()})
        audit = models.AuditEvent.objects.filter(object_id=row.record_id, event_type="MAINTENANCE_REFUSED").get()
        self.assertEqual((audit.metadata["codes"], audit.metadata["sequence"]), (["PLAN_STALE"], 2))

    def test_append_of_a_journal_step_writes_no_audit_event(self):
        row = self.row()
        before = models.AuditEvent.objects.count()
        entry = evidence.append(row, kind=evidence.STEP, actor="nmas", at=T0, payload={"event": "before", "operation": "op1"})
        self.assertEqual((entry.kind, models.AuditEvent.objects.count()), (evidence.STEP, before))

    def test_journal_reports_the_last_event_and_the_open_operation(self):
        row = self.row()
        self.assertEqual(evidence.journal(row), {"last": "", "open": "", "probe_runs": []})
        for payload in ({"event": "probes", "probe_run": "PR-1"}, {"event": "before", "operation": "op1"}, {"event": "after", "operation": "op1"},
                        {"event": "before", "operation": "op2"}):
            evidence.append(row, kind=evidence.STEP, actor="nmas", at=T0, payload=payload)
        self.assertEqual(evidence.journal(row), {"last": "before op2", "open": "op2", "probe_runs": ["PR-1"]})


HOST = topology.Host("H1", "clab-h1", "eth1", (4, 6), "S1")


class HostCommands:
    """Answers the fixed read-only host commands from canned text; records each argv."""

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, container, argv):
        self.calls.append((container, tuple(argv)))
        for key, text in self.answers.items():
            if key in " ".join(argv):
                return text
        return ""


ADDR = json.dumps([{"addr_info": [{"local": "2001:db8:10::101", "scope": "global"}, {"local": "fe80::1", "scope": "link"},
                                  {"local": "2001:db8:10::99", "scope": "global", "deprecated": True}, {"local": "192.168.10.101", "scope": "global"},
                                  {"local": "2001:db8:10::77", "scope": "global", "tentative": True}]}])
SNMP6 = "Ip6InReceives 100\nIp6InMcastPkts 30\nIp6OutRequests 50\nIp6OutMcastPkts 5\n"
SNMP = "Ip: Forwarding InDelivers OutRequests\nIp: 2 40 20\n"
NETSTAT = "IpExt: InMcastPkts InBcastPkts OutMcastPkts OutBcastPkts\nIpExt: 4 1 2 0\n"


class HostReaderTests(SimpleTestCase):
    def test_addresses_are_the_usable_global_ones_per_family(self):
        run = HostCommands({"addr show": ADDR})
        self.assertEqual(collector.HostReader(run).addresses(HOST), {4: ["192.168.10.101"], 6: ["2001:db8:10::101"]})
        self.assertEqual(run.calls, [("clab-h1", ("ip", "-j", "addr", "show", "dev", "eth1"))])

    def test_addresses_and_gateways_none_for_a_host_without_output_and_malformed_output_raises(self):
        silent = collector.HostReader(HostCommands({}))
        self.assertEqual((silent.addresses(HOST), silent.gateways(HOST)), ({4: [], 6: []}, {4: [], 6: []}))
        with self.assertRaises(json.JSONDecodeError):
            collector.HostReader(HostCommands({"addr show": "not json"})).addresses(HOST)

    def test_gateways_are_the_default_routes_per_family(self):
        run = HostCommands({"-4 route": json.dumps([{"gateway": "192.168.10.1"}]), "-6 route": json.dumps([{"gateway": "2001:db8:10::1"}, {"dst": "x"}])})
        self.assertEqual(collector.HostReader(run).gateways(HOST), {4: ["192.168.10.1"], 6: ["2001:db8:10::1"]})

    def test_counters_are_unicast_packets_per_family_and_direction(self):
        run = HostCommands({"dev_snmp6": SNMP6, "/proc/net/snmp": SNMP, "netstat": NETSTAT})
        self.assertEqual(collector.HostReader(run).counters(HOST), {(6, SOUTHBOUND): 70, (6, NORTHBOUND): 45, (4, SOUTHBOUND): 35, (4, NORTHBOUND): 18})


def device(name, *, observed=T0, data=("x",), reachable=True):
    found = DeviceEvidence(device=name, platform="ceos", live_attempted=True, live_error="" if reachable else "TIMEOUT")
    found.groups = {g: FactGroup(data=list(data) if data is not None else None, source="LIVE", observed_at=observed) for g in ("addresses", "routes", "ospf", "isis", "config_paths")}
    return found


THRESHOLDS = {"healthy": 60, "stale": 300}


class CollectorEvidenceTests(SimpleTestCase):
    def test_digest_is_the_hash_of_the_sanitized_statements(self):
        self.assertRegex(collector.digest(device("R1")), r"^[0-9a-f]{64}$")
        self.assertNotEqual(collector.digest(device("R1")), collector.digest(device("R1", data=("y",))))

    def test_digest_none_for_unread_or_unavailable_configuration(self):
        self.assertIsNone(collector.digest(None))
        self.assertIsNone(collector.digest(device("R1", data=None)))

    def test_provenance_records_source_time_and_availability_per_group(self):
        found = collector.provenance({"R1": device("R1")})["R1"]
        self.assertEqual((found["platform"], found["reachable"], found["live_error"]), ("ceos", True, ""))
        self.assertEqual(found["groups"]["routes"], {"source": "LIVE", "observed_at": T0.isoformat(), "available": True, "complete": True, "error": ""})
        self.assertIsNone(found["groups"]["bgp"])                     # not collected

    def test_provenance_of_an_unreachable_device_marks_groups_unavailable(self):
        found = collector.provenance({"R1": device("R1", data=None, reachable=False)})["R1"]
        self.assertEqual((found["reachable"], found["live_error"], found["groups"]["routes"]["available"]), (False, "TIMEOUT", False))

    def test_freshness_is_the_oldest_routing_group(self):
        summary = {"provenance": collector.provenance({"R1": device("R1"), "R2": device("R2", observed=T0 - timedelta(seconds=200)),
                                                       "R5": device("R5", observed=T0 - timedelta(seconds=900))})}
        self.assertEqual(collector.freshness(summary, now=T0, thresholds=THRESHOLDS), {"R1": "FRESH", "R2": "STALE", "R5": "EXPIRED"})

    def test_freshness_of_unread_or_unreachable_evidence_is_unknown(self):
        summary = {"provenance": collector.provenance({"R3": device("R3", data=None), "R4": device("R4", reachable=False)})}
        self.assertEqual(collector.freshness(summary, now=T0, thresholds=THRESHOLDS), {"R3": "UNKNOWN", "R4": "UNKNOWN"})
        self.assertEqual(collector.freshness({}, now=T0, thresholds=THRESHOLDS), {})

    def test_primary_dhcp_active_only_when_every_family_is_active(self):
        self.assertTrue(collector.primary_dhcp_active({"ipv4": "active", "ipv6": " active "}))

    def test_primary_dhcp_active_none_when_unknown_and_false_when_inactive(self):
        for label, status, expected in (("missing", None, None), ("missing family", {"ipv4": "active"}, None), ("empty family", {"ipv4": "active", "ipv6": ""}, None),
                                        ("failed family", {"ipv4": "active", "ipv6": "failed"}, False)):
            with self.subTest(case=f"failure {label}"):
                self.assertIs(collector.primary_dhcp_active(status), expected)

    def test_read_all_reads_every_device_except_management(self):
        from core.tests.test_maintenance_live import topo

        seen = []
        found = collector.read_all(collector.Sources(topology=topo(), read=lambda d: seen.append(d["name"]) or d["name"]))
        self.assertEqual(sorted(found), ["R1", "R2", "R3", "R4", "R5", "S1", "S2"])
        self.assertNotIn("mgmt_swt", seen)

    def test_read_all_propagates_a_reader_failure(self):
        from core.tests.test_maintenance_live import topo

        def broken(_device):
            raise OSError("unreachable")

        with self.assertRaises(OSError):
            collector.read_all(collector.Sources(topology=topo(), read=broken))
