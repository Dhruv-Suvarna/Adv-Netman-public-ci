"""V2 Phase 8 -- the dynamic collector consumes the exported monitoring targets and follows the management path.

NMAS database + an in-memory session (the health engine's session interface); the EOS JSON below is the shape cEOS 4.36.2F
returned live (labs/decommission-isolated STUB, ``show version | json`` / ``show interfaces counters | json``).  The live
proof over the path-bound SSH transport is the Phase 8 live harness, not these tests.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import mock

from django.test import TestCase

from core import models
from core.services.health import live
from core.services.infrastructure import collector, dispatcher, grafana, monitoring
from core.services.management import paths
from core.tests import test_infrastructure_fixtures as F

T = models.MonitoringTargetState
VERSION = json.dumps({"modelName": "cEOSLab", "version": "4.36.2F", "uptime": 1419.88, "memTotal": 98824700, "memFree": 55567576})
COUNTERS = json.dumps({"interfaces": {
    "Ethernet1": {"inOctets": 53566, "inUcastPkts": 11, "inDiscards": 0, "outOctets": 0, "outUcastPkts": 0, "outDiscards": 0},
    "Management0": {"inOctets": 9, "outOctets": 7, "lastUpdateTimestamp": 1.5}}})
INTERFACES = json.dumps({"interfaces": {"Ethernet1": {"interfaceStatus": "connected", "lineProtocolStatus": "up"},
                                        "Ethernet2": {"interfaceStatus": "disabled", "lineProtocolStatus": "down"}}})


class Session:
    opened: list = []

    def __init__(self, device, outputs=None, fail=None):
        self.device, self.outputs, self.fail, self.ran, self.closed = device, outputs, fail, [], False
        Session.opened.append(self)

    def run(self, key):
        self.ran.append(key)
        if self.fail == key:
            raise live.LiveError("TIMEOUT")
        return (self.outputs or {"version": VERSION, "interface_counters": COUNTERS, "interfaces": INTERFACES})[key]

    def close(self):
        self.closed = True


def factory(**kwargs):
    return lambda device: Session(device, **kwargs)


class Base(TestCase):
    def setUp(self):
        Session.opened = []
        self.env = F.lab()
        self.r1 = self.env["devices"]["R1"]
        self.oob = F.activate(self.r1, F.oob_path(self.env))
        dispatcher.dispatch("monitoring", limit=200)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.file = Path(self.tmp.name) / "targets.json"

    def export(self):
        return monitoring.write_runtime_targets(self.file)

    def entries(self):
        return collector.load_targets(self.export())


class CollectorTests(Base):
    def test_collect_one_reads_the_exported_target_over_its_path_and_emits_points(self):
        entry, = self.entries()
        outcome = collector.collect_one(entry, session_factory=factory())
        self.assertEqual((outcome.status, outcome.code, outcome.management_path, outcome.generation), ("COLLECTED", "", self.oob.path_id, 1))
        session, = Session.opened
        self.assertEqual((session.device, session.ran, session.closed),
                         ({"name": "R1", "platform": "ceos"}, ["version", "interface_counters", "interfaces"], True))
        device, *interfaces = outcome.points
        self.assertTrue(device.startswith("nmas_dynamic_device,collector=nmas-path-eos,device=R1,"))
        self.assertIn(f"management_path={self.oob.path_id}", device)
        self.assertIn("generation=1i,mem_free_kb=55567576i,mem_total_kb=98824700i,reachable=1i,uptime_seconds=1419i", device)
        self.assertEqual([p.split(",interface=")[1].split(",")[0].split(" ")[0] for p in interfaces], ["Ethernet1", "Ethernet2", "Management0"])
        self.assertIn("in_octets=53566i", interfaces[0])
        self.assertIn("oper_up=1i", interfaces[0])
        self.assertIn("admin_up=0i", interfaces[1])
        self.assertNotIn("in_octets", interfaces[1])                                   # never a default counter
        self.assertIn(",error=none,", device)

    def test_collected_and_refused_device_points_carry_exactly_the_same_tag_keys(self):
        entry, = self.entries()
        collected = collector.collect_one(entry, session_factory=factory()).points[0]
        refused = collector.collect_one({**entry, "generation": 99}, session_factory=factory()).points[0]

        def keys(point):
            return [pair.split("=")[0] for pair in point.split(" ")[0].split(",")[1:]]
        self.assertEqual(keys(collected), keys(refused))       # one schema per series (Grafana's Flux decoder needs it)
        self.assertIn("error=none", collected)
        self.assertNotIn("error=none", refused)

    def test_collect_follows_failover_only_after_the_export_and_never_reuses_a_stale_entry(self):
        stale, = self.entries()
        vrf = F.activate(self.r1, F.vrf_path(self.r1, self.env), previous=self.oob, kind=F.K.FAILOVER)
        dispatcher.dispatch("monitoring", limit=200)
        refused = collector.collect_one(stale, session_factory=factory())
        self.assertEqual((refused.status, refused.code), ("REFUSED", "STALE_TARGET"))
        self.assertEqual(Session.opened, [])                                          # never connected over the old path
        self.assertIn("error=STALE_TARGET", refused.points[0])
        self.assertIn("reachable=0i", refused.points[0])
        fresh, = self.entries()
        outcome = collector.collect_one(fresh, session_factory=factory())
        self.assertEqual((outcome.status, outcome.management_path, outcome.generation), ("COLLECTED", vrf.path_id, 2))
        self.assertIn(f"management_path={vrf.path_id}", outcome.points[0])
        self.assertIn("path_type=ROUTED_VRF", outcome.points[0])

    def test_run_pushes_every_point_and_reports_counts(self):
        self.export()
        with mock.patch.object(grafana, "push", return_value={"status": 204, "points": 4}) as push:
            report = collector.run(targets_path=self.file, push={"url": "http://influx.invalid", "org": "o", "bucket": "b"},
                                   session_factory=factory())
        self.assertEqual((report["targets"], report["counts"], report["push"]), (1, {"COLLECTED": 1}, {"status": 204, "points": 4}))
        self.assertEqual(len(push.call_args.args[0]), 4)
        self.assertEqual(push.call_args.kwargs, {"url": "http://influx.invalid", "org": "o", "bucket": "b"})

    def test_parse_counters_returns_only_numeric_reported_counters(self):
        self.assertEqual(collector.parse_counters(COUNTERS),
                         {"Ethernet1": {"in_octets": 53566, "in_ucast_pkts": 11, "in_discards": 0, "out_octets": 0, "out_ucast_pkts": 0,
                                        "out_discards": 0},
                          "Management0": {"in_octets": 9, "out_octets": 7}})

    def test_parse_version_returns_integer_fields(self):
        self.assertEqual(collector.parse_version(VERSION), {"uptime_seconds": 1419, "mem_total_kb": 98824700, "mem_free_kb": 55567576})


class CollectorRefusalTests(Base):
    def test_collect_of_a_lost_path_is_refused_without_connecting(self):
        entry, = self.entries()
        F.lose_paths(self.r1, self.oob)
        outcome = collector.collect_one(entry, session_factory=factory())
        self.assertEqual((outcome.status, outcome.code, Session.opened), ("REFUSED", "MGMT_NO_USABLE_PATH", []))

    def test_collect_of_a_revoked_path_is_refused_without_connecting(self):
        entry, = self.entries()
        self.assertTrue(paths.revoke_path(self.oob, actor="operator:test", reason="key compromised", acknowledge_active=True).ok)
        outcome = collector.collect_one(entry, session_factory=factory())
        self.assertEqual((outcome.status, outcome.code, Session.opened), ("REFUSED", "MGMT_NO_USABLE_PATH", []))

    def test_collect_of_a_suspended_or_unknown_target_is_never_active(self):
        entry, = self.entries()
        models.MonitoringTarget.objects.filter(device=self.r1).update(state=T.SUSPENDED)
        self.assertEqual(collector.collect_one(entry, session_factory=factory()).code, "TARGET_NOT_ACTIVE")
        self.assertEqual(collector.collect_one({**entry, "device_id": "DEV-999999"}, session_factory=factory()).code, "TARGET_NOT_ACTIVE")
        self.assertEqual(Session.opened, [])

    def test_collect_of_an_unverified_platform_is_refused(self):
        entry, = self.entries()
        models.MonitoringTarget.objects.filter(device=self.r1).update(platform="vendor_x")
        self.assertEqual(collector.collect_one(entry, session_factory=factory()).code, "PLATFORM_UNSUPPORTED")
        self.assertEqual(Session.opened, [])

    def test_collect_failure_is_a_reachable_zero_point_and_the_session_is_closed(self):
        entry, = self.entries()
        outcome = collector.collect_one(entry, session_factory=factory(fail="interface_counters"))
        self.assertEqual((outcome.status, outcome.code, Session.opened[0].closed), ("FAILED", "TIMEOUT", True))
        self.assertIn("error=TIMEOUT", outcome.points[0])
        self.assertEqual(len(outcome.points), 1)

    def test_collect_of_unparseable_output_fails_with_parse_error(self):
        entry, = self.entries()
        outcome = collector.collect_one(entry, session_factory=factory(outputs={"version": "% Invalid input", "interface_counters": "{}",
                                                                                 "interfaces": "{}"}))
        self.assertEqual((outcome.status, outcome.code, Session.opened[0].closed), ("FAILED", "PARSE_ERROR", True))

    def test_collect_when_the_session_cannot_open_reports_the_code(self):
        entry, = self.entries()

        def refuse(_device):
            raise live.LiveError("MANAGEMENT_UNREACHABLE")

        outcome = collector.collect_one(entry, session_factory=refuse)
        self.assertEqual((outcome.status, outcome.code), ("FAILED", "MANAGEMENT_UNREACHABLE"))

    def test_load_targets_of_a_missing_or_invalid_file_raises_a_fixed_code(self):
        with self.assertRaisesMessage(collector.TargetFileError, "TARGET_FILE_UNREADABLE"):
            collector.load_targets(self.file)
        self.file.write_text(json.dumps({"targets": [{"address": "x"}]}))
        with self.assertRaisesMessage(collector.TargetFileError, "TARGET_FILE_INVALID"):
            collector.load_targets(self.file)

    def test_run_with_a_failing_push_reports_the_code_without_raising(self):
        self.export()
        with mock.patch.object(grafana, "push", side_effect=grafana.PushError("INFLUX_UNREACHABLE")):
            report = collector.run(targets_path=self.file, push={"url": "http://influx.invalid", "org": "o", "bucket": "b"},
                                   session_factory=factory())
        self.assertEqual(report["push"], {"error": "INFLUX_UNREACHABLE"})


class CollectorUnitTests(Base):
    """Direct cases for the collector's building blocks (the flows above exercise them indirectly)."""

    def test_check_returns_the_active_target_and_no_refusal_for_a_current_entry(self):
        entry, = self.entries()
        target, refusal = collector.check(entry)
        self.assertEqual((target.name, target.state, refusal), ("R1", T.ACTIVE, ""))
        self.assertEqual(Session.opened, [])                                      # pure database reads

    def test_check_refuses_a_stale_generation_and_an_unknown_device(self):
        entry, = self.entries()
        self.assertEqual(collector.check({**entry, "generation": entry["generation"] + 1})[1], "STALE_TARGET")
        self.assertEqual(collector.check({**entry, "address": "192.0.2.99"})[1], "STALE_TARGET")
        self.assertEqual(collector.check({**entry, "device_id": "DEV-999999"}), (None, "TARGET_NOT_ACTIVE"))
        self.assertEqual(Session.opened, [])

    def test_parse_version_refuses_output_missing_a_reading(self):
        with self.assertRaises(KeyError):
            collector.parse_version(json.dumps({"uptime": 5, "memTotal": 10}))   # memFree missing: never a default
        with self.assertRaises(ValueError):
            collector.parse_version("% Invalid input")

    def test_parse_counters_never_invents_a_counter_for_missing_or_non_numeric_values(self):
        text = json.dumps({"interfaces": {"Ethernet1": "n/a", "Ethernet2": {"inOctets": "12"}, "Ethernet3": {"outOctets": 4}}})
        self.assertEqual(collector.parse_counters(text), {"Ethernet3": {"out_octets": 4}})

    def test_collect_returns_one_outcome_per_entry_in_order(self):
        entry, = self.entries()
        stale = {**entry, "generation": entry["generation"] + 1}
        outcomes = collector.collect([entry, stale], session_factory=factory())
        self.assertEqual([(o.status, o.code) for o in outcomes], [("COLLECTED", ""), ("REFUSED", "STALE_TARGET")])
        self.assertEqual(len(Session.opened), 1)                                   # the refused entry never connected

    def test_collect_refuses_every_stale_entry_without_connecting(self):
        entry, = self.entries()
        outcomes = collector.collect([{**entry, "generation": 0}, {**entry, "device_id": "DEV-999999"}], session_factory=factory())
        self.assertEqual([o.code for o in outcomes], ["STALE_TARGET", "TARGET_NOT_ACTIVE"])
        self.assertEqual(Session.opened, [])

    def test_outcome_as_dict_returns_exact_counts_not_the_points(self):
        entry, = self.entries()
        outcome = collector.collect_one(entry, session_factory=factory())
        self.assertEqual(outcome.as_dict(), {"device": "R1", "status": "COLLECTED", "code": "", "generation": 1,
                                             "management_path": self.oob.path_id, "points": 4, "interfaces": 3})
