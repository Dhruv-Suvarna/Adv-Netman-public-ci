"""Lab 7 closure -- the console's pure helpers and its state store, each function called directly (no Tk, no thread, no I/O).

POSITIVE: the exact formatted text, filtered rows, record, redacted copy, stored state and version.  NEGATIVE: missing values format
as "-", unknown filters drop everything, secrets never survive scrubbing, a failed refresh keeps the last good data marked stale,
unknown keys / collectors are empty or raise, and a broken subscriber never breaks a publisher.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from challenge_console import filters as f
from challenge_console import models as m
from challenge_console import redact
from challenge_console.state import EventBus, StateStore

T0 = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)


def sample(ok=True, *, ts=T0, key_source="H1", family=m.V4):
    return m.ProbeSample(ts, f"{key_source}/{family}", key_source, family, "H2", "192.168.10.102", "192.168.20.101", ok, 3.0 if ok else None,
                         "" if ok else "TIMEOUT")


def row(name="Ethernet1", *, device="R1", oper=m.UP, admin=m.UP, rx_bps=None, errors=None, last_change=None, present=True, description=""):
    counters = m.InterfaceCounters(device, name, admin, oper, description=description, rx_errors=errors)
    return m.InterfaceRow(counters, T0, rx_bps=rx_bps, last_change=last_change, present=present)


class FormatTests(unittest.TestCase):
    def test_fmt_time_and_iso_render_the_moment(self):
        self.assertEqual((f.fmt_time(T0), f.fmt_time(T0, date=True), f.fmt_iso("2026-10-19T12:00:00.123Z")),
                         ("12:00:00Z", "2026-10-19 12:00:00Z", "2026-10-19 12:00:00Z"))

    def test_fmt_time_and_iso_of_a_missing_value_is_a_dash_never_a_made_up_time(self):
        self.assertEqual((f.fmt_time(None), f.fmt_iso("")), ("-", "-"))

    def test_fmt_duration_and_age_render_seconds_and_days(self):
        self.assertEqual((f.fmt_duration(3725), f.fmt_duration(90061)), ("01:02:05", "1d 01:01:01"))
        self.assertEqual((f.fmt_age(T0 - timedelta(seconds=30), T0), f.fmt_age(T0 - timedelta(seconds=3600), T0)), ("30 s", "01:00:00"))

    def test_fmt_duration_and_age_of_none_or_negative_are_dash_or_zero(self):
        self.assertEqual((f.fmt_duration(None), f.fmt_duration(-5), f.fmt_age(None)), ("-", "00:00:00", "-"))

    def test_fmt_count_and_speed_render_numbers(self):
        self.assertEqual((f.fmt_count(1234567), f.fmt_speed(1_000_000_000), f.fmt_speed(2_500_000)), ("1,234,567", "1 Gbit/s", "2.50 Mbit/s"))

    def test_fmt_count_and_speed_of_unknown_values_are_a_dash_never_zero(self):
        self.assertEqual((f.fmt_count(None), f.fmt_speed(None), f.fmt_speed(0)), ("-", "-", "-"))

    def test_sparkline_and_loss_percent_return_the_probe_history(self):
        history = [sample(True), sample(False), sample(True), sample(True)]
        self.assertEqual((f.sparkline(history), f.sparkline(history, width=2)), (".X..", ".."))
        self.assertEqual(f.loss_percent(history), 25.0)
        self.assertIsNone(f.loss_percent([]))


class InterfaceFilterTests(unittest.TestCase):
    def test_activity_predicates_return_true_for_drops_and_traffic(self):
        self.assertTrue(f.has_errors(row(errors=3)))
        self.assertTrue(f.carrying_traffic(row(rx_bps=800.0)))
        self.assertFalse(f.carrying_traffic(row()))

    def test_filter_interfaces_by_state_text_device_and_recency(self):
        rows = [row("Ethernet10"), row("Ethernet2", oper=m.DOWN), row("Ethernet3", admin=m.DOWN, oper=m.DOWN), row("Ethernet4", errors=1),
                row("Ethernet5", rx_bps=1.0), row("Ethernet6", last_change=T0 - timedelta(minutes=1)), row("Ethernet1", device="R2", description="uplink")]
        names = lambda found: [(r.sample.device, r.sample.name) for r in found]  # noqa: E731
        self.assertEqual(names(f.filter_interfaces(rows, device="R1", state="Up"))[:2], [("R1", "Ethernet4"), ("R1", "Ethernet5")])
        self.assertEqual(names(f.filter_interfaces(rows, state="Down")), [("R1", "Ethernet2"), ("R1", "Ethernet3")])
        self.assertEqual(names(f.filter_interfaces(rows, state="Admin down")), [("R1", "Ethernet3")])
        self.assertEqual(names(f.filter_interfaces(rows, state="Errors / drops")), [("R1", "Ethernet4")])
        self.assertEqual(names(f.filter_interfaces(rows, state="Carrying traffic")), [("R1", "Ethernet5")])
        self.assertEqual(names(f.filter_interfaces(rows, state="Changed recently", now=T0)), [("R1", "Ethernet6")])
        self.assertEqual(names(f.filter_interfaces(rows, text="UPLINK")), [("R2", "Ethernet1")])
        self.assertEqual(names(f.filter_interfaces(rows, device="R1"))[-1], ("R1", "Ethernet10"))  # natural order: 10 after 6

    def test_filter_interfaces_with_an_unknown_device_or_text_is_empty(self):
        self.assertEqual(f.filter_interfaces([row()], device="R9"), [])
        self.assertEqual(f.filter_interfaces([row()], text="no-such-port"), [])

    def test_filter_devices_with_no_match_or_the_wrong_scope_is_empty(self):
        devices = [{"name": "R1", "role": "Router", "managed": True, "interfaces": [{"name": "Ethernet1", "addresses": [{"address": "10.0.0.1/31"}]}]},
                   {"name": "H1", "role": "Host", "managed": False, "interfaces": []}]
        self.assertEqual(f.filter_devices(devices, text="10.0.0.1"), [devices[0]])
        self.assertEqual(f.filter_devices(devices, scope="Unmanaged"), [devices[1]])
        self.assertEqual(f.filter_devices(devices, role="Switch"), [])
        self.assertEqual(f.filter_devices(devices, text="nothing-matches"), [])
        self.assertEqual(f.filter_devices([{"name": "X", "managed": None}], scope="Managed"), [])


class ModelRecordTests(unittest.TestCase):
    def test_parse_time_returns_aware_utc(self):
        self.assertEqual(m.parse_time("2026-10-19T12:00:00Z"), T0)
        self.assertEqual(m.parse_time("2026-10-19 12:00:00"), T0)
        self.assertEqual(m.parse_time(datetime(2026, 10, 19, 12, 0)), T0)

    def test_parse_time_of_empty_or_malformed_text_is_none(self):
        for value in ("", None, "yesterday", "2026-13-40"):
            with self.subTest("malformed is none", value=value):
                self.assertIsNone(m.parse_time(value))

    def test_records_to_dict_return_iso_timestamps(self):
        self.assertEqual(sample().to_dict()["ts"], "2026-10-19T12:00:00.000Z")
        self.assertEqual(m.FreshnessRow("R1", True, T0, 4.0, "FRESH").to_dict()["last_sample"], "2026-10-19T12:00:00.000Z")
        observation = m.ServiceObservation(T0, "nmas-web", "NMAS Web", m.DOWN, (m.Check("http", False, "CONNECTION_REFUSED"),), 2.5)
        self.assertEqual(observation.to_dict(), {"component": "nmas-web", "state": m.DOWN, "latency_ms": 2.5,
                                                 "checks": [{"name": "http", "ok": False, "detail": "CONNECTION_REFUSED"}]})


class RedactTests(unittest.TestCase):
    def test_scrub_text_returns_plain_text_unchanged(self):
        self.assertEqual(redact.scrub_text("R1 Ethernet1 up"), "R1 Ethernet1 up")

    def test_scrub_text_never_keeps_credential_shaped_values(self):
        for raw, secret in (("Authorization: Bearer abcdefgh12345", "abcdefgh12345"), ("https://admin:hunter2@netbox/api", "hunter2"),
                            ("password=hunter2", "hunter2"), ("secret sha512 $6$abcdefghijklmnopqrstuvwxyz0123", "$6$abcdefghij"),
                            ("nbt_abc123.def456", "nbt_abc123")):
            with self.subTest("never kept", secret=secret[:6]):
                self.assertNotIn(secret, redact.scrub_text(raw))
        self.assertTrue(redact.scrub_text("x" * 3000).endswith("...[truncated]"))

    def test_scrub_never_keeps_a_secret_named_value(self):
        out = redact.scrub({"password": "hunter2", "credential_id": "cred-1", "nested": [{"api_key": "k1"}], "flag": True, "obj": T0, "token": ""})
        self.assertEqual(out, {"password": redact.REDACTED, "credential_id": "cred-1", "nested": [{"api_key": redact.REDACTED}], "flag": True,
                               "obj": str(T0), "token": ""})

    def test_classify_exception_maps_unknown_errors_to_fixed_codes_never_the_text(self):
        cases = ((TimeoutError("host 10.0.0.1"), "TIMEOUT"), (ConnectionRefusedError("pw=x"), "IO_ERROR"), (KeyError("k"), "PARSE_ERROR"),
                 (RuntimeError("secret"), "INTERNAL_ERROR"))
        self.assertEqual([redact.classify_exception(exc) for exc, _ in cases], [code for _, code in cases])


class EventBusTests(unittest.TestCase):
    def test_publish_records_logs_and_notifies(self):
        store, log, seen = StateStore(), [], []
        bus = EventBus(store, log=type("L", (), {"append": lambda self, e: log.append(e)})())
        bus.subscribe(seen.append)
        event = bus.emit(m.CONNECTIVITY, "connectivity.sample", "H1/IPV4", m.OK, {"rtt": 3}, ts=T0)
        direct = m.Event(T0, m.SERVICES, "services.state")
        bus.publish(direct)
        self.assertEqual((seen, log, store.recent_events()), ([event, direct], [event, direct], [direct, event]))

    def test_a_broken_subscriber_never_blocks_publishing_and_a_bus_without_a_log_still_records(self):
        store = StateStore()
        bus = EventBus(store)
        bus.subscribe(lambda event: (_ for _ in ()).throw(RuntimeError("subscriber bug")))
        bus.publish(m.Event(T0, m.SERVICES, "services.state"))
        self.assertEqual(bus.emit(m.SERVICES, "services.state").outcome, m.INFO)
        self.assertEqual(len(store.recent_events(collector=m.SERVICES)), 2)


class StateStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = StateStore(history_maxlen=10, retention_seconds=60, recent_events=5)

    def test_new_store_has_no_version_events_or_history(self):
        self.assertEqual((self.store.version(m.CONNECTIVITY), self.store.recent_events(), self.store.history_span_seconds("H1/IPV4")), (0, [], 0.0))
        self.assertEqual(self.store.recent_samples(), [])

    def test_version_counts_each_mutation(self):
        self.store.set_probe_specs([m.ProbeSpec("H1", m.V4, "H2")])
        self.store.set_probe_specs([m.ProbeSpec("H1", m.V4, "H3")])
        self.assertEqual(self.store.version(m.CONNECTIVITY), 2)
        self.assertEqual(self.store.probe_rows()[0].spec.destination, "H3")  # re-plan keeps the row, updates the spec

    def test_record_event_counts_per_collector_and_recent_events_filters(self):
        self.store.register_collector(m.NSOT, 30)
        for kind in ("nsot.read", "nsot.fail", "nsot.read"):
            self.store.record_event(m.Event(T0, m.NSOT, kind))
        self.store.record_event(m.Event(T0, m.SERVICES, "x"))
        self.assertEqual(self.store.collector_status()[m.NSOT].events, 3)
        self.assertEqual([e.kind for e in self.store.recent_events(collector=m.NSOT, kinds=("nsot.read",))], ["nsot.read", "nsot.read"])

    def test_recent_events_for_an_unknown_collector_is_empty_and_the_ring_is_bounded(self):
        for index in range(8):
            self.store.record_event(m.Event(T0, m.NSOT, f"k{index}"))
        self.assertEqual(self.store.recent_events(collector="no-such-collector"), [])
        self.assertEqual(len(self.store.recent_events()), 5)

    def test_register_and_update_collector_return_the_status(self):
        status = self.store.register_collector(m.COUNTERS, 5.0)
        self.assertIs(self.store.register_collector(m.COUNTERS, 99.0), status)  # idempotent
        self.store.update_collector(m.COUNTERS, state="RUNNING", cycles=2)
        self.assertEqual((self.store.collector_status()[m.COUNTERS].state, self.store.version("collectors")), ("RUNNING", 1))

    def test_register_collector_twice_never_replaces_the_status(self):
        first = self.store.register_collector(m.NSOT, 30.0)
        second = self.store.register_collector(m.NSOT, 1.0)
        self.assertIs(second, first)
        self.assertEqual(self.store.collector_status()[m.NSOT].interval, 30.0)

    def test_update_of_an_unregistered_collector_raises(self):
        with self.assertRaises(KeyError):
            self.store.update_collector("never-registered", state="RUNNING")
        self.assertEqual(self.store.collector_status(), {})

    def test_add_probe_sample_reports_failure_and_recovery_transitions(self):
        self.store.set_probe_specs([m.ProbeSpec("H1", m.V4, "H2")])
        transitions = [self.store.add_probe_sample(sample(ok, ts=T0 + timedelta(seconds=i))) for i, ok in enumerate((True, False, False, True))]
        self.assertEqual(transitions, [None, "FAILED", None, "RECOVERED"])
        probe = self.store.probe_rows()[0]
        self.assertEqual((probe.state, probe.samples, probe.failures, probe.consecutive_failures), (m.UP, 4, 2, 0))

    def test_add_probe_sample_for_an_unplanned_row_creates_it_and_old_samples_expire(self):
        self.assertIsNone(self.store.add_probe_sample(sample(False, ts=T0, key_source="H3")))
        self.store.add_probe_sample(sample(False, ts=T0 + timedelta(seconds=120), key_source="H3"))
        self.assertEqual(len(self.store.probe_history("H3/IPV4")), 1)  # the first is beyond the 60 s retention
        self.assertEqual(self.store.history_span_seconds("H3/IPV4"), 0.0)

    def test_recent_samples_returns_newest_first_and_failures_only(self):
        for i, ok in enumerate((True, False, True)):
            self.store.add_probe_sample(sample(ok, ts=T0 + timedelta(seconds=i)))
        self.assertEqual([s.ts.second for s in self.store.recent_samples()], [2, 1, 0])
        self.assertEqual([s.success for s in self.store.recent_samples(key="H1/IPV4", limit=2)], [True, False])

    def test_recent_samples_failures_only_without_failures_is_empty(self):
        self.store.add_probe_sample(sample(True))
        self.assertEqual(self.store.recent_samples(failures_only=True), [])

    def test_set_service_returns_the_previous_state_on_a_transition(self):
        up = m.ServiceObservation(T0, "nmas-web", "Web", m.UP)
        self.assertIsNone(self.store.set_service(up))
        self.assertEqual(self.store.set_service(m.ServiceObservation(T0 + timedelta(seconds=5), "nmas-web", "Web", m.DOWN)), m.UP)
        self.assertEqual(self.store.services()[0]["last_up"], T0)

    def test_set_service_without_a_state_change_reports_none(self):
        self.store.set_service(m.ServiceObservation(T0, "nmas-web", "Web", m.DOWN))
        self.assertIsNone(self.store.set_service(m.ServiceObservation(T0 + timedelta(seconds=5), "nmas-web", "Web", m.DOWN)))
        self.assertEqual(self.store.services()[0]["since"], T0)

    def test_set_telemetry_keeps_the_rows_and_last_ok(self):
        rows = [m.FreshnessRow("R1", True, T0, 1.0, "FRESH")]
        self.store.set_telemetry(ts=T0, available=True, rows=rows, thresholds={"healthy": 60.0}, backend="influx")
        self.assertEqual((self.store.telemetry()["rows"], self.store.telemetry()["last_ok"]), (rows, T0))

    def test_set_telemetry_unavailable_keeps_the_previous_last_good_time_and_no_rows(self):
        self.store.set_telemetry(ts=T0, available=True)
        self.store.set_telemetry(ts=T0 + timedelta(seconds=30), available=False, reason="BACKEND_UNREACHABLE")
        telemetry = self.store.telemetry()
        self.assertEqual((telemetry["available"], telemetry["last_ok"], telemetry["rows"], telemetry["reason"]), (False, T0, [], "BACKEND_UNREACHABLE"))

    def test_set_document_stores_current_data(self):
        self.store.set_document(m.NSOT, ts=T0, data={"devices": [1]})
        self.assertEqual({k: self.store.document(m.NSOT)[k] for k in ("available", "stale", "data")}, {"available": True, "stale": False, "data": {"devices": [1]}})

    def test_set_document_for_an_unknown_topic_is_stored_and_a_fail_of_one_never_read_raises(self):
        self.store.set_document("other", ts=T0, data={})
        self.assertTrue(self.store.document("other")["available"])
        with self.assertRaises(KeyError):
            self.store.fail_document("never-declared", ts=T0, reason="X")

    def test_a_refresh_problem_keeps_the_last_good_document_flagged(self):
        self.store.set_document(m.AUTOMATION, ts=T0, data={"soaks": [1]})
        self.store.fail_document(m.AUTOMATION, ts=T0 + timedelta(seconds=30), reason="DB_UNAVAILABLE")
        document = self.store.document(m.AUTOMATION)
        self.assertEqual((document["available"], document["stale"], document["data"], document["last_ok"]), (False, True, {"soaks": [1]}, T0))

    def test_fail_document_without_previous_data_is_not_stale(self):
        self.store.fail_document(m.NSOT, ts=T0, reason="NETBOX_UNREACHABLE")
        self.assertEqual((self.store.document(m.NSOT)["stale"], self.store.document(m.NSOT)["reason"]), (False, "NETBOX_UNREACHABLE"))

    def test_counters_apply_then_an_unread_device_keeps_rows_and_clears_rates(self):
        first = [m.InterfaceCounters("R1", "Ethernet1", m.UP, m.UP, rx_bytes=0, tx_bytes=0)]
        later = [m.InterfaceCounters("R1", "Ethernet1", m.UP, m.UP, rx_bytes=1000, tx_bytes=0)]
        self.store.apply_counters("R1", T0, first)
        self.store.apply_counters("R1", T0 + timedelta(seconds=10), later)
        self.assertEqual(self.store.interface_rows()[0].rx_bps, 800.0)
        self.store.fail_counters("R1", T0 + timedelta(seconds=20), "TIMEOUT")
        self.assertIsNone(self.store.interface_rows()[0].rx_bps)
        self.assertEqual({k: self.store.counter_devices()["R1"][k] for k in ("ok", "reason", "interfaces")}, {"ok": False, "reason": "TIMEOUT", "interfaces": 1})

    def test_counter_devices_returns_each_read_device(self):
        self.store.apply_counters("R1", T0, [m.InterfaceCounters("R1", "Ethernet1")])
        self.assertEqual(self.store.counter_devices()["R1"]["ok"], True)

    def test_fail_counters_for_a_never_read_device_records_only_the_failure(self):
        self.store.fail_counters("R9", T0, "UNREACHABLE")
        self.assertEqual((self.store.counter_devices(), self.store.interface_rows()), ({"R9": {"ts": T0, "ok": False, "reason": "UNREACHABLE"}}, []))

    def test_summary_returns_every_section(self):
        self.store.register_collector(m.CONNECTIVITY, 2.0)
        self.store.add_probe_sample(sample(False))
        self.store.set_service(m.ServiceObservation(T0, "nmas-web", "Web", m.UP))
        summary = self.store.summary()
        self.assertEqual(sorted(summary), ["automation", "collectors", "connectivity", "counters", "nsot", "services", "telemetry"])
        self.assertEqual((summary["connectivity"][0]["failures"], summary["services"], summary["nsot"]["available"]), (1, {"nmas-web": m.UP}, False))


if __name__ == "__main__":
    unittest.main()
