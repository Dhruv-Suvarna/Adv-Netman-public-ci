"""Collector lifecycle, isolation, the event bus, the append-only session log, save / discard, redaction and configuration."""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import timedelta

from challenge_console import models as m
from challenge_console import redact
from challenge_console.config import MIN_RETENTION_SECONDS, ConsoleConfig
from challenge_console.runtime import DISCARD, SAVE, ConsoleRuntime
from challenge_console.sessionlog import SessionLog, read_session, safe_filename
from challenge_console.state import StateStore
from challenge_console.supervisor import CollectorError, Supervisor

from .helpers import ConsoleTestCase, CountingCollector, wait_until

NAMES = ("connectivity", "services", "nsot", "automation", "counters")


class SupervisorTests(ConsoleTestCase):
    def make(self, **special):
        collectors = [CountingCollector(self.config, self.store, self.bus, name, **special.get(name, {})) for name in NAMES]
        supervisor = Supervisor(self.config, self.store, self.bus, collectors)
        self.addCleanup(supervisor.stop)
        return supervisor, {c.name: c for c in collectors}

    def test_all_five_collectors_start_and_run_concurrently(self):
        supervisor, collectors = self.make()
        supervisor.start()
        self.assertTrue(wait_until(lambda: all(c.count >= 5 for c in collectors.values())))
        self.assertEqual(supervisor.alive(), sorted(NAMES))
        self.assertEqual(len({t.ident for t in threading.enumerate() if t.name.startswith("console-") and t.name != "console-watchdog"}), 5)
        self.assertEqual({e.collector for e in self.kinds("collector.start")}, set(NAMES))
        self.assertTrue(all(s.state == "RUNNING" for s in self.store.collector_status().values()))

    def test_a_failing_collector_does_not_stop_the_others_or_crash(self):
        supervisor, collectors = self.make(nsot={"fail": lambda n: RuntimeError("password=hunter2 for https://admin:pw@netbox")})
        supervisor.start()
        self.assertTrue(wait_until(lambda: len(self.kinds("collector.error")) >= 2))
        before = {name: c.count for name, c in collectors.items() if name != "nsot"}
        self.assertTrue(wait_until(lambda: all(collectors[name].count > before[name] + 5 for name in before)))
        self.assertIn("nsot", supervisor.alive())                      # still alive, still retrying
        errors = self.kinds("collector.error")
        self.assertTrue(all(e.collector == "nsot" and e.outcome == m.ERROR for e in errors))
        self.assertEqual(errors[0].data["code"], "INTERNAL_ERROR")
        self.assertEqual(errors[0].data["exception"], "RuntimeError")
        self.assertNotIn("hunter2", json.dumps([e.to_record() for e in errors]))   # the exception TEXT is never an event
        self.assertEqual(self.store.collector_status()["nsot"].state, "FAILING")

    def test_every_failed_cycle_is_an_event_and_recovery_is_recorded(self):
        supervisor, collectors = self.make(automation={"fail": lambda n: CollectorError("DB_BUSY", "automation-db") if n <= 3 else None})
        supervisor.start()
        self.assertTrue(wait_until(lambda: self.kinds("collector.recovered")))
        errors = self.kinds("collector.error")
        self.assertEqual([e.data["consecutive"] for e in errors], [1, 2, 3])
        self.assertTrue(all(e.data["code"] == "DB_BUSY" and e.target == "automation-db" and e.ts.tzinfo for e in errors))
        self.assertEqual(self.kinds("collector.recovered")[0].data["after_errors"], 3)
        self.assertTrue(wait_until(lambda: self.store.collector_status()["automation"].state == "RUNNING"))

    def test_failures_back_off_instead_of_spinning(self):
        supervisor, collectors = self.make(nsot={"fail": lambda n: CollectorError("NETBOX_UNAVAILABLE")})
        supervisor.start()
        time.sleep(0.6)
        # interval 0.01 s would allow ~60 attempts; exponential backoff capped at max_backoff (0.2 s) allows only a handful
        self.assertLess(collectors["nsot"].count, 12)
        self.assertGreater(collectors["connectivity"].count, 20)

    def test_a_dead_worker_is_restarted_and_reported(self):
        supervisor, collectors = self.make(counters={"fail": lambda n: SystemExit() if n == 2 else None})
        supervisor.start()
        self.assertTrue(wait_until(lambda: self.kinds("collector.restart")))
        restart = self.kinds("collector.restart")[0]
        self.assertEqual((restart.collector, restart.target, restart.data["reason"]), ("supervisor", "counters", "WORKER_DIED"))
        self.assertTrue(wait_until(lambda: collectors["counters"].count >= 6))
        self.assertEqual(self.store.collector_status()["counters"].restarts, 1)

    def test_a_silent_collector_is_reported_as_stalled_then_resumed(self):
        gate = threading.Event()
        config = self.config.with_overrides(command_timeout=0.02)
        blocker = CountingCollector(config, self.store, self.bus, "nsot", fail=lambda n: gate.wait(5) and None if n == 2 else None)
        other = CountingCollector(config, self.store, self.bus, "counters")
        supervisor = Supervisor(config, self.store, self.bus, [blocker, other])
        self.addCleanup(supervisor.stop)
        supervisor.start()
        self.assertTrue(wait_until(lambda: self.kinds("collector.stall"), timeout=5))
        self.assertEqual(self.kinds("collector.stall")[0].target, "nsot")
        self.assertEqual(self.store.collector_status()["nsot"].state, "STALLED")
        stalled_at = other.count
        self.assertTrue(wait_until(lambda: other.count > stalled_at + 5))          # the stalled collector blocks nobody
        gate.set()
        self.assertTrue(wait_until(lambda: self.kinds("collector.resumed")))

    def test_stop_signals_joins_and_leaves_no_worker(self):
        supervisor, collectors = self.make()
        supervisor.start()
        wait_until(lambda: all(c.count >= 2 for c in collectors.values()))
        started = time.monotonic()
        leftover = supervisor.stop()
        self.assertEqual(leftover, [])
        self.assertLess(time.monotonic() - started, self.config.join_timeout)
        self.assertEqual(supervisor.alive(), [])
        self.assertTrue(all(c.torn_down for c in collectors.values()))
        self.assertEqual({e.collector for e in self.kinds("collector.stop")}, set(NAMES))
        self.assertFalse([t for t in threading.enumerate() if t.name.startswith("console-")])
        counts = {name: c.count for name, c in collectors.items()}
        time.sleep(0.1)
        self.assertEqual(counts, {name: c.count for name, c in collectors.items()})   # polling really stopped

    def test_stop_reports_a_worker_that_will_not_finish(self):
        gate = threading.Event()
        self.addCleanup(gate.set)
        stuck = CountingCollector(self.config, self.store, self.bus, "nsot", fail=lambda n: gate.wait(10) and None)
        supervisor = Supervisor(self.config, self.store, self.bus, [stuck])
        supervisor.start()
        wait_until(lambda: stuck.count >= 1)
        self.assertEqual(supervisor.stop(timeout=0.2), ["nsot"])                    # bounded: stop() returns, and says who is left


class EventBusTests(ConsoleTestCase):
    def test_events_reach_store_log_and_subscribers_with_timestamps(self):
        log = SessionLog(self.config.spool_dir)
        self.addCleanup(log.close)
        from challenge_console.state import EventBus
        bus = EventBus(self.store, log)
        seen = []
        bus.subscribe(seen.append)
        bus.subscribe(lambda event: 1 / 0)                                          # a broken subscriber is contained
        event = bus.emit("connectivity", "connectivity.sample", "H1/IPV4", m.PASS, {"rtt_ms": 1.0})
        self.assertEqual(seen, [event])
        self.assertEqual(self.store.recent_events(collector="connectivity"), [event])
        log.flush()
        record = read_session(log.path)[-1]
        self.assertEqual((record["kind"], record["target"], record["outcome"]), ("connectivity.sample", "H1/IPV4", "PASS"))
        self.assertRegex(record["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")

    def test_publishing_from_many_threads_loses_nothing(self):
        store = StateStore(recent_events=100000)
        from challenge_console.state import EventBus
        bus = EventBus(store)
        seen, lock = [], threading.Lock()
        bus.subscribe(lambda e: (lock.acquire(), seen.append(e), lock.release()))
        threads = [threading.Thread(target=lambda i=i: [bus.emit("counters", "x", str(i)) for _ in range(500)]) for i in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(seen), 4000)
        self.assertEqual(len(store.recent_events(limit=100000)), 4000)


class SessionLogTests(ConsoleTestCase):
    def test_log_is_append_only_jsonl_with_private_permissions(self):
        log = SessionLog(self.config.spool_dir, metadata={"config": {"lab_name": "lab"}})
        for index in range(50):
            log.append(m.Event(m.utcnow(), "connectivity", "connectivity.sample", "H1/IPV4", m.PASS, {"n": index}))
        log.flush()
        first = log.path.read_bytes()
        self.assertEqual(os.stat(log.path).st_mode & 0o777, 0o600)
        for index in range(50, 60):
            log.append(m.Event(m.utcnow(), "connectivity", "connectivity.sample", "H1/IPV4", m.FAIL, {"n": index}))
        log.close()
        second = log.path.read_bytes()
        self.assertTrue(second.startswith(first))                                   # earlier bytes are never rewritten
        records = read_session(log.path)
        self.assertEqual(records[0]["kind"], "session.meta")
        self.assertEqual([r["data"]["n"] for r in records[1:]], list(range(60)))    # complete, in order
        self.assertEqual(log.status()["written"], 61)

    def test_an_existing_session_file_is_never_reopened(self):
        log = SessionLog(self.config.spool_dir)
        log.close()
        with self.assertRaises(FileExistsError):
            os.open(log.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)

    def test_save_moves_the_file_and_never_overwrites(self):
        log = SessionLog(self.config.spool_dir)
        log.close()
        target = self.tmp / "out" / "my session?.jsonl"
        target.parent.mkdir()
        (target.parent / "my-session-.jsonl").write_text("existing")
        saved = log.save(target)
        self.assertEqual(saved.name, "my-session--1.jsonl")
        self.assertEqual((target.parent / "my-session-.jsonl").read_text(), "existing")
        self.assertFalse(list(self.config.spool_dir.iterdir()))
        self.assertEqual(safe_filename("../../etc/passwd"), "etc-passwd")

    def test_secrets_never_reach_the_file(self):
        log = SessionLog(self.config.spool_dir)
        log.append(m.Event(m.utcnow(), "nsot", "x", "netbox", m.ERROR, {
            "password": "hunter2", "NETBOX_TOKEN": "nbt_abc.def", "nested": {"api_key": "K-123", "totp_seed": "JBSWY3DP"},
            "detail": "Authorization: Bearer abcdef0123456789 and password=hunter2 at https://admin:s3cret@host/x",
            "key": "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nAAAA\n-----END OPENSSH " + "PRIVATE KEY-----",   # split: not a key block in source
            "rtt_ms": 3.1, "passed": True}))
        log.close()
        text = log.path.read_text()
        for secret in ("hunter2", "nbt_abc.def", "K-123", "JBSWY3DP", "abcdef0123456789", "s3cret", "AAAA"):
            self.assertNotIn(secret, text)
        record = read_session(log.path)[-1]["data"]
        self.assertEqual((record["rtt_ms"], record["passed"]), (3.1, True))         # ordinary data is untouched

    def test_redaction_helpers(self):
        self.assertEqual(redact.scrub({"secret_ref": "runtime://x", "session_id": "abc", "samples": {"PASS": 3}}),
                         {"secret_ref": redact.REDACTED, "session_id": "abc", "samples": {"PASS": 3}})
        self.assertEqual(redact.classify_exception(TimeoutError("x")), "TIMEOUT")
        self.assertEqual(redact.classify_exception(KeyError("x")), "PARSE_ERROR")
        self.assertEqual(redact.classify_exception(ConnectionRefusedError("x")), "IO_ERROR")


class RuntimeTests(ConsoleTestCase):
    def runtime(self):
        factory = lambda config, store, bus: [CountingCollector(config, store, bus, name) for name in NAMES]  # noqa: E731
        runtime = ConsoleRuntime(self.config, collector_factory=factory)
        self.addCleanup(runtime.stop)
        return runtime

    def test_save_persists_the_complete_session_then_stops(self):
        runtime = self.runtime()
        runtime.start()
        wait_until(lambda: all(s.cycles >= 3 for s in runtime.store.collector_status().values()))
        saved = runtime.finish(SAVE)
        self.assertEqual(saved.parent, self.config.save_dir)
        self.assertFalse(str(saved).startswith(str(self.config.repo_root / "challenge_console")))
        self.assertEqual(runtime.supervisor.alive(), [])
        records = read_session(saved)
        kinds = [r["kind"] for r in records]
        self.assertEqual((kinds[0], kinds[1], kinds[-1]), ("session.meta", "app.start", "app.stop"))
        self.assertIn("session.summary", kinds)
        for name in NAMES:
            self.assertIn(f"{name}.sample", kinds)
            self.assertIn(name, {r["collector"] for r in records if r["kind"] == "collector.stop"})
        meta, end = records[0]["data"], records[-1]["data"]
        self.assertEqual(meta["session_id"], runtime.log.session_id)
        self.assertTrue(meta["started_at"] and end["ended_at"] and end["duration_seconds"] >= 0)
        self.assertEqual(end["leftover_workers"], [])
        self.assertTrue(all(r["ts"] for r in records))                              # every record is timestamped
        self.assertFalse(list(self.config.spool_dir.iterdir()))

    def test_dont_save_discards_persistence_and_stops(self):
        runtime = self.runtime()
        runtime.start()
        wait_until(lambda: runtime.store.collector_status()["connectivity"].cycles >= 2)
        spool = runtime.log.path
        self.assertTrue(spool.exists())
        self.assertIsNone(runtime.finish(DISCARD))
        self.assertFalse(spool.exists())
        self.assertFalse(self.config.save_dir.exists() and list(self.config.save_dir.iterdir()))
        self.assertEqual(runtime.supervisor.alive(), [])

    def test_cancel_is_not_a_finish_action_and_stop_is_idempotent(self):
        runtime = self.runtime()
        runtime.start()
        with self.assertRaises(ValueError):
            runtime.finish("cancel")
        self.assertTrue(runtime.running)
        self.assertEqual(sorted(runtime.supervisor.alive()), sorted(NAMES))        # nothing was stopped
        self.assertEqual(runtime.stop(), [])
        self.assertEqual(runtime.stop(), [])


class ConfigTests(ConsoleTestCase):
    def test_environment_overrides_and_central_defaults(self):
        config = ConsoleConfig.from_env({"NMAS_CONSOLE_CONNECTIVITY_INTERVAL": "2.5", "NMAS_CONSOLE_LAB_NAME": "other",
                                         "NMAS_CONSOLE_DEPLOY_ROOT": "/srv/deploy", "NMAS_CONSOLE_AUTOMATION_ROWS": "7"})
        self.assertEqual((config.connectivity_interval, config.lab_name, config.automation_rows), (2.5, "other", 7))
        self.assertEqual(str(config.automation_db_path), "/srv/deploy/web/db.sqlite3")
        self.assertEqual(config.container("R1"), "clab-other-R1")

    def test_retention_can_never_be_configured_below_one_hour(self):
        config = ConsoleConfig.from_env({"NMAS_CONSOLE_RETENTION_SECONDS": "60"})
        self.assertEqual(config.retention_seconds, MIN_RETENTION_SECONDS)
        self.assertGreaterEqual(config.history_maxlen * config.connectivity_interval, 3600)

    def test_intervals_differ_per_collector_and_session_data_stays_out_of_the_checkout(self):
        config = ConsoleConfig()
        periods = [config.connectivity_interval, config.counters_interval, config.services_interval, config.automation_interval, config.nsot_interval]
        self.assertEqual(periods, sorted(periods))
        self.assertEqual(len(set(periods)), 5)
        for path in (config.save_dir, config.spool_dir):
            self.assertNotIn(str(config.repo_root), str(path))
        self.assertFalse([k for k in config.public_dict() if redact._SECRET_KEY.search(k)])     # no secret-named field exists


class RingBufferTests(ConsoleTestCase):
    def sample(self, ts, ok=True):
        return m.ProbeSample(ts, "H1/IPV4", "H1", m.V4, "H2", "a", "b", ok, 1.0 if ok else None, "" if ok else "TIMEOUT")

    def test_one_hour_of_samples_is_retained_and_older_ones_are_dropped(self):
        config = ConsoleConfig(retention_seconds=3600, connectivity_interval=5)
        store = StateStore(history_maxlen=config.history_maxlen, retention_seconds=config.retention_seconds)
        start = m.utcnow()
        for index in range(1000):                                                   # 5000 s of 5 s samples
            store.add_probe_sample(self.sample(start + timedelta(seconds=5 * index)))
        history = store.probe_history("H1/IPV4")
        self.assertEqual(len(history), 721)                                         # exactly the last hour, inclusive
        self.assertEqual(history[0].ts, start + timedelta(seconds=5 * 999 - 3600))
        self.assertGreaterEqual(store.history_span_seconds("H1/IPV4"), 3600)
        self.assertEqual(store.probe_rows()[0].samples, 1000)                       # the row's totals are not truncated

    def test_ring_is_bounded_even_if_probes_arrive_faster_than_planned(self):
        store = StateStore(history_maxlen=100, retention_seconds=3600)
        start = m.utcnow()
        for index in range(1000):
            store.add_probe_sample(self.sample(start + timedelta(milliseconds=index)))
        self.assertEqual(len(store.probe_history("H1/IPV4")), 100)
