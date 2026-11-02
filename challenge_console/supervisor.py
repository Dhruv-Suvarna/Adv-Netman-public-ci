"""Collector lifecycle: one worker thread per collector, started once and kept running for the whole application lifetime.

Nothing here is tied to which view is visible -- the UI cannot start, stop or pause a collector.  The supervisor:

* runs each collector's ``collect()`` on its own period, on its own thread;
* turns every failure into an EVENT (``collector.error``) with a fixed, secret-free code -- a failed cycle never disappears;
* backs off (bounded, exponential) after a failed cycle instead of spinning;
* isolates collectors from one another: an exception in one never reaches another, or the UI;
* watches heartbeats: a dead worker is restarted, a silent one is reported as stalled;
* stops everything on request and joins the workers within a bounded time.
"""

from __future__ import annotations

import threading
import time

from . import models as m
from .redact import classify_exception
from .state import EventBus, StateStore


class CollectorError(Exception):
    """An expected whole-cycle failure with a fixed code (e.g. NETBOX_UNAVAILABLE).  ``code`` is the only thing that is logged."""

    def __init__(self, code: str, target: str = ""):
        super().__init__(code)
        self.code, self.target = code, target


class Collector:
    """Base class.  Subclasses implement ``collect()`` (one bounded cycle) and publish through ``self.emit``."""

    name = "collector"
    backoff_on_error = True

    def __init__(self, config, store: StateStore, bus: EventBus, *, interval: float):
        self.config, self.store, self.bus = config, store, bus
        self.interval = float(interval)
        self.stop_event = threading.Event()      # replaced by the supervisor's shared event on registration

    @property
    def stopping(self) -> bool:
        return self.stop_event.is_set()

    def emit(self, kind: str, target: str = "", outcome: str = m.INFO, data: dict | None = None, ts=None):
        return self.bus.emit(self.name, kind, target, outcome, data, ts)

    def setup(self) -> None:
        """Called on the worker thread before the first cycle."""

    def collect(self) -> None:
        raise NotImplementedError

    def teardown(self) -> None:
        """Called on the worker thread after the last cycle: close sessions / pools here."""


class Supervisor:
    WATCH_PERIOD = 0.5

    def __init__(self, config, store: StateStore, bus: EventBus, collectors: list[Collector]):
        self.config, self.store, self.bus = config, store, bus
        self.collectors = list(collectors)
        self._stop = threading.Event()
        self._threads: dict[str, threading.Thread] = {}
        self._deadline: dict[str, float] = {}
        self._stalled: set[str] = set()
        self._watchdog: threading.Thread | None = None
        self._lock = threading.Lock()
        self._started = False
        for collector in self.collectors:
            collector.stop_event = self._stop
            self.store.register_collector(collector.name, collector.interval)

    # --- lifecycle --------------------------------------------------------------------------------------------------------------
    def start(self) -> None:
        if self._started:
            return
        self._started = True
        for collector in self.collectors:
            self._spawn(collector)
        self._watchdog = threading.Thread(target=self._watch, name="console-watchdog", daemon=True)
        self._watchdog.start()

    def _spawn(self, collector: Collector) -> None:
        thread = threading.Thread(target=self._loop, args=(collector,), name=f"console-{collector.name}", daemon=True)
        with self._lock:
            self._threads[collector.name] = thread
            self._deadline[collector.name] = time.monotonic() + self._margin(collector)
        thread.start()

    def _margin(self, collector: Collector) -> float:
        return self.config.stall_factor * collector.interval + 2 * self.config.command_timeout

    def stop(self, timeout: float | None = None) -> list[str]:
        """Signal every collector, join within ``timeout`` seconds in total.  Returns the names of workers still alive (normally none)."""
        timeout = self.config.join_timeout if timeout is None else timeout
        self._stop.set()
        deadline = time.monotonic() + timeout
        with self._lock:
            threads = dict(self._threads)
        if self._watchdog is not None:
            self._watchdog.join(max(0.0, deadline - time.monotonic()))
        for thread in threads.values():
            thread.join(max(0.0, deadline - time.monotonic()))
        leftover = sorted(name for name, thread in threads.items() if thread.is_alive())
        for name in threads:
            if name not in leftover:
                self.store.update_collector(name, state="STOPPED")
        return leftover

    def alive(self) -> list[str]:
        with self._lock:
            return sorted(name for name, thread in self._threads.items() if thread.is_alive())

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    # --- one collector's worker ---------------------------------------------------------------------------------------------------
    def _loop(self, collector: Collector) -> None:
        name = collector.name
        status_errors = 0
        try:
            collector.setup()
        except Exception as exc:  # noqa: BLE001 - reported, then the cycles themselves get their chance
            self._report_error(collector, classify_exception(exc), type(exc).__name__, "", phase="setup")
        collector.emit("collector.start", data={"interval": collector.interval})
        self.store.update_collector(name, state="RUNNING")
        delay = 0.0
        try:
            while not self._stop.wait(delay):
                started = time.monotonic()
                self._deadline[name] = started + self._margin(collector)
                now = m.utcnow()
                try:
                    collector.collect()
                except CollectorError as exc:
                    status_errors += 1
                    self._report_error(collector, exc.code, "", exc.target)
                except Exception as exc:  # noqa: BLE001 - isolation: an unexpected failure is an event, never a crash
                    status_errors += 1
                    self._report_error(collector, classify_exception(exc), type(exc).__name__, "")
                else:
                    if status_errors:
                        collector.emit("collector.recovered", outcome=m.OK, data={"after_errors": status_errors})
                    status_errors = 0
                    current = self.store.collector_status()[name]
                    self.store.update_collector(name, state="RUNNING", cycles=current.cycles + 1, consecutive_errors=0,
                                                last_cycle=now, last_ok=now)
                elapsed = time.monotonic() - started
                if status_errors and collector.backoff_on_error:
                    delay = min(collector.interval * (2 ** min(status_errors, 8)), self.config.max_backoff)
                else:
                    delay = max(0.0, collector.interval - elapsed)
                self._deadline[name] = time.monotonic() + delay + self._margin(collector)
        finally:
            try:
                collector.teardown()
            except Exception:  # noqa: BLE001
                pass
            if self._stop.is_set():
                collector.emit("collector.stop")

    def _report_error(self, collector: Collector, code: str, exception: str, target: str, phase: str = "collect") -> None:
        now = m.utcnow()
        current = self.store.collector_status()[collector.name]
        self.store.update_collector(collector.name, state="FAILING", errors=current.errors + 1,
                                    consecutive_errors=current.consecutive_errors + 1, last_cycle=now, last_error=code, last_error_at=now)
        data = {"code": code, "phase": phase, "consecutive": current.consecutive_errors + 1}
        if exception:
            data["exception"] = exception        # the class name only; never the message
        collector.emit("collector.error", target=target, outcome=m.ERROR, data=data, ts=now)

    # --- the watchdog ---------------------------------------------------------------------------------------------------------------
    def _watch(self) -> None:
        while not self._stop.wait(self.WATCH_PERIOD):
            for collector in self.collectors:
                name = collector.name
                with self._lock:
                    thread = self._threads.get(name)
                if thread is not None and not thread.is_alive() and not self._stop.is_set():
                    current = self.store.collector_status()[name]
                    self.store.update_collector(name, restarts=current.restarts + 1, state="STARTING")
                    self.bus.emit(m.SUPERVISOR, "collector.restart", target=name, outcome=m.ERROR,
                                  data={"restarts": current.restarts + 1, "reason": "WORKER_DIED"})
                    self._spawn(collector)
                    continue
                overdue = time.monotonic() > self._deadline.get(name, float("inf"))
                if overdue and name not in self._stalled:
                    self._stalled.add(name)
                    self.store.update_collector(name, state="STALLED")
                    self.bus.emit(m.SUPERVISOR, "collector.stall", target=name, outcome=m.ERROR, data={"reason": "NO_HEARTBEAT"})
                elif not overdue and name in self._stalled:
                    self._stalled.discard(name)
                    self.bus.emit(m.SUPERVISOR, "collector.resumed", target=name, outcome=m.OK)
