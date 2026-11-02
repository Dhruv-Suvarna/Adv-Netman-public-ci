"""The shared current-state / history models and the event bus.

Collectors (worker threads) write here; views (the Tk thread) read snapshots from here.  Nothing in this module knows about Tk, and
no collector knows about a widget: the only thing that crosses to the UI is a topic name on a queue (see ``ui/bridge.py``).

Every mutation and every read takes the store lock, and every read returns copies, so a view can never observe a half-applied update
and can never mutate state from the UI thread.
"""

from __future__ import annotations

import copy
import threading
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from . import models as m
from .models import Event, InterfaceCounters, InterfaceRow, ProbeRow, ProbeSample, ProbeSpec, utcnow


@dataclass
class CollectorStatus:
    name: str
    interval: float
    state: str = "STARTING"            # STARTING / RUNNING / FAILING / STALLED / STOPPED
    cycles: int = 0
    errors: int = 0
    consecutive_errors: int = 0
    restarts: int = 0
    last_cycle: datetime | None = None
    last_ok: datetime | None = None
    last_error: str = ""
    last_error_at: datetime | None = None
    events: int = 0


class EventBus:
    """Fan-out of published events: the store's recent ring, the append-only log, and topic notifications for the UI."""

    def __init__(self, store: "StateStore", log=None):
        self._store = store
        self._log = log
        self._subscribers: list = []
        self._lock = threading.Lock()

    def subscribe(self, callback) -> None:
        """``callback(event)`` is invoked on the PUBLISHING thread; it must only enqueue (the UI bridge does exactly that)."""
        with self._lock:
            self._subscribers.append(callback)

    def publish(self, event: Event) -> None:
        self._store.record_event(event)
        if self._log is not None:
            self._log.append(event)
        with self._lock:
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:  # noqa: BLE001 - a broken subscriber must never break a collector
                pass

    def emit(self, collector: str, kind: str, target: str = "", outcome: str = m.INFO, data: dict | None = None,
             ts: datetime | None = None) -> Event:
        event = Event(ts or utcnow(), collector, kind, target, outcome, data or {})
        self.publish(event)
        return event


class StateStore:
    def __init__(self, *, history_maxlen: int = 2000, retention_seconds: float = 7200.0, recent_events: int = 2000):
        self._lock = threading.RLock()
        self._history_maxlen = history_maxlen
        self._retention = timedelta(seconds=retention_seconds)
        self._recent: deque[Event] = deque(maxlen=recent_events)
        self._versions: dict[str, int] = {}
        self._collectors: dict[str, CollectorStatus] = {}
        self.started_at = utcnow()
        # connectivity
        self._probes: dict[str, ProbeRow] = {}
        self._history: dict[str, deque[ProbeSample]] = {}
        # services / telemetry
        self._services: dict[str, m.ServiceObservation] = {}
        self._service_last_up: dict[str, datetime] = {}
        self._service_since: dict[str, datetime] = {}
        self._telemetry: dict = {"ts": None, "available": False, "reason": "No telemetry read yet.", "rows": [], "thresholds": {}}
        self._telemetry_last_ok: datetime | None = None
        # nsot / automation: one snapshot document each
        self._documents: dict[str, dict] = {
            m.NSOT: {"ts": None, "available": False, "stale": False, "reason": "No NSOT read yet.", "data": {}},
            m.AUTOMATION: {"ts": None, "available": False, "stale": False, "reason": "No automation read yet.", "data": {}},
        }
        # counters
        self._interfaces: dict[tuple[str, str], InterfaceRow] = {}
        self._devices: dict[str, dict] = {}

    # --- generic ------------------------------------------------------------------------------------------------------------
    def _bump(self, topic: str) -> None:
        self._versions[topic] = self._versions.get(topic, 0) + 1

    def version(self, topic: str) -> int:
        with self._lock:
            return self._versions.get(topic, 0)

    def record_event(self, event: Event) -> None:
        with self._lock:
            self._recent.append(event)
            status = self._collectors.get(event.collector)
            if status is not None:
                status.events += 1

    def recent_events(self, *, collector: str | None = None, kinds: tuple[str, ...] = (), limit: int = 200) -> list[Event]:
        with self._lock:
            found = [e for e in reversed(self._recent)
                     if (collector is None or e.collector == collector) and (not kinds or e.kind in kinds)]
        return found[:limit]

    # --- collector lifecycle --------------------------------------------------------------------------------------------------
    def register_collector(self, name: str, interval: float) -> CollectorStatus:
        with self._lock:
            return self._collectors.setdefault(name, CollectorStatus(name, interval))

    def update_collector(self, name: str, **changes) -> None:
        with self._lock:
            status = self._collectors[name]
            for key, value in changes.items():
                setattr(status, key, value)
            self._bump("collectors")

    def collector_status(self) -> dict[str, CollectorStatus]:
        with self._lock:
            return {name: replace(status) for name, status in self._collectors.items()}

    # --- connectivity ---------------------------------------------------------------------------------------------------------
    def set_probe_specs(self, specs: list[ProbeSpec]) -> None:
        """Declare the matrix rows.  Existing rows (and their history) are kept: navigation or a re-plan never resets them."""
        with self._lock:
            for spec in specs:
                if spec.key not in self._probes:
                    self._probes[spec.key] = ProbeRow(spec=spec)
                    self._history[spec.key] = deque(maxlen=self._history_maxlen)
                else:
                    self._probes[spec.key].spec = spec
            self._bump(m.CONNECTIVITY)

    def add_probe_sample(self, sample: ProbeSample) -> str | None:
        """Apply one probe result.  Returns "RECOVERED" / "FAILED" when the row's state changed, else None."""
        with self._lock:
            row = self._probes.get(sample.key)
            if row is None:
                row = self._probes[sample.key] = ProbeRow(spec=ProbeSpec(sample.source, sample.family, sample.destination))
                self._history[sample.key] = deque(maxlen=self._history_maxlen)
            history = self._history[sample.key]
            history.append(sample)
            horizon = sample.ts - self._retention
            while history and history[0].ts < horizon:
                history.popleft()
            previous = row.state
            row.samples += 1
            row.last_ts, row.last_rtt_ms, row.last_reason = sample.ts, sample.rtt_ms, sample.reason
            row.source_address, row.target_address = sample.source_address, sample.target_address
            if sample.success:
                row.state, row.consecutive_failures, row.last_success = m.UP, 0, sample.ts
            else:
                row.state, row.last_failure = m.DOWN, sample.ts
                row.consecutive_failures += 1
                row.failures += 1
            transition = None
            if previous != row.state:
                row.last_change = sample.ts
                if previous != m.UNKNOWN:
                    transition = "RECOVERED" if sample.success else "FAILED"
            self._bump(m.CONNECTIVITY)
            return transition

    def probe_rows(self) -> list[ProbeRow]:
        with self._lock:
            return [replace(row) for row in self._probes.values()]

    def probe_history(self, key: str, *, limit: int | None = None) -> list[ProbeSample]:
        with self._lock:
            history = list(self._history.get(key, ()))
        return history if limit is None else history[-limit:]

    def history_span_seconds(self, key: str) -> float:
        with self._lock:
            history = self._history.get(key)
            return (history[-1].ts - history[0].ts).total_seconds() if history else 0.0

    def recent_samples(self, *, limit: int = 300, failures_only: bool = False, key: str | None = None) -> list[ProbeSample]:
        """Newest first, across rows (or one row)."""
        with self._lock:
            keys = [key] if key else list(self._history)
            merged = []
            for name in keys:
                tail = list(self._history.get(name, ()))
                tail = [s for s in tail if not s.success] if failures_only else tail
                merged.extend(tail[-limit:])
        merged.sort(key=lambda s: s.ts, reverse=True)
        return merged[:limit]

    # --- services / telemetry -----------------------------------------------------------------------------------------------------
    def set_service(self, observation: m.ServiceObservation) -> str | None:
        """Returns the previous state when it differs from the new one (a transition), else None."""
        with self._lock:
            previous = self._services.get(observation.component)
            self._services[observation.component] = observation
            if observation.state == m.UP:
                self._service_last_up[observation.component] = observation.ts
            changed = previous is None or previous.state != observation.state
            if changed:
                self._service_since[observation.component] = observation.ts
            self._bump(m.SERVICES)
            return previous.state if previous is not None and changed else None

    def services(self) -> list[dict]:
        with self._lock:
            return [{"observation": obs, "last_up": self._service_last_up.get(name), "since": self._service_since.get(name)}
                    for name, obs in self._services.items()]

    def set_telemetry(self, *, ts: datetime, available: bool, reason: str = "", rows: list | None = None,
                      thresholds: dict | None = None, backend: str = "", generated_at: datetime | None = None) -> None:
        with self._lock:
            if available:
                self._telemetry_last_ok = ts
            self._telemetry = {"ts": ts, "available": available, "reason": reason, "rows": list(rows or []),
                               "thresholds": dict(thresholds or {}), "backend": backend, "generated_at": generated_at,
                               "last_ok": self._telemetry_last_ok}
            self._bump(m.SERVICES)

    def telemetry(self) -> dict:
        with self._lock:
            return dict(self._telemetry, rows=list(self._telemetry["rows"]))

    # --- NSOT / automation documents ------------------------------------------------------------------------------------------------
    def set_document(self, topic: str, *, ts: datetime, data: dict) -> None:
        with self._lock:
            self._documents[topic] = {"ts": ts, "available": True, "stale": False, "reason": "", "data": data, "last_ok": ts}
            self._bump(topic)

    def fail_document(self, topic: str, *, ts: datetime, reason: str) -> None:
        """A failed refresh keeps the last good data and marks it STALE; it never blanks the view and never pretends to be current."""
        with self._lock:
            current = self._documents[topic]
            self._documents[topic] = {**current, "ts": ts, "available": False, "stale": bool(current.get("data")), "reason": reason}
            self._bump(topic)

    def document(self, topic: str) -> dict:
        with self._lock:
            return copy.copy(self._documents[topic])

    # --- interface counters -----------------------------------------------------------------------------------------------------------
    def apply_counters(self, device: str, ts: datetime, samples: list[InterfaceCounters]) -> list[dict]:
        """Apply one successful read of a device.  Returns change notes ({"interface", "note"}) for appear / disappear / state / reset."""
        changes: list[dict] = []
        with self._lock:
            first_read = device not in self._devices or not self._devices[device].get("ever_ok")
            seen = set()
            for sample in samples:
                key = (device, sample.name)
                seen.add(sample.name)
                previous = self._interfaces.get(key)
                row = InterfaceRow(sample=sample, ts=ts, last_change=previous.last_change if previous else None,
                                   change_note=previous.change_note if previous else "")
                if previous is None or not previous.present:
                    if not first_read:
                        row.last_change, row.change_note = ts, "appeared"
                        changes.append({"interface": sample.name, "note": "appeared"})
                else:
                    _derive(row, previous)
                    notes = []
                    if (previous.sample.admin, previous.sample.oper) != (sample.admin, sample.oper):
                        notes.append(f"state {previous.sample.admin}/{previous.sample.oper} -> {sample.admin}/{sample.oper}")
                    if row.counter_reset:
                        notes.append("counter reset")
                    if row.error_delta > 0:
                        notes.append(f"errors/drops +{row.error_delta}")
                    if notes:
                        row.last_change, row.change_note = ts, "; ".join(notes)
                        changes.append({"interface": sample.name, "note": row.change_note})
                self._interfaces[key] = row
            for (dev, name), row in self._interfaces.items():
                if dev == device and name not in seen and row.present:
                    row.present, row.last_change, row.change_note = False, ts, "disappeared"
                    row.rx_bps = row.tx_bps = row.rx_pps = row.tx_pps = None
                    changes.append({"interface": name, "note": "disappeared"})
            self._devices[device] = {"ts": ts, "ok": True, "reason": "", "last_ok": ts, "ever_ok": True, "interfaces": len(samples)}
            self._bump(m.COUNTERS)
        return changes

    def fail_counters(self, device: str, ts: datetime, reason: str) -> None:
        """The device could not be read: its last counters stay visible (flagged), and no rate is carried forward."""
        with self._lock:
            current = self._devices.get(device, {})
            self._devices[device] = {**current, "ts": ts, "ok": False, "reason": reason}
            for (dev, _), row in self._interfaces.items():
                if dev == device:
                    row.rx_bps = row.tx_bps = row.rx_pps = row.tx_pps = None
            self._bump(m.COUNTERS)

    def interface_rows(self) -> list[InterfaceRow]:
        with self._lock:
            return [replace(row, sample=replace(row.sample)) for row in self._interfaces.values()]

    def counter_devices(self) -> dict[str, dict]:
        with self._lock:
            return {name: dict(status) for name, status in self._devices.items()}

    # --- summary (written to the session log at close) ------------------------------------------------------------------------------------
    def summary(self) -> dict:
        with self._lock:
            return {
                "collectors": {name: {"state": s.state, "cycles": s.cycles, "errors": s.errors, "restarts": s.restarts, "events": s.events}
                               for name, s in self._collectors.items()},
                "connectivity": [{"key": row.spec.key, "destination": row.spec.destination, "state": row.state, "samples": row.samples,
                                  "failures": row.failures, "consecutive_failures": row.consecutive_failures,
                                  "last_success": m.iso(row.last_success), "last_failure": m.iso(row.last_failure),
                                  "in_memory_samples": len(self._history.get(row.spec.key, ()))} for row in self._probes.values()],
                "services": {name: obs.state for name, obs in self._services.items()},
                "telemetry": {row.device: row.freshness for row in self._telemetry["rows"]},
                "nsot": {"available": self._documents[m.NSOT]["available"], "stale": self._documents[m.NSOT]["stale"],
                         "last_ok": m.iso(self._documents[m.NSOT].get("last_ok"))},
                "automation": {"available": self._documents[m.AUTOMATION]["available"], "stale": self._documents[m.AUTOMATION]["stale"],
                               "last_ok": m.iso(self._documents[m.AUTOMATION].get("last_ok"))},
                "counters": {name: {"ok": status.get("ok"), "interfaces": status.get("interfaces"), "last_ok": m.iso(status.get("last_ok"))}
                             for name, status in self._devices.items()},
            }


def _derive(row: InterfaceRow, previous: InterfaceRow) -> None:
    """Rates = delta counter / delta time.  A counter that went backwards (reset or rollover) yields NO rate for that interval."""
    elapsed = (row.ts - previous.ts).total_seconds()
    now, before = row.sample, previous.sample
    pairs = [(getattr(now, name), getattr(before, name)) for name in m.COUNTER_FIELDS]
    if any(a is not None and b is not None and a < b for a, b in pairs):
        row.counter_reset = True
        return
    if elapsed <= 0:
        return

    def rate(current, earlier, scale=1.0):
        return None if current is None or earlier is None else (current - earlier) * scale / elapsed

    row.rx_bps, row.tx_bps = rate(now.rx_bytes, before.rx_bytes, 8.0), rate(now.tx_bytes, before.tx_bytes, 8.0)
    row.rx_pps, row.tx_pps = rate(now.rx_packets, before.rx_packets), rate(now.tx_packets, before.tx_packets)
    row.error_delta = sum((getattr(now, name) or 0) - (getattr(before, name) or 0)
                          for name in ("rx_errors", "tx_errors", "rx_drops", "tx_drops")
                          if getattr(now, name) is not None and getattr(before, name) is not None)
