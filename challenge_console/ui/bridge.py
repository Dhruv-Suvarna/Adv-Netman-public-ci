"""The single crossing point between worker threads and the Tk thread.

Worker side: ``_on_event`` runs on whichever collector thread published; it does one thing -- put a topic name on a queue.  It never
touches a widget.  Tk side: ``_pump`` runs from ``root.after`` on the Tk main thread, drains the queue and hands the set of changed
topics to the application, which re-renders from the store.  So every widget mutation happens on the Tk thread, and a slow render can
never delay a probe (collectors do not wait for the queue to be drained).
"""

from __future__ import annotations

import queue

from ..models import COLLECTORS

COLLECTORS_TOPIC = "collectors"


class UiBridge:
    def __init__(self, root, bus, on_topics, *, period_ms: int = 300):
        self._root, self._on_topics, self._period = root, on_topics, period_ms
        self._queue: queue.SimpleQueue = queue.SimpleQueue()
        self._after_id = None
        self._running = False
        self.delivered = 0
        bus.subscribe(self._on_event)

    def _on_event(self, event) -> None:        # ANY thread
        self._queue.put(event.collector if event.collector in COLLECTORS else COLLECTORS_TOPIC)

    def start(self) -> None:
        self._running = True
        self._after_id = self._root.after(self._period, self._pump)

    def drain(self) -> set[str]:
        topics: set[str] = set()
        while True:
            try:
                topics.add(self._queue.get_nowait())
                self.delivered += 1
            except queue.Empty:
                return topics

    def _pump(self) -> None:                   # Tk thread only
        if not self._running:
            return
        topics = self.drain()
        try:
            self._on_topics(topics)
        finally:
            if self._running:
                self._after_id = self._root.after(self._period, self._pump)

    def stop(self) -> None:
        self._running = False
        if self._after_id is not None:
            try:
                self._root.after_cancel(self._after_id)
            except Exception:  # noqa: BLE001 - the root may already be gone
                pass
            self._after_id = None
