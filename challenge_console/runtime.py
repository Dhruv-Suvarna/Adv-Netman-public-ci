"""The headless core of the console: configuration, state, log, bus and the collector supervisor -- no Tk anywhere.

The Tk application is a thin shell over this object, which is why collection is independent of the UI: collectors are started here
once and stopped here once, and no view can reach them.  The same object runs without a display (``--headless``) and in the tests.
"""

from __future__ import annotations

import threading
from pathlib import Path

from . import APP_NAME, VERSION
from . import models as m
from .config import ConsoleConfig
from .sessionlog import SessionLog
from .state import EventBus, StateStore
from .supervisor import Supervisor

SAVE, DISCARD, CANCEL = "save", "discard", "cancel"


class ConsoleRuntime:
    def __init__(self, config: ConsoleConfig | None = None, *, collectors: list | None = None, collector_factory=None):
        self.config = config or ConsoleConfig.from_env()
        self.store = StateStore(history_maxlen=self.config.history_maxlen, retention_seconds=self.config.retention_seconds,
                                recent_events=self.config.recent_events)
        self.log = SessionLog(self.config.spool_dir, started_at=self.store.started_at, metadata={"config": self.config.public_dict()})
        self.bus = EventBus(self.store, self.log)
        if collectors is None:
            if collector_factory is None:
                from .collectors import build_default as collector_factory
            collectors = collector_factory(self.config, self.store, self.bus)
        self.supervisor = Supervisor(self.config, self.store, self.bus, collectors)
        self._lock = threading.Lock()
        self._started = self._stopped = False
        self.leftover_workers: list[str] = []

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
        self.bus.emit(m.APP, "app.start", outcome=m.OK, data={"app": APP_NAME, "version": VERSION, "session_id": self.log.session_id,
                                                              "collectors": [c.name for c in self.supervisor.collectors]})
        self.supervisor.start()

    @property
    def running(self) -> bool:
        return self._started and not self._stopped

    def stop(self) -> list[str]:
        """Stop every collector, record the closing summary, flush and close the log.  Idempotent.  Returns workers still alive."""
        with self._lock:
            if self._stopped:
                return self.leftover_workers
            self._stopped = True
        self.leftover_workers = self.supervisor.stop() if self._started else []
        ended = m.utcnow()
        self.bus.emit(m.APP, "session.summary", outcome=m.INFO, ts=ended, data=self.store.summary())
        self.bus.emit(m.APP, "app.stop", outcome=m.OK if not self.leftover_workers else m.ERROR, ts=ended,
                      data={"started_at": m.iso(self.store.started_at), "ended_at": m.iso(ended),
                            "duration_seconds": round((ended - self.store.started_at).total_seconds(), 3),
                            "leftover_workers": self.leftover_workers})
        self.log.close()
        return self.leftover_workers

    def finish(self, action: str, destination: Path | None = None) -> Path | None:
        """``save``: stop, then move the session log to ``destination`` (default: the save directory).  ``discard``: stop, delete it."""
        if action not in (SAVE, DISCARD):
            raise ValueError("finish() takes save or discard; cancel means: do nothing and keep running")
        self.stop()
        if action == SAVE:
            return self.log.save(destination or self.log.default_destination(self.config.save_dir))
        self.log.discard()
        return None
