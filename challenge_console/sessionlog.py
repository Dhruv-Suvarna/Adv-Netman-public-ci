"""The append-only session log: one JSON object per line, written by its own thread.

* Collectors never touch the disk: ``append`` only enqueues.  A writer thread drains the queue and appends to the spool file, so a slow
  disk can never delay a probe and the Tk thread never writes.
* The spool file is opened for append only and is never rewritten, truncated or seeked.  ``Save`` moves the finished file to the chosen
  destination; ``Don't Save`` deletes it.  Until one of those happens the spool is the session's only persistence.
* Every record passes ``redact.scrub`` on its way to disk.
* The format needs no tooling: ``jq``, ``grep`` or ``json.loads`` per line.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import threading
import uuid
from datetime import datetime
from pathlib import Path

from . import APP_NAME, VERSION
from .models import Event, iso, utcnow
from .redact import scrub

SCHEMA = 1
_STOP = object()
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(text: str) -> str:
    return _SAFE_NAME.sub("-", text).strip("-.") or "session"


class SessionLog:
    def __init__(self, spool_dir: Path, *, started_at: datetime | None = None, metadata: dict | None = None):
        self.session_id = uuid.uuid4().hex[:12]
        self.started_at = started_at or utcnow()
        self.metadata = dict(metadata or {})
        self.spool_dir = Path(spool_dir)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.spool_dir, 0o700)
        self.default_name = safe_filename(f"{APP_NAME}-{self.started_at.strftime('%Y%m%dT%H%M%SZ')}-{self.session_id}") + ".jsonl"
        self.path = self.spool_dir / self.default_name
        self._queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._written = 0
        self._dropped = 0
        self._closed = False
        self._failed = ""
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        self._handle = os.fdopen(fd, "a", encoding="utf-8")
        self._thread = threading.Thread(target=self._run, name="console-session-log", daemon=True)
        self._thread.start()
        self.append_record({"ts": iso(self.started_at), "collector": "app", "kind": "session.meta", "target": "", "outcome": "INFO",
                            "data": {"schema": SCHEMA, "app": APP_NAME, "version": VERSION, "session_id": self.session_id,
                                     "started_at": iso(self.started_at), **self.metadata}})

    # --- producers (any thread) ---------------------------------------------------------------------------------------------
    def append(self, event: Event) -> None:
        self.append_record(event.to_record())

    def append_record(self, record: dict) -> None:
        if self._closed:
            with self._lock:
                self._dropped += 1
            return
        self._queue.put(record)

    # --- the writer thread ----------------------------------------------------------------------------------------------------
    def _run(self) -> None:
        while True:
            item = self._queue.get()
            batch = [item]
            try:
                while len(batch) < 500:
                    batch.append(self._queue.get_nowait())
            except queue.Empty:
                pass
            stop = False
            lines = []
            for entry in batch:
                if entry is _STOP:
                    stop = True
                    continue
                if isinstance(entry, threading.Event):      # a flush barrier
                    lines.append(entry)
                    continue
                try:
                    lines.append(json.dumps(scrub(entry), separators=(",", ":"), sort_keys=False, default=str))
                except (TypeError, ValueError):
                    lines.append(json.dumps({"ts": iso(utcnow()), "collector": "app", "kind": "log.unserialisable", "target": "",
                                             "outcome": "ERROR", "data": {}}))
            self._write(lines)
            if stop:
                return

    def _write(self, lines: list) -> None:
        barriers = [entry for entry in lines if isinstance(entry, threading.Event)]
        text = [entry for entry in lines if isinstance(entry, str)]
        try:
            if text and not self._failed:
                self._handle.write("\n".join(text) + "\n")
                self._handle.flush()
                with self._lock:
                    self._written += len(text)
        except OSError as exc:
            self._failed = type(exc).__name__     # the log reports its own failure through ``status``; collectors keep running
        finally:
            for barrier in barriers:
                barrier.set()

    # --- control ----------------------------------------------------------------------------------------------------------------
    def flush(self, timeout: float = 5.0) -> bool:
        """Block until everything appended so far is on disk."""
        if not self._thread.is_alive():
            return True
        barrier = threading.Event()
        self._queue.put(barrier)
        return barrier.wait(timeout)

    def close(self, timeout: float = 5.0) -> None:
        """Flush, stop the writer and close the file.  Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._queue.put(_STOP)
        self._thread.join(timeout)
        try:
            self._handle.flush()
            os.fsync(self._handle.fileno())
        except OSError:
            pass
        self._handle.close()

    def status(self) -> dict:
        with self._lock:
            return {"path": str(self.path), "written": self._written, "dropped": self._dropped, "pending": self._queue.qsize(),
                    "failed": self._failed, "closed": self._closed}

    def default_destination(self, save_dir: Path) -> Path:
        return Path(save_dir) / self.default_name

    def save(self, destination: Path) -> Path:
        """Move the closed session file to ``destination`` (a file path).  Never overwrites an existing file."""
        if not self._closed:
            raise RuntimeError("close() the session log before saving it")
        destination = Path(destination).expanduser()
        if destination.is_dir():
            destination = destination / self.default_name
        destination = destination.with_name(safe_filename(destination.name))
        destination.parent.mkdir(parents=True, exist_ok=True)
        candidate, counter = destination, 1
        while candidate.exists():
            candidate = destination.with_name(f"{destination.stem}-{counter}{destination.suffix}")
            counter += 1
        shutil.move(str(self.path), str(candidate))
        os.chmod(candidate, 0o600)
        self.path = candidate
        return candidate

    def discard(self) -> None:
        """Delete the session file (``Don't Save``)."""
        if not self._closed:
            raise RuntimeError("close() the session log before discarding it")
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


def read_session(path: Path) -> list[dict]:
    """Load a saved session: a list of records in the order they were appended."""
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
