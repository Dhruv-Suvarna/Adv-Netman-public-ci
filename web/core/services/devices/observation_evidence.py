"""Durable *local* evidence sink for governed device observations (``observation_collector.collect(evidence_sink=...)``).

This is operator-side retention, NOT gateway attestation: references carry the ``local-unattested:`` scheme so nobody can mistake
them for a gateway-recorded artifact.  Guarantees:

* writes only inside one explicitly supplied directory that must resolve (symlinks followed) under an approved development root
  and must already exist, be a real directory and not be group/world writable;
* generated, sanitized filenames only (``obs-<device>-<utc>-<nonce>.json``); the caller never supplies a name, so no traversal;
* atomic and exclusive: content goes to a private temp file (0600, O_EXCL, fsync) and is hard-linked into place, so an existing
  file is never replaced and a reader never sees a partial file; the directory is fsynced;
* the returned reference embeds the SHA-256 of the exact bytes written; ``verify_reference`` re-reads and checks it independently.

Any failure raises ``EvidenceError`` (stable code only, no paths or content) which the collector turns into ``EVIDENCE_UNAVAILABLE``
so nothing is ingested.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

APPROVED_ROOTS = ("/home/student/Scripts", "/home/student/clab-quickstart")
SCHEME = "local-unattested"
_NAME = re.compile(r"^obs-[A-Za-z0-9_.-]{1,40}-\d{8}T\d{6}Z-[0-9a-f]{8,32}\.json$")
_REF = re.compile(r"^local-unattested:(?P<name>[A-Za-z0-9_.-]{1,120}\.json)#sha256=(?P<digest>[0-9a-f]{64})$")
_SAFE = re.compile(r"[^A-Za-z0-9_-]+")


class EvidenceError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def validate_directory(directory, approved_roots=APPROVED_ROOTS) -> Path:
    """Return the resolved evidence directory or raise ``EvidenceError`` (no filesystem writes)."""
    raw = str(directory or "").strip()
    if not raw or "\x00" in raw or not os.path.isabs(raw):
        raise EvidenceError("DIRECTORY_NOT_ABSOLUTE")
    try:
        resolved = Path(raw).resolve(strict=True)
    except OSError:
        raise EvidenceError("DIRECTORY_MISSING") from None
    if not resolved.is_dir():
        raise EvidenceError("DIRECTORY_NOT_A_DIRECTORY")
    roots = [Path(r).resolve() for r in approved_roots]
    if not any(resolved == r or r in resolved.parents for r in roots):
        raise EvidenceError("DIRECTORY_OUTSIDE_APPROVED_ROOTS")
    mode = resolved.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise EvidenceError("DIRECTORY_TOO_PERMISSIVE")
    if not os.access(resolved, os.W_OK | os.X_OK):
        raise EvidenceError("DIRECTORY_NOT_WRITABLE")
    return resolved


class LocalEvidenceSink:
    """Callable ``record -> reference``; see module docstring."""

    def __init__(self, directory, *, approved_roots=APPROVED_ROOTS):
        self.directory = validate_directory(directory, approved_roots)
        self.references: list[str] = []

    def __call__(self, record: dict) -> str:
        if not isinstance(record, dict):
            raise EvidenceError("RECORD_INVALID")
        try:
            body = json.dumps({"schema": 1, "storage": "local-unattested (not gateway attestation)", "record": record},
                              sort_keys=True, indent=1, default=str).encode() + b"\n"
        except (TypeError, ValueError):
            raise EvidenceError("RECORD_INVALID") from None
        digest = hashlib.sha256(body).hexdigest()
        device = _SAFE.sub("-", str(record.get("device") or "device"))[:40].strip("-") or "device"
        stamp = re.sub(r"[^0-9TZ]", "", _compact_time(record.get("captured_at"))) or "00000000T000000Z"
        nonce = re.sub(r"[^0-9a-f]", "", str(record.get("nonce") or "").lower())[:16]
        name = f"obs-{device}-{stamp}-{nonce if len(nonce) >= 8 else digest[:16]}.json"
        if not _NAME.fullmatch(name):
            raise EvidenceError("FILENAME_INVALID")
        self._write_exclusive(name, body)
        ref = f"{SCHEME}:{name}#sha256={digest}"
        self.references.append(ref)
        return ref

    def _write_exclusive(self, name: str, body: bytes) -> None:
        final = self.directory / name
        tmp = self.directory / f".{name}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        fd = -1
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(tmp, final)                      # fails with FileExistsError instead of overwriting
            _fsync_dir(self.directory)
        except FileExistsError:
            raise EvidenceError("EVIDENCE_EXISTS") from None
        except OSError:
            raise EvidenceError("EVIDENCE_WRITE_FAILED") from None
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _compact_time(value) -> str:
    text = str(value or "")
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", text)
    return f"{m[1]}{m[2]}{m[3]}T{m[4]}{m[5]}{m[6]}Z" if m else ""


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_reference(directory, reference: str, approved_roots=APPROVED_ROOTS) -> dict:
    """Independently re-read the retained file and check its digest; return the stored record or raise ``EvidenceError``."""
    m = _REF.fullmatch(str(reference or ""))
    if not m:
        raise EvidenceError("REFERENCE_INVALID")
    base = validate_directory(directory, approved_roots)
    path = base / m["name"]
    if path.is_symlink() or path.parent != base:
        raise EvidenceError("REFERENCE_INVALID")
    try:
        body = path.read_bytes()
    except OSError:
        raise EvidenceError("EVIDENCE_MISSING") from None
    if hashlib.sha256(body).hexdigest() != m["digest"]:
        raise EvidenceError("DIGEST_MISMATCH")
    return json.loads(body)["record"]
