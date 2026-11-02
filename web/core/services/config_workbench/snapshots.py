"""Running-configuration snapshots for the workbench pages.  READ-ONLY toward devices.

Acquisition is the ONE existing path: ``config_import.service.fetch_running_config_outcome`` (the legacy-bootstrap /
Phase-15 read-only transport + ``bundles.legacy_sanitize``).  The digest is the SAME formula as the import provenance
(``running_config_digest``), so a Change built from a snapshot can prove its import matched what the operator saw, and
execution can refuse a basis that has since changed.

A capture happens only on an explicit operator POST ("Refresh running configuration") -- never on page load.
Limitation (inherited from the sanitizer, stated not hidden): a change to ONLY a redacted secret value does not change
the digest.

Configuration Changes and Remove Configuration share THIS module end to end: the same device scope (``scope``: NetBox-managed
AND inventory-capturable), the same transport and credential routing (``health.live`` -> the device-aware
``nsot_live.get_live_target`` resolver for cEOS, credential-free ``docker exec`` for Ubuntu/FRR), the same sanitizer, digest and
persistence.  Every refusal carries one stable code from ``CAPTURE_ERRORS`` with a fixed, secret-free message.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import DatabaseError
from django.utils import timezone

from ... import models
from ..bootstrap import capture as bootstrap_capture
from ..config_import import service as import_service
from . import scope as device_scope

# Tests replace this with a fake read-only session factory; None means the real read-only transport.
SESSION_FACTORY = None

PLATFORMS = device_scope.PLATFORMS
PRIMARY_SECTION = {"ceos": "running_config", "linux": "frr_config"}

CAPTURE_ERRORS = {
    "DEVICE_OUT_OF_SCOPE": "{device} is outside NMAS management scope; it cannot be captured or changed here.",
    "DEVICE_NOT_FOUND": "{device} is not a known managed device.",
    "MANAGEMENT_SCOPE_UNAVAILABLE": "The authoritative management scope (NetBox) could not be read; nothing was captured.",
    "UNSUPPORTED_PLATFORM": "Read-only running-configuration capture is not supported for the platform of {device}.",
    "ACCESS_TARGET_NOT_CONFIGURED": "No management access target is configured for {device}.",
    "CREDENTIAL_NOT_CONFIGURED": "No usable automation credential for {device} is available to this server's runtime credential store.",
    "AUTHENTICATION_FAILED": "{device} rejected the configured automation credential.",
    "CONNECTION_FAILED": "{device} could not be reached for a read-only capture.",
    "RETRIEVAL_FAILED": "The running configuration of {device} could not be read and sanitized completely; nothing was saved.",
    "SNAPSHOT_DATABASE_UNAVAILABLE": "The snapshot database is unavailable or not migrated on this server; nothing was captured.",
    "SNAPSHOT_STALE": "{device} no longer matches the captured snapshot; capture it again.",
}
# Refusals of the REQUEST itself (a crafted POST cannot pass them), as opposed to runtime / device failures.
SCOPE_REFUSALS = frozenset({"DEVICE_OUT_OF_SCOPE", "DEVICE_NOT_FOUND", "UNSUPPORTED_PLATFORM"})

# sanitized ``health.live`` / ``config_import`` codes -> capture codes (anything else: RETRIEVAL_FAILED)
_FETCH_CODES = {
    "DEVICE_NOT_FOUND": "DEVICE_NOT_FOUND", "UNSUPPORTED_PLATFORM": "UNSUPPORTED_PLATFORM", "NOT_SUPPORTED": "UNSUPPORTED_PLATFORM",
    "NOT_CONFIGURED": "ACCESS_TARGET_NOT_CONFIGURED", "CREDENTIAL_NOT_CONFIGURED": "CREDENTIAL_NOT_CONFIGURED",
    "AUTH_FAILED": "AUTHENTICATION_FAILED",
    "TIMEOUT": "CONNECTION_FAILED", "CONNECTION_FAILED": "CONNECTION_FAILED", "DOCKER_UNAVAILABLE": "CONNECTION_FAILED",
    "MANAGEMENT_UNREACHABLE": "CONNECTION_FAILED",
}


@dataclass(frozen=True)
class CaptureOutcome:
    snapshot: object = None
    code: str = ""
    message: str = ""

    @property
    def refused_request(self) -> bool:
        return self.code in SCOPE_REFUSALS


def _refusal(code: str, device_name: str) -> CaptureOutcome:
    return CaptureOutcome(code=code, message=f"{code}: {CAPTURE_ERRORS[code].format(device=device_name)}")


def workbench_scope() -> device_scope.WorkbenchScope:
    return device_scope.workbench_scope()


def workbench_devices() -> list[dict]:
    """Selectable devices for BOTH workbench pages (server-side list; never browser-supplied)."""
    return workbench_scope().devices


def device_platform(name: str) -> str | None:
    row, _code = device_scope.resolve(name)
    return row["platform"] if row else None


def _database_ready() -> bool:
    try:
        models.RunningConfigSnapshot.objects.exists()
    except DatabaseError:
        return False
    return True


def capture(device_name: str, *, actor: str = "", session_factory=None, now=None) -> CaptureOutcome:
    """The ONE explicit read-only capture: scope -> database -> fetch (sanitized) -> digest -> persist.  Sends no configuration."""
    return capture_with_sections(device_name, actor=actor, session_factory=session_factory, now=now)[0]


def capture_with_sections(device_name: str, *, actor: str = "", session_factory=None, now=None) -> tuple[CaptureOutcome, dict]:
    """``capture`` plus every sanitized section of the SAME read ({command_key: text}) -- V2 Phase 3 template extraction parses
    the secondary Linux sections (addresses, nftables) that the persisted snapshot text does not carry."""
    row, code = device_scope.resolve(device_name)
    if row is None:
        return _refusal(code, device_name), {}
    if not _database_ready():   # checked BEFORE contacting the device: a read nobody can store is not attempted
        return _refusal("SNAPSHOT_DATABASE_UNAVAILABLE", device_name), {}
    fetched, fetch_code, _message = import_service.fetch_running_config_outcome(
        device_name, session_factory=session_factory or SESSION_FACTORY, now=now)
    if fetched is None:
        return _refusal(_FETCH_CODES.get(fetch_code, "RETRIEVAL_FAILED"), device_name), {}
    entry, read, sections = fetched["entry"], fetched["read"], fetched["sections"]
    platform = entry.get("platform", "")
    by_key = {section["command_key"]: section for section in sections}
    primary = by_key.get(PRIMARY_SECTION.get(platform, ""))
    if primary is None:
        return _refusal("RETRIEVAL_FAILED", device_name), {}
    text = primary["sanitized"]
    try:
        snapshot = models.RunningConfigSnapshot.objects.create(
            device_name=device_name, platform=PLATFORMS[platform], digest=import_service.running_config_digest(sections), text=text,
            line_count=len(text.splitlines()), redacted_lines=int(primary.get("redacted_lines") or 0), source=bootstrap_capture.transport_of(entry)[:160],
            captured_at=read.read_at or now or timezone.now(), created_by=actor[:150],
        )
    except DatabaseError:
        return _refusal("SNAPSHOT_DATABASE_UNAVAILABLE", device_name), {}
    return CaptureOutcome(snapshot=snapshot), {key: section["sanitized"] for key, section in by_key.items()}


def capture_snapshot(device_name: str, *, actor: str = "", session_factory=None, now=None):
    """-> (RunningConfigSnapshot | None, error message).  One explicit read-only fetch (see ``capture``)."""
    outcome = capture(device_name, actor=actor, session_factory=session_factory, now=now)
    return outcome.snapshot, outcome.message


def recheck(snapshot, *, session_factory=None, now=None) -> dict:
    """Fresh read-only fetch: is the device still on exactly this snapshot?  Never mutates anything."""
    fetched, fetch_code, _message = import_service.fetch_running_config_outcome(
        snapshot.device_name, session_factory=session_factory or SESSION_FACTORY, now=now)
    if fetched is None:
        return {"current": False, "digest": "", "error": _FETCH_CODES.get(fetch_code, "RETRIEVAL_FAILED")}
    digest = import_service.running_config_digest(fetched["sections"])
    current = digest == snapshot.digest
    return {"current": current, "digest": digest, "error": "" if current else "SNAPSHOT_STALE"}


def numbered(snapshot, *, highlight=()) -> list[dict]:
    marked = set(highlight or ())
    return [{"number": n, "text": line, "highlight": n in marked} for n, line in enumerate(snapshot.text.splitlines(), start=1)]


def get_snapshot(snapshot_id, device_name: str | None = None):
    query = models.RunningConfigSnapshot.objects.filter(snapshot_id=snapshot_id)
    if device_name:
        query = query.filter(device_name=device_name)
    return query.first()
