"""Raw Configlet persistence: stable identity, immutable revisions, soft enable / disable, and the effective Change input.

Everything semantic is on the immutable revision, so "editing" is always a NEW revision (an identical save is an idempotent no-op).
Text and metadata are validated SERVER-side before anything is persisted: a revision that fails the static gate -- in particular a
secret-shaped line -- is refused and never stored.  Nothing here verifies, plans, contacts a device or writes NetBox / Git.
"""

from __future__ import annotations

import re

from django.db import IntegrityError, transaction

from ... import models
from ..ci import redact as ci_redact
from . import assertions as assertions_module, capability, codes, static_gate, text as text_module, verification
from .codes import finding

_NODE_REF_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}/[a-z][a-z0-9_]{0,40}/[A-Za-z0-9_.:#-]{1,80}$")
_PRINTABLE_RE = re.compile(r"^[\x20-\x7E]*$")
MAX_ID_RETRIES = 10


class RawConfigletError(ValueError):
    """A refused save: carries the structured findings (stable codes) so the UI can show them.  Nothing was persisted."""

    def __init__(self, findings: list[dict]):
        super().__init__("; ".join(f["code"] for f in findings))
        self.findings = findings


def node_id(device: str, raw_id: str) -> str:
    """The stable dependency-graph reference of a Raw Configlet (never a display name, never a database id)."""
    return f"{device}/raw_configlet/{raw_id}"


def _intent_for(change, device: str):
    return change.device_intents.filter(device_name=device).first()


def _clean_text(value, *, limit: int, multiline: bool = False) -> str | None:
    value = str(value or "").replace("\r\n", "\n").strip()
    pattern = re.compile(r"^[\x20-\x7E\n]*$") if multiline else _PRINTABLE_RE
    if len(value) > limit or not pattern.match(value) or any(ci_redact.scan_line(line) for line in value.splitlines()):
        return None
    return value


def validate_authoring(change, *, target_device, name, description, priority, content, dependencies, assertions, own_node: str | None = None):
    """-> (clean fields dict, findings).  ``findings`` non-blocking means the save may proceed."""
    findings: list[dict] = []
    clean_name = _clean_text(name, limit=codes.MAX_NAME_LENGTH)
    if not clean_name:
        findings.append(finding("RAW_NAME_INVALID"))
    clean_description = _clean_text(description, limit=codes.MAX_DESCRIPTION_LENGTH, multiline=True)
    if clean_description is None:
        findings.append(finding("RAW_NAME_INVALID", "The description must be short printable text without credentials."))

    intent = _intent_for(change, str(target_device or "").strip())
    if intent is None:
        findings.append(finding("RAW_TARGET_INVALID"))
        platform = ""
    else:
        platform = intent.platform
        if not capability.can_author(platform):
            cap = capability.verification_capability(platform)
            findings.append(finding("RAW_PLATFORM_UNSUPPORTED", f"Raw verification is {cap.status} for platform {platform}."))

    try:
        priority_value = int(priority)
        if priority_value not in models.DeploymentPriority.values:
            raise ValueError
    except (TypeError, ValueError):
        findings.append(finding("RAW_PRIORITY_INVALID"))
        priority_value = 0

    refs = sorted({str(ref).strip() for ref in (dependencies or []) if str(ref).strip()})
    if len(refs) > codes.MAX_DEPENDENCIES:
        findings.append(finding("RAW_DEPENDENCY_INVALID", f"At most {codes.MAX_DEPENDENCIES} dependencies are allowed."))
    for ref in refs:
        if not _NODE_REF_RE.match(ref):
            findings.append(finding("RAW_DEPENDENCY_INVALID", "A dependency reference is malformed.", reference=ref[:80]))
        elif own_node and ref == own_node:
            findings.append(finding("RAW_DEPENDENCY_SELF"))

    clean_assertions, assertion_errors = assertions_module.normalize(assertions)
    for message in assertion_errors:
        findings.append(finding("RAW_ASSERTION_INVALID", message))

    gate = static_gate.evaluate(content)
    findings.extend(gate.findings)
    clean = {
        "name": clean_name or "", "description": clean_description or "", "target_device": str(target_device or "").strip(),
        "platform": platform, "priority": priority_value, "dependencies": refs, "assertions": clean_assertions,
        "content": gate.normalized,
    }
    return clean, findings


def redisplay_safe(fields: dict, findings: list[dict]) -> dict:
    """A copy of a REFUSED submission that is safe to render back to the operator.

    A refused secret must not be echoed either: lines the gate flagged as secret-shaped are replaced by a placeholder comment, and a
    name / description that failed the credential check is blanked.  Everything else is kept so the operator can fix and resubmit.
    """
    safe = dict(fields)
    flagged = {f["line"] for f in findings if f["code"] == "RAW_SECRET_SHAPED_CONTENT" and f.get("line")}
    if flagged and isinstance(safe.get("content"), str):
        lines = safe["content"].replace("\r\n", "\n").replace("\r", "\n").split("\n")
        safe["content"] = "\n".join(
            f"! [line {number}: secret-shaped content was not kept]" if number in flagged else line for number, line in enumerate(lines, start=1)
        )
    if any(f["code"] == "RAW_NAME_INVALID" for f in findings):
        safe["name"], safe["description"] = "", ""
    return safe


def _audit(change, event_type: str, summary: str, actor: str, metadata: dict, *, object_id: str) -> None:
    models.AuditEvent.objects.create(
        event_type=event_type, change=change, object_type="RawConfiglet", object_id=object_id, actor=actor, summary=summary[:255], metadata=metadata,
    )


def _next_sequence(change) -> int:
    last = change.raw_configlets.order_by("-sequence").values_list("sequence", flat=True).first()
    return (last or 0) + 1


def _new_revision(raw, clean: dict, number: int, actor: str) -> models.RawConfigletRevision:
    normalized = clean["content"]
    return models.RawConfigletRevision.objects.create(
        raw=raw, revision=number, schema_version=codes.SCHEMA_VERSION, name=clean["name"], description=clean["description"],
        target_device=clean["target_device"], platform=clean["platform"], priority=clean["priority"], dependencies=clean["dependencies"],
        assertions=clean["assertions"], content=normalized, content_hash=text_module.content_hash(normalized),
        content_bytes=len(normalized.encode("utf-8")), content_lines=len(normalized.splitlines()), policy_version=codes.POLICY_VERSION,
        created_by=actor,
    )


def _blocking(findings: list[dict]) -> bool:
    return any(f["blocking"] for f in findings)


def create_raw_configlet(change, *, target_device, name, content, priority, description="", dependencies=(), assertions=(), actor="") -> tuple:
    """-> (raw, first revision).  Raises ``RawConfigletError`` (nothing persisted) when any check fails."""
    for _ in range(MAX_ID_RETRIES):
        sequence = _next_sequence(change)
        raw_id = f"RAW-{sequence:03d}"
        clean, findings = validate_authoring(
            change, target_device=target_device, name=name, description=description, priority=priority, content=content,
            dependencies=dependencies, assertions=assertions, own_node=node_id(str(target_device or "").strip(), raw_id),
        )
        if _blocking(findings):
            raise RawConfigletError(findings)
        try:
            with transaction.atomic():
                raw = models.RawConfiglet.objects.create(change=change, raw_id=raw_id, sequence=sequence, created_by=actor)
                revision = _new_revision(raw, clean, 1, actor)
                _audit(change, models.AuditEventType.RAW_CONFIGLET_CREATED, f"{change.change_id}: {raw_id} created for {clean['target_device']}", actor,
                       {"raw_id": raw_id, "revision": 1, "device": clean["target_device"], "platform": clean["platform"], "priority": clean["priority"],
                        "content_hash": revision.content_hash}, object_id=raw_id)
            return raw, revision
        except IntegrityError:  # a concurrent creation took this id: the DB UNIQUE constraint decides, we retry with the next
            continue
    raise RuntimeError("Could not allocate a Raw Configlet identifier.")


def save_revision(raw, *, target_device, name, content, priority, description="", dependencies=(), assertions=(), actor="") -> tuple:
    """-> (revision, created).  A NEW immutable revision unless nothing changed (then the latest one, ``created=False``)."""
    change = raw.change
    clean, findings = validate_authoring(
        change, target_device=target_device, name=name, description=description, priority=priority, content=content,
        dependencies=dependencies, assertions=assertions, own_node=node_id(str(target_device or "").strip(), raw.raw_id),
    )
    if _blocking(findings):
        raise RawConfigletError(findings)
    with transaction.atomic():
        latest = raw.latest_revision()
        digest = text_module.content_hash(clean["content"])
        same = latest is not None and (
            latest.content_hash == digest and latest.name == clean["name"] and latest.description == clean["description"]
            and latest.target_device == clean["target_device"] and latest.platform == clean["platform"] and latest.priority == clean["priority"]
            and list(latest.dependencies) == clean["dependencies"] and list(latest.assertions) == clean["assertions"]
        )
        if same:
            return latest, False
        number = (latest.revision if latest else 0) + 1
        revision = _new_revision(raw, clean, number, actor)
        _audit(change, models.AuditEventType.RAW_REVISION_SAVED, f"{change.change_id}: {raw.raw_id} revision {number} saved", actor,
               {"raw_id": raw.raw_id, "revision": number, "device": clean["target_device"], "platform": clean["platform"],
                "priority": clean["priority"], "content_hash": revision.content_hash,
                "previous_content_hash": latest.content_hash if latest else ""}, object_id=raw.raw_id)
    return revision, True


def set_enabled(raw, enabled: bool, *, actor: str = "") -> bool:
    """Add to / remove from the EFFECTIVE Change input.  Soft: revisions, verifications and historical plans are untouched."""
    enabled = bool(enabled)
    if raw.enabled == enabled:
        return False
    with transaction.atomic():
        raw.enabled = enabled
        raw.save(update_fields=["enabled", "updated_at"])
        _audit(raw.change, models.AuditEventType.RAW_ENABLED_CHANGED,
               f"{raw.change.change_id}: {raw.raw_id} {'added to' if enabled else 'removed from'} the effective Change", actor,
               {"raw_id": raw.raw_id, "enabled": enabled}, object_id=raw.raw_id)
    return True


# --- reads ----------------------------------------------------------------------------------------------------------------------
def list_raw(change):
    return list(change.raw_configlets.order_by("sequence"))


def get_raw(change, raw_id: str):
    return change.raw_configlets.filter(raw_id=str(raw_id)).first()


def get_revision(raw, number):
    try:
        return raw.revisions.filter(revision=int(number)).first()
    except (TypeError, ValueError):
        return None


def get_verification_run(raw, run_id):
    import uuid

    try:
        parsed = uuid.UUID(str(run_id))
    except ValueError:
        return None
    return models.RawConfigletVerificationRun.objects.filter(run_id=parsed, revision__raw=raw).select_related("revision").first()


def snapshot_entries(change) -> list[dict]:
    """The EFFECTIVE Change input contributed by Raw Configlets: every ENABLED one's latest revision + its verification status.

    Deterministic (ordered by ``raw_id``).  Verification status is part of the hashed input on purpose: re-verifying, or a
    verification going STALE (policy / verifier / backend / platform change), changes the effective input, so an earlier validation
    or plan can no longer be CURRENT.  Text is never in the snapshot -- only the revision number and its content hash.
    """
    entries = []
    intents = {intent.device_name: intent.platform for intent in change.device_intents.all()}
    for raw in change.raw_configlets.filter(enabled=True).order_by("raw_id"):
        revision = raw.latest_revision()
        if revision is None:
            continue
        current_platform = intents.get(revision.target_device, "")
        status = verification.currency(revision, current_platform=current_platform or None)
        run = status["run"]
        entries.append({
            "raw_id": raw.raw_id, "node_id": node_id(revision.target_device, raw.raw_id), "name": revision.name,
            "device": revision.target_device, "platform": revision.platform, "current_platform": current_platform,
            "revision": revision.revision, "content_hash": revision.content_hash, "priority": revision.priority,
            "dependencies": sorted(revision.dependencies), "assertions": list(revision.assertions),
            "verification": {
                "currency": status["state"], "reasons": list(status["reasons"]), "result": status["result"],
                "run_id": str(run.run_id) if run else "", "policy_version": run.policy_version if run else "",
                "verifier": f"{run.adapter_id}@{run.adapter_version}" if run else "", "backend": run.backend if run else "",
            },
        })
    return entries


def status_of(raw) -> dict:
    """UI status of a Raw Configlet's LATEST revision (currency + result + in-progress flag).  Never starts anything."""
    revision = raw.latest_revision()
    if revision is None:
        return {"revision": None, "currency": codes.Currency.NEVER_RUN, "result": None, "run": None, "reasons": [], "in_progress": False}
    intent = _intent_for(raw.change, revision.target_device)
    status = verification.currency(revision, current_platform=intent.platform if intent else None)
    return {"revision": revision, "currency": status["state"], "result": status["result"], "run": status["run"], "reasons": status["reasons"],
            "in_progress": verification.active_run(revision) is not None, "acceptable": verification.acceptable(status)}
