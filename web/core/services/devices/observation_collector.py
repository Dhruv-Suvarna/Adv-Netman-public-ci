"""Governed read-only observation collector: bridges an injected, authorized, host-key-pinned session to ``observations.ingest``.

The bridge is deliberately thin.  It owns no credentials, opens no connection and decides nothing about identity:

  1. the target comes from the authoritative resolver (``resolver.resolve``); READ_ONLY / NOT_MANAGED_YET scope (e.g. R5) is refused;
  2. the command is the platform's own ``observations.SPECS`` version command (nothing else is ever sent);
  3. the injected ``session_provider(target, address)`` returns a session whose *own* attributes prove the provenance
     (``transport == "SSH"``, ``address`` among the resolver's declared management candidates, ``read_only``, ``authorization_ref``,
     ``host_key_pinned`` and the actually presented ``host_key``).  Docker / Containerlab runtime paths are never accepted;
  4. the raw output is retained through the injected ``evidence_sink`` *before* ingest; no retained reference -> nothing is submitted;
  5. the envelope (fresh nonce, capture timestamp, session host key, evidence reference) is signed with the injected source's key
     and handed to ``observations.ingest``, which remains the only writer.

Fail closed: any missing authorization, provenance or retention yields a refusal with a code and no ingest call.  The bridge never
calls ``lifecycle.verify_identity`` / admission / deployment; see ``docs/troubleshooting/observation-collector.md``.
"""

from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass, field
from datetime import datetime

from django.utils import timezone

from ... import models
from . import identity, observations, resolver

REFUSALS = {
    "SOURCE_UNCONFIGURED": "The collector source is not configured with a signing key.",
    "TARGET_UNKNOWN": "The authoritative resolver does not know this device.",
    "TARGET_NOT_MANAGEABLE": "The device is read-only, excluded or not yet reachable; it is not observed.",
    "PLATFORM_UNSUPPORTED": "No allowlisted version command exists for the device platform.",
    "NO_MANAGEMENT_PATH": "The resolver declares no SSH management address for the device.",
    "SESSION_UNAVAILABLE": "No authorized read-only session could be provided.",
    "SESSION_NOT_SSH": "The session is not an inventory-declared SSH management session (Docker/Containerlab paths are refused).",
    "SESSION_ADDRESS_NOT_DECLARED": "The session address is not a resolver-declared management candidate.",
    "SESSION_NOT_READ_ONLY": "The session is not marked read-only.",
    "SESSION_NOT_AUTHORIZED": "The session carries no authorization reference.",
    "HOST_KEY_NOT_PINNED": "The session did not verify a pinned host key.",
    "HOST_KEY_MISSING": "The session presented no valid host key.",
    "SESSION_FAILED": "The version command failed on the session.",
    "OUTPUT_EMPTY": "The session returned no output.",
    "EVIDENCE_UNAVAILABLE": "The raw output could not be retained; the observation is not submitted.",
    "AUTHORIZATION_UNVERIFIABLE": "The observation authorization could not be re-checked before ingest; nothing is submitted.",
}


@dataclass
class CollectResult:
    ok: bool
    codes: list = field(default_factory=list)
    ingest: object | None = None
    evidence_ref: str = ""

    @property
    def record(self):
        return getattr(self.ingest, "record", None)

    @property
    def messages(self) -> list[str]:
        return [REFUSALS.get(code) or observations.REFUSALS.get(code, code) for code in self.codes]


def _refuse(*codes) -> CollectResult:
    return CollectResult(False, list(codes))


def _close(session) -> None:
    closer = getattr(session, "close", None)
    if callable(closer):
        try:
            closer()
        except Exception:  # noqa: BLE001 - closing never changes the outcome
            pass


def collect(device_name: str, *, source_id: str, sources: dict, session_provider, evidence_sink, document: dict | None = None,
            now: datetime | None = None, nonce_factory=None, pre_ingest_guard=None) -> CollectResult:
    """Capture one version observation for ``device_name`` and submit it.  Never raises for operational failures.

    ``sources``: ``{source_id: {"key": bytes, "platforms": tuple}}`` (the shape of ``observations.trusted_sources()``).
    ``session_provider(target, address)`` -> session with ``execute(command) -> str``, ``close()`` and the provenance attributes above.
    ``evidence_sink(record: dict) -> str`` retains the raw output and returns a non-empty reference (<=200 chars).
    ``pre_ingest_guard() -> str`` (optional) is called after the evidence is retained and immediately before ingest; a non-empty
    code (e.g. ``AUTHORIZATION_EXPIRED`` / ``AUTHORIZATION_REVOKED``) refuses the observation and nothing is ingested.
    """
    source = (sources or {}).get(source_id)
    if not source or not source.get("key"):
        return _refuse("SOURCE_UNCONFIGURED")
    target = resolver.resolve(str(device_name), document=document)
    if target is None:
        return _refuse("TARGET_UNKNOWN")
    if target.scope not in resolver.WRITABLE_SCOPES:
        return _refuse("TARGET_NOT_MANAGEABLE")
    spec = observations.SPECS.get(target.platform)
    if spec is None:
        return _refuse("PLATFORM_UNSUPPORTED")
    candidates = [c for c in target.management_candidates if "SSH" in target.transports]
    if not candidates:
        return _refuse("NO_MANAGEMENT_PATH")

    session = None
    for candidate in candidates:                       # declared order; first the provider can serve
        try:
            session = session_provider(target, candidate.address)
        except Exception:  # noqa: BLE001 - provider detail may contain connection parameters
            session = None
        if session is not None:
            break
    if session is None:
        return _refuse("SESSION_UNAVAILABLE")
    try:
        problem = _session_problem(session, candidates)
        if problem:
            return _refuse(problem)
        host_key, bad = identity.normalize_host_key(getattr(session, "host_key", ""))
        if bad or not host_key:
            return _refuse("HOST_KEY_MISSING")
        try:
            output = session.execute(spec.command)
        except Exception:  # noqa: BLE001 - never echo connection details
            return _refuse("SESSION_FAILED")
        if not isinstance(output, str) or not output.strip():
            return _refuse("OUTPUT_EMPTY")
        captured_at = now or timezone.now()
        nonce = (nonce_factory or (lambda: secrets.token_hex(16)))()
        provenance = {"device": target.name, "platform": target.platform, "command": spec.command, "output": output,
                      "host_key": host_key, "address": session.address, "source_id": source_id, "nonce": nonce,
                      "captured_at": captured_at.isoformat(), "authorization_ref": str(session.authorization_ref),
                      "session_evidence": list(getattr(session, "evidence_refs", None) or ())}
        try:
            ref = evidence_sink(provenance)
        except Exception:  # noqa: BLE001
            ref = ""
        ref, bad = identity.clean_text(ref if isinstance(ref, str) else "", max_length=200)
        if bad or not ref:
            return _refuse("EVIDENCE_UNAVAILABLE")
    finally:
        _close(session)

    if pre_ingest_guard is not None:
        try:
            blocked = str(pre_ingest_guard() or "")
        except Exception:  # noqa: BLE001 - an unanswerable guard refuses
            blocked = "AUTHORIZATION_UNVERIFIABLE"
        if blocked:
            return CollectResult(False, [blocked], None, ref)
    envelope = {"source_id": source_id, "nonce": nonce, "command": spec.command, "output": output, "host_key": host_key,
                "evidence_ref": ref, "observed_at": captured_at.isoformat()}
    envelope["signature"] = observations.sign(source["key"], target.name, envelope)
    result = observations.ingest(target.name, envelope, sources=sources, now=now)
    return CollectResult(result.ok, list(result.codes), result, ref)


def _session_problem(session, candidates) -> str:
    if getattr(session, "transport", "") != "SSH":
        return "SESSION_NOT_SSH"
    try:
        address = str(ipaddress.ip_address(str(getattr(session, "address", ""))))
    except ValueError:
        return "SESSION_ADDRESS_NOT_DECLARED"
    if address not in {c.address for c in candidates}:
        return "SESSION_ADDRESS_NOT_DECLARED"
    if getattr(session, "read_only", False) is not True:
        return "SESSION_NOT_READ_ONLY"
    if not str(getattr(session, "authorization_ref", "") or "").strip():
        return "SESSION_NOT_AUTHORIZED"
    if getattr(session, "host_key_pinned", False) is not True:
        return "HOST_KEY_NOT_PINNED"
    return ""
