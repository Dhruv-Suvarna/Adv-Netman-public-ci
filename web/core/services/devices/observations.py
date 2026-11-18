"""Authenticated device observations: current NOS version persistence bound to a host-key-pinned identity observation.

A trusted collector (a service that holds an authorized read-only management session, e.g. the gateway-backed
``NetmikoAdapter``) submits an *envelope*: the raw output of the platform's version command, the SSH host key of the session,
a nonce and the observation time, authenticated with an HMAC-SHA256 over the canonical envelope under that collector's
registered key.  ``ingest`` then

  1. authenticates the collector (unknown source / bad signature -> refused, nothing written),
  2. refuses excluded (read-only / out-of-scope) devices, unknown or terminal devices, unsupported platforms and commands,
  3. parses the version with the platform's own parser from the raw output (never an image default, inventory ``os_version`` or
     capability-ledger value) and recomputes the raw-output digest itself,
  4. refuses stale, future-dated, replayed (source nonce) and out-of-order observations,
  5. records the identity claims (serial, base MAC, host key) as an ``AUTHENTICATED_SESSION`` ``DeviceObservation`` through
     ``lifecycle.record_observation`` -- which can only deny, never verify -- and refuses a contradicting identity,
  6. appends an immutable ``DeviceVersionObservation``.

Nothing here verifies identity, admits a device or edits lifecycle state beyond what ``record_observation`` already does for any
observation.  ``lifecycle.verify_identity`` stays a separate human action that must be taken by someone other than the recorder.

``observed_version`` is the read-only consumer API (database reads only): the current version only while the observation is
fresh, the device identity is VERIFIED and the observation's host key is the verified one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from . import identity, lifecycle, resolver

DEFAULT_INGEST_MAX_AGE = 3600          # a submitted observation older than this is refused as stale
DEFAULT_CURRENT_MAX_AGE = 86400        # an accepted version older than this is no longer "current"
CLOCK_SKEW = 60                        # seconds an observation may be dated into the future
SOURCE_PREFIX = "source:"
_VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)?[A-Za-z0-9]{0,8}(?:[-.][A-Za-z0-9.]{1,24})?$")
_NONCE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_SOURCE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ENV = re.compile(r"^NMAS_OBSERVATION_KEY(?:_[A-Z0-9]{1,32})?$")   # dedicated variable namespace (never another service secret)
MAX_OUTPUT = 256 * 1024

REFUSALS = {
    "ENVELOPE_INVALID": "The observation envelope is malformed.",
    "SOURCE_UNTRUSTED": "The collector is not a registered trusted observation source.",
    "SIGNATURE_INVALID": "The envelope signature does not verify under the source's key.",
    "DEVICE_UNKNOWN": "No live managed device has this name.",
    "DEVICE_EXCLUDED": "The device is excluded from NMAS management scope (read-only inventory such as R5).",
    "PLATFORM_UNSUPPORTED": "No supported version parser exists for the device platform.",
    "SOURCE_NOT_ALLOWED": "The source is not registered for this device platform.",
    "COMMAND_MISMATCH": "The command is not the platform's read-only version command.",
    "PARSE_FAILED": "The raw output is not a recognisable version report for the platform.",
    "OBSERVATION_STALE": "The observation is older than the freshness limit.",
    "OBSERVATION_FUTURE": "The observation is dated in the future.",
    "OBSERVATION_OUT_OF_ORDER": "A newer or equal observation for this device is already recorded.",
    "REPLAY": "This nonce or raw output was already recorded.",
    "IDENTITY_MISMATCH": "The observed identity contradicts the authorized or verified identity.",
    "IDENTITY_RECORD_REFUSED": "The lifecycle service refused the identity observation.",
}


@dataclass
class Spec:
    platform: str
    command: str
    parse: callable          # raw output -> {"version": str, "serial": str, "base_mac": str} | None


def _parse_eos(output: str):
    start = str(output or "").find("{")
    try:
        data = json.loads(output[start:]) if start >= 0 else None
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("mfgName") != "Arista":
        return None
    return {"version": str(data.get("version") or "").split(maxsplit=1)[0], "serial": str(data.get("serialNumber") or "").strip(),
            "base_mac": str(data.get("systemMacAddress") or "").strip().lower()}


def _parse_iosxe(output: str):
    release = re.search(r"^Cisco IOS XE Software, Version (\d+\.\d+\.\d+\w*)", output, re.M)
    serial = re.search(r"^Processor board ID (\S+)", output, re.M)
    if not release:
        return None
    return {"version": release.group(1), "serial": serial.group(1) if serial else "", "base_mac": ""}


def _parse_frr(output: str):
    release = re.search(r"^FRRouting (\d+\.\d+(?:\.\d+)?)\b", output, re.M)
    return {"version": release.group(1), "serial": "", "base_mac": ""} if release else None


SPECS = {
    models.Platform.ARISTA_CEOS: Spec(models.Platform.ARISTA_CEOS, "show version | json", _parse_eos),
    models.Platform.CISCO_C8000V_IOSXE: Spec(models.Platform.CISCO_C8000V_IOSXE, "show version", _parse_iosxe),
    models.Platform.UBUNTU_FRR: Spec(models.Platform.UBUNTU_FRR, "vtysh -c 'show version'", _parse_frr),
}


@dataclass
class IngestResult:
    ok: bool
    codes: list = field(default_factory=list)
    record: object | None = None
    identity_observation: object | None = None

    @property
    def messages(self) -> list[str]:
        return [REFUSALS.get(code, code) for code in self.codes]


def _refuse(*codes_: str) -> IngestResult:
    return IngestResult(False, list(codes_))


# --- authentication -----------------------------------------------------------------------------------------------------------
MIN_KEY_LENGTH = 32
MIN_KEY_DISTINCT = 10   # rejects degenerate keys ("kkkk...", "abab..."); a secrets.token_hex(32) key fails with p ≈ 1.2e-12


def key_is_strong(key: str) -> bool:
    """Shape check for an observation HMAC key (the operator generates it with ``secrets.token_hex(32)``)."""
    return len(key) >= MIN_KEY_LENGTH and len(set(key)) >= MIN_KEY_DISTINCT


def trusted_sources() -> dict[str, dict]:
    """Registered collectors from ``settings.NMAS_OBSERVATION_SOURCES``: ``{source_id: {"key_env": "ENV_NAME", "platforms": [...]}}``.

    The key is read from the named environment variable at use time and never stored or logged.  Absent / unset = untrusted.
    Fail closed (the source is simply untrusted) when the entry carries anything but ``key_env`` / ``platforms`` (key material
    must never be configured in settings or source), when ``key_env`` is not a dedicated ``NMAS_OBSERVATION_KEY*`` variable (so
    it cannot point at another service secret), when the key fails ``key_is_strong`` (shorter than 32 characters or fewer than 10
    distinct characters), or when it equals the Django ``SECRET_KEY``.
    """
    found = {}
    secret = str(getattr(settings, "SECRET_KEY", "") or "")
    for source_id, entry in (getattr(settings, "NMAS_OBSERVATION_SOURCES", None) or {}).items():
        entry = entry if isinstance(entry, dict) else {}
        key_env = str(entry.get("key_env") or "")
        if set(entry) - {"key_env", "platforms"} or not _KEY_ENV.fullmatch(key_env):
            continue
        key = os.environ.get(key_env, "")
        if _SOURCE_ID.fullmatch(str(source_id)) and key_is_strong(key) and key != secret:
            found[str(source_id)] = {"key": key.encode(), "platforms": tuple(entry.get("platforms") or ())}
    return found


def _instant(value) -> str:
    """The signed timestamp is the UTC instant, so any equivalent ISO spelling (``Z`` / ``+00:00``) signs identically."""
    parsed = _parse_time(value) if not isinstance(value, datetime) else value.astimezone(dt_timezone.utc)
    return parsed.isoformat() if parsed else ""


def canonical(device_name: str, envelope: dict, raw_digest: str) -> bytes:
    body = {"device": device_name, "source_id": envelope.get("source_id"), "nonce": envelope.get("nonce"),
            "command": envelope.get("command"), "observed_at": _instant(envelope.get("observed_at")), "host_key": envelope.get("host_key"),
            "evidence_ref": envelope.get("evidence_ref", ""), "raw_digest": raw_digest}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign(key: bytes, device_name: str, envelope: dict) -> str:
    """Collector-side helper: the HMAC-SHA256 hex over the canonical envelope (device-, nonce- and digest-bound)."""
    digest = hashlib.sha256(str(envelope.get("output", "")).encode()).hexdigest()
    return hmac.new(key, canonical(device_name, envelope, digest), hashlib.sha256).hexdigest()


def _parse_time(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(dt_timezone.utc) if parsed.tzinfo else None


def _envelope_problem(envelope) -> bool:
    if not isinstance(envelope, dict):
        return True
    output = envelope.get("output")
    return (not isinstance(output, str) or not output or len(output) > MAX_OUTPUT
            or not _SOURCE_ID.fullmatch(str(envelope.get("source_id", ""))) or not _NONCE.fullmatch(str(envelope.get("nonce", "")))
            or not _DIGEST.fullmatch(str(envelope.get("signature", "")))
            or not isinstance(envelope.get("command"), str) or _parse_time(envelope.get("observed_at")) is None
            or not isinstance(envelope.get("evidence_ref", ""), str))


# --- ingest -------------------------------------------------------------------------------------------------------------------
def ingest(device_name: str, envelope: dict, *, sources: dict | None = None, now: datetime | None = None,
           max_age: int = DEFAULT_INGEST_MAX_AGE) -> IngestResult:
    """Authenticate and persist one observation.  Writes only on acceptance (plus the identity observation recorded with it)."""
    now = now or timezone.now()
    if _envelope_problem(envelope):
        return _refuse("ENVELOPE_INVALID")
    sources = trusted_sources() if sources is None else sources
    source = sources.get(envelope["source_id"])
    if source is None or not source.get("key"):
        return _refuse("SOURCE_UNTRUSTED")
    raw_digest = hashlib.sha256(envelope["output"].encode()).hexdigest()
    expected = hmac.new(source["key"], canonical(str(device_name), envelope, raw_digest), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope["signature"]):
        return _refuse("SIGNATURE_INVALID")
    ref, problems = identity.clean_text(envelope.get("evidence_ref", ""), max_length=200)
    host_key, host_problems = identity.normalize_host_key(envelope.get("host_key"))
    if problems or host_problems or not host_key:
        return _refuse("ENVELOPE_INVALID")

    target = resolver.resolve(str(device_name))
    if target is not None and target.scope == resolver.Scope.READ_ONLY:
        return _refuse("DEVICE_EXCLUDED")
    device = models.ManagedDevice.objects.filter(identity.LIVE, name=str(device_name)).first()
    if device is None:
        return _refuse("DEVICE_UNKNOWN")
    spec = SPECS.get(device.platform)
    if spec is None:
        return _refuse("PLATFORM_UNSUPPORTED")
    if source["platforms"] and device.platform not in source["platforms"]:
        return _refuse("SOURCE_NOT_ALLOWED")
    if envelope["command"] != spec.command:
        return _refuse("COMMAND_MISMATCH")
    parsed = spec.parse(envelope["output"])
    if not parsed or not _VERSION.fullmatch(parsed["version"]):
        return _refuse("PARSE_FAILED")

    observed_at = _parse_time(envelope["observed_at"])
    if observed_at > now + timedelta(seconds=CLOCK_SKEW):
        return _refuse("OBSERVATION_FUTURE")
    if observed_at < now - timedelta(seconds=max_age):
        return _refuse("OBSERVATION_STALE")
    if models.DeviceVersionObservation.objects.filter(source_id=envelope["source_id"], nonce=envelope["nonce"]).exists():
        return _refuse("REPLAY")
    latest = models.DeviceVersionObservation.objects.filter(device=device).order_by("-observed_at").values_list("observed_at", flat=True).first()
    if latest is not None and observed_at <= latest:
        return _refuse("OBSERVATION_OUT_OF_ORDER")

    claims = {"host_key": host_key}
    if parsed["serial"]:
        claims["serial"] = parsed["serial"]
    if parsed["base_mac"]:
        claims["base_mac"] = parsed["base_mac"]
    recorded = lifecycle.record_observation(
        device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.AUTHENTICATED_SESSION,
        actor=f"{SOURCE_PREFIX}{envelope['source_id']}", actor_kind=lifecycle.AUTOMATION, claims=claims, observed_at=observed_at,
        correlation_id=f"version:{envelope['nonce']}")
    observation = getattr(recorded, "observation", None)
    if not recorded.ok or observation is None:
        return _refuse("IDENTITY_RECORD_REFUSED", *recorded.codes)
    if observation.result == models.ObservationResult.MISMATCH:
        return IngestResult(False, ["IDENTITY_MISMATCH"], None, observation)
    try:
        with transaction.atomic():
            row = models.DeviceVersionObservation.objects.create(
                device=device, platform=device.platform, version=parsed["version"], source_id=envelope["source_id"],
                nonce=envelope["nonce"], command=spec.command, raw_digest=raw_digest, evidence_ref=ref, signature=envelope["signature"],
                host_key=host_key, serial=claims.get("serial", ""), base_mac=claims.get("base_mac", ""), identity_observation=observation,
                observed_at=observed_at)
    except IntegrityError:
        return _refuse("REPLAY")
    return IngestResult(True, [], row, observation)


def reverify(row, raw_output: str, *, sources: dict | None = None) -> bool:
    """Independent re-check of a stored row against the retained raw evidence: digest, signature and parsed version all agree."""
    sources = trusted_sources() if sources is None else sources
    source = sources.get(row.source_id)
    spec = SPECS.get(row.platform)
    if source is None or spec is None or hashlib.sha256(raw_output.encode()).hexdigest() != row.raw_digest:
        return False
    envelope = {"source_id": row.source_id, "nonce": row.nonce, "command": row.command, "evidence_ref": row.evidence_ref,
                "host_key": row.host_key, "observed_at": row.observed_at}
    wanted = hmac.new(source["key"], canonical(row.device.name, envelope, row.raw_digest), hashlib.sha256).hexdigest()
    parsed = spec.parse(raw_output)
    return bool(parsed) and parsed["version"] == row.version and hmac.compare_digest(wanted, row.signature)


# --- read API (database reads only; no approval side effects) -------------------------------------------------------------------
def current_max_age() -> int:
    return int(getattr(settings, "NMAS_VERSION_MAX_AGE_SECONDS", DEFAULT_CURRENT_MAX_AGE))


def current(device_name: str, *, now: datetime | None = None, max_age: int | None = None) -> dict:
    """Provenance and freshness of the device's latest accepted version observation.

    -> ``{"version", "usable", "reason", "observed_at", "age_seconds", "fresh", "source_id", "host_key", "raw_digest",
    "evidence_ref", "platform", "identity_observation"}``; ``usable`` is True only when ``version`` may be treated as the
    authoritative current version.  ``reason`` is "" when usable, else one of NO_DEVICE, NO_OBSERVATION, STALE,
    IDENTITY_NOT_VERIFIED, HOST_KEY_CHANGED, PLATFORM_CHANGED, IDENTITY_CONTRADICTED.
    """
    now = now or timezone.now()
    max_age = current_max_age() if max_age is None else max_age
    device = models.ManagedDevice.objects.filter(identity.LIVE, name=str(device_name)).first()
    out = {"version": None, "usable": False, "reason": "NO_DEVICE", "observed_at": None, "age_seconds": None, "fresh": False,
           "source_id": "", "host_key": "", "raw_digest": "", "evidence_ref": "", "platform": "", "identity_observation": None}
    if device is None:
        return out
    row = models.DeviceVersionObservation.objects.filter(device=device).order_by("-observed_at", "-id").first()
    if row is None:
        return {**out, "reason": "NO_OBSERVATION"}
    age = max(0, int((now - row.observed_at).total_seconds()))
    out.update(version=row.version, observed_at=row.observed_at, age_seconds=age, fresh=age <= max_age, source_id=row.source_id,
               host_key=row.host_key, raw_digest=row.raw_digest, evidence_ref=row.evidence_ref, platform=row.platform,
               identity_observation=row.identity_observation_id)
    if age > max_age:
        reason = "STALE"
    elif device.identity_state != models.IdentityVerificationState.VERIFIED:
        reason = "IDENTITY_NOT_VERIFIED"
    elif row.host_key != device.verified_host_key:
        reason = "HOST_KEY_CHANGED"
    elif row.platform != device.platform:
        reason = "PLATFORM_CHANGED"
    elif models.DeviceObservation.objects.filter(
            device=device, kind=models.ObservationKind.IDENTITY, trust=models.ObservationTrust.OBSERVED,
            result=models.ObservationResult.MISMATCH, observed_at__gt=row.observed_at).exists():
        reason = "IDENTITY_CONTRADICTED"
    else:
        reason = ""
    out.update(reason=reason, usable=not reason)
    return out


def observed_version(device_name: str) -> str | None:
    """The authoritative current NOS version string of ``device_name``, or None.  Database reads only; never approves anything."""
    info = current(device_name)
    return info["version"] if info["usable"] else None
