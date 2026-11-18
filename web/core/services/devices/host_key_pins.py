"""Host-key pin enrollment evidence: derive a pin from independent device-side key material, never from a network handshake.

A pin (``SHA256:<43 base64 chars>``) is the trust anchor of every pinned NMAS management session, so it must come from a channel
that does NOT depend on the SSH path it will later protect.  This module is the read-only validation half of the enrollment
procedure in ``docs/troubleshooting/host-key-pin-enrollment.md``:

1. A *collector* captures the device's own **public host key** (not a fingerprint) through an independent device-side channel
   (``CHANNELS``): the device console, the container host's authorized administrator reading the node's
   ``/etc/ssh/ssh_host_*_key.pub``, NMAS's existing ZTP enrollment record, or the device's configuration/flash archive.  Network
   handshakes (``ssh-keyscan``, first-contact/TOFU, ``known_hosts``) are refused as ``CHANNEL_NOT_INDEPENDENT``.
2. A different *enroller* runs ``validate_evidence``: NMAS parses the SSH wire-format key blob itself and **computes** the
   fingerprint; a pin typed by a person is only compared with it, never trusted on its own.
3. ``compare_registered`` reports, read-only, how the computed pin relates to every pin NMAS already holds for the device
   (inventory ``ssh_host_key``, registered ``ManagementPath.expected_host_key``, ZTP ``enrolled_host_key``, the verified identity
   and the latest authenticated observation).  Any disagreement is a ``CONFLICT`` that blocks enrollment.
4. Enrollment then uses only the EXISTING mechanisms: for cEOS, ``management.paths.register_path(expected_host_key=<pin>)`` through
   the Management page followed by ``approve_path`` by a different account (self-approval is already refused); for Ubuntu/FRR
   (legacy route only), a reviewed Git change adding ``network_devices.<name>.ssh_host_key`` that cites the evidence digest.

Nothing here writes, connects, approves or reads a credential.  R5 and every read-only / excluded device are refused.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone as dt_timezone

from django.utils import timezone

from ... import models
from . import identity, resolver

SCHEMA = "nmas.host-key-pin-evidence/1"
MAX_EVIDENCE_AGE = timedelta(days=7)
CLOCK_SKEW = timedelta(minutes=5)
CHANNELS = {
    "DEVICE_CONSOLE": "device console (cEOS: show management ssh hostkey <type> public)",
    "CONTAINER_HOST_ADMIN": "container host administrator reading the node's /etc/ssh/ssh_host_<type>_key.pub",
    "ZTP_ENROLLMENT": "NMAS ZTP enrollment record (ZtpSession.enrolled_host_key) for a natively onboarded device",
    "CONFIG_ARCHIVE": "device configuration / flash archive copied by an authorized administrator",
}
FORBIDDEN_CHANNELS = {"SSH_HANDSHAKE", "SSH_KEYSCAN", "KNOWN_HOSTS", "TOFU", "FIRST_CONTACT", "NETWORK"}
KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa")
_PIN = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_COLLECTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,149}$")

REFUSALS = {
    "EVIDENCE_INVALID": "The evidence document is not a nmas.host-key-pin-evidence/1 object.",
    "DEVICE_UNKNOWN": "The device is not in the authoritative inventory.",
    "DEVICE_EXCLUDED": "The device is read-only / excluded (e.g. R5); no pin is enrolled for it.",
    "PLATFORM_MISMATCH": "The evidence platform is not the device's platform.",
    "CHANNEL_NOT_INDEPENDENT": "The key was obtained over the network path it would protect (keyscan / TOFU / known_hosts).",
    "CHANNEL_UNKNOWN": "The capture channel is not an approved device-side channel.",
    "COLLECTOR_MISSING": "The person who captured the key must be named.",
    "ENROLLER_NOT_INDEPENDENT": "The enroller may not validate key material they captured themselves.",
    "EVIDENCE_STALE": "The capture is older than the evidence age limit.",
    "EVIDENCE_FUTURE": "The capture is dated in the future.",
    "PUBLIC_KEY_INVALID": "The public key is not a well-formed OpenSSH public key of a supported type.",
    "CLAIMED_PIN_MISMATCH": "The pin offered for enrollment is not the fingerprint of the captured public key.",
    "CLAIMED_PIN_INVALID": "The pin offered for enrollment is malformed.",
}


@dataclass
class Verdict:
    ok: bool
    codes: list = field(default_factory=list)
    pin: str = ""
    key_type: str = ""
    evidence_digest: str = ""
    registered: dict = field(default_factory=dict)

    @property
    def messages(self) -> list[str]:
        return [REFUSALS.get(code, code) for code in self.codes]


def fingerprint(public_key: str) -> tuple[str, str]:
    """``(pin, key_type)`` computed from an OpenSSH public key line, or ``("", "")`` when it is not a valid supported key.

    The base64 blob is decoded and its SSH wire-format type string must equal the declared type, so a fingerprint or an arbitrary
    string can never pass as key material."""
    parts = str(public_key or "").strip().split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        return "", ""
    try:
        blob = base64.b64decode(parts[1], validate=True)
        (length,) = struct.unpack(">I", blob[:4])
        embedded = blob[4:4 + length].decode("ascii")
    except (binascii.Error, struct.error, UnicodeDecodeError, ValueError):
        return "", ""
    if embedded != parts[0] or len(blob) < 4 + length + 16:
        return "", ""
    pin = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return pin, parts[0]


def evidence_digest(document: dict) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _time(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(dt_timezone.utc) if parsed.tzinfo else None


def validate_evidence(document, *, enroller: str, claimed_pin: str = "", now: datetime | None = None,
                      inventory: dict | None = None) -> Verdict:
    """Validate one capture and compute its pin.  Read-only; never trusts a pin it did not compute."""
    now = now or timezone.now()
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        return Verdict(False, ["EVIDENCE_INVALID"])
    device = str(document.get("device") or "").strip()
    target = resolver.resolve(device, document=inventory) if device else None
    if target is None:
        return Verdict(False, ["DEVICE_UNKNOWN"])
    if target.scope not in resolver.WRITABLE_SCOPES:
        return Verdict(False, ["DEVICE_EXCLUDED"])
    codes: list[str] = []
    if str(document.get("platform") or "") != target.platform:
        codes.append("PLATFORM_MISMATCH")
    channel = str(document.get("channel") or "").strip().upper()
    if channel in FORBIDDEN_CHANNELS:
        codes.append("CHANNEL_NOT_INDEPENDENT")
    elif channel not in CHANNELS:
        codes.append("CHANNEL_UNKNOWN")
    collector = str(document.get("captured_by") or "").strip()
    if not _COLLECTOR.fullmatch(collector):
        codes.append("COLLECTOR_MISSING")
    elif collector.lower() == str(enroller or "").strip().lower() or not str(enroller or "").strip():
        codes.append("ENROLLER_NOT_INDEPENDENT")
    captured = _time(document.get("captured_at"))
    if captured is None:
        codes.append("EVIDENCE_INVALID")
    elif captured > now + CLOCK_SKEW:
        codes.append("EVIDENCE_FUTURE")
    elif captured < now - MAX_EVIDENCE_AGE:
        codes.append("EVIDENCE_STALE")
    pin, key_type = fingerprint(document.get("public_key"))
    if not pin:
        codes.append("PUBLIC_KEY_INVALID")
    if claimed_pin:
        if not _PIN.fullmatch(claimed_pin):
            codes.append("CLAIMED_PIN_INVALID")
        elif pin and claimed_pin != pin:
            codes.append("CLAIMED_PIN_MISMATCH")
    registered = compare_registered(device, pin, inventory=inventory) if pin else {}
    return Verdict(not codes, codes, pin if not codes else "", key_type, evidence_digest(document), registered)


def compare_registered(device: str, pin: str, *, inventory: dict | None = None) -> dict:
    """How ``pin`` relates to each pin NMAS already holds for ``device``: {source: MATCH | MISMATCH | ABSENT}, plus ``conflict``."""
    if inventory is None:
        from ..health import inventory as health_inventory

        inventory = health_inventory.load_inventory()
    held = {"inventory_ssh_host_key": str((((inventory.get("network_devices") or {}).get(device)) or {}).get("ssh_host_key") or "")}
    managed = models.ManagedDevice.objects.filter(identity.LIVE, name=device).order_by("-pk").first()
    held["verified_host_key"] = managed.verified_host_key if managed else ""
    paths = list(models.ManagementPath.objects.filter(device=managed).values_list("expected_host_key", flat=True)) if managed else []
    held["management_paths"] = sorted({p for p in paths if p})
    ztp = models.ZtpSession.objects.filter(device=managed).exclude(enrolled_host_key="").order_by("-pk").first() if managed else None
    held["ztp_enrolled_host_key"] = ztp.enrolled_host_key if ztp else ""
    obs = (models.DeviceObservation.objects.filter(device=managed, source=models.ObservationSource.AUTHENTICATED_SESSION)
           .order_by("-observed_at", "-pk").first()) if managed else None
    held["latest_authenticated_observation"] = str(((obs.claims if obs else None) or {}).get("host_key") or "")
    report, conflict = {}, False
    for source, value in held.items():
        values = value if isinstance(value, list) else ([value] if value else [])
        if not values:
            report[source] = "ABSENT"
        elif all(v == pin for v in values):
            report[source] = "MATCH"
        else:
            report[source], conflict = "MISMATCH", True
    report["conflict"] = conflict
    return report


def enrollment_route(platform: str) -> str:
    """The existing mechanism that must record the validated pin (never this module)."""
    if platform == models.Platform.ARISTA_CEOS:
        return ("register a management path with expected_host_key=<pin> on the Management page (management.paths.register_path), "
                "then approve it as a different NMAS Approver (approve_path refuses self-approval)")
    if platform == models.Platform.UBUNTU_FRR:
        return ("reviewed Git change: network_devices.<device>.ssh_host_key: <pin> in inventory.yml citing the evidence digest "
                "(Ubuntu/FRR observations use the legacy inventory route only)")
    return "no supported enrollment route"
