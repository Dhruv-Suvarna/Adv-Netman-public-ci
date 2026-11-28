"""Cross-vendor normalization for NMAS V2 troubleshooting (Stage 1 "Normalize").

Pure, Django-free and ORM-free: every function takes plain dictionaries / strings and returns serializable
dictionaries, so it can be replayed from recorded evidence without devices (spec section 2.1) and reused by any caller.

What this module guarantees (each is covered by ``test_troubleshooting_collectors``):

* **Provenance** -- every observation carries the evidence id, transport, parser id + version, raw hash, redaction
  status, observation time (the *event* time, not the arrival time), freshness and a quality flag.
* **Fail closed** -- a parser is selected by (parser id, platform, OS version); a wrong NOS or an out-of-range version
  raises ``ParserSelectionError`` and the caller records a missing-data record, never an observation (UT-020).
* **Partial parses are labelled** -- a parse that recovers fewer records / fields than the raw text announces yields
  quality ``PARTIAL``; a parse that disagrees with raw text or with another parser yields ``UNTRUSTED_PARSE`` (spec 3.2).
* **Counters** -- ``analyze_counter`` distinguishes wrap, reset, gap, duplicate and time regression and converts
  octets/s to bits/s; a reset or gap never produces a fabricated rate (UT-015).
* **Time** -- ``to_utc`` handles epoch s/ms/us/ns, ISO-8601 with offsets, and zone-less device strings with an
  explicit zone; ``estimate_skew`` + ``correct_time`` model device clock skew (UT-021).
* **Absent data is not data** -- ``missing_record`` is the only way a failed/denied/unsupported read is represented;
  ``trusted_value`` returns the string ``"UNKNOWN"`` for stale / untrusted / unknown observations (UT-006, UT-024).

Quality vocabulary (``Quality``): OK, PARTIAL, UNTRUSTED_PARSE, STALE, UNKNOWN.  Evidence class (``EvidenceClass``):
``operational`` (observed on the device / by telemetry), ``intent`` (NetBox / golden: *intent is not proof of
operational state*), ``snapshot`` (config/state snapshot).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

OBSERVATION_SCHEMA = "nmas.troubleshooting.observation/1"
EVIDENCE_SCHEMA = "nmas.troubleshooting.evidence/1"
MISSING_SCHEMA = "nmas.troubleshooting.missing-data/1"
NORMALIZER_VERSION = "1.0.0"
UNKNOWN = "UNKNOWN"


class Quality:
    OK = "OK"
    PARTIAL = "PARTIAL"
    UNTRUSTED_PARSE = "UNTRUSTED_PARSE"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"
    ALL = (OK, PARTIAL, UNTRUSTED_PARSE, STALE, UNKNOWN)
    UNTRUSTED = (UNTRUSTED_PARSE, STALE, UNKNOWN)


class EvidenceClass:
    OPERATIONAL = "operational"
    INTENT = "intent"
    SNAPSHOT = "snapshot"


class Missing:
    """Reason codes of a missing-data record (the only representation of a failed read)."""

    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    COMMAND_NOT_ALLOWED = "COMMAND_NOT_ALLOWED"
    NOT_ADMITTED = "NOT_ADMITTED"
    TIMEOUT = "TIMEOUT"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    OUTPUT_TOO_LARGE = "OUTPUT_TOO_LARGE"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    PARSER_UNAVAILABLE = "PARSER_UNAVAILABLE"
    PARSE_FAILED = "PARSE_FAILED"
    EMPTY = "EMPTY"
    STALE_SOURCE = "STALE_SOURCE"
    UNAUTHORIZED_CAPTURE = "UNAUTHORIZED_CAPTURE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"


class ParserSelectionError(Exception):
    """No parser may be used for this (parser id, platform, OS version): fail closed."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------------------------------------------------
# Platforms, versions, interface names, states
# --------------------------------------------------------------------------------------------------------------------
PLATFORM_ALIASES = {
    "ceos": "ceos", "arista_ceos": "ceos", "eos": "ceos", "arista_eos": "ceos", "arista": "ceos",
    "iosxe": "iosxe", "ios-xe": "iosxe", "ios_xe": "iosxe", "cisco_iosxe": "iosxe", "cisco_ios8000v": "iosxe", "c8000v": "iosxe",
    "linux": "linux", "linux_frr": "linux", "frr": "linux", "ubuntu": "linux", "ubuntu_frr": "linux",
}


def canonical_platform(platform: str) -> str:
    """Canonical platform id (``ceos`` / ``iosxe`` / ``linux``); unknown platforms are returned lower-cased, never guessed."""
    key = str(platform or "").strip().lower()
    return PLATFORM_ALIASES.get(key, key)


def parse_version(text: str) -> tuple[int, ...]:
    """``4.36.2F`` -> (4, 36, 2); ``17.06.01a`` -> (17, 6, 1); ``8.4.4`` -> (8, 4, 4).  Unparseable -> ``()``."""
    match = re.search(r"\d+(?:\.\d+)+", str(text or ""))
    if not match:
        return ()
    parts: list[int] = []
    for chunk in match.group().split("."):
        parts.append(int(chunk))
    return tuple(parts)


_IFACE_PREFIXES = (
    ("tengigabitethernet", "TenGigabitEthernet"), ("tengige", "TenGigabitEthernet"), ("te", "TenGigabitEthernet"),
    ("gigabitethernet", "GigabitEthernet"), ("gigethernet", "GigabitEthernet"), ("gig", "GigabitEthernet"), ("gi", "GigabitEthernet"),
    ("fastethernet", "FastEthernet"), ("fa", "FastEthernet"),
    ("ethernet", "Ethernet"), ("eth", "Ethernet"), ("et", "Ethernet"),
    ("port-channel", "Port-Channel"), ("portchannel", "Port-Channel"), ("po", "Port-Channel"),
    ("loopback", "Loopback"), ("lo", "Loopback"),
    ("management", "Management"), ("mgmt", "Management"), ("ma", "Management"),
    ("vlan", "Vlan"), ("vxlan", "Vxlan"), ("tunnel", "Tunnel"), ("tu", "Tunnel"),
)


def canonical_interface(name: str, *, platform: str = "") -> str:
    """Canonical long interface name (``Et1`` / ``Eth1`` -> ``Ethernet1``; ``Gi2`` -> ``GigabitEthernet2``).

    Linux interface names (``eth1``, ``lo``) are kept verbatim: on a Linux host ``eth1`` is not EOS ``Ethernet1``.
    """
    text = str(name or "").strip()
    if not text:
        return ""
    if canonical_platform(platform) == "linux":
        return text
    match = re.match(r"^([A-Za-z\-]+?)\s*([0-9][0-9/.:]*)$", text)
    if not match:
        return text
    prefix, number = match.group(1).lower(), match.group(2)
    for short, long_name in _IFACE_PREFIXES:
        if prefix == short:
            return long_name + number
    return text


_OPER_MAP = {
    "up": "up", "connected": "up", "established": "up", "1": "up", "link-up": "up", "running": "up",
    "down": "down", "notconnect": "down", "notconnected": "down", "2": "down", "link-down": "down", "disabled": "down",
    "administratively down": "down", "admin-down": "down",
    "testing": "testing", "3": "testing",
    "unknown": "unknown", "4": "unknown",
    "dormant": "dormant", "5": "dormant",
    "notpresent": "not_present", "not_present": "not_present", "not-present": "not_present", "6": "not_present",
    "lowerlayerdown": "lower_layer_down", "lower_layer_down": "lower_layer_down", "lower-layer-down": "lower_layer_down", "7": "lower_layer_down",
}
_ADMIN_MAP = {"up": "up", "1": "up", "enabled": "up", "down": "down", "2": "down", "disabled": "down", "testing": "testing", "3": "testing",
              "administratively down": "down"}


def norm_oper_state(value) -> str:
    return _OPER_MAP.get(str(value).strip().lower().replace(" ", "") if str(value).strip().lower() != "administratively down"
                         else "administratively down", "unknown")


def norm_admin_state(value) -> str:
    return _ADMIN_MAP.get(str(value).strip().lower(), "unknown")


def normalize_address(text) -> str | None:
    """Canonical text of an IP address / interface address (``2001:DB8::1/64`` -> ``2001:db8::1/64``); ``None`` if not an address."""
    try:
        return str(ipaddress.ip_interface(str(text).strip())) if "/" in str(text) else str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return None


# --------------------------------------------------------------------------------------------------------------------
# Time: UTC normalization, clock skew, freshness
# --------------------------------------------------------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$")
_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _zone(tz) -> timezone | Any:
    if tz is None or tz == "":
        return timezone.utc
    if isinstance(tz, (timezone, type(timezone.utc))) or hasattr(tz, "utcoffset"):
        return tz
    if isinstance(tz, (int, float)):
        return timezone(timedelta(seconds=tz))
    text = str(tz)
    if text.upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text)
    if match:
        sign = -1 if match.group(1) == "-" else 1
        return timezone(sign * timedelta(hours=int(match.group(2)), minutes=int(match.group(3))))
    from zoneinfo import ZoneInfo  # raises ZoneInfoNotFoundError for a bogus zone -> caller error, never silently UTC
    return ZoneInfo(text)


def to_utc(value, *, tz=None, unit: str | None = None, reference: datetime | None = None) -> datetime:
    """Normalize a device/collector timestamp to an aware UTC datetime.

    * numbers: ``unit`` in {s, ms, us, ns} or inferred from magnitude;
    * ISO-8601 strings: explicit offset wins; a zone-less string is interpreted in ``tz`` (default UTC, flagged by caller);
    * syslog ``Nov  9 12:00:01`` (no year): year taken from ``reference`` (the arrival time), rolled back one year when the
      result would lie more than a day in the future.
    Raises ``ValueError`` for anything else.
    """
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=_zone(tz)).astimezone(timezone.utc)
    if isinstance(value, bool):
        raise ValueError("boolean is not a timestamp")
    if isinstance(value, (int, float)):
        scale = {"s": 1, "ms": 1e3, "us": 1e6, "ns": 1e9}.get(unit or "")
        if scale is None:
            magnitude = abs(float(value))
            scale = 1e9 if magnitude >= 1e17 else 1e6 if magnitude >= 1e14 else 1e3 if magnitude >= 1e11 else 1
        return datetime.fromtimestamp(float(value) / scale, tz=timezone.utc)
    text = str(value).strip()
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return to_utc(float(text) if "." in text else int(text), unit=unit)
    match = _SYSLOG_TS.match(text)
    if match:
        reference = (reference or utcnow()).astimezone(timezone.utc)
        month, day, hh, mm, ss, frac = match.groups()
        micro = int((frac or "0")[:6].ljust(6, "0"))
        zone = _zone(tz)
        local_ref = reference.astimezone(zone)

        def build(year):
            return datetime(year, _MONTHS[month], int(day), int(hh), int(mm), int(ss), micro, tzinfo=zone).astimezone(timezone.utc)
        result = build(local_ref.year)
        if result - reference > timedelta(days=1):
            result = build(local_ref.year - 1)
        return result
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"unrecognized timestamp {text!r}") from exc
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=_zone(tz)).astimezone(timezone.utc)


def estimate_skew(device_time: datetime, collector_time: datetime, *, rtt_s: float = 0.0, tolerance_s: float = 2.0) -> dict:
    """Clock model: ``skew_s`` = device clock - collector clock (positive: device ahead), RTT-compensated.

    ``status`` is ``OK`` within ``tolerance_s``, ``SKEWED`` beyond it, ``UNKNOWN`` when either time is absent.
    """
    if device_time is None or collector_time is None:
        return {"skew_s": None, "tolerance_s": tolerance_s, "status": UNKNOWN, "rtt_s": rtt_s}
    skew = (device_time - (collector_time - timedelta(seconds=rtt_s / 2.0))).total_seconds()
    return {"skew_s": round(skew, 6), "tolerance_s": tolerance_s, "rtt_s": rtt_s,
            "status": "OK" if abs(skew) <= tolerance_s else "SKEWED"}


def correct_time(device_time: datetime, clock: dict | None) -> tuple[datetime, bool]:
    """Apply a clock model; returns (time, corrected?).  An OK/UNKNOWN clock leaves the time untouched."""
    if clock and clock.get("status") == "SKEWED" and clock.get("skew_s") is not None:
        return device_time - timedelta(seconds=clock["skew_s"]), True
    return device_time, False


def freshness(observed_at: datetime | None, now: datetime, max_age_s: float) -> dict:
    """``FRESH`` | ``STALE`` | ``FUTURE`` (observed after ``now`` by more than 5 s: clock problem) | ``UNKNOWN``."""
    if observed_at is None:
        return {"status": UNKNOWN, "age_s": None, "max_age_s": max_age_s}
    age = (now - observed_at).total_seconds()
    status = "FUTURE" if age < -5.0 else "STALE" if age > max_age_s else "FRESH"
    return {"status": status, "age_s": round(age, 3), "max_age_s": max_age_s}


# --------------------------------------------------------------------------------------------------------------------
# Redaction (spec 0: no secret exposure)
# --------------------------------------------------------------------------------------------------------------------
REDACTED = "<redacted>"
_REDACTIONS = (
    # ``(?![=:])``: a ``password = value`` / ``secret: value`` line is the key/value form below; matching here would redact only the ``=``
    re.compile(r"(?im)^(\s*(?:enable\s+)?(?:secret|password)\s+(?:\d+\s+)?)(?![=:])\S+"),
    re.compile(r"(?im)^(\s*username\s+\S+.*?\s(?:secret|password)\s+(?:\d+\s+)?)(?![=:])\S+"),
    re.compile(r"(?im)^(\s*(?:snmp-server\s+community|snmp-server\s+host\s+\S+(?:\s+version\s+\S+)?)\s+)\S+"),
    re.compile(r"(?im)((?:authentication-key|message-digest-key\s+\d+\s+md5|key-string|key|shared-secret|pre-shared-key|"
               r"auth-password|priv-password|authentication\s+(?:md5|sha)|privacy\s+(?:aes|des)(?:\s+\d+)?|neighbor\s+\S+\s+password)\s+(?:\d+\s+)?)\S+"),
    re.compile(r"(?im)((?:community|token|api[_-]?key|secret|passwd|password|bearer)\s*[=:]\s*)\S+"),
    re.compile(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
)


def redact_text(text: str) -> tuple[str, int]:
    """Redact secret-bearing lines.  Returns (redacted text, number of redactions).  Not a universal detector -- see collection.md."""
    count = 0
    out = str(text or "")
    for pattern in _REDACTIONS:
        def _sub(match):
            nonlocal count
            count += 1
            return (match.group(1) + REDACTED) if match.groups() else REDACTED
        out = pattern.sub(_sub, out)
    return out, count


def sha256_text(text: str | bytes) -> str:
    data = text if isinstance(text, bytes) else str(text).encode("utf-8", "replace")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_json(value) -> str:
    return sha256_text(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")))


# --------------------------------------------------------------------------------------------------------------------
# Missing-data records and observation construction
# --------------------------------------------------------------------------------------------------------------------
def missing_record(reason: str, *, source_type: str, device: str = "", detail: str = "", evidence_id: str = "",
                   command: str = "", observed_at: datetime | None = None, extra: dict | None = None) -> dict:
    """A permission denial / unsupported op / budget failure / parse failure.  It is NEVER an observation: the corresponding
    key is UNKNOWN (missing evidence is not evidence of absence)."""
    record = {
        "schema": MISSING_SCHEMA, "kind": "missing", "reason": reason, "source_type": source_type, "device": device,
        "detail": detail, "command_or_api": command, "evidence_id": evidence_id, "recorded_at": iso(observed_at or utcnow()),
        "observation_emitted": False, "interpretation": UNKNOWN,
    }
    if extra:
        record["extra"] = dict(extra)
    return record


def make_observation(key: str, value, *, unit: str = "", device: str, evidence: dict, observed_at: datetime | None,
                     interface: str = "", target: dict | None = None, quality: str = Quality.OK, parser: dict | None = None,
                     now: datetime | None = None, max_age_s: float | None = None, flags: Iterable[str] = (),
                     evidence_class: str = EvidenceClass.OPERATIONAL, confidence: float | None = None,
                     clock: dict | None = None, extra: dict | None = None) -> dict:
    """The one constructor of the observation contract (``nmas.troubleshooting.observation/1``)."""
    now = now or utcnow()
    flags = list(dict.fromkeys(flags))
    max_age = max_age_s if max_age_s is not None else (evidence.get("freshness_max_age_s") or 300.0)
    fresh = freshness(observed_at, now, max_age)
    if quality == Quality.OK and fresh["status"] == "STALE":
        quality = Quality.STALE
        flags.append("STALE_AT_NORMALIZATION")
    if fresh["status"] == "FUTURE":
        flags.append("OBSERVED_IN_FUTURE_CLOCK_SUSPECT")
        quality = Quality.UNTRUSTED_PARSE if quality == Quality.OK else quality
    if observed_at is None and quality == Quality.OK:
        quality = Quality.UNKNOWN
        flags.append("NO_OBSERVATION_TIME")
    tgt = {"device": device}
    if interface:
        tgt["interface"] = interface
    if target:
        tgt.update({k: v for k, v in target.items() if v not in (None, "")})
    if confidence is None:
        confidence = {Quality.OK: 0.95, Quality.PARTIAL: 0.6, Quality.STALE: 0.3, Quality.UNTRUSTED_PARSE: 0.1, Quality.UNKNOWN: 0.0}[quality]
    identity = sha256_json([evidence.get("evidence_id"), key, tgt, iso(observed_at), value])[7:23]
    obs = {
        "schema": OBSERVATION_SCHEMA, "observation_id": f"obs-{identity}", "key": key, "value": value, "unit": unit,
        "target": tgt, "evidence_class": evidence_class,
        "observed_at": iso(observed_at), "collected_at": evidence.get("collected_at"), "freshness": fresh,
        "source": {"evidence_id": evidence.get("evidence_id"), "source_type": evidence.get("source_type"),
                   "transport": evidence.get("transport"), "adapter": evidence.get("adapter"),
                   "command_or_api": evidence.get("command_or_api")},
        "quality": quality, "confidence": confidence, "flags": flags,
        "parser": dict(parser or {}), "normalizer_version": NORMALIZER_VERSION,
        "raw_hash": (evidence.get("raw_ref") or {}).get("hash"),
        "redaction_status": (evidence.get("redaction") or {}).get("status", "NOT_APPLICABLE"),
        "clock": dict(clock) if clock else None,
    }
    if extra:
        obs["extra"] = dict(extra)
    return obs


def trusted_value(observation: dict | None, now: datetime | None = None):
    """The observation's value only when it may be relied on; otherwise the string ``"UNKNOWN"`` (never a false healthy/fault)."""
    if not observation or observation.get("quality") in Quality.UNTRUSTED:
        return UNKNOWN
    if now is not None and observation.get("observed_at"):
        max_age = (observation.get("freshness") or {}).get("max_age_s") or 300.0
        if freshness(to_utc(observation["observed_at"]), now, max_age)["status"] != "FRESH":
            return UNKNOWN
    return observation.get("value")


# --------------------------------------------------------------------------------------------------------------------
# Counters: wrap / reset / gap / unit conversion  (UT-015)
# --------------------------------------------------------------------------------------------------------------------
def analyze_counter(prev: dict | None, cur: dict, *, width_bits: int | None = 64, speed_bps: float | None = None,
                    unit: str = "bytes", max_gap_s: float | None = None, last_clear_changed: bool = False) -> dict:
    """Compare two samples ``{"value": int, "at": datetime}`` of a cumulative counter.

    Event vocabulary: ``FIRST`` (no previous sample), ``NORMAL``, ``WRAP`` (counter rolled over its width; delta computed
    modulo 2**width when the implied rate is physically plausible), ``RESET`` (device restart / clear -- delta and rate are
    ``None``, never fabricated), ``GAP`` (sample interval exceeds ``max_gap_s`` -- the delta is real but the rate over the
    gap is only an average, so rate is ``None``), ``DUPLICATE_SAMPLE``, ``TIME_REGRESSION``.

    Wrap-vs-reset heuristic: on a decrease, the modulo delta is a wrap only if (a) the width is known and (b) the implied
    rate does not exceed 1.05 x the interface speed (when the speed is known).  Otherwise it is a reset.
    ``rate_per_s`` is in ``<unit>/s``; for ``unit == "bytes"`` ``rate_bps`` converts octets/s to bits/s.
    """
    result = {"event": "FIRST", "delta": None, "interval_s": None, "rate_per_s": None, "rate_bps": None, "unit": unit, "flags": []}
    if prev is None:
        return result
    interval = (cur["at"] - prev["at"]).total_seconds()
    result["interval_s"] = round(interval, 6)
    if interval < 0:
        result["event"] = "TIME_REGRESSION"
        result["flags"].append("SAMPLE_TIME_WENT_BACKWARDS")
        return result
    if interval == 0:
        result["event"] = "DUPLICATE_SAMPLE" if cur["value"] == prev["value"] else "TIME_REGRESSION"
        result["flags"].append("ZERO_INTERVAL")
        return result
    if last_clear_changed:
        result["event"] = "RESET"
        result["flags"].append("DEVICE_REPORTED_COUNTER_CLEAR")
        return result
    delta = cur["value"] - prev["value"]
    event = "NORMAL"
    if delta < 0:
        modulo = (1 << width_bits) if width_bits else None
        wrapped = (modulo - prev["value"] + cur["value"]) if modulo else None
        plausible = False
        if wrapped is not None:
            if speed_bps and unit == "bytes":
                plausible = (wrapped * 8.0 / interval) <= speed_bps * 1.05
            elif speed_bps is None:
                plausible = prev["value"] >= modulo * 0.5   # no speed known: only a counter that was near the top can have wrapped
        if plausible:
            event, delta = "WRAP", wrapped
        else:
            result["event"] = "RESET"
            result["flags"].append("DECREASE_NOT_EXPLAINED_BY_WRAP")
            return result
    result["delta"] = delta
    if max_gap_s is not None and interval > max_gap_s:
        result["event"] = "GAP"
        result["flags"].append("INTERVAL_EXCEEDS_MAX_GAP")
        return result
    rate = delta / interval
    result.update(event=event, rate_per_s=rate)
    if unit == "bytes":
        result["rate_bps"] = rate * 8.0
        if speed_bps and result["rate_bps"] > speed_bps * 1.05:
            result["flags"].append("RATE_EXCEEDS_LINE_RATE")   # inaccurate telemetry: caller marks the sample UNTRUSTED
    return result


class CounterTracker:
    """Keeps the previous sample per series and applies ``analyze_counter``; the only mutable state is the last sample."""

    def __init__(self, max_gap_s: float | None = None):
        self._last: dict[tuple, dict] = {}
        self.max_gap_s = max_gap_s

    def update(self, series: tuple, value: int, at: datetime, **kwargs) -> dict:
        prev = self._last.get(series)
        kwargs.setdefault("max_gap_s", self.max_gap_s)
        out = analyze_counter(prev, {"value": value, "at": at}, **kwargs)
        if out["event"] != "TIME_REGRESSION":
            self._last[series] = {"value": value, "at": at}
        return out


# --------------------------------------------------------------------------------------------------------------------
# Parser registry: selection by (id, platform, OS version) -- fails closed  (UT-020)
# --------------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ParserSpec:
    parser_id: str
    version: str
    platforms: tuple
    min_version: tuple = ()
    max_version: tuple | None = None     # exclusive upper bound; None = no upper bound known
    input_kind: str = "text"              # text | json | dict
    func: Callable | None = None
    template: str = ""                    # template id for operator-facing provenance (spec 3.2)


PARSERS: dict[str, list[ParserSpec]] = {}


def register_parser(spec: ParserSpec) -> ParserSpec:
    PARSERS.setdefault(spec.parser_id, []).append(spec)
    return spec


def select_parser(parser_id: str, platform: str, os_version: str = "") -> ParserSpec:
    """Return the parser for the platform+version or raise ``ParserSelectionError`` (``PARSER_UNKNOWN`` /
    ``WRONG_PLATFORM`` / ``VERSION_UNSUPPORTED`` / ``VERSION_UNKNOWN``).  An unknown OS version is NOT assumed compatible."""
    specs = PARSERS.get(parser_id)
    if not specs:
        raise ParserSelectionError("PARSER_UNKNOWN", parser_id)
    plat = canonical_platform(platform)
    candidates = [s for s in specs if plat in s.platforms]
    if not candidates:
        raise ParserSelectionError("WRONG_PLATFORM", f"{parser_id} does not apply to platform {plat or '?'}")
    version = parse_version(os_version)
    for spec in candidates:
        if spec.min_version == (0,) and spec.max_version is None:   # protocol/model parsers (OpenConfig, IF-MIB) are NOS-version independent
            return spec
    if not version:
        raise ParserSelectionError("VERSION_UNKNOWN", f"{parser_id} needs a known OS version on {plat}")
    for spec in candidates:
        if version >= spec.min_version and (spec.max_version is None or version < spec.max_version):
            return spec
    raise ParserSelectionError("VERSION_UNSUPPORTED", f"{parser_id} not validated for {plat} {os_version}")


@dataclass
class ParseResult:
    """Records recovered from raw data.  ``expected`` is the count announced by the raw data itself (if derivable)."""

    records: list
    expected: int | None = None
    errors: list | None = None
    notes: list | None = None

    @property
    def partial(self) -> bool:
        return bool(self.errors) or (self.expected is not None and len(self.records) < self.expected)

    @property
    def over_parsed(self) -> bool:
        return self.expected is not None and len(self.records) > self.expected


def _int(value) -> int | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    if isinstance(value, int):
        return value                       # never via float: 64-bit counters lose precision above 2**53
    try:
        text = str(value).replace(",", "").strip()
        return int(text) if re.fullmatch(r"-?\d+", text) else int(float(text))
    except (ValueError, OverflowError):
        return None


def _json_load(text: str, *, what: str) -> Any:
    try:
        return json.loads(text) if isinstance(text, str) else text
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{what}: not valid JSON") from exc


# -- interface records: canonical shape ------------------------------------------------------------------------------
# {"name", "admin", "oper", "mtu", "speed_bps", "counters": {"in_octets": n, ...}, "duplex", "mac", "observed_at": datetime|None,
#  "last_clear": datetime|None, "addresses": [...], "missing_fields": [...]}
_COUNTER_KEYS = ("in_octets", "out_octets", "in_packets", "out_packets", "in_errors", "out_errors", "in_discards", "out_discards",
                 "in_crc_errors", "in_runts", "in_giants", "in_frame_errors")
_COUNTER_WIDTH = {k: 64 for k in _COUNTER_KEYS}


def parse_eos_interfaces_json(raw) -> ParseResult:
    data = _json_load(raw, what="eos interfaces")
    interfaces = data.get("interfaces") if isinstance(data, dict) else None
    if not isinstance(interfaces, dict):
        raise ValueError("eos interfaces: no 'interfaces' object")
    records, errors = [], []
    for name, row in interfaces.items():
        if not isinstance(row, dict):
            errors.append(f"{name}: not an object")
            continue
        status, proto = str(row.get("interfaceStatus", "")), str(row.get("lineProtocolStatus", ""))
        counters_in = row.get("interfaceCounters") or {}
        detail = counters_in.get("inputErrorsDetail") or {}
        counters = {k: _int(v) for k, v in {
            "in_octets": counters_in.get("inOctets"), "out_octets": counters_in.get("outOctets"),
            "in_packets": counters_in.get("inUcastPkts"), "out_packets": counters_in.get("outUcastPkts"),
            "in_errors": counters_in.get("totalInErrors"), "out_errors": counters_in.get("totalOutErrors"),
            "in_discards": counters_in.get("inDiscards"), "out_discards": counters_in.get("outDiscards"),
            "in_crc_errors": detail.get("fcsErrors"), "in_runts": detail.get("runtFrames"), "in_giants": detail.get("giantFrames"),
            "in_frame_errors": detail.get("alignmentErrors"),
        }.items() if _int(v) is not None}
        refresh = counters_in.get("counterRefreshTime")
        missing = [f for f, present in (("status", status), ("mtu", row.get("mtu") is not None)) if not present]
        records.append({
            "name": canonical_interface(row.get("name") or name, platform="ceos"),
            "admin": "down" if status == "disabled" else ("up" if status else "unknown"),
            "oper": norm_oper_state(proto) if proto else "unknown",
            "mtu": _int(row.get("mtu")), "speed_bps": _int(row.get("bandwidth")), "duplex": str(row.get("duplex", "")).replace("duplex", "").lower() or None,
            "mac": str(row.get("physicalAddress", "")) or None, "counters": counters,
            "observed_at": to_utc(float(refresh)) if isinstance(refresh, (int, float)) and refresh > 0 else None,
            "last_clear": None, "missing_fields": missing,
        })
    return ParseResult(records, expected=len(interfaces), errors=errors or None)


_IOS_HEADER = re.compile(r"^(?P<name>\S+) is (?P<admin>administratively down|up|down|deleted|initializing),? line protocol is (?P<proto>up|down)", re.M)
_IOS_LOOSE_HEADER = re.compile(r"^\S+ is .*line protocol is", re.M)
_IOS_MTU = re.compile(r"MTU (\d+) bytes, BW (\d+) Kbit/sec")
_IOS_DUPLEX = re.compile(r"(Full|Half|Auto)[- ][Dd]uplex, (?:(\d+)\s*([MG])b/s|Auto)")
_IOS_SPEED_ALT = re.compile(r"(\d+)\s*([MG])b/s", re.I)
_IOS_IN_ERR = re.compile(r"(\d+) input errors, (\d+) CRC, (\d+) frame, (\d+) overrun, (\d+) ignored")
_IOS_RUNTS = re.compile(r"(\d+) runts, (\d+) giants")
_IOS_OUT_ERR = re.compile(r"(\d+) output errors")
_IOS_PKTS_IN = re.compile(r"(\d+) packets input, (\d+) bytes")
_IOS_PKTS_OUT = re.compile(r"(\d+) packets output, (\d+) bytes")
_IOS_MAC = re.compile(r"address is ([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", re.I)
_IOS_CLEAR = re.compile(r"Last clearing of \"show interface\" counters (.+)$", re.M)


def parse_iosxe_interfaces_text(raw: str) -> ParseResult:
    """Text template ``iosxe.show_interfaces`` (validated on 17.06.01a).  Mirrors the TextFSM ``cisco_ios_show_interfaces`` fields
    we need; a block missing a recognised sub-field is kept but listed in ``missing_fields`` (partial)."""
    text = str(raw or "")
    headers = list(_IOS_HEADER.finditer(text))
    expected = len(_IOS_LOOSE_HEADER.findall(text))
    records, errors = [], []
    for index, match in enumerate(headers):
        block = text[match.end(): headers[index + 1].start() if index + 1 < len(headers) else len(text)]
        missing = []
        mtu_m = _IOS_MTU.search(block)
        if not mtu_m:
            missing.append("mtu")
        dup_m = _IOS_DUPLEX.search(block)
        speed = None
        if dup_m and dup_m.group(2):
            speed = int(dup_m.group(2)) * (1_000_000 if dup_m.group(3) == "M" else 1_000_000_000)
        counters: dict = {}
        in_err = _IOS_IN_ERR.search(block)
        if in_err:
            counters.update(in_errors=int(in_err.group(1)), in_crc_errors=int(in_err.group(2)), in_frame_errors=int(in_err.group(3)))
        else:
            missing.append("input_errors")
        runts = _IOS_RUNTS.search(block)
        if runts:
            counters.update(in_runts=int(runts.group(1)), in_giants=int(runts.group(2)))
        out_err = _IOS_OUT_ERR.search(block)
        if out_err:
            counters["out_errors"] = int(out_err.group(1))
        pin, pout = _IOS_PKTS_IN.search(block), _IOS_PKTS_OUT.search(block)
        if pin:
            counters.update(in_packets=int(pin.group(1)), in_octets=int(pin.group(2)))
        else:
            missing.append("input_counters")
        if pout:
            counters.update(out_packets=int(pout.group(1)), out_octets=int(pout.group(2)))
        mac_m = _IOS_MAC.search(block)
        admin_text = match.group("admin")
        records.append({
            "name": canonical_interface(match.group("name"), platform="iosxe"),
            "admin": "down" if admin_text == "administratively down" else "up",
            "oper": "up" if match.group("proto") == "up" and admin_text == "up" else "down",
            "mtu": int(mtu_m.group(1)) if mtu_m else None,
            "speed_bps": speed if speed else (int(mtu_m.group(2)) * 1000 if mtu_m else None),
            "duplex": dup_m.group(1).lower() if dup_m else None, "mac": mac_m.group(1).lower() if mac_m else None,
            "counters": counters, "observed_at": None, "last_clear": None, "missing_fields": missing,
        })
    if expected and len(records) < expected:
        errors.append(f"{expected - len(records)} interface header(s) not recognised by template")
    return ParseResult(records, expected=expected or None, errors=errors or None)


def parse_openconfig_interfaces(raw) -> ParseResult:
    """OpenConfig ``openconfig-interfaces`` state (gNMI Get / NETCONF get reply rendered as JSON-IETF)."""
    data = _json_load(raw, what="openconfig interfaces")
    root = data.get("openconfig-interfaces:interfaces") or data.get("interfaces") if isinstance(data, dict) else None
    rows = root.get("interface") if isinstance(root, dict) else None
    if not isinstance(rows, list):
        raise ValueError("openconfig interfaces: no interface list")
    records = []
    for row in rows:
        state = row.get("state") or {}
        counters_in = state.get("counters") or {}
        counters = {k: _int(counters_in.get(src)) for k, src in {
            "in_octets": "in-octets", "out_octets": "out-octets", "in_packets": "in-pkts", "out_packets": "out-pkts",
            "in_errors": "in-errors", "out_errors": "out-errors", "in_discards": "in-discards", "out_discards": "out-discards",
            "in_crc_errors": "in-fcs-errors"}.items() if _int(counters_in.get(src)) is not None}
        ethernet = (row.get("openconfig-if-ethernet:ethernet") or row.get("ethernet") or {}).get("state") or {}
        port_speed = str(ethernet.get("port-speed", ""))
        speed = {"SPEED_10MB": 10e6, "SPEED_100MB": 100e6, "SPEED_1GB": 1e9, "SPEED_10GB": 10e9, "SPEED_25GB": 25e9,
                 "SPEED_40GB": 40e9, "SPEED_100GB": 100e9}.get(port_speed.split(":")[-1])
        last_clear = state.get("counters", {}).get("last-clear")
        records.append({
            "name": canonical_interface(row.get("name") or state.get("name"), platform="ceos"),
            "admin": norm_admin_state(state.get("admin-status", "")), "oper": norm_oper_state(state.get("oper-status", "")),
            "mtu": _int(state.get("mtu")), "speed_bps": int(speed) if speed else None, "duplex": None, "mac": None,
            "counters": counters, "observed_at": None,
            "last_clear": to_utc(last_clear) if last_clear not in (None, "", 0, "0") else None,
            "missing_fields": [f for f, ok in (("admin-status", "admin-status" in state), ("oper-status", "oper-status" in state)) if not ok],
        })
    return ParseResult(records, expected=len(rows))


_SNMP_IF = {
    "name": "1.3.6.1.2.1.31.1.1.1.1", "descr": "1.3.6.1.2.1.2.2.1.2", "mtu": "1.3.6.1.2.1.2.2.1.4", "speed": "1.3.6.1.2.1.2.2.1.5",
    "admin": "1.3.6.1.2.1.2.2.1.7", "oper": "1.3.6.1.2.1.2.2.1.8", "high_speed": "1.3.6.1.2.1.31.1.1.1.15",
}
_SNMP_COUNTERS64 = {"in_octets": "1.3.6.1.2.1.31.1.1.1.6", "out_octets": "1.3.6.1.2.1.31.1.1.1.10"}
_SNMP_COUNTERS32 = {"in_octets": "1.3.6.1.2.1.2.2.1.10", "out_octets": "1.3.6.1.2.1.2.2.1.16", "in_errors": "1.3.6.1.2.1.2.2.1.14",
                    "out_errors": "1.3.6.1.2.1.2.2.1.20", "in_discards": "1.3.6.1.2.1.2.2.1.13", "out_discards": "1.3.6.1.2.1.2.2.1.19"}


def parse_snmp_if_mib(raw) -> ParseResult:
    """IF-MIB walk rendered as ``{numeric OID: value}`` (the shape ``modules.snmp.poll`` returns).  HC (64-bit) octet counters
    are preferred over 32-bit ones; the width travels with the record so wrap analysis is correct."""
    data = _json_load(raw, what="snmp if-mib")
    if not isinstance(data, dict):
        raise ValueError("snmp if-mib: expected an OID map")

    def column(prefix):
        return {oid.rsplit(".", 1)[-1]: value for oid, value in data.items() if oid.startswith(prefix + ".")}
    names = column(_SNMP_IF["name"]) or column(_SNMP_IF["descr"])
    oper, admin = column(_SNMP_IF["oper"]), column(_SNMP_IF["admin"])
    mtu, speed, high = column(_SNMP_IF["mtu"]), column(_SNMP_IF["speed"]), column(_SNMP_IF["high_speed"])
    hc = {k: column(v) for k, v in _SNMP_COUNTERS64.items()}
    c32 = {k: column(v) for k, v in _SNMP_COUNTERS32.items()}
    records = []
    for index, name in sorted(names.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
        counters, widths = {}, {}
        for key in _SNMP_COUNTERS32:
            if key in hc and index in hc[key]:
                counters[key], widths[key] = _int(hc[key][index]), 64
            elif index in c32[key]:
                counters[key], widths[key] = _int(c32[key][index]), 32
        speed_bps = (_int(high.get(index)) or 0) * 1_000_000 or _int(speed.get(index))
        records.append({
            "name": canonical_interface(name), "admin": norm_admin_state(admin.get(index, "")), "oper": norm_oper_state(oper.get(index, "")),
            "mtu": _int(mtu.get(index)), "speed_bps": speed_bps, "duplex": None, "mac": None,
            "counters": {k: v for k, v in counters.items() if v is not None}, "counter_widths": widths, "observed_at": None,
            "last_clear": None, "ifindex": index,
            "missing_fields": [f for f, ok in (("oper", index in oper), ("admin", index in admin)) if not ok],
        })
    return ParseResult(records, expected=len(names))


def parse_linux_ip_addr(raw) -> ParseResult:
    """``ip -j addr show`` on Ubuntu/FRR.  Linux has no separate admin state: the ``UP`` flag is administrative, ``operstate`` operational."""
    data = _json_load(raw, what="ip -j addr")
    if not isinstance(data, list):
        raise ValueError("ip -j addr: expected a list")
    records = []
    for row in data:
        flags = row.get("flags") or []
        records.append({
            "name": str(row.get("ifname", "")), "admin": "up" if "UP" in flags else "down",
            "oper": norm_oper_state(str(row.get("operstate", "UNKNOWN")).lower()), "mtu": _int(row.get("mtu")), "speed_bps": None,
            "duplex": None, "mac": row.get("address"), "counters": {}, "observed_at": None, "last_clear": None,
            "addresses": [f"{a['local']}/{a['prefixlen']}" for a in row.get("addr_info", []) if a.get("local") and a.get("prefixlen") is not None
                          and normalize_address(f"{a['local']}/{a['prefixlen']}")],
            "missing_fields": [] if row.get("operstate") else ["operstate"],
        })
    return ParseResult(records, expected=len(data))


# -- routing neighbor records: {"protocol","neighbor","state","interface","vrf","family","router_id"} ---------------------
_OSPF_STATES = {"down": "down", "attempt": "attempt", "init": "init", "2-way": "two_way", "twoway": "two_way", "two-way": "two_way",
                "exstart": "exstart", "exchange": "exchange", "loading": "loading", "full": "full"}


def norm_ospf_state(value) -> str:
    base = re.split(r"[/ ]", str(value).strip().lower().strip(",.;:"))[0].strip(",.;:")
    return _OSPF_STATES.get(base.replace("_", ""), "unknown")


_BGP_STATES = {"idle": "idle", "connect": "connect", "active": "active", "opensent": "opensent", "openconfirm": "openconfirm",
               "established": "established"}


def norm_bgp_state(value) -> str:
    return _BGP_STATES.get(str(value).strip().lower().replace(" ", ""), "unknown")


def parse_eos_ospf_json(raw) -> ParseResult:
    data = _json_load(raw, what="eos ospf neighbors")
    if not isinstance(data, dict) or "vrfs" not in data:
        raise ValueError("eos ospf: no 'vrfs'")
    records = []
    for vrf, body in (data["vrfs"] or {}).items():
        for instance in (body.get("instList") or {}).values():
            for key in ("ospfNeighborEntries", "ospf3NeighborEntries"):
                for row in instance.get(key, []) or []:
                    records.append({"protocol": "ospfv3" if key.startswith("ospf3") else "ospfv2", "neighbor": str(row.get("routerId", "")),
                                    "state": norm_ospf_state(row.get("adjacencyState", "")), "interface": canonical_interface(row.get("interfaceName", ""), platform="ceos"),
                                    "vrf": vrf, "address": str(row.get("details", {}).get("neighborAddress", "") or row.get("interfaceAddress", ""))})
    return ParseResult(records)


def parse_frr_ospf_json(raw) -> ParseResult:
    """FRR 8.x ``show ip ospf neighbor json`` -> ``{"neighbors": {"<router-id>": [ {nbrState, ifaceName, ifaceAddress...} ]}}``."""
    data = _json_load(raw, what="frr ospf neighbors")
    if not isinstance(data, dict):
        raise ValueError("frr ospf: expected object")
    neighbors = data.get("neighbors", data)
    records = []
    for router_id, rows in neighbors.items():
        for row in rows if isinstance(rows, list) else [rows]:
            if not isinstance(row, dict):
                continue
            state = row.get("nbrState") or row.get("converged") or ""
            records.append({"protocol": "ospfv2", "neighbor": str(router_id), "state": norm_ospf_state(state),
                            "interface": str(row.get("ifaceName", "")).split(":")[0], "vrf": "default", "address": str(row.get("ifaceAddress", ""))})
    return ParseResult(records)


_IOS_OSPF_ROW = re.compile(r"^(?P<id>\d+\.\d+\.\d+\.\d+)\s+(?P<pri>\d+)\s+(?P<state>[A-Z0-9\-]+(?:/\s*[A-Z\-]+|/\s*-)?)\s+(?P<dead>\S+)\s+(?P<addr>\d+\.\d+\.\d+\.\d+)\s+(?P<iface>\S+)\s*$", re.M)


def parse_iosxe_ospf_text(raw: str) -> ParseResult:
    text = str(raw or "")
    records = [{"protocol": "ospfv2", "neighbor": m["id"], "state": norm_ospf_state(m["state"].replace(" ", "")), "interface": canonical_interface(m["iface"], platform="iosxe"),
                "vrf": "default", "address": m["addr"]} for m in _IOS_OSPF_ROW.finditer(text)]
    announced = len(re.findall(r"^\d+\.\d+\.\d+\.\d+\s+\d+\s", text, re.M))
    return ParseResult(records, expected=announced if announced else None)


def parse_eos_bgp_json(raw) -> ParseResult:
    data = _json_load(raw, what="eos bgp summary")
    if not isinstance(data, dict):
        raise ValueError("eos bgp: expected object")
    records = []
    for vrf, body in (data.get("vrfs") or {}).items():
        for peer, row in (body.get("peers") or {}).items():
            records.append({"protocol": "bgp", "neighbor": normalize_address(peer) or str(peer), "state": norm_bgp_state(row.get("peerState", "")),
                            "interface": "", "vrf": vrf, "remote_as": str(row.get("asn", "")), "prefixes_received": _int(row.get("prefixReceived"))})
    return ParseResult(records)


def parse_frr_bgp_json(raw) -> ParseResult:
    data = _json_load(raw, what="frr bgp summary")
    if not isinstance(data, dict):
        raise ValueError("frr bgp: expected object")
    records = []
    for family, body in data.items():
        if not isinstance(body, dict):
            continue
        for peer, row in (body.get("peers") or {}).items():
            records.append({"protocol": "bgp", "neighbor": normalize_address(peer) or str(peer), "state": norm_bgp_state(row.get("state", "")),
                            "interface": "", "vrf": "default", "family": family, "remote_as": str(row.get("remoteAs", "")),
                            "prefixes_received": _int(row.get("pfxRcd"))})
    return ParseResult(records)


# -- STP (RB04 canonical key ``stp.state``) --------------------------------------------------------------------------
# cEOS ``show spanning-tree | json`` -> one record per spanning-tree instance.  Version-gated (see _register_defaults); the layout was written
# from the EOS JSON schema and exercised on recorded/simulated documents -- NOT yet pinned to a gateway-recorded live run (docs/troubleshooting/stp-source.md).
_STP_STATES = {"forwarding": "forwarding", "discarding": "discarding", "blocking": "blocking", "learning": "learning", "listening": "listening",
               "disabled": "disabled", "broken": "broken", "bkn": "broken", "dis": "disabled"}
_STP_ROLES = {"root": "root", "designated": "designated", "alternate": "alternate", "backup": "backup", "disabled": "disabled", "master": "master", "boundary": "boundary"}
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:.-]?[0-9a-fA-F]{2}){5}$|^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$")
_STP_VL = re.compile(r"^(?:VL|VLAN|Vlan)\s*0*(\d{1,4})$")
STP_TCN_WINDOW_S = 3600
STP_ROOT_WINDOW_S = 86400


def _stp_bool(value):
    # JSON booleans only: bool("false") would fabricate a guard or loop alarm.
    return value if isinstance(value, bool) else None


def _stp_count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _stp_bridge_id(node) -> str | None:
    if not isinstance(node, dict):
        return None
    prio, mac = _stp_count(node.get("priority")), str(node.get("macAddress") or "")
    if prio is None or not _MAC_RE.match(mac):
        return None
    hexmac = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    return f"{prio}/{':'.join(hexmac[i:i + 2] for i in range(0, 12, 2))}"


def _stp_subject(instance: str) -> str:
    m = _STP_VL.match(instance.strip())
    return m.group(1) if m else instance.strip().lower()


def parse_eos_stp_json(raw) -> ParseResult:
    """``show spanning-tree | json`` -> instance records.  An EMPTY ``spanningTreeInstances`` is a valid document (records == []): the caller records
    it as "no STP instance reported" (STP-free OR disabled -- NetBox intent decides), never as a healthy topology."""
    data = _json_load(raw, what="eos spanning-tree")
    if not isinstance(data, dict) or not isinstance(data.get("spanningTreeInstances"), dict):
        raise ValueError("eos spanning-tree: no 'spanningTreeInstances' object")
    records, errors = [], []
    for name, body in data["spanningTreeInstances"].items():
        if not isinstance(body, dict):
            errors.append(f"{name}: instance is not an object")
            continue
        root, bridge = _stp_bridge_id(body.get("rootBridge")), _stp_bridge_id(body.get("bridge"))
        if bridge is None:
            errors.append(f"{name}: bridge priority/macAddress missing or malformed")
        if root is None:
            errors.append(f"{name}: rootBridge priority/macAddress missing or malformed")
            continue
        ports, protection = [], {}
        ifaces = body.get("interfaces")
        if not isinstance(ifaces, dict):
            errors.append(f"{name}: 'interfaces' missing; port roles unknown")
            ifaces = {}
        if not ifaces:
            errors.append(f"{name}: no port roles reported")
        for pname, row in ifaces.items():
            if not isinstance(row, dict):
                errors.append(f"{name}/{pname}: port row is not an object")
                continue
            state = _STP_STATES.get(str(row.get("state", "")).strip().lower())
            role = _STP_ROLES.get(str(row.get("role", "")).strip().lower())
            if state is None:
                errors.append(f"{name}/{pname}: unrecognised port state {row.get('state')!r}")
                continue
            if role is None:
                errors.append(f"{name}/{pname}: unrecognised port role")
            for field in ("loopInconsistent", "rootInconsistent", "bpduGuardTriggered", "typeInconsistent", "pvidInconsistent", "bpduGuard", "bpduFilter", "loopGuard"):
                if field in row and _stp_bool(row[field]) is None:
                    errors.append(f"{name}/{pname}: {field} is not a JSON boolean")
            port = canonical_interface(pname, platform="ceos")
            flags = [f for f in ("loopInconsistent", "rootInconsistent", "bpduGuardTriggered", "typeInconsistent", "pvidInconsistent") if _stp_bool(row.get(f)) is True]
            ports.append({"name": port, "state": state, "role": role or "unknown", "link_type": str(row.get("portType") or row.get("linkType") or ""),
                          "bpdu_rx": _int(row.get("bpduReceived")), "bpdu_tx": _int(row.get("bpduSent")), "inconsistent": flags})
            prot = {k: _stp_bool(row[src]) for k, src in (("bpdu_guard", "bpduGuard"), ("bpdu_filter", "bpduFilter"), ("loop_guard", "loopGuard")) if src in row and _stp_bool(row[src]) is not None}
            if prot:
                link_type = str(row.get("portType") or row.get("linkType") or "").lower()
                prot["link_type"] = "edge" if link_type in ("edge", "edgep2p") else "inter-switch" if link_type in ("p2p", "pointtopoint", "trunk", "inter-switch") else "unknown"
                prot["bpdu_rx_on_edge"] = (_stp_count(row.get("bpduReceived")) or 0) if prot["link_type"] == "edge" else 0
                prot["uncertain"] = (not all(k in prot for k in ("bpdu_guard", "bpdu_filter", "loop_guard")) or
                                     prot["link_type"] == "unknown" or
                                     (prot["link_type"] == "edge" and _stp_count(row.get("bpduReceived")) is None))
                protection[port] = prot
        secs = body.get("timeSinceLastTopologyChange", body.get("timeSinceTopologyChange"))
        if str(body.get("protocol") or "").lower() not in ("rapidpvst", "rapid-pvst", "pvst", "rstp", "mstp", "mst", "stp"):
            errors.append(f"{name}: unknown STP protocol")
        records.append({"instance": str(name), "subject": _stp_subject(str(name)), "mode": str(body.get("protocol") or "").lower() or "unknown",
                        "root_id": root, "bridge_id": bridge, "is_root": root == bridge if bridge is not None else None, "root_port": body.get("rootPort"),
                        "topology_changes": _stp_count(body.get("topologyChanges")), "seconds_since_tc": (float(secs) if isinstance(secs, (int, float)) and not isinstance(secs, bool) and math.isfinite(secs) and secs >= 0 else None),
                        "last_tc_port": body.get("lastTopologyChangeInterface") or body.get("topologyChangeInterface") or None, "ports": ports, "protection": protection})
    return ParseResult(records, expected=len(data["spanningTreeInstances"]), errors=errors or None)


class StpHistory:
    """Previous-sample memory per (device, subject): turns the cumulative EOS topology-change counter and the root bridge id into windowed
    facts.  Without a prior sample those facts are reported as unknown/lower-bound, never as zero."""

    def __init__(self):
        self._prev: dict[tuple, dict] = {}

    def previous(self, device: str, subject: str) -> dict | None:
        return self._prev.get((device, subject))

    def record(self, device: str, subject: str, entry: dict) -> None:
        self._prev[(device, subject)] = entry


def _stp_windowed(rec: dict, at: datetime | None, prev: dict | None) -> tuple[dict, list, list]:
    """-> (derived fields, uncertainty notes, flags)."""
    notes, flags, out = [], [], {}
    tot, secs = rec["topology_changes"], rec["seconds_since_tc"]
    if prev is not None and at is not None and tot is not None and prev.get("tcn_total") is not None and prev.get("at") is not None and at > prev["at"]:
        interval = (at - prev["at"]).total_seconds()
        if tot < prev["tcn_total"]:
            out["tcn_count_1h"] = None
            notes.append("tcn_counter_reset")
            flags.append("STP_TCN_COUNTER_RESET")
        else:
            delta = tot - prev["tcn_total"]
            buckets = [(start, end, count) for start, end, count in prev.get("tcn_buckets", [])
                       if end > at - timedelta(seconds=STP_TCN_WINDOW_S)]
            buckets.append((prev["at"], at, delta))
            out["_tcn_buckets"] = buckets
            boundary = any(start < at - timedelta(seconds=STP_TCN_WINDOW_S) and count for start, end, count in buckets)
            out["tcn_count_1h"] = sum(count for start, end, count in buckets) if interval <= STP_TCN_WINDOW_S and not boundary else None
            if boundary:
                notes.append("tcn_window_boundary_uncertain")
            if interval > STP_TCN_WINDOW_S:
                flags.append("STP_TCN_WINDOW_GAP")
                notes.append("tcn_window_gap")
        out["tcn_basis"] = "counter-delta"
        changes = [t for t in prev.get("root_changes", []) if at - t <= timedelta(seconds=STP_ROOT_WINDOW_S)]
        if prev.get("root_id") != rec["root_id"]:
            changes.append(at)
        out["root_changes_24h"], out["_root_changes"] = len(changes), changes
        coverage_start = prev.get("coverage_start", prev["at"])
        if at - coverage_start < timedelta(seconds=STP_ROOT_WINDOW_S):
            notes.append("root_change_history_partial")
        if at - coverage_start < timedelta(seconds=STP_TCN_WINDOW_S) and not (secs is not None and secs >= STP_TCN_WINDOW_S):
            notes.append("tcn_history_partial")
    else:
        if secs is not None and secs >= STP_TCN_WINDOW_S:
            out["tcn_count_1h"], out["tcn_basis"] = 0, "age-of-last-tc"
        elif secs is not None:
            out["tcn_count_1h"], out["tcn_basis"] = 1, "lower-bound"
            notes.append("tcn_count_is_lower_bound")
            flags.append("STP_TCN_LOWER_BOUND")
        else:
            out["tcn_count_1h"], out["tcn_basis"] = None, "unknown"
            notes.append("tcn_rate_unknown")
            flags.append("STP_TCN_RATE_UNKNOWN")
        out["root_changes_24h"], out["_root_changes"] = 0, []
        notes.append("root_change_history_unknown")
        flags.append("STP_ROOT_HISTORY_UNKNOWN")
    return out, notes, flags


def normalize_stp(raw, *, platform: str, os_version: str, device: str, evidence: dict, now: datetime | None = None, observed_at: datetime | None = None,
                  history: StpHistory | None = None, vlans: Iterable[str] = (), parser_id: str = "stp.state") -> dict:
    """Spanning-tree state -> ``stp.state`` (target ``vlan`` = subject RB04 asks for) and ``stp.port_protection`` (target ``interface``) observations.

    Unsupported/unknown OS version -> PARSER_UNAVAILABLE; malformed JSON -> PARSE_FAILED; a document with NO instance -> EMPTY (STP-free or disabled:
    not evidence of a healthy topology); a partially parsed document -> PARTIAL quality with the dropped parts listed under ``uncertain``."""
    now = now or utcnow()
    command = evidence.get("command_or_api", "")
    def miss(reason, detail, extra=None):
        return {"observations": [], "missing": [missing_record(reason, source_type=evidence.get("source_type", ""), device=device, detail=detail,  # noqa: E731
                                                                                              evidence_id=evidence.get("evidence_id", ""), command=command, observed_at=now, extra=extra)]}
    try:
        spec = select_parser(parser_id, platform, os_version)
        parsed = spec.func(raw)
    except ParserSelectionError as exc:
        return miss(Missing.PARSER_UNAVAILABLE, str(exc), {"selection_error": exc.code})
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return miss(Missing.PARSE_FAILED, str(exc)[:200])
    if not parsed.records and not parsed.errors:
        return miss(Missing.EMPTY, "no spanning-tree instance reported: STP is disabled or the domain is STP-free (EVPN-VXLAN); NetBox intent decides -- this is NOT evidence of a healthy L2 topology",
                    {"stp_instances": 0})
    if not parsed.records:
        return miss(Missing.PARSE_FAILED, "; ".join(parsed.errors)[:200])
    obs_time = observed_at or (to_utc(evidence["collected_at"]) if evidence.get("collected_at") else now)
    meta = _parser_meta(spec)
    out = []
    alias = list(dict.fromkeys(str(v) for v in vlans))
    taken = {r["subject"] for r in parsed.records}
    for rec in parsed.records:
        subject = rec["subject"]
        prev = history.previous(device, subject) if history is not None else None
        derived, notes, flags = _stp_windowed(rec, obs_time, prev)
        if prev is not None and obs_time <= prev.get("at", obs_time):
            notes.append("non_monotonic_sample")
        if parsed.errors:
            notes.append("partial_parse:" + "; ".join(parsed.errors)[:160])
            flags.append("PARTIAL_PARSE")
        if rec["topology_changes"] is None:
            notes.append("topology_change_counter_missing")
        loop_ind = [f"{p['name']}:{i}" for p in rec["ports"] for i in p["inconsistent"]]
        value = {"instance": rec["instance"], "mode": rec["mode"], "root_id": rec["root_id"], "bridge_id": rec["bridge_id"], "is_root": rec["is_root"],
                 "root_port": rec["root_port"], "root_changes_24h": derived["root_changes_24h"], "tcn_count_1h": derived["tcn_count_1h"], "tcn_basis": derived["tcn_basis"],
                 "tcn_total": rec["topology_changes"], "seconds_since_tc": rec["seconds_since_tc"], "last_tc_port": rec["last_tc_port"], "ports": rec["ports"],
                 "loop_indicators": loop_ind, "uncertain": notes, "stp_free": False}
        quality = Quality.PARTIAL if notes else Quality.OK
        subjects = [subject] + ([a for a in alias if a not in taken] if len(parsed.records) == 1 and (rec["mode"] == "rstp" or (rec["mode"] in ("mstp", "mst") and subject == "mst0")) else [])
        for sub in subjects:
            out.append(make_observation("stp.state", value, device=device, evidence=evidence, observed_at=obs_time, target={"vlan": sub}, quality=quality, parser=meta, now=now,
                                        flags=flags + (["STP_INSTANCE_ALIAS"] if sub != subject else [])))
        for port, prot in rec["protection"].items():
            out.append(make_observation("stp.port_protection", prot, device=device, evidence=evidence, observed_at=obs_time, interface=port, target={"vlan": subject},
                                        quality=Quality.UNTRUSTED_PARSE if prot.get("uncertain") else quality, parser=meta, now=now, flags=flags))
        if history is not None and not parsed.errors and (prev is None or obs_time > prev.get("at", obs_time)):
            history.record(device, subject, {"tcn_total": rec["topology_changes"], "root_id": rec["root_id"], "at": obs_time, "root_changes": derived["_root_changes"], "tcn_buckets": derived.get("_tcn_buckets", []),
                                             "coverage_start": (prev.get("coverage_start", prev["at"]) if prev and
                                                                rec["topology_changes"] is not None and
                                                                prev.get("tcn_total") is not None and
                                                                rec["topology_changes"] >= prev["tcn_total"] and
                                                                (obs_time - prev["at"]).total_seconds() <= STP_TCN_WINDOW_S else obs_time)})
    return {"observations": out, "missing": [], "parser": meta}



# -- DNS (RB05 canonical keys ``dns.*`` / ``time.sync``) ------------------------------------------------------------
# The runner (injected, read-only; see collectors.DnsCollector) returns ONE JSON document per typed request (schema nmas.dns.response/1).  The documents
# below are validated against the request that produced them: an answer to a different question/server is never attributed to the asked one.
# Nothing is inferred: absent / malformed / contradictory parts make the observation UNTRUSTED_PARSE (value retained for audit) or a missing-data record.
DNS_SCHEMA = "nmas.dns.response/1"
DNS_OPS = ("resolver_config", "transport", "query", "soa", "zone_status", "delegation", "records", "dnssec", "time_sync")
DNS_QTYPES = ("A", "AAAA", "CNAME", "PTR", "SOA", "NS")
DNS_REFUSED_QTYPES = ("AXFR", "IXFR", "ANY", "RRSIG", "DNSKEY", "DS", "NSEC", "NSEC3", "TXT", "MX", "SRV")   # transfers / amplification-prone / unvalidated types
DNS_RCODES = ("NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE")
DNS_MAX_ANSWERS = 64
DNS_MAX_TTL = 2 ** 31 - 1
_DNS_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def validate_dns_name(value, *, what: str = "name") -> tuple[str | None, str]:
    """(normalised lower-case name without trailing dot, error).  Rejects empty / over-long / bad labels, wildcards, whitespace and IP-literal-as-name."""
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        return None, f"{what} must be a non-empty string without surrounding whitespace"
    text = value[:-1] if value.endswith(".") and value != "." else value
    text = text.lower()
    if len(text) > 253 or text == ".":
        return None, f"{what} is empty or longer than 253 characters"
    labels = text.split(".")
    for label in labels:
        if not _DNS_LABEL.match(label):
            return None, f"{what} has an invalid label {label[:20]!r}"
    return text, ""


def validate_dns_server(value) -> tuple[str | None, str]:
    """IP literal (compressed canonical form) or hostname.  Multicast / unspecified / broadcast addresses are never DNS servers."""
    if not isinstance(value, str) or not value.strip():
        return None, "server must be a non-empty string"
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        name, err = validate_dns_name(value, what="server")
        return name, err
    if ip.is_multicast or ip.is_unspecified or (ip.version == 4 and int(ip) == 0xFFFFFFFF):
        return None, f"server {ip} is multicast/unspecified/broadcast"
    return str(ip), ""


def dns_engine_key(request: dict) -> tuple[str, str]:
    """(engine key, subject) RB05 asks for, for a request dict ``{op, name, zone, server, ...}``."""
    op = request.get("op")
    if op == "resolver_config":
        return "dns.resolver_config", "resolv"
    if op == "transport":
        return "dns.transport", request.get("server", "")
    if op == "query":
        return "dns.query", f"{request.get('name', '')}/{request.get('server', '')}"
    if op == "soa":
        return "dns.soa", f"{request.get('zone', '')}/{request.get('server', '')}"
    if op == "zone_status":
        return "dns.xfr", request.get("zone", "")
    if op == "delegation":
        return "dns.delegation", request.get("zone", "")
    if op == "records":
        return "dns.records", request.get("name", "")
    if op == "dnssec":
        return "dns.dnssec", request.get("zone", "")
    return "time.sync", ""


class _DnsBad(ValueError):
    pass


def _dns_ttl(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= DNS_MAX_TTL:
        raise _DnsBad(f"ttl {value!r} is not an integer in 0..2^31-1")
    return value


def _dns_ip(value, family: int | None = None) -> str:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        raise _DnsBad(f"{str(value)[:40]!r} is not an IP address") from None
    if family and ip.version != family:
        raise _DnsBad(f"{ip} has the wrong address family")
    return str(ip)


def _dns_rows(rows, *, qtypes: Iterable[str], limit: int = DNS_MAX_ANSWERS) -> list[dict]:
    if rows is None:
        return []
    if not isinstance(rows, list) or len(rows) > limit:
        raise _DnsBad(f"record list is not a list of at most {limit} rows")
    out = []
    for row in rows:
        if not isinstance(row, dict):
            raise _DnsBad("record row is not an object")
        rtype = str(row.get("type", "")).upper()
        if rtype not in DNS_QTYPES:
            raise _DnsBad(f"unsupported record type {rtype[:12]!r}")
        owner, err = validate_dns_name(row.get("name"), what="record owner")
        if err:
            raise _DnsBad(err)
        ttl = _dns_ttl(row.get("ttl"))
        data = row.get("data")
        if rtype == "A":
            data = _dns_ip(data, 4)
        elif rtype == "AAAA":
            data = _dns_ip(data, 6)
        elif rtype in ("CNAME", "PTR", "NS"):
            data, err = validate_dns_name(data, what=f"{rtype} data")
            if err:
                raise _DnsBad(err)
        elif rtype == "SOA":
            data = str(data or "").strip()
        out.append({"name": owner, "type": rtype, "ttl": ttl, "data": data})
    return out


def _dns_flags(doc) -> dict:
    flags = doc.get("flags") or {}
    if not isinstance(flags, dict):
        raise _DnsBad("flags is not an object")
    out = {}
    for name in ("aa", "tc", "rd", "ra", "ad"):
        if name in flags:
            if not isinstance(flags[name], bool):
                raise _DnsBad(f"flag {name} is not a JSON boolean")
            out[name] = flags[name]
    return out


def _dns_soa(row: dict) -> dict:
    parts = str(row["data"]).split()
    if len(parts) != 7:
        raise _DnsBad("SOA data must be 'mname rname serial refresh retry expire minimum'")
    mname, err = validate_dns_name(parts[0], what="SOA mname")
    if err:
        raise _DnsBad(err)
    nums = []
    for p in parts[2:]:
        if not p.isdigit() or int(p) > 2 ** 32 - 1:
            raise _DnsBad(f"SOA field {p[:12]!r} is not an unsigned 32-bit integer")
        nums.append(int(p))
    return {"mname": mname, "rname": parts[1].lower().rstrip("."), "serial": nums[0], "refresh": nums[1], "retry": nums[2], "expire": nums[3], "minimum": nums[4], "ttl": row["ttl"]}


def _dns_query_record(doc: dict, req: dict) -> dict:
    rcode = str(doc.get("rcode", "")).upper()
    if rcode not in DNS_RCODES:
        raise _DnsBad(f"rcode {rcode[:16]!r} is not a DNS response code")
    name, err = validate_dns_name(doc.get("name"), what="response name")
    qtype = str(doc.get("qtype", "")).upper()
    server = (validate_dns_server(doc.get("server"))[0] or "")
    if err or name != req["name"] or qtype != req["qtype"] or server != req["server"]:
        raise _DnsBad(f"response answers {doc.get('name')!r}/{qtype or '?'}@{str(doc.get('server'))[:40]!r}, not the requested {req['name']}/{req['qtype']}@{req['server']}")
    if doc.get("transport") is not None and str(doc["transport"]).lower() != req["transport"]:
        raise _DnsBad(f"response arrived over {doc['transport']!r}, requested {req['transport']}")
    flags = _dns_flags(doc)
    rows = _dns_rows(doc.get("answers"), qtypes=DNS_QTYPES)
    auth = _dns_rows(doc.get("authority"), qtypes=DNS_QTYPES)
    cname = {r["name"]: r["data"] for r in rows if r["type"] == "CNAME"}
    if len(cname) != len([r for r in rows if r["type"] == "CNAME"]):
        raise _DnsBad("one owner name has several CNAME records")
    chain, cur, seen, loop = [], req["name"], {req["name"]}, False
    while cur in cname:
        cur = cname[cur]
        chain.append(cur)
        if cur in seen:
            loop = True
            break
        seen.add(cur)
    final = [r for r in rows if r["type"] == req["qtype"]]
    if req["qtype"] != "CNAME" and not loop:
        final = [r for r in final if r["name"] == cur]          # only the record set at the end of the CNAME chain answers the question
    role = req["role"]
    reported = doc.get("server_role")
    if reported is not None and reported != role:
        raise _DnsBad(f"server_role {reported!r} contradicts the requested role {role!r}")
    cache = str(doc.get("cache", "unknown")).lower()
    if cache not in ("hit", "miss", "unknown"):
        raise _DnsBad("cache must be hit|miss|unknown")
    rec = {"rcode": rcode, "role": role, "qtype": req["qtype"], "transport": req["transport"], "flags": flags, "aa": flags.get("aa"), "tc": flags.get("tc", False),
           "answers": sorted({r["data"] for r in final}), "cname_chain": chain, "cname_loop": loop, "cache": cache, "rows": final, "soa": None, "negative": False, "ttl": None}
    soa = [r for r in auth if r["type"] == "SOA"]
    if req["qtype"] == "SOA":
        rec["soa"] = _dns_soa(final[0]) if len(final) == 1 else None
        if len(final) > 1:
            raise _DnsBad("several SOA records in one answer")
    if final:
        rec["ttl"] = min(r["ttl"] for r in final)
        if doc.get("original_ttl") is not None:
            rec["original_ttl"] = _dns_ttl(doc["original_ttl"])
    elif rcode in ("NXDOMAIN", "NOERROR"):
        rec["negative"] = True                                    # NXDOMAIN or NODATA: cached for min(SOA TTL, SOA minimum) (RFC 2308)
        if soa:
            s = _dns_soa(soa[0])
            rec["ttl"] = min(s["ttl"], s["minimum"])
        elif rcode == "NXDOMAIN":
            rec["ttl"] = 0
            rec["ttl_unknown"] = True
        else:
            rec["ttl_unknown"] = True                            # NODATA without an SOA in AUTHORITY: negative TTL cannot be known
    else:
        rec["ttl"] = 0                                          # SERVFAIL / REFUSED / ...: no cacheable data
    return rec


def _dns_status(doc: dict) -> tuple[str, str]:
    status = str(doc.get("status", "response")).lower()
    if status not in ("response", "timeout", "unreachable", "error"):
        raise _DnsBad(f"status {status[:16]!r} unknown")
    return status, str(doc.get("error", ""))[:160]


def parse_dns_response(raw, *, request: dict | None = None) -> ParseResult:  # pylint: disable=too-many-branches  # one flat validation per DNS wire/JSON field; each branch records a distinct missing/untrusted reason
    """One document -> one record ``{op, value, ...}``.  ``request`` (validated request dict) is mandatory: a document is only meaningful for the question asked."""
    if request is None:
        raise ValueError("a DNS response can only be parsed against the request that produced it")
    try:
        doc = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except ValueError as exc:
        raise ValueError(f"not JSON: {exc}") from None
    if not isinstance(doc, dict) or doc.get("schema") != DNS_SCHEMA or doc.get("op") != request["op"]:
        raise ValueError(f"document is not a {DNS_SCHEMA} {request['op']!r} response")
    op = request["op"]
    status, error = _dns_status(doc)
    if status != "response" and op in ("query", "soa", "zone_status", "delegation", "records", "dnssec", "resolver_config", "time_sync"):
        return ParseResult([{"op": op, "no_response": status, "error": error}], errors=[f"{status}: {error}".strip(": ")])
    try:
        if op == "resolver_config":
            ns = doc.get("nameservers")
            search = doc.get("search", [])
            if not isinstance(ns, list) or not isinstance(search, list) or len(ns) > 8 or len(search) > 16:
                raise _DnsBad("nameservers/search must be lists (<= 8 / <= 16 entries)")
            domains = []
            for x in search:
                dom, err = validate_dns_name(x, what="search domain")
                if err:
                    raise _DnsBad(err)
                domains.append(dom)
            value = {"nameservers": [_dns_ip(x) for x in ns], "search": domains}
        elif op == "transport":
            if (validate_dns_server(doc.get("server"))[0] or "") != request["server"]:
                raise _DnsBad("transport probe is for a different server")
            attempts = {}
            for a in doc.get("attempts") or []:
                t = str(a.get("transport", "")).lower() if isinstance(a, dict) else ""
                st = str(a.get("status", "")).lower() if isinstance(a, dict) else ""
                rc = str(a.get("rcode", "")).upper() if isinstance(a, dict) else ""
                if t not in ("udp", "tcp") or st not in ("response", "timeout", "unreachable", "error") or (rc and rc not in DNS_RCODES) or t in attempts:
                    raise _DnsBad("attempt must be {transport: udp|tcp (once), status: response|timeout|unreachable|error, rcode?}")
                attempts[t] = (st, rc)
            known = {t: attempts[t] for t in ("udp", "tcp") if t in attempts}
            value = {"udp_ok": None, "tcp_ok": None, "acl_refused": any(rc == "REFUSED" for _s, rc in known.values()), "attempts": {t: {"status": s, "rcode": rc or None} for t, (s, rc) in known.items()}}
            for t in ("udp", "tcp"):
                if t in known:
                    value[f"{t}_ok"] = known[t][0] == "response" and known[t][1] != "REFUSED"
            value["detail"] = " ".join(f"{t}={known[t][0]}{'/' + known[t][1] if known[t][1] else ''}" for t in known)
        elif op in ("query", "soa"):
            value = _dns_query_record(doc, {"name": request["zone"] if op == "soa" else request["name"], "qtype": "SOA" if op == "soa" else request["qtype"], "server": request["server"], "transport": request["transport"], "role": request["role"]})
        elif op == "zone_status":
            zone, err = validate_dns_name(doc.get("zone"), what="zone")
            if err or zone != request["zone"] or (validate_dns_server(doc.get("server"))[0] or "") != request["server"]:
                raise _DnsBad("zone status is for a different zone/server")
            last = doc.get("last_result")
            if not isinstance(last, str) or not last.strip():
                raise _DnsBad("last_result missing")
            serial = doc.get("serial")
            if serial is not None and (isinstance(serial, bool) or not isinstance(serial, int) or not 0 <= serial <= 2 ** 32 - 1):
                raise _DnsBad("serial is not an unsigned 32-bit integer")
            value = {"last_result": last.strip()[:200], "serial": serial, "last_transfer_at": doc.get("last_transfer_at")}
        elif op == "delegation":
            zone, err = validate_dns_name(doc.get("zone"), what="zone")
            if err or zone != request["zone"]:
                raise _DnsBad("delegation is for a different zone")
            servers = doc.get("servers")
            if not isinstance(servers, list) or not servers or len(servers) > 16:
                raise _DnsBad("servers must be a non-empty list of at most 16 delegated name servers")
            ns, lame, unknown = [], [], []
            for s in servers:
                name, err = validate_dns_name(s.get("ns") if isinstance(s, dict) else None, what="delegated ns")
                if err:
                    raise _DnsBad(err)
                st, rc, aa = str(s.get("status", "")).lower(), str(s.get("rcode", "")).upper(), s.get("aa")
                if st not in ("response", "timeout", "unreachable", "error") or (rc and rc not in DNS_RCODES) or (aa is not None and not isinstance(aa, bool)):
                    raise _DnsBad("delegated server row is malformed")
                ns.append(name)
                if st != "response":
                    unknown.append(name)
                elif rc != "NOERROR" or aa is not True:
                    lame.append(name)
            value = {"ns": ns, "lame": lame, "unknown": unknown}
        elif op == "records":
            name, err = validate_dns_name(doc.get("name"), what="name")
            if err or name != request["name"]:
                raise _DnsBad("records are for a different name")
            sections, unknown = {}, []
            for sec, qt in (("a", "A"), ("aaaa", "AAAA"), ("cname", "CNAME"), ("ptr", "PTR")):
                s = doc.get(sec)
                if not isinstance(s, dict) or str(s.get("status", "")).lower() != "response" or str(s.get("rcode", "")).upper() not in ("NOERROR", "NXDOMAIN"):
                    unknown.append(sec)
                    continue
                rows = [r for r in _dns_rows(s.get("rows"), qtypes=(qt,)) if r["type"] == qt]
                sections[sec] = rows if sec == "ptr" else [r for r in rows if r["name"] == name]
            cn = sections.get("cname", [])
            cmap = {r["name"]: r["data"] for r in cn}
            loop, cur, seen = False, name, {name}
            while cur in cmap:
                cur = cmap[cur]
                if cur in seen:
                    loop = True
                    break
                seen.add(cur)
            value = {"a": sorted({r["data"] for r in sections["a"]}) if "a" in sections else None, "aaaa": sorted({r["data"] for r in sections["aaaa"]}) if "aaaa" in sections else None,
                     "cname": (cn[0]["data"] if cn else None) if "cname" in sections else None, "cname_loop": loop,
                     "ptr": (sorted({r["data"] for r in sections["ptr"]})[0] if sections["ptr"] else None) if "ptr" in sections else None,
                     "ptr_count": len(sections.get("ptr", [])), "unknown_sections": unknown}
        elif op == "dnssec":
            zone, err = validate_dns_name(doc.get("zone"), what="zone")
            if err or zone != request["zone"]:
                raise _DnsBad("DNSSEC evidence is for a different zone")
            ad = doc.get("ad")
            ds = doc.get("ds")
            rrsig = doc.get("rrsig")
            if (ad is not None and not isinstance(ad, bool)) or (ds is not None and not isinstance(ds, dict)) or (rrsig is not None and not isinstance(rrsig, dict)):
                raise _DnsBad("ad must be boolean, ds/rrsig objects")
            exp = None
            if rrsig and rrsig.get("expiration") is not None:
                exp = to_utc(rrsig["expiration"])
            match = ds.get("match") if ds else None
            if match is not None and not isinstance(match, bool):
                raise _DnsBad("ds.match must be boolean")
            value = {"ad": ad, "rrsig_expiration": iso(exp) if exp else None, "ds_match": match, "validation": str(doc.get("validation", "unknown")).lower()[:16]}
        else:   # time_sync
            off = doc.get("offset_ms")
            synced = doc.get("synchronized")
            if not isinstance(synced, bool) or (off is not None and (isinstance(off, bool) or not isinstance(off, (int, float)) or not math.isfinite(off))):
                raise _DnsBad("synchronized must be boolean and offset_ms a finite number")
            value = {"synchronized": synced, "offset_ms": off, "source": str(doc.get("source", ""))[:40]}
    except _DnsBad as exc:
        return ParseResult([], errors=[str(exc)])
    return ParseResult([{"op": op, "value": value}], errors=None)


def _dns_value_for_engine(op: str, value: dict, *, now: datetime, observed_at: datetime, request: dict):
    """(engine value, quality, flags, missing_detail).  ``missing_detail`` set => no observation, a missing-data record."""
    flags: list[str] = []
    quality = Quality.OK
    if op == "query" or op == "soa":
        v = value
        if op == "soa":
            if v["soa"] is None:
                return None, None, [], f"no single SOA record in the answer (rcode {v['rcode']}, {len(v['rows'])} record(s)); the zone serial is unknown"
            out = {**v["soa"], "aa": v["aa"], "rcode": v["rcode"], "role": v["role"], "transport": v["transport"]}
            if v["tc"] and v["transport"] == "udp":
                return out, Quality.UNTRUSTED_PARSE, ["DNS_TRUNCATED"], ""
            return out, quality, flags, ""
        out = {"rcode": v["rcode"], "answers": v["answers"], "aa": v["aa"] is True, "aa_reported": v["aa"], "ttl": v["ttl"], "negative": v["negative"], "role": v["role"],
               "qtype": v["qtype"], "transport": v["transport"], "ra": v["flags"].get("ra"), "ad": v["flags"].get("ad"), "cache": v["cache"], "truncated": v["tc"],
               "cname_chain": v["cname_chain"], "cname_loop": v["cname_loop"]}
        if v["ttl"] is not None and (v["answers"] or v["negative"]):
            out["expires_at"] = iso(observed_at + timedelta(seconds=v["ttl"]))          # when a cached copy of this very answer ceases to be served
        if "original_ttl" in v:
            out["original_ttl"] = v["original_ttl"]
            out["cache_age_s"] = max(0, v["original_ttl"] - v["ttl"]) if v["ttl"] is not None else None
        if v["tc"] and v["transport"] == "udp":
            flags.append("DNS_TRUNCATED")
            quality = Quality.UNTRUSTED_PARSE            # a truncated UDP answer may be missing records: retry over TCP before reasoning
        if v.get("ttl_unknown") and not (v["rcode"] == "NXDOMAIN"):
            flags.append("DNS_NEGATIVE_TTL_UNKNOWN")
            quality = Quality.UNTRUSTED_PARSE
        if v["cname_loop"]:
            flags.append("DNS_CNAME_LOOP")
        if v["rcode"] == "NOERROR" and v["role"] == "authoritative" and v["aa"] is None:
            flags.append("DNS_AA_FLAG_ABSENT")
            quality = Quality.UNTRUSTED_PARSE            # authoritative-vs-cached cannot be told apart
        return out, quality, flags, ""
    if op == "transport":
        if value["udp_ok"] is None or value["tcp_ok"] is None:
            return value, Quality.UNTRUSTED_PARSE, ["DNS_TRANSPORT_ATTEMPT_MISSING"], ""
        return value, quality, flags, ""
    if op == "records":
        if value["unknown_sections"]:
            return value, Quality.UNTRUSTED_PARSE, [f"DNS_SECTION_UNKNOWN:{s}" for s in value["unknown_sections"]], ""
        out = {k: value[k] for k in ("a", "aaaa", "cname", "cname_loop", "ptr", "ptr_count")}
        aaaa_expected = request.get("aaaa_expected")
        if aaaa_expected is not None:
            out["aaaa_expected"] = bool(aaaa_expected)
        return out, quality, flags, ""
    if op == "delegation":
        if value["unknown"] and not value["lame"]:
            return value, Quality.UNTRUSTED_PARSE, ["DNS_DELEGATED_SERVER_UNKNOWN"], ""
        return value, (Quality.PARTIAL if value["unknown"] else quality), (["DNS_DELEGATED_SERVER_UNKNOWN"] if value["unknown"] else []), ""
    if op == "dnssec":
        ad, exp, match = value["ad"], value["rrsig_expiration"], value["ds_match"]
        if ad is None:
            return None, None, [], "DNSSEC validation state (AD) unavailable: no validating-resolver result; the zone is neither proven valid nor invalid"
        out = {"ad": ad, "validation": value["validation"]}
        if exp:
            out["rrsig_days_left"] = math.floor((to_utc(exp) - observed_at).total_seconds() / 86400)
        if match is not None:
            out["ds_match"] = match
        if ad and ("rrsig_days_left" not in out or "ds_match" not in out):
            return None, None, [], "DNSSEC evidence incomplete: AD set but RRSIG expiry or DS match unavailable; validity is not asserted"
        return out, quality, flags, ""
    if op == "time_sync":
        if not value["synchronized"] or value["offset_ms"] is None:
            return None, None, [], f"clock not synchronised or offset unreported (source {value['source'] or 'unknown'}); time skew is unknown"
        return {"offset_ms": value["offset_ms"], "source": value["source"]}, quality, flags, ""
    return value, quality, flags, ""


def normalize_dns(raw, *, request: dict, device: str, evidence: dict, now: datetime | None = None, observed_at: datetime | None = None) -> dict:
    """One runner document -> ``{observations, missing, parser}``.  Key/subject are the ones RB05 requests (``dns_engine_key``); the subject travels in
    ``target['dns']``.  Timeouts / error statuses / malformed documents are missing-data records carrying ``extra.engine_key`` so the exact engine key is
    marked unavailable; no answer is ever synthesised."""
    now = now or utcnow()
    command = evidence.get("command_or_api", "")
    key, subject = dns_engine_key(request)
    engine_key = f"{key}@{subject}" if subject else key
    spec = PARSERS["dns.response"][0]
    meta = _parser_meta(spec)
    def miss(reason, detail, extra=None):
        return {"observations": [], "missing": [missing_record(reason, source_type=evidence.get("source_type", ""), device=device, detail=detail[:240],  # noqa: E731
                                                                                              evidence_id=evidence.get("evidence_id", ""), command=command, observed_at=now,
                                                                                              extra={"engine_key": engine_key, **(extra or {})})], "parser": meta}
    try:
        parsed = spec.func(raw, request=request)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return miss(Missing.PARSE_FAILED, str(exc)[:200])
    if parsed.records and parsed.records[0].get("no_response"):
        status = parsed.records[0]["no_response"]
        return miss(Missing.TIMEOUT if status == "timeout" else Missing.TRANSPORT_ERROR, f"DNS {request['op']} got no response ({status}) {parsed.records[0].get('error', '')}".strip(),
                    {"dns_status": status})
    if not parsed.records:
        return miss(Missing.PARSE_FAILED, "; ".join(parsed.errors or ["no record"]))
    obs_time = observed_at or (to_utc(evidence["collected_at"]) if evidence.get("collected_at") else now)
    rec = parsed.records[0]
    value, quality, flags, why = _dns_value_for_engine(request["op"], rec["value"], now=now, observed_at=obs_time, request=request)
    if why:
        return miss(Missing.EMPTY, why)
    obs = make_observation(key, value, device=device, evidence=evidence, observed_at=obs_time, target={"dns": subject} if subject else None, quality=quality, parser=meta, now=now,
                           flags=flags)
    return {"observations": [obs], "missing": [], "parser": meta}



# -- Forwarding source: RIB routes and ARP/ND neighbours (HC10 / HC15 / HC24) ----------------------------------------
# Structured, version-gated parsers for EXISTING read-only commands.  What is and is not claimed:
# * ``route.table`` is a RIB / routing-table view (cEOS ``show ip[v6] route | json``; Linux ``ip -j route`` = the KERNEL routing table).  It is never a FIB:
#   forwarding-table evidence needs a distinct validated source and stays an explicit gap (``route.fib``).  EOS's ``allRoutesProgrammed*`` flags come
#   from the same RIB command, so they are recorded as a hint only.
# * ``neighbor.table`` is the ARP / ND cache.  An ABSENT entry is a cache fact, not proof of a resolution failure.
FWD_MAX_ROUTES = 5000
FWD_MAX_NEIGHBORS = 4096
_ROUTE_DISCARD = ("blackhole", "unreachable", "prohibit", "throw")
_ND_KNOWN = ("REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE", "PERMANENT", "NOARP")


def _fwd_prefix(text, family: str | None) -> tuple[str, str]:
    """(canonical prefix, family).  ``default`` needs a family hint; a bare host address is /32 or /128."""
    t = str(text).strip().lower()
    if t == "default":
        if family not in ("ipv4", "ipv6"):
            raise ValueError("default route without an address family")
        return ("0.0.0.0/0" if family == "ipv4" else "::/0"), family
    net = ipaddress.ip_network(t, strict=True)
    return str(net), "ipv4" if net.version == 4 else "ipv6"


def _fwd_addr(text, family: str | None = None) -> str | None:
    t = str(text or "").strip()
    if not t:
        return None
    ip = ipaddress.ip_address(t.split("%")[0])
    if family and ("ipv4" if ip.version == 4 else "ipv6") != family:
        raise ValueError(f"address {t} is not {family}")
    return str(ip)


def _fwd_metric(value):
    n = _int(value)
    return n if n is not None and n >= 0 else None


def parse_eos_route_json(raw, family: str | None = None) -> ParseResult:
    doc = _json_load(raw, what="EOS route table")
    vrfs = doc.get("vrfs") if isinstance(doc, dict) else None
    if not isinstance(vrfs, dict):
        raise ValueError("EOS route table: missing 'vrfs'")
    recs, errors, notes = [], [], []
    for vrf, body in vrfs.items():
        routes = body.get("routes") if isinstance(body, dict) else None
        if not isinstance(routes, dict):
            errors.append(f"vrf {str(vrf)[:32]}: no 'routes' map")
            continue
        if body.get("allRoutesProgrammedHardware") is False or body.get("allRoutesProgrammedKernel") is False:
            notes.append(f"eos_reports_unprogrammed_routes:{str(vrf)[:32]} (hint from the RIB command; not FIB evidence)")
        for text, r in routes.items():
            try:
                prefix, fam = _fwd_prefix(text, family)
                if family and fam != family:
                    raise ValueError("address family mismatch")
                vias = r.get("vias") or []
                if not isinstance(vias, list):
                    raise ValueError("vias not a list")
                nhs = []
                for v in vias:
                    nhs.append({"address": _fwd_addr(v.get("nexthopAddr"), fam), "interface": canonical_interface(str(v.get("interface") or "").split(",")[0], platform="ceos")})
                kind = str(r.get("routeType") or "").strip()
                recs.append({"vrf": str(vrf), "family": fam, "prefix": prefix, "protocol": (kind.split() or ["unknown"])[0].lower(),
                             "connected": bool(r.get("directlyConnected")) or kind.lower() == "connected", "next_hops": nhs,
                             "metric": _fwd_metric(r.get("metric")), "preference": _fwd_metric(r.get("preference")), "discard": "null0" if any("null0" in n["interface"].lower() for n in nhs) else None})
            except (ValueError, AttributeError, TypeError) as exc:
                errors.append(f"route {str(text)[:48]}: {str(exc)[:60]}")
    return ParseResult(recs, None, errors or None, notes or None)


def parse_linux_ip_route(raw, family: str | None = None) -> ParseResult:
    doc = _json_load(raw, what="ip -j route")
    if not isinstance(doc, list):
        raise ValueError("ip -j route: expected a JSON list")
    recs, errors = [], []
    for r in doc:
        try:
            prefix, fam = _fwd_prefix(r["dst"], family)
            if family and fam != family:
                raise ValueError("address family mismatch")
            hops = r.get("nexthops") if isinstance(r.get("nexthops"), list) else [r]
            nhs = [{"address": _fwd_addr(h.get("gateway"), fam), "interface": str(h.get("dev") or "")} for h in hops]
            typ = str(r.get("type") or "unicast")
            recs.append({"vrf": "default", "family": fam, "prefix": prefix, "protocol": str(r.get("protocol") or "unknown").lower(),
                         "connected": str(r.get("scope") or "") == "link" and not any(n["address"] for n in nhs), "next_hops": [] if typ in _ROUTE_DISCARD else nhs,
                         "metric": _fwd_metric(r.get("metric")), "preference": None, "discard": typ if typ in _ROUTE_DISCARD else None})
        except (KeyError, ValueError, AttributeError, TypeError) as exc:
            errors.append(f"route {str(r.get('dst') if isinstance(r, dict) else r)[:48]}: {str(exc)[:60]}")
    return ParseResult(recs, None, errors or None)


def _mac_or_none(text):
    t = str(text or "").strip().lower()
    return t if _MAC_RE.match(t) else None


def parse_eos_neighbors_json(raw, family: str | None = None) -> ParseResult:
    doc = _json_load(raw, what="EOS neighbor table")
    if not isinstance(doc, dict):
        raise ValueError("EOS neighbor table: not an object")
    rows = doc.get("ipV4Neighbors") if "ipV4Neighbors" in doc else doc.get("ipV6Neighbors")
    if not isinstance(rows, list):
        raise ValueError("EOS neighbor table: missing ipV4Neighbors/ipV6Neighbors")
    fam = "ipv4" if "ipV4Neighbors" in doc else "ipv6"
    recs, errors, notes = [], [], []
    for r in rows:
        try:
            addr = _fwd_addr(r["address"], fam)
            mac = _mac_or_none(r.get("hwAddress"))
            state_text = str(r.get("state") or "").upper()
            state = state_text or None
            if state is not None and state not in _ND_KNOWN:
                raise ValueError(f"unrecognised state {state_text[:16]}")
            recs.append({"address": addr, "family": fam, "mac": mac, "interface": canonical_interface(str(r.get("interface") or "").split(",")[0].strip(), platform="ceos"),
                         "vrf": "default", "state": state, "age_s": _fwd_metric(r.get("age")), "state_reported": state is not None})
        except (KeyError, ValueError, AttributeError, TypeError) as exc:
            errors.append(f"neighbor {str(r.get('address') if isinstance(r, dict) else r)[:48]}: {str(exc)[:60]}")
    if _int(doc.get("notLearnedEntries")):
        notes.append(f"eos_reports_{_int(doc.get('notLearnedEntries'))}_unlearned_entries")
    return ParseResult(recs, _int(doc.get("totalEntries")), errors or None, notes or None)


def parse_linux_ip_neigh(raw, family: str | None = None) -> ParseResult:
    doc = _json_load(raw, what="ip -j neigh")
    if not isinstance(doc, list):
        raise ValueError("ip -j neigh: expected a JSON list")
    recs, errors = [], []
    for r in doc:
        try:
            addr = _fwd_addr(r["dst"], family)
            st = r.get("state")
            state = str((st[0] if isinstance(st, list) and st else st) or "").upper()
            if state not in _ND_KNOWN:
                raise ValueError(f"unrecognised state {state[:16]}")
            recs.append({"address": addr, "family": "ipv4" if ":" not in addr else "ipv6", "mac": _mac_or_none(r.get("lladdr")), "interface": str(r.get("dev") or ""),
                         "vrf": "default", "state": state, "age_s": None, "state_reported": True, "router": bool(r.get("router"))})
        except (KeyError, ValueError, AttributeError, TypeError) as exc:
            errors.append(f"neighbor {str(r.get('dst') if isinstance(r, dict) else r)[:48]}: {str(exc)[:60]}")
    return ParseResult(recs, None, errors or None)


def _fwd_normalize(raw, kind: str, *, parser_id: str, family, platform: str, os_version: str, device: str, evidence: dict, now, observed_at) -> dict:
    now = now or utcnow()
    command = evidence.get("command_or_api", "")
    def miss(reason, detail, extra=None):
        return {"observations": [], "missing": [missing_record(reason, source_type=evidence.get("source_type", ""), device=device, detail=detail,  # noqa: E731
                                                                                              evidence_id=evidence.get("evidence_id", ""), command=command, observed_at=now, extra=extra)]}
    try:
        spec = select_parser(parser_id, platform, os_version)
        parsed = spec.func(raw, family=family)
    except ParserSelectionError as exc:
        return miss(Missing.PARSER_UNAVAILABLE, str(exc), {"selection_error": exc.code})
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return miss(Missing.PARSE_FAILED, str(exc)[:200])
    if not parsed.records and not parsed.errors:
        return miss(Missing.EMPTY, f"device returned no {kind} entries: an empty table is not evidence about any specific destination")
    if not parsed.records:
        return miss(Missing.PARSE_FAILED, "; ".join(parsed.errors)[:200])
    obs_time = observed_at or (to_utc(evidence["collected_at"]) if evidence.get("collected_at") else now)
    meta = _parser_meta(spec)
    limit = FWD_MAX_ROUTES if kind == "route" else FWD_MAX_NEIGHBORS
    truncated = len(parsed.records) > limit
    records = parsed.records[:limit]
    notes = list(parsed.notes or [])
    if parsed.errors:
        notes.append("partial_parse:" + "; ".join(parsed.errors)[:160])
    if truncated:
        notes.append(f"truncated_at_{limit}_of_{len(parsed.records)}")
    if parsed.over_parsed:
        notes.append("more_records_than_announced")
    complete = not (parsed.partial or truncated or parsed.over_parsed)
    flags = (["PARTIAL_PARSE"] if parsed.partial or parsed.over_parsed else []) + (["TRUNCATED"] if truncated else [])
    quality = Quality.OK if complete else Quality.PARTIAL
    out = []
    if kind == "route":
        groups: dict[tuple, list] = {}
        for rec in records:
            groups.setdefault((rec["vrf"], rec["family"]), []).append(rec)
        for (vrf, fam), recs in sorted(groups.items()):
            value = {"vrf": vrf, "family": fam, "route_count": len(recs), "complete": complete, "uncertain": notes, "routes": recs,
                     "table_kind": "kernel-routing-table" if canonical_platform(platform) == "linux" else "rib", "fib_evidence": False}
            out.append(make_observation("route.table", value, device=device, evidence=evidence, observed_at=obs_time, target={"vrf": vrf, "family": fam}, quality=quality,
                                        parser=meta, now=now, flags=flags))
    else:
        for rec in records:
            out.append(make_observation("neighbor.entry", {**rec, "uncertain": notes, "complete": complete}, device=device, evidence=evidence, observed_at=obs_time,
                                        interface=rec["interface"], target={"neighbor": rec["address"], "vrf": rec["vrf"], "family": rec["family"]}, quality=quality,
                                        parser=meta, now=now, flags=flags))
    return {"observations": out, "missing": [], "parser": meta}


def normalize_routes(raw, *, platform: str, os_version: str, device: str, evidence: dict, family: str | None = None, now: datetime | None = None,
                     observed_at: datetime | None = None, parser_id: str = "route.table") -> dict:
    """RIB / kernel routing table -> one bounded ``route.table`` observation per (VRF, family).  Unsupported version -> PARSER_UNAVAILABLE; bad JSON -> PARSE_FAILED."""
    return _fwd_normalize(raw, "route", parser_id=parser_id, family=family, platform=platform, os_version=os_version, device=device, evidence=evidence, now=now, observed_at=observed_at)


def normalize_neighbor_table(raw, *, platform: str, os_version: str, device: str, evidence: dict, family: str | None = None, now: datetime | None = None,
                             observed_at: datetime | None = None, parser_id: str = "neighbor.table") -> dict:
    """ARP / ND cache -> one ``neighbor.entry`` observation per entry (target ``neighbor`` = address, ``vrf``, ``family``)."""
    return _fwd_normalize(raw, "neighbor", parser_id=parser_id, family=family, platform=platform, os_version=os_version, device=device, evidence=evidence, now=now, observed_at=observed_at)


# -- L2 (HC08 ``l2.port`` / HC09 ``mac.table``) -----------------------------------------------------------------------
# Version-gated cEOS parsers.  Consumer contract (runbooks/hc.py):
#   l2.port@<interface>   -> {"mode": "access"|"trunk", "access_vlan": int, "allowed_vlans": [int]}
#   mac.table@<vlan>      -> {"moves_per_min": number, "flapping_macs": [mac]}
# MAC movement is only ever DERIVED FROM HISTORICAL SAMPLES (MacHistory); a first sample, a gap, a partial table or a counter-less document yields
# ``moves_per_min = None`` plus ``uncertain`` notes, which the runtime holds as UNTRUSTED (never a PASS).  An empty table never proves absence.
MAC_WINDOW_S = 600
MAC_MIN_SPAN_S = 60
MAC_MAX_GAP_S = 900
MAC_MAX_ENTRIES = 20000
L2_MAX_VLAN = 4094
_L2_MODES = ("access", "trunk")


def _vlan_id(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= L2_MAX_VLAN else None


def parse_vlan_list(text) -> list[int]:
    """EOS allowed-VLAN notation (``ALL``/``NONE``/``10,20-30``) -> sorted ints; any malformed element raises ValueError (never guessed)."""
    t = str(text if text is not None else "").strip().upper()
    if t in ("ALL", ""):
        if not t:
            raise ValueError("empty allowed VLAN list")
        return list(range(1, L2_MAX_VLAN + 1))
    if t == "NONE":
        return []
    out: set[int] = set()
    for part in t.split(","):
        m = re.match(r"^(\d{1,4})(?:-(\d{1,4}))?$", part.strip())
        if not m:
            raise ValueError(f"malformed VLAN list element {part!r}")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= lo <= hi <= L2_MAX_VLAN):
            raise ValueError(f"VLAN range out of bounds {part!r}")
        out.update(range(lo, hi + 1))
    return sorted(out)


def parse_eos_switchport_json(raw) -> ParseResult:
    """``show interfaces switchport | json`` -> one record per port.  Malformed rows are retained as ``uncertain`` records (never coerced)."""
    data = _json_load(raw, what="eos switchport")
    if not isinstance(data, dict) or not isinstance(data.get("switchports"), dict):
        raise ValueError("eos switchport: no 'switchports' object")
    records, errors = [], []
    for name, row in data["switchports"].items():
        port = canonical_interface(name, platform="ceos")
        info = row.get("switchportInfo") if isinstance(row, dict) else None
        if not isinstance(info, dict):
            errors.append(f"{port}: switchportInfo missing")
            continue
        mode = str(info.get("mode") or "").strip().lower()
        rec = {"name": port, "mode": mode or "unknown", "access_vlan": None, "allowed_vlans": [], "native_vlan": None, "uncertain": []}
        if mode not in _L2_MODES:
            rec["uncertain"].append(f"unsupported_port_mode:{mode or 'missing'}")
        if mode == "access":
            rec["access_vlan"] = _vlan_id(info.get("accessVlanId"))
            if rec["access_vlan"] is None:
                rec["uncertain"].append("access_vlan_missing_or_invalid")
        elif mode == "trunk":
            try:
                rec["allowed_vlans"] = parse_vlan_list(info.get("trunkAllowedVlans"))
            except ValueError as exc:
                rec["uncertain"].append(f"allowed_vlans_invalid:{str(exc)[:60]}")
            rec["native_vlan"] = _vlan_id(info.get("trunkingNativeVlanId"))
        if rec["uncertain"]:
            errors.append(f"{port}: " + ",".join(rec["uncertain"]))
        records.append(rec)
    return ParseResult(records, expected=len(data["switchports"]), errors=errors or None)


def normalize_l2_ports(raw, *, platform: str, os_version: str, device: str, evidence: dict, now: datetime | None = None, observed_at: datetime | None = None,
                       parser_id: str = "l2.port") -> dict:
    """-> ``l2.port`` observations (interface = port).  Any parse problem makes EVERY port PARTIAL (a dropped sibling must not let a partial set pass);
    a port with an unusable mode/VLAN is UNTRUSTED_PARSE.  Unsupported version -> PARSER_UNAVAILABLE (before any contact in the collector)."""
    now = now or utcnow()
    def miss(reason, detail, extra=None):
        return {"observations": [], "missing": [missing_record(reason, source_type=evidence.get("source_type", ""), device=device, detail=detail,  # noqa: E731
                                                                                              evidence_id=evidence.get("evidence_id", ""), command=evidence.get("command_or_api", ""), observed_at=now, extra=extra)]}
    try:
        spec = select_parser(parser_id, platform, os_version)
        parsed = spec.func(raw)
    except ParserSelectionError as exc:
        return miss(Missing.PARSER_UNAVAILABLE, str(exc), {"selection_error": exc.code})
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return miss(Missing.PARSE_FAILED, str(exc)[:200])
    if not parsed.records and not parsed.errors:
        return miss(Missing.EMPTY, "no switchport reported: the device has no L2 ports or the feature is absent; this is NOT evidence about any specific port")
    if not parsed.records:
        return miss(Missing.PARSE_FAILED, "; ".join(parsed.errors)[:200])
    obs_time = observed_at or (to_utc(evidence["collected_at"]) if evidence.get("collected_at") else now)
    meta = _parser_meta(spec)
    out = []
    for rec in parsed.records:
        notes = list(rec["uncertain"])
        flags = []
        if parsed.partial:
            notes.append("partial_parse:" + "; ".join(parsed.errors or ["fewer ports than announced"])[:160])
            flags.append("PARTIAL_PARSE")
        value = {"mode": rec["mode"], "access_vlan": rec["access_vlan"], "allowed_vlans": rec["allowed_vlans"], "native_vlan": rec["native_vlan"], "uncertain": notes}
        quality = Quality.UNTRUSTED_PARSE if rec["uncertain"] else (Quality.PARTIAL if notes else Quality.OK)
        out.append(make_observation("l2.port", value, device=device, evidence=evidence, observed_at=obs_time, interface=rec["name"], quality=quality, parser=meta, now=now, flags=flags))
    return {"observations": out, "missing": [], "parser": meta}


def _norm_mac(text):
    t = str(text or "").strip().lower()
    if not _MAC_RE.match(t):
        return None
    hexmac = re.sub(r"[^0-9a-f]", "", t)
    return ":".join(hexmac[i:i + 2] for i in range(0, 12, 2)) if len(hexmac) == 12 else None


def parse_eos_mac_json(raw) -> ParseResult:
    """``show mac address-table | json`` -> one record per unicast entry.  Rows with a bad VLAN/MAC/interface are dropped and listed as errors; a duplicate
    (VLAN, MAC) is an error (contradictory).  ``expected`` is the announced total when the document carries one."""
    data = _json_load(raw, what="eos mac address-table")
    table = data.get("unicastTable") if isinstance(data, dict) else None
    if not isinstance(table, dict) or not isinstance(table.get("tableEntries"), list):
        raise ValueError("eos mac address-table: no 'unicastTable.tableEntries' list")
    records, errors, seen = [], [], set()
    for i, row in enumerate(table["tableEntries"]):
        if not isinstance(row, dict):
            errors.append(f"entry {i}: not an object")
            continue
        vlan, mac, iface = _vlan_id(row.get("vlanId")), _norm_mac(row.get("macAddress")), str(row.get("interface") or "").strip()
        if vlan is None or mac is None or not iface or "," in iface:
            errors.append(f"entry {i}: vlan/mac/interface missing or malformed")
            continue
        if (vlan, mac) in seen:
            errors.append(f"entry {i}: duplicate vlan/mac")
            continue
        seen.add((vlan, mac))
        etype = str(row.get("entryType") or "").lower()
        records.append({"vlan": str(vlan), "mac": mac, "interface": canonical_interface(iface, platform="ceos"), "dynamic": "dynamic" in etype or etype.startswith("learned")})
    total = table.get("totalMacAddresses")
    expected = total if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else None
    if len(records) > MAC_MAX_ENTRIES:
        errors.append(f"table exceeds {MAC_MAX_ENTRIES} entries")
        records = records[:MAC_MAX_ENTRIES]
    return ParseResult(records, expected=expected, errors=errors or None)


class MacHistory:
    """Per-(device, vlan) memory of the last sample: ``macs`` {mac: interface}, observed ``at``, ``coverage_start`` and recent move events.  Movement is
    ONLY derivable from two consecutive complete samples; history never advances on a partial parse."""

    def __init__(self):
        self._prev: dict[tuple, dict] = {}

    def previous(self, device: str, vlan: str) -> dict | None:
        return self._prev.get((device, vlan))

    def record(self, device: str, vlan: str, entry: dict) -> None:
        self._prev[(device, vlan)] = entry


def normalize_mac_table(raw, *, platform: str, os_version: str, device: str, evidence: dict, now: datetime | None = None, observed_at: datetime | None = None,
                        history: MacHistory | None = None, parser_id: str = "mac.table") -> dict:
    """-> one ``mac.table`` observation per VLAN present in the table (target ``vlan``).  A VLAN absent from the table yields NO observation (a gap),
    and an empty table is EMPTY: neither proves the absence of MACs or of instability."""
    now = now or utcnow()
    def miss(reason, detail, extra=None):
        return {"observations": [], "missing": [missing_record(reason, source_type=evidence.get("source_type", ""), device=device, detail=detail,  # noqa: E731
                                                                                              evidence_id=evidence.get("evidence_id", ""), command=evidence.get("command_or_api", ""), observed_at=now, extra=extra)]}
    try:
        spec = select_parser(parser_id, platform, os_version)
        parsed = spec.func(raw)
    except ParserSelectionError as exc:
        return miss(Missing.PARSER_UNAVAILABLE, str(exc), {"selection_error": exc.code})
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return miss(Missing.PARSE_FAILED, str(exc)[:200])
    if not parsed.records and not parsed.errors:
        return miss(Missing.EMPTY, "MAC table is empty: learning may not have occurred or the table was cleared; an empty table is NOT evidence of stability or absence")
    if not parsed.records:
        return miss(Missing.PARSE_FAILED, "; ".join(parsed.errors)[:200])
    obs_time = observed_at or (to_utc(evidence["collected_at"]) if evidence.get("collected_at") else now)
    meta = _parser_meta(spec)
    by_vlan: dict[str, list] = {}
    for rec in parsed.records:
        by_vlan.setdefault(rec["vlan"], []).append(rec)
    base_notes, base_flags = [], []
    if parsed.partial:
        base_notes.append("partial_parse:" + "; ".join(parsed.errors or [f"{len(parsed.records)} of {parsed.expected} entries parsed"])[:160])
        base_flags.append("PARTIAL_PARSE")
    if parsed.over_parsed:
        base_notes.append("more_entries_than_announced")
        base_flags.append("PARTIAL_PARSE")
    out = []
    for vlan, recs in sorted(by_vlan.items(), key=lambda kv: int(kv[0])):
        dyn = {r["mac"]: r["interface"] for r in recs if r["dynamic"]}
        notes, flags = list(base_notes), list(base_flags)
        prev = history.previous(device, vlan) if history is not None else None
        moves_per_min, flapping, events, window_moves, coverage = None, [], [], None, obs_time
        usable = prev is not None and prev["at"] < obs_time and (obs_time - prev["at"]).total_seconds() <= MAC_MAX_GAP_S
        if prev is not None and obs_time <= prev["at"]:
            notes.append("non_monotonic_sample")
        if usable:
            events = [e for e in prev["events"] if (obs_time - e[0]).total_seconds() <= MAC_WINDOW_S]
            events += [(obs_time, mac, prev["macs"][mac], iface) for mac, iface in dyn.items() if mac in prev["macs"] and prev["macs"][mac] != iface]
            coverage = prev["coverage_start"]
            span = min((obs_time - coverage).total_seconds(), MAC_WINDOW_S)
            if span < MAC_MIN_SPAN_S:
                notes.append("mac_history_too_short")
                flags.append("MAC_HISTORY_SHORT")
            else:
                window_moves = len(events)
                moves_per_min = round(window_moves / (span / 60.0), 2)
                counts: dict[str, int] = {}
                for e in events:
                    counts[e[1]] = counts.get(e[1], 0) + 1
                flapping = sorted(mac for mac, n in counts.items() if n >= 2)
        else:
            notes.append("mac_movement_history_unknown" if prev is None else "mac_history_gap")
            flags.append("MAC_HISTORY_UNKNOWN")
        value = {"vlan": vlan, "moves_per_min": moves_per_min, "flapping_macs": flapping, "move_count_window": window_moves, "window_s": MAC_WINDOW_S,
                 "mac_count": len(recs), "dynamic_count": len(dyn), "interfaces": sorted({r["interface"] for r in recs}), "uncertain": notes}
        out.append(make_observation("mac.table", value, device=device, evidence=evidence, observed_at=obs_time, target={"vlan": vlan},
                                    quality=Quality.PARTIAL if notes else Quality.OK, parser=meta, now=now, flags=flags))
        if history is not None and not parsed.partial and not parsed.over_parsed and (prev is None or obs_time > prev["at"]):
            history.record(device, vlan, {"macs": dyn, "at": obs_time, "events": events, "coverage_start": coverage if usable else obs_time})
    return {"observations": out, "missing": [], "parser": meta}


# -- ACL (HC18 ``acl.counters``) ---------------------------------------------------------------------------------------
# Two version-gated cEOS parsers (``acl.rules`` = ``show ip access-lists | json``, ``acl.attachment`` = ``show ip access-lists summary | json``).  The
# runtime joins them on (ACL name, address family) into ``acl.counters@<interface>-<direction>``.  Rule text is parsed by a deliberately SMALL grammar:
#   (permit|deny) (ip|tcp|udp|icmp) <addr> <addr> [eq <1-65535>] [log]          <addr> := any | host A.B.C.D | A.B.C.D/len
# Everything else (wildcard masks, source-port operators, ranges, named ports/ICMP types, flags, established, fragments, tracked, object groups,
# standard ACLs, IPv6 ACLs) is kept IN ORDER as ``unsupported`` rules: a rule that might match cannot be skipped, so first-match evaluation downstream
# becomes inconclusive instead of guessing.  Attachment is NEVER inferred from rule content: only the summary command can establish it.
# Counter history (``AclHistory``) yields ``prev_hits`` only from two consecutive complete samples of an unchanged rule; first sample, gap, short span,
# reset (hits decreased), changed rule text or missing counters give ``prev_hits = None`` and an explicit ``history`` status.
ACL_MIN_SPAN_S = 10
ACL_MAX_GAP_S = 900
ACL_MAX_RULES = 5000
ACL_AF = "ipv4"
_ACL_PROTOS = ("ip", "tcp", "udp", "icmp")
_ACL_PORT_OPS = ("eq", "neq", "gt", "lt", "range")


def _acl_addr(tokens: list, i: int):
    """-> (network|'any', next_index) or (None, i) when the token sequence is not a supported address."""
    if i >= len(tokens):
        return None, i
    t = tokens[i]
    if t == "any":
        return "any", i + 1
    if t == "host" and i + 1 < len(tokens):
        try:
            return str(ipaddress.IPv4Network(tokens[i + 1] + "/32")), i + 2
        except ValueError:
            return None, i
    if "/" in t:
        try:
            return str(ipaddress.IPv4Network(t, strict=False)), i + 1
        except ValueError:
            return None, i
    return None, i


def parse_acl_rule_text(text: str) -> dict:
    """-> {"action","proto","port","src","dst"} or {"unsupported": reason}.  Never raises."""
    tokens = str(text or "").strip().lower().split()
    if len(tokens) < 4 or tokens[0] not in ("permit", "deny"):
        return {"unsupported": "unrecognised_rule_syntax"}
    action, proto = tokens[0], tokens[1]
    if proto not in _ACL_PROTOS:
        return {"unsupported": f"unsupported_protocol:{proto[:20]}", "action": action}
    src, i = _acl_addr(tokens, 2)
    if src is None:
        return {"unsupported": "unsupported_source_address_syntax", "action": action}
    if i < len(tokens) and tokens[i] in _ACL_PORT_OPS:
        return {"unsupported": "source_port_match", "action": action}
    dst, i = _acl_addr(tokens, i)
    if dst is None:
        return {"unsupported": "unsupported_destination_address_syntax", "action": action}
    port = None
    if i < len(tokens) and tokens[i] in _ACL_PORT_OPS:
        if tokens[i] != "eq" or proto not in ("tcp", "udp") or i + 1 >= len(tokens) or not tokens[i + 1].isdigit() or not 1 <= int(tokens[i + 1]) <= 65535:
            return {"unsupported": "unsupported_port_match", "action": action}
        port, i = int(tokens[i + 1]), i + 2
    if i < len(tokens) and tokens[i] == "log":
        i += 1
    if i != len(tokens):
        return {"unsupported": f"unsupported_option:{tokens[i][:20]}", "action": action}
    return {"action": action, "proto": proto, "port": port, "src": src, "dst": dst}


def parse_eos_acl_json(raw) -> ParseResult:
    """``show ip access-lists | json`` -> one record per ACL ``{"name","af","rules","errors"}`` (rules keep device order)."""
    data = _json_load(raw, what="eos access-lists")
    acls = data.get("aclList") if isinstance(data, dict) else None
    if not isinstance(acls, list):
        raise ValueError("eos access-lists: no 'aclList' list")
    records, errors, names = [], [], set()
    for i, row in enumerate(acls):
        name = str(row.get("name") or "").strip() if isinstance(row, dict) else ""
        if not name or name in names:
            errors.append(f"acl {i}: name missing or duplicate")
            continue
        names.add(name)
        rec = {"name": name, "af": ACL_AF, "rules": [], "errors": [], "unsupported_acl": None}
        if row.get("standard") is True:
            rec["unsupported_acl"] = "standard_acl"
        seqs = row.get("sequence")
        if not isinstance(seqs, list):
            rec["errors"].append("sequence list missing")
        seen = set()
        for j, s in enumerate(seqs if isinstance(seqs, list) else []):
            seq = s.get("sequenceNumber") if isinstance(s, dict) else None
            text = s.get("text") if isinstance(s, dict) else None
            if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0 or seq in seen or not isinstance(text, str):
                rec["errors"].append(f"rule {j}: sequence number/text missing, invalid or duplicate")
                continue
            seen.add(seq)
            if text.strip().lower().startswith("remark"):
                continue
            cd = s.get("counterData")
            hits = cd.get("matchedPackets") if isinstance(cd, dict) else None
            hits = hits if isinstance(hits, int) and not isinstance(hits, bool) and hits >= 0 else None
            p = parse_acl_rule_text(text)
            rec["rules"].append({"seq": seq, "text": text.strip()[:200], "hits": hits, "unsupported": p.get("unsupported"), "action": p.get("action"),
                                 "proto": p.get("proto"), "port": p.get("port"), "src": p.get("src"), "dst": p.get("dst")})
        if len(rec["rules"]) > ACL_MAX_RULES:
            rec["errors"].append(f"ACL exceeds {ACL_MAX_RULES} rules")
            rec["rules"] = rec["rules"][:ACL_MAX_RULES]
        rec["rules"].sort(key=lambda r: r["seq"])
        records.append(rec)
    return ParseResult(records, expected=len(acls), errors=errors or None)


def parse_eos_acl_summary_json(raw) -> ParseResult:
    """``show ip access-lists summary | json`` -> one record per (ACL, interface, direction) actually CONFIGURED; an interface listed as configured
    but not active is kept with an ``uncertain`` note."""
    data = _json_load(raw, what="eos access-lists summary")
    acls = data.get("aclList") if isinstance(data, dict) else None
    if not isinstance(acls, list):
        raise ValueError("eos access-lists summary: no 'aclList' list")
    records, errors = [], []
    for i, row in enumerate(acls):
        name = str(row.get("name") or "").strip() if isinstance(row, dict) else ""
        if not name:
            errors.append(f"acl {i}: name missing")
            continue
        for direction, ckey, akey in (("in", "configuredIngressIntfs", "activeIngressIntfs"), ("out", "configuredEgressIntfs", "activeEgressIntfs")):
            conf = row.get(ckey)
            if conf is None:
                continue
            if not isinstance(conf, list) or not all(isinstance(x, str) and x.strip() and "," not in x for x in conf):
                errors.append(f"acl {name}: {ckey} malformed")
                continue
            active = row.get(akey)
            for ifn in conf:
                note = []
                if isinstance(active, list) and ifn not in active:
                    note.append("configured_not_active")
                elif active is not None and not isinstance(active, list):
                    note.append("active_list_malformed")
                records.append({"acl": name, "interface": canonical_interface(ifn.strip(), platform="ceos"), "direction": direction, "af": ACL_AF, "uncertain": note})
    return ParseResult(records, expected=None, errors=errors or None)


class AclHistory:
    """Per-(device, ACL) memory of the last complete sample: ``at``, per-sequence ``hits`` and rule ``text``.  Counter deltas are derived ONLY from
    two consecutive complete samples; history never advances on a partial parse and never goes backwards in time."""

    def __init__(self):
        self._prev: dict[tuple, dict] = {}

    def previous(self, device: str, acl: str) -> dict | None:
        return self._prev.get((device, acl))

    def record(self, device: str, acl: str, entry: dict) -> None:
        self._prev[(device, acl)] = entry


def _acl_rule_history(rule: dict, prev: dict | None, span_problem: str | None) -> tuple:
    """-> (prev_hits | None, history status)."""
    if rule["hits"] is None:
        return None, "no_counter"
    if prev is None:
        return None, "no_history"
    if span_problem:
        return None, span_problem
    old = prev["rules"].get(rule["seq"])
    if old is None or old["text"] != rule["text"]:
        return None, "rule_changed"
    if old["hits"] is None:
        return None, "no_counter"
    if rule["hits"] < old["hits"]:
        return None, "counter_reset"
    return old["hits"], "ok"


def normalize_acl_rules(raw, *, platform: str, os_version: str, device: str, evidence: dict, now: datetime | None = None, observed_at: datetime | None = None,
                        history: AclHistory | None = None, parser_id: str = "acl.rules") -> dict:
    """-> one ``acl.rules`` observation per ACL (target ``acl``).  Parse problems make every ACL PARTIAL + ``uncertain``; an empty list never proves
    that no ACL exists."""
    now = now or utcnow()
    def miss(reason, detail, extra=None):
        return {"observations": [], "missing": [missing_record(reason, source_type=evidence.get("source_type", ""), device=device, detail=detail,  # noqa: E731
                                                                                              evidence_id=evidence.get("evidence_id", ""), command=evidence.get("command_or_api", ""), observed_at=now, extra=extra)]}
    try:
        spec = select_parser(parser_id, platform, os_version)
        parsed = spec.func(raw)
    except ParserSelectionError as exc:
        return miss(Missing.PARSER_UNAVAILABLE, str(exc), {"selection_error": exc.code})
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return miss(Missing.PARSE_FAILED, str(exc)[:200])
    if not parsed.records and not parsed.errors:
        return miss(Missing.EMPTY, "no IPv4 ACL reported: absence of an ACL listing is NOT evidence that no policy filters the path")
    if not parsed.records:
        return miss(Missing.PARSE_FAILED, "; ".join(parsed.errors)[:200])
    obs_time = observed_at or (to_utc(evidence["collected_at"]) if evidence.get("collected_at") else now)
    meta = _parser_meta(spec)
    out = []
    for rec in parsed.records:
        notes = list(rec["errors"])
        flags = []
        if rec["unsupported_acl"]:
            notes.append("unsupported_acl_type:" + rec["unsupported_acl"])
        if parsed.errors:
            notes.append("partial_parse:" + "; ".join(parsed.errors)[:160])
            flags.append("PARTIAL_PARSE")
        prev = history.previous(device, rec["name"]) if history is not None else None
        span_problem = None
        if prev is not None:
            span = (obs_time - prev["at"]).total_seconds()
            span_problem = "stale_history" if span > ACL_MAX_GAP_S else ("short_history" if span < ACL_MIN_SPAN_S else None)
        rules = []
        for r in rec["rules"]:
            prev_hits, status = _acl_rule_history(r, prev, span_problem)
            rules.append({**r, "prev_hits": prev_hits, "history": status})
        value = {"acl": rec["name"], "af": rec["af"], "rules": rules, "uncertain": notes, "complete": not notes,
                 "sample_interval_s": round((obs_time - prev["at"]).total_seconds(), 3) if prev is not None and not span_problem else None,
                 "unsupported_rules": [r["seq"] for r in rules if r["unsupported"]]}
        if not notes and history is not None and (prev is None or obs_time > prev["at"]):
            history.record(device, rec["name"], {"at": obs_time, "rules": {r["seq"]: {"hits": r["hits"], "text": r["text"]} for r in rules}})
        out.append(make_observation("acl.rules", value, device=device, evidence=evidence, observed_at=obs_time, target={"acl": rec["name"], "af": rec["af"]},
                                    quality=Quality.PARTIAL if notes else Quality.OK, parser=meta, now=now, flags=flags))
    return {"observations": out, "missing": [], "parser": meta}


def normalize_acl_attachment(raw, *, platform: str, os_version: str, device: str, evidence: dict, now: datetime | None = None, observed_at: datetime | None = None,
                             parser_id: str = "acl.attachment") -> dict:
    """-> one ``acl.attachment`` observation per (ACL, interface, direction).  Zero attachments is an EMPTY gap: no ``acl.counters`` observation is
    produced and an unattached or unreported ACL is never assumed to filter any interface."""
    now = now or utcnow()
    def miss(reason, detail, extra=None):
        return {"observations": [], "missing": [missing_record(reason, source_type=evidence.get("source_type", ""), device=device, detail=detail,  # noqa: E731
                                                                                              evidence_id=evidence.get("evidence_id", ""), command=evidence.get("command_or_api", ""), observed_at=now, extra=extra)]}
    try:
        spec = select_parser(parser_id, platform, os_version)
        parsed = spec.func(raw)
    except ParserSelectionError as exc:
        return miss(Missing.PARSER_UNAVAILABLE, str(exc), {"selection_error": exc.code})
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return miss(Missing.PARSE_FAILED, str(exc)[:200])
    if not parsed.records:
        return miss(Missing.EMPTY if not parsed.errors else Missing.PARSE_FAILED,
                    "; ".join(parsed.errors)[:200] if parsed.errors else "no ACL attachment reported; an unattached or unreported ACL is never assumed to filter any interface")
    obs_time = observed_at or (to_utc(evidence["collected_at"]) if evidence.get("collected_at") else now)
    meta = _parser_meta(spec)
    out = []
    for rec in parsed.records:
        notes = list(rec["uncertain"])
        flags = []
        if parsed.errors:
            notes.append("partial_parse:" + "; ".join(parsed.errors)[:160])
            flags.append("PARTIAL_PARSE")
        value = {"acl": rec["acl"], "interface": rec["interface"], "direction": rec["direction"], "af": rec["af"], "vrf": None, "uncertain": notes}
        out.append(make_observation("acl.attachment", value, device=device, evidence=evidence, observed_at=obs_time, interface=rec["interface"],
                                    target={"acl": rec["acl"], "direction": rec["direction"], "af": rec["af"]},
                                    quality=Quality.PARTIAL if notes else Quality.OK, parser=meta, now=now, flags=flags))
    return {"observations": out, "missing": [], "parser": meta}


def _register_defaults() -> None:
    reg = register_parser
    reg(ParserSpec("interfaces.state", "eos-json-1.0", ("ceos",), (4, 20), None, "json", parse_eos_interfaces_json, "eos.show_interfaces.json"))
    reg(ParserSpec("interfaces.state", "iosxe-text-1.0", ("iosxe",), (16, 9), (18, 0), "text", parse_iosxe_interfaces_text, "iosxe.show_interfaces.text"))
    reg(ParserSpec("interfaces.openconfig", "openconfig-1.0", ("ceos", "iosxe", "linux"), (0,), None, "json", parse_openconfig_interfaces, "openconfig-interfaces.state"))
    reg(ParserSpec("interfaces.snmp", "snmp-if-mib-1.0", ("ceos", "iosxe", "linux"), (0,), None, "json", parse_snmp_if_mib, "IF-MIB/IF-MIB-X"))
    reg(ParserSpec("interfaces.state", "linux-ip-json-1.0", ("linux",), (5, 0), None, "json", parse_linux_ip_addr, "iproute2.addr.json"))
    reg(ParserSpec("ospf.neighbors", "eos-json-1.0", ("ceos",), (4, 20), None, "json", parse_eos_ospf_json, "eos.show_ip_ospf_neighbor.json"))
    reg(ParserSpec("ospf.neighbors", "frr-json-1.0", ("linux",), (7, 0), (10, 0), "json", parse_frr_ospf_json, "frr.show_ip_ospf_neighbor.json"))
    reg(ParserSpec("ospf.neighbors", "iosxe-text-1.0", ("iosxe",), (16, 9), (18, 0), "text", parse_iosxe_ospf_text, "iosxe.show_ip_ospf_neighbor.text"))
    reg(ParserSpec("bgp.summary", "eos-json-1.0", ("ceos",), (4, 20), None, "json", parse_eos_bgp_json, "eos.show_ip_bgp_summary.json"))
    reg(ParserSpec("stp.state", "eos-json-1.0", ("ceos",), (4, 28), (5, 0), "json", parse_eos_stp_json, "eos.show_spanning_tree.json"))
    reg(ParserSpec("mac.table", "eos-json-1.0", ("ceos",), (4, 28), (5, 0), "json", parse_eos_mac_json, "eos.show_mac_address_table.json"))
    reg(ParserSpec("l2.port", "eos-json-1.0", ("ceos",), (4, 28), (5, 0), "json", parse_eos_switchport_json, "eos.show_interfaces_switchport.json"))
    reg(ParserSpec("acl.rules", "eos-json-1.0", ("ceos",), (4, 28), (5, 0), "json", parse_eos_acl_json, "eos.show_ip_access_lists.json"))
    reg(ParserSpec("acl.attachment", "eos-json-1.0", ("ceos",), (4, 28), (5, 0), "json", parse_eos_acl_summary_json, "eos.show_ip_access_lists_summary.json"))
    reg(ParserSpec("route.table", "eos-json-1.0", ("ceos",), (4, 28), (5, 0), "json", parse_eos_route_json, "eos.show_ip_route.json"))
    reg(ParserSpec("route.table", "linux-ip-route-json-1.0", ("linux",), (5, 0), None, "json", parse_linux_ip_route, "iproute2.route.json"))
    reg(ParserSpec("neighbor.table", "eos-json-1.0", ("ceos",), (4, 28), (5, 0), "json", parse_eos_neighbors_json, "eos.show_arp_nd.json"))
    reg(ParserSpec("neighbor.table", "linux-ip-neigh-json-1.0", ("linux",), (5, 0), None, "json", parse_linux_ip_neigh, "iproute2.neigh.json"))
    reg(ParserSpec("dns.response", "dns-json-1.0", ("ceos", "iosxe", "linux"), (0,), None, "json", parse_dns_response, "nmas.dns.response/1"))   # vantage-OS independent
    reg(ParserSpec("bgp.summary", "frr-json-1.0", ("linux",), (7, 0), (10, 0), "json", parse_frr_bgp_json, "frr.show_bgp_summary.json"))


_register_defaults()


# --------------------------------------------------------------------------------------------------------------------
# Record -> observations
# --------------------------------------------------------------------------------------------------------------------
def _parser_meta(spec: ParserSpec) -> dict:
    return {"id": spec.parser_id, "version": spec.version, "template": spec.template, "input_kind": spec.input_kind}


def _interface_observations(rec: dict, *, device: str, evidence: dict, spec: ParserSpec, quality: str, now: datetime, observed_at,
                            base_flags: list, clock: dict | None, default_widths: dict | None = None) -> list[dict]:
    out = []
    parser = _parser_meta(spec)
    name = rec["name"]
    rec_quality = Quality.PARTIAL if rec.get("missing_fields") and quality == Quality.OK else quality
    flags = list(base_flags) + [f"MISSING_FIELD:{f}" for f in rec.get("missing_fields", [])]

    def emit(key, value, unit="", extra=None, q=None, more_flags=()):
        if value is None:
            return
        out.append(make_observation(key, value, unit=unit, device=device, evidence=evidence, observed_at=observed_at, interface=name,
                                    quality=q or rec_quality, parser=parser, now=now, flags=flags + list(more_flags), clock=clock, extra=extra))
    emit("interface.admin_state", rec["admin"] if rec["admin"] != "unknown" else None)
    emit("interface.oper_state", rec["oper"] if rec["oper"] != "unknown" else None)
    emit("interface.mtu", rec.get("mtu"), "bytes")
    emit("interface.speed", rec.get("speed_bps"), "bps")
    emit("interface.duplex", rec.get("duplex"))
    for address in rec.get("addresses", []):
        emit("interface.address", address)
    widths = {**(default_widths or {}), **(rec.get("counter_widths") or {})}
    for key, value in sorted(rec.get("counters", {}).items()):
        unit = "bytes" if key.endswith("octets") else "packets" if key.endswith("packets") else "frames" if key.endswith(("errors", "discards", "runts", "giants")) else "count"
        emit(f"interface.counter.{key}", value, unit, extra={"counter": {"cumulative": True, "width_bits": widths.get(key, 64),
                                                                       "last_clear": iso(rec.get("last_clear"))}})
    return out


def normalize_interfaces(raw, *, parser_id: str = "interfaces.state", platform: str, os_version: str, device: str, evidence: dict,
                         now: datetime | None = None, observed_at: datetime | None = None, clock: dict | None = None,
                         raw_text_check: Callable[[str, ParseResult], list] | None = None) -> dict:
    """Select the parser (fail closed), parse, validate, and emit canonical ``interface.*`` observations.

    Returns ``{"observations": [...], "missing": [...], "parser": {...}|None, "quality": ..., "parse": {...}}``.  A selection or
    parse failure returns an empty observation list and a missing-data record (UT-020, UT-024).
    """
    now = now or utcnow()
    command = evidence.get("command_or_api", "")
    try:
        spec = select_parser(parser_id, platform, os_version)
    except ParserSelectionError as exc:
        reason = Missing.PARSER_UNAVAILABLE
        return {"observations": [], "missing": [missing_record(reason, source_type=evidence.get("source_type", ""), device=device, detail=str(exc),
                                                              evidence_id=evidence.get("evidence_id", ""), command=command, observed_at=now,
                                                              extra={"selection_error": exc.code})],
                "parser": None, "quality": Quality.UNKNOWN, "parse": None}
    try:
        parsed = spec.func(raw)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return {"observations": [], "missing": [missing_record(Missing.PARSE_FAILED, source_type=evidence.get("source_type", ""), device=device,
                                                              detail=str(exc)[:200], evidence_id=evidence.get("evidence_id", ""), command=command,
                                                              observed_at=now, extra={"parser": _parser_meta(spec)})],
                "parser": _parser_meta(spec), "quality": Quality.UNKNOWN, "parse": None}
    flags: list[str] = []
    quality = Quality.OK
    if not parsed.records:
        return {"observations": [], "missing": [missing_record(Missing.EMPTY, source_type=evidence.get("source_type", ""), device=device,
                                                              detail="parser recovered no interface records", evidence_id=evidence.get("evidence_id", ""),
                                                              command=command, observed_at=now, extra={"parser": _parser_meta(spec)})],
                "parser": _parser_meta(spec), "quality": Quality.UNKNOWN, "parse": {"records": 0, "expected": parsed.expected}}
    if parsed.partial:
        quality = Quality.PARTIAL
        flags.append("PARTIAL_PARSE")
        flags.extend(f"PARSE_ERROR:{e}" for e in (parsed.errors or []))
    if parsed.over_parsed:
        quality = Quality.UNTRUSTED_PARSE
        flags.append("PARSER_RECOVERED_MORE_RECORDS_THAN_RAW_ANNOUNCES")
    if raw_text_check is not None and isinstance(raw, str):
        problems = raw_text_check(raw, parsed)
        if problems:
            quality = Quality.UNTRUSTED_PARSE
            flags.extend(f"RAW_TEXT_DISAGREES:{p}" for p in problems)
    problems = consistency_problems(parsed.records)
    by_iface: dict[str, list[str]] = {}
    for problem in problems:
        by_iface.setdefault(problem.split(":")[1], []).append(problem)
    overall = Quality.UNTRUSTED_PARSE if (problems and quality == Quality.OK) else quality
    observations: list[dict] = []
    for rec in parsed.records:
        obs_time = rec.get("observed_at") or observed_at or (to_utc(evidence["collected_at"]) if evidence.get("collected_at") else None)
        used_corrected = clock is not None and clock.get("status") == "SKEWED"
        if rec.get("observed_at") is not None and clock:
            obs_time, _ = correct_time(rec["observed_at"], clock)
        rec_flags = list(flags)
        if rec.get("observed_at") is None:
            rec_flags.append("OBSERVATION_TIME_IS_COLLECTION_TIME")
        if used_corrected and rec.get("observed_at") is not None:
            rec_flags.append("DEVICE_CLOCK_SKEW_CORRECTED")
        rec_quality = Quality.UNTRUSTED_PARSE if (rec["name"] in by_iface and quality == Quality.OK) else quality
        observations.extend(_interface_observations(rec, device=device, evidence=evidence, spec=spec, quality=rec_quality, now=now, observed_at=obs_time,
                                                    base_flags=rec_flags + by_iface.get(rec["name"], []), clock=clock))
    return {"observations": observations, "missing": [], "parser": _parser_meta(spec), "quality": overall,
            "parse": {"records": len(parsed.records), "expected": parsed.expected, "errors": parsed.errors or []}}


def consistency_problems(records: list) -> list[str]:   # flat list (kept for callers); see problems_by_interface
    """Plausibility checks that catch inaccurate telemetry: impossible MTU, negative counters, oper up while admin down."""
    problems: list[str] = []
    for rec in records:
        name = rec.get("name", "?")
        mtu = rec.get("mtu")
        if mtu is not None and not 68 <= mtu <= 262_144:   # loopback is 65536; jumbo Ethernet 9216+
            problems.append(f"IMPLAUSIBLE_MTU:{name}:{mtu}")
        if rec.get("admin") == "down" and rec.get("oper") == "up":
            problems.append(f"OPER_UP_WHILE_ADMIN_DOWN:{name}")
        for key, value in (rec.get("counters") or {}).items():
            if value is not None and value < 0:
                problems.append(f"NEGATIVE_COUNTER:{name}:{key}")
    return problems


def ios_raw_text_check(raw: str, parsed: ParseResult) -> list[str]:
    """Parser-vs-raw-text check for the IOS XE interface template: interface names announced in the raw text must be the ones parsed."""
    announced = {canonical_interface(m.group(1), platform="iosxe") for m in re.finditer(r"^(\S+) is .*line protocol is", raw, re.M)}
    got = {r["name"] for r in parsed.records}
    problems = [f"MISSING_INTERFACE:{n}" for n in sorted(announced - got)]
    for rec in parsed.records:
        for state_m in re.finditer(rf"^{re.escape(rec['name'])}\S* is (up|down|administratively down), line protocol is (up|down)", raw, re.M):
            raw_oper = "up" if state_m.group(2) == "up" and state_m.group(1) == "up" else "down"
            if raw_oper != rec["oper"]:
                problems.append(f"OPER_STATE_MISMATCH:{rec['name']}")
    return problems


def normalize_neighbors(raw, *, parser_id: str, platform: str, os_version: str, device: str, evidence: dict, now: datetime | None = None,
                        observed_at: datetime | None = None) -> dict:
    """Routing neighbor state (``routing.ospf.neighbor_state`` / ``routing.bgp.neighbor_state``)."""
    now = now or utcnow()
    command = evidence.get("command_or_api", "")
    try:
        spec = select_parser(parser_id, platform, os_version)
        parsed = spec.func(raw)
    except ParserSelectionError as exc:
        return {"observations": [], "missing": [missing_record(Missing.PARSER_UNAVAILABLE, source_type=evidence.get("source_type", ""), device=device, detail=str(exc),
                                                              evidence_id=evidence.get("evidence_id", ""), command=command, observed_at=now,
                                                              extra={"selection_error": exc.code})]}
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return {"observations": [], "missing": [missing_record(Missing.PARSE_FAILED, source_type=evidence.get("source_type", ""), device=device, detail=str(exc)[:200],
                                                              evidence_id=evidence.get("evidence_id", ""), command=command, observed_at=now)]}
    obs_time = observed_at or (to_utc(evidence["collected_at"]) if evidence.get("collected_at") else now)
    quality = Quality.PARTIAL if parsed.partial else Quality.OK
    out = []
    for rec in parsed.records:
        proto = "bgp" if rec["protocol"] == "bgp" else "ospf"
        out.append(make_observation(f"routing.{proto}.neighbor_state", rec["state"], device=device, evidence=evidence, observed_at=obs_time,
                                    interface=rec.get("interface", ""), quality=quality if rec["state"] != "unknown" else Quality.PARTIAL, now=now, parser=_parser_meta(spec),
                                    target={"neighbor": rec["neighbor"], "vrf": rec.get("vrf"), "protocol": rec["protocol"], "family": rec.get("family")},
                                    flags=["PARTIAL_PARSE"] if parsed.partial else (["UNRECOGNISED_STATE"] if rec["state"] == "unknown" else [])))
    return {"observations": out, "missing": [], "parser": _parser_meta(spec)}


# --------------------------------------------------------------------------------------------------------------------
# Parser disagreement / equivalence (UT-019, spec 3.2 "UNTRUSTED_PARSE")
# --------------------------------------------------------------------------------------------------------------------
def _obs_index(observations: Iterable[dict]) -> dict:
    return {(o["key"], json.dumps(o["target"], sort_keys=True)): o for o in observations}


def compare_observations(a: list[dict], b: list[dict], *, keys: Iterable[str] | None = None) -> dict:
    """Compare two independent renderings (e.g. CLI template vs OpenConfig vs SNMP) of the same state.

    Returns ``{"agreed": [...], "disagreements": [{key,target,a,b}], "only_a": [...], "only_b": [...]}`` -- only keys present in both
    sides can agree/disagree; a key seen by one side is reported, never counted as agreement."""
    wanted = set(keys) if keys else None
    ia, ib = _obs_index(a), _obs_index(b)
    agreed, disagreements, only_a, only_b = [], [], [], []
    for ident in sorted(set(ia) | set(ib)):
        if wanted and ident[0] not in wanted:
            continue
        if ident in ia and ident in ib:
            (agreed if ia[ident]["value"] == ib[ident]["value"] else disagreements).append(
                {"key": ident[0], "target": ia[ident]["target"], "a": ia[ident]["value"], "b": ib[ident]["value"]}
                if ia[ident]["value"] != ib[ident]["value"] else {"key": ident[0], "target": ia[ident]["target"], "value": ia[ident]["value"]})
        elif ident in ia:
            only_a.append({"key": ident[0], "target": ia[ident]["target"]})
        else:
            only_b.append({"key": ident[0], "target": ib[ident]["target"]})
    return {"agreed": agreed, "disagreements": disagreements, "only_a": only_a, "only_b": only_b}


def mark_untrusted(observations: list[dict], comparison: dict) -> list[dict]:
    """Return copies of the observations involved in a disagreement with quality ``UNTRUSTED_PARSE`` and a disagreement flag
    (confidence 0.1): downstream diagnosis must treat them as ``UNKNOWN`` (``trusted_value``)."""
    bad = {(d["key"], json.dumps(d["target"], sort_keys=True)) for d in comparison["disagreements"]}
    out = []
    for obs in observations:
        copy = json.loads(json.dumps(obs))
        if (obs["key"], json.dumps(obs["target"], sort_keys=True)) in bad:
            copy["quality"] = Quality.UNTRUSTED_PARSE
            copy["confidence"] = 0.1
            copy["flags"] = list(dict.fromkeys(copy["flags"] + ["PARSER_DISAGREEMENT"]))
        out.append(copy)
    return out


def canonical_view(observations: Iterable[dict]) -> dict:
    """``{(key, interface/neighbor): value}`` -- the vendor-neutral content of a list of observations (for equivalence assertions)."""
    view = {}
    for o in observations:
        t = o["target"]
        view[(o["key"], t.get("interface") or t.get("neighbor") or "")] = o["value"]
    return view


# --------------------------------------------------------------------------------------------------------------------
# gNMI / OpenConfig streaming  (UT-014)
# --------------------------------------------------------------------------------------------------------------------
_GNMI_LEAVES = {
    "state/oper-status": ("interface.oper_state", "", norm_oper_state),
    "state/admin-status": ("interface.admin_state", "", norm_admin_state),
    "state/mtu": ("interface.mtu", "bytes", _int),
    "state/counters/in-octets": ("interface.counter.in_octets", "bytes", _int),
    "state/counters/out-octets": ("interface.counter.out_octets", "bytes", _int),
    "state/counters/in-errors": ("interface.counter.in_errors", "frames", _int),
    "state/counters/out-errors": ("interface.counter.out_errors", "frames", _int),
    "state/counters/in-discards": ("interface.counter.in_discards", "frames", _int),
    "state/counters/out-discards": ("interface.counter.out_discards", "frames", _int),
    "state/counters/in-fcs-errors": ("interface.counter.in_crc_errors", "frames", _int),
}
_GNMI_NAME = re.compile(r"interface\[name=([^\]]+)\]")


def normalize_gnmi_notification(notification: dict, *, device: str, platform: str = "", evidence: dict, arrival: datetime,
                                now: datetime | None = None, clock: dict | None = None, future_tolerance_s: float = 5.0) -> dict:
    """Map one gNMI ``Notification`` (``{"timestamp": ns, "prefix": ..., "update": [{"path","val"}], "delete": [...]}``) to
    observations whose **event time is the notification timestamp** (skew-corrected), not the arrival time.

    A missing/invalid timestamp or one in the future falls back to arrival time and is flagged (``TIMESTAMP_FALLBACK_TO_ARRIVAL``,
    quality PARTIAL).  Paths outside the OpenConfig leaf map are returned in ``unmapped`` (never silently dropped).  Deletes
    produce a missing-data-style note, not a fabricated value."""
    now = now or arrival
    out, unmapped, flags = [], [], []
    ts = notification.get("timestamp")
    event_time, quality = None, Quality.OK
    try:
        event_time = to_utc(ts, unit="ns") if ts not in (None, 0) else None
    except (ValueError, OverflowError, OSError):
        event_time = None
    if event_time is not None:
        event_time, corrected = correct_time(event_time, clock)
        if corrected:
            flags.append("DEVICE_CLOCK_SKEW_CORRECTED")
    if event_time is None or (event_time - arrival).total_seconds() > future_tolerance_s:
        event_time = arrival
        quality = Quality.PARTIAL
        flags.append("TIMESTAMP_FALLBACK_TO_ARRIVAL")
    prefix = str(notification.get("prefix", "") or "")
    for upd in notification.get("update", []) or []:
        path = prefix.rstrip("/") + "/" + str(upd.get("path", "")).lstrip("/") if prefix else str(upd.get("path", ""))
        name_m = _GNMI_NAME.search(path)
        leaf = path.split("]/", 1)[-1] if "]/" in path else ""
        mapped = _GNMI_LEAVES.get(leaf)
        if not name_m or not mapped:
            unmapped.append(path)
            continue
        key, unit, fn = mapped
        value = fn(upd.get("val"))
        if value is None:
            unmapped.append(path)
            continue
        extra = {"gnmi_path": path, "update_kind": notification.get("kind", "sample")}
        if key.startswith("interface.counter."):
            extra["counter"] = {"cumulative": True, "width_bits": 64, "last_clear": None}
        out.append(make_observation(key, value, unit=unit, device=device, evidence=evidence, observed_at=event_time,
                                    interface=canonical_interface(name_m.group(1), platform=platform), quality=quality, now=now, flags=flags,
                                    parser={"id": "gnmi.openconfig", "version": "1.0", "template": "openconfig-interfaces", "input_kind": "dict"},
                                    clock=clock, extra=extra))
    deletes = [str(d) for d in notification.get("delete", []) or []]
    return {"observations": out, "unmapped_paths": unmapped, "deleted_paths": deletes, "event_time": iso(event_time)}


# --------------------------------------------------------------------------------------------------------------------
# Syslog  (UT-016, UT-021)
# --------------------------------------------------------------------------------------------------------------------
_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(r"^<\d+>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:-|\[.*?\])\s*(.*)$", re.S)
_RFC3164 = re.compile(r"^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<host>\S+)\s+(?P<msg>.*)$", re.S)
_MNEMONIC = re.compile(r"%(?P<fac>[A-Z0-9_\-]+)-(?P<sev>\d)-(?P<mnem>[A-Z0-9_\-]+):\s*(?P<text>.*)")
_LINK_RULES = (
    re.compile(r"Line protocol on Interface (?P<ifc>\S+?),? changed state to (?P<state>up|down)", re.I),
    re.compile(r"Interface (?P<ifc>\S+?),? changed state to (?P<state>up|down|administratively down)", re.I),
    re.compile(r"(?:Interface\s+)?(?P<ifc>\S+) is (?P<state>up|down)\b", re.I),
)
_OSPF_RULE = re.compile(r"Nbr (?P<nbr>\S+) on (?P<ifc>\S+) from (?P<old>\S+) to (?P<state>\S+)", re.I)
_BGP_RULE = re.compile(r"neighbor (?P<nbr>\S+).*?(?P<state>Up|Down)", re.I)
_STP_RULE = re.compile(r"(topology change|TCN|root (?:bridge )?change|new root)", re.I)
_OPTIC_RULE = re.compile(r"(?:transceiver|DOM|optic|rx power|tx power).*?(?:alarm|warning|threshold|low|high)", re.I)


def parse_syslog_line(line: str, *, received_at: datetime, tz=None, device: str = "", evidence_ref: str = "") -> dict:
    """Parse one RFC3164/RFC5424 line into an event dict.  ``device_time`` is None if the header has no usable timestamp (arrival is
    then used and flagged by ``normalize_syslog_events``).  The message is redacted; ``raw_hash`` identifies the original line."""
    raw = str(line).rstrip("\n")
    pri = _PRI.match(raw)
    severity = int(pri.group(1)) % 8 if pri else None
    facility = int(pri.group(1)) // 8 if pri else None
    host, ts_text, message = device, None, raw
    m5424 = _RFC5424.match(raw)
    m3164 = _RFC3164.match(raw)
    if m5424:
        ts_text, host, message = m5424.group(2), m5424.group(3) if m5424.group(3) != "-" else device, m5424.group(7)
    elif m3164:
        ts_text, host, message = m3164.group("ts"), m3164.group("host"), m3164.group("msg")
    device_time, flags = None, []
    if ts_text and ts_text != "-":
        try:
            device_time = to_utc(ts_text, tz=tz, reference=received_at)
            if not re.search(r"(Z|[+-]\d{2}:?\d{2})$", ts_text):
                flags.append("TIMEZONE_ASSUMED")
        except ValueError:
            flags.append("UNPARSEABLE_TIMESTAMP")
    redacted, count = redact_text(message)
    event = {"raw_hash": sha256_text(raw), "evidence_ref": evidence_ref, "received_at": iso(received_at), "device_time": iso(device_time), "device": host or device,
             "severity": severity, "facility": facility, "message": redacted, "redactions": count, "flags": flags, "event_type": "other", "subject": "", "state": ""}
    mm = _MNEMONIC.search(redacted)
    if mm:
        event["mnemonic"] = f"{mm.group('fac')}-{mm.group('sev')}-{mm.group('mnem')}"
        event["severity"] = int(mm.group("sev")) if event["severity"] is None else event["severity"]
    body = mm.group("text") if mm else redacted
    for rule in _LINK_RULES[:2] if mm or "changed state" in body else _LINK_RULES:
        found = rule.search(body)
        if found:
            event.update(event_type="link_state", subject=canonical_interface(found.group("ifc").rstrip(","), platform="linux" if not mm else ""),
                         state="down" if "down" in found.group("state").lower() else "up")
            break
    else:
        if (found := _OSPF_RULE.search(body)):
            event.update(event_type="ospf_adjacency", subject=found.group("nbr"), state=norm_ospf_state(found.group("state")), interface=found.group("ifc"))
        elif "ADJCHG" in redacted and (found := _BGP_RULE.search(body)):
            event.update(event_type="bgp_adjacency", subject=found.group("nbr"), state=found.group("state").lower())
        elif _STP_RULE.search(body):
            event.update(event_type="stp_topology_change", subject="", state="change")
        elif _OPTIC_RULE.search(body):
            event.update(event_type="optics_warning", subject="", state="warning")
    return event


def normalize_syslog_events(events: list[dict], *, evidence: dict, device: str, clock: dict | None = None, dedupe_window_s: float = 2.0,
                            now: datetime | None = None, max_age_s: float | None = None) -> dict:
    """Skew-correct, order and de-duplicate syslog events; preserve every original source event reference.

    * Event time = device time (skew-corrected) when present, else arrival time with ``ARRIVAL_TIME_USED``.
    * Events are sorted by corrected time regardless of arrival order.
    * Duplicates (same device, type, subject, state, normalized message core within ``dedupe_window_s``) collapse into one
      observation whose ``extra.source_event_refs`` lists *all* contributing raw events (hash + arrival time + evidence ref)."""
    now = now or utcnow()
    prepared = []
    for ev in events:
        flags = list(ev.get("flags", []))
        if ev.get("device_time"):
            t, corrected = correct_time(to_utc(ev["device_time"]), clock)
            if corrected:
                flags.append("DEVICE_CLOCK_SKEW_CORRECTED")
        else:
            t = to_utc(ev["received_at"])
            flags.append("ARRIVAL_TIME_USED")
        prepared.append((t, ev, flags))
    prepared.sort(key=lambda item: (item[0], item[1]["raw_hash"]))
    groups: list[dict] = []
    for t, ev, flags in prepared:
        core = re.sub(r"\d{2}:\d{2}:\d{2}(\.\d+)?", "", ev["message"]).strip()
        ident = (ev["device"] or device, ev["event_type"], ev["subject"], ev["state"], core if ev["event_type"] == "other" else "")
        matched = False
        for g in reversed(groups):
            if (t - g["last"]).total_seconds() > dedupe_window_s and t >= g["last"]:
                break          # groups are time-ordered: nothing earlier can be inside the window
            if g["ident"] == ident and abs((t - g["last"]).total_seconds()) <= dedupe_window_s:
                g["refs"].append({"raw_hash": ev["raw_hash"], "received_at": ev["received_at"], "evidence_ref": ev["evidence_ref"]})
                g["last"] = t
                g["flags"] = list(dict.fromkeys(g["flags"] + flags + ["DEDUPLICATED"]))
                matched = True
                break
        if not matched:
            groups.append({"ident": ident, "first": t, "last": t, "event": ev, "flags": flags,
                           "refs": [{"raw_hash": ev["raw_hash"], "received_at": ev["received_at"], "evidence_ref": ev["evidence_ref"]}]})
    observations = []
    for g in groups:
        ev = g["event"]
        key = {"link_state": "interface.link_event", "ospf_adjacency": "routing.ospf.adjacency_event", "bgp_adjacency": "routing.bgp.adjacency_event",
               "stp_topology_change": "stp.topology_change_event", "optics_warning": "interface.optics_warning_event"}.get(ev["event_type"], "syslog.event")
        quality = Quality.PARTIAL if any(f in g["flags"] for f in ("ARRIVAL_TIME_USED", "UNPARSEABLE_TIMESTAMP", "TIMEZONE_ASSUMED")) else Quality.OK
        observations.append(make_observation(
            key, ev["state"] or ev["message"][:200], device=ev["device"] or device, evidence=evidence, observed_at=g["first"],
            interface=ev["subject"] if ev["event_type"] == "link_state" else "", quality=quality, now=now, max_age_s=max_age_s, flags=g["flags"],
            parser={"id": "syslog.rules", "version": "1.0", "template": ev.get("mnemonic", "free-text"), "input_kind": "text"}, clock=clock,
            target={"neighbor": ev["subject"]} if ev["event_type"] in ("ospf_adjacency", "bgp_adjacency") else None,
            extra={"event_type": ev["event_type"], "occurrences": len(g["refs"]), "source_event_refs": g["refs"], "last_seen": iso(g["last"]),
                   "message": ev["message"][:300], "severity": ev.get("severity")}))
    return {"observations": observations, "input_events": len(events), "unique_events": len(groups)}


# --------------------------------------------------------------------------------------------------------------------
# SNMP polling  (UT-015)
# --------------------------------------------------------------------------------------------------------------------
def normalize_snmp_poll(samples: list[dict], *, device: str, evidence: dict, tracker: CounterTracker, now: datetime | None = None,
                        platform: str = "", sys_uptime_ticks: int | None = None) -> dict:
    """Turn an IF-MIB poll (see ``parse_snmp_if_mib``) into state observations plus counter-rate observations.

    ``samples`` are ``parse_snmp_if_mib`` records at one poll instant (``evidence['collected_at']``).  Counters pass through
    ``tracker`` so wraps/resets/gaps are detected across polls; rate observations are emitted only when the delta is meaningful
    (NORMAL / WRAP); RESET / GAP / FIRST yield an *event* observation (``interface.counter_event``) instead of a number.
    ``sys_uptime_ticks`` (1/100 s) is converted to seconds and a drop is reported as ``device.restart_suspected``."""
    now = now or utcnow()
    at = to_utc(evidence["collected_at"])
    spec = select_parser("interfaces.snmp", platform or "linux", "1.0")
    parser = _parser_meta(spec)
    out = []
    if sys_uptime_ticks is not None:
        prev = tracker._last.get((device, "sysUpTime"))
        uptime_s = sys_uptime_ticks / 100.0
        out.append(make_observation("device.uptime", uptime_s, unit="seconds", device=device, evidence=evidence, observed_at=at, now=now, parser=parser))
        if prev and uptime_s < prev["value"]:
            out.append(make_observation("device.restart_suspected", True, device=device, evidence=evidence, observed_at=at, now=now, parser=parser,
                                        flags=["SYSUPTIME_DECREASED"]))
        tracker._last[(device, "sysUpTime")] = {"value": uptime_s, "at": at}
    for rec in samples:
        out.extend(_interface_observations({**rec, "counters": {}}, device=device, evidence=evidence, spec=spec, quality=Quality.OK, now=now,
                                           observed_at=at, base_flags=[], clock=None))
        for key, value in sorted(rec.get("counters", {}).items()):
            width = (rec.get("counter_widths") or {}).get(key, 32)
            result = tracker.update((device, rec["name"], key), value, at, width_bits=width, speed_bps=rec.get("speed_bps"),
                                    unit="bytes" if key.endswith("octets") else "frames")
            common = dict(device=device, evidence=evidence, observed_at=at, interface=rec["name"], now=now, parser=parser)
            if result["event"] in ("NORMAL", "WRAP"):
                flags = (["COUNTER_WRAP_HANDLED"] if result["event"] == "WRAP" else []) + result["flags"]
                quality = Quality.UNTRUSTED_PARSE if "RATE_EXCEEDS_LINE_RATE" in result["flags"] else Quality.OK
                if key.endswith("octets"):
                    out.append(make_observation(f"interface.rate.{key}", result["rate_bps"], unit="bps", quality=quality, flags=flags,
                                                extra={"delta": result["delta"], "interval_s": result["interval_s"], "counter_width_bits": width}, **common))
                else:
                    out.append(make_observation(f"interface.rate.{key}", result["rate_per_s"], unit="frames/s", quality=quality, flags=flags,
                                                extra={"delta": result["delta"], "interval_s": result["interval_s"], "counter_width_bits": width}, **common))
            elif result["event"] != "FIRST":
                out.append(make_observation("interface.counter_event", result["event"].lower(), quality=Quality.PARTIAL, flags=result["flags"],
                                            extra={"counter": key, "interval_s": result["interval_s"], "delta": result["delta"]}, **common))
    return {"observations": out}


# --------------------------------------------------------------------------------------------------------------------
# NetFlow / IPFIX  (UT-017)
# --------------------------------------------------------------------------------------------------------------------
def _in_prefixes(address: str, prefixes: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(p, strict=False) for p in prefixes)


def flow_matches(record: dict, selector: dict) -> bool:
    """Service scoping: protocol, destination/source ports, src/dst prefixes (all optional, all must hold)."""
    if selector.get("protocol") is not None and record.get("proto") != selector["protocol"]:
        return False
    if selector.get("dst_ports") and record.get("dport") not in selector["dst_ports"]:
        return False
    if selector.get("src_ports") and record.get("sport") not in selector["src_ports"]:
        return False
    if selector.get("src_prefixes") and not _in_prefixes(str(record.get("src", "")), selector["src_prefixes"]):
        return False
    if selector.get("dst_prefixes") and not _in_prefixes(str(record.get("dst", "")), selector["dst_prefixes"]):
        return False
    return True


def _mask_host(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ""
    return str(ipaddress.ip_network((ip, 24 if ip.version == 4 else 64), strict=False))


def normalize_flow_records(records: list[dict], selector: dict, *, device: str, evidence: dict, expected_exporters: Iterable[str] = (),
                           now: datetime | None = None, privacy: str = "prefix") -> dict:
    """Service-scoped flow observations with sampling uncertainty.

    Each flow record: ``{src,dst,sport,dport,proto,bytes,packets,first,last,exporter,sampling_rate}``.  ``sampling_rate`` N means 1-in-N
    packets sampled.  Scaled estimates (bytes x N) are labelled ``estimated`` with a relative error bound ``1.96/sqrt(sampled_records)``
    (Poisson approximation); N=1 is exact; an unknown rate yields NO estimate (quality UNKNOWN, raw sampled bytes retained).
    Exporter coverage = exporters seen / expected exporters.  ``privacy='prefix'`` (default) masks endpoints to /24 (/64) in output.
    Flows that do not match the service selector are counted (``out_of_scope``) but never aggregated into the service."""
    now = now or utcnow()
    scoped = [r for r in records if flow_matches(r, selector)]
    out_of_scope = len(records) - len(scoped)
    rates = {r.get("sampling_rate") for r in scoped}
    exporters = sorted({str(r.get("exporter")) for r in scoped if r.get("exporter")})
    expected = sorted(set(expected_exporters))
    coverage = {"exporters_seen": exporters, "exporters_expected": expected,
                "ratio": (len(set(exporters) & set(expected)) / len(expected)) if expected else None,
                "missing_exporters": sorted(set(expected) - set(exporters))}
    times = [to_utc(r["last"]) for r in scoped if r.get("last") is not None]
    observed_at = max(times) if times else None
    raw_bytes = sum(int(r.get("bytes", 0)) for r in scoped)
    raw_packets = sum(int(r.get("packets", 0)) for r in scoped)
    unknown_rate = any(not isinstance(r.get("sampling_rate"), int) or r["sampling_rate"] < 1 for r in scoped)
    parser = {"id": "netflow.ipfix", "version": "1.0", "template": "ipfix-5tuple", "input_kind": "dict"}
    obs = []
    scope_label = json.dumps(selector, sort_keys=True)
    base_flags = ["SAMPLED_DATA"] if rates - {1} else []
    if coverage["missing_exporters"]:
        base_flags.append("EXPORTER_COVERAGE_INCOMPLETE")
    common = dict(device=device, evidence=evidence, observed_at=observed_at, now=now, parser=parser, target={"service_selector": scope_label})
    obs.append(make_observation("flow.service.sampled_records", len(scoped), unit="records", quality=Quality.OK if scoped else Quality.PARTIAL, flags=base_flags,
                                extra={"out_of_scope_records": out_of_scope, "coverage": coverage}, **common))
    if scoped and not unknown_rate:
        # Aggregate by sampling-rate scaling per record
        est_bytes = sum(int(r["bytes"]) * r["sampling_rate"] for r in scoped)
        est_packets = sum(int(r["packets"]) * r["sampling_rate"] for r in scoped)
        exact = rates == {1}
        rel_err = 0.0 if exact else round(1.96 / math.sqrt(len(scoped)), 4)
        uncertainty = {"method": "exact" if exact else "poisson_approx_95", "relative_error_95": rel_err, "sampling_rates": sorted(rates),
                       "sampled_records": len(scoped), "estimated": not exact}
        obs.append(make_observation("flow.service.bytes", est_bytes, unit="bytes", quality=Quality.OK if coverage["ratio"] in (None, 1.0) else Quality.PARTIAL,
                                    flags=base_flags + ([] if exact else ["ESTIMATED_FROM_SAMPLES"]), extra={"uncertainty": uncertainty, "coverage": coverage, "raw_sampled_bytes": raw_bytes}, **common))
        obs.append(make_observation("flow.service.packets", est_packets, unit="packets", quality=Quality.OK if coverage["ratio"] in (None, 1.0) else Quality.PARTIAL,
                                    flags=base_flags + ([] if exact else ["ESTIMATED_FROM_SAMPLES"]), extra={"uncertainty": uncertainty, "coverage": coverage}, **common))
    elif scoped:
        obs.append(make_observation("flow.service.bytes", None, unit="bytes", quality=Quality.UNKNOWN, flags=base_flags + ["SAMPLING_RATE_UNKNOWN"],
                                    extra={"raw_sampled_bytes": raw_bytes, "raw_sampled_packets": raw_packets, "coverage": coverage}, **common))
    endpoints = {}
    for r in scoped:
        src, dst = (_mask_host(str(r.get("src", ""))), _mask_host(str(r.get("dst", "")))) if privacy == "prefix" else (str(r.get("src")), str(r.get("dst")))
        endpoints[(src, dst, r.get("proto"), r.get("dport"))] = endpoints.get((src, dst, r.get("proto"), r.get("dport")), 0) + 1
    obs.append(make_observation("flow.service.endpoints", [{"src": s, "dst": d, "protocol": p, "dst_port": dp, "records": n} for (s, d, p, dp), n in sorted(endpoints.items(), key=str)],
                                quality=Quality.OK if scoped else Quality.PARTIAL, flags=base_flags + ([f"PRIVACY_{privacy.upper()}"] if privacy == "prefix" else []),
                                extra={"privacy": privacy}, **common))
    return {"observations": obs, "in_scope": len(scoped), "out_of_scope": out_of_scope, "coverage": coverage}


# --------------------------------------------------------------------------------------------------------------------
# Packet-capture metadata  (UT-018)
# --------------------------------------------------------------------------------------------------------------------
PAYLOAD_KEYS = frozenset({"payload", "data", "raw", "hex", "hexdump", "bytes_hex", "packets_hex", "decoded_payload", "body", "frames", "pcap_bytes", "ascii"})
CAPTURE_SUMMARY_KEYS = ("tcp_syn", "tcp_retransmissions", "tcp_resets", "icmp_frag_needed", "icmp6_packet_too_big", "arp_requests", "arp_replies",
                        "nd_solicitations", "bpdu_frames", "dns_queries", "dns_nxdomain", "dns_servfail", "dns_responses", "stp_tcn_frames")
MAX_CAPTURE_SNAPLEN = 128           # header-only
MAX_CAPTURE_PACKETS = 10_000
MAX_CAPTURE_SECONDS = 60.0
MAX_CAPTURE_BYTES = 8_000_000


def capture_bound_violations(meta: dict, bounds: dict | None = None) -> list[str]:
    b = {"snaplen": MAX_CAPTURE_SNAPLEN, "packets": MAX_CAPTURE_PACKETS, "seconds": MAX_CAPTURE_SECONDS, "bytes": MAX_CAPTURE_BYTES, **(bounds or {})}
    problems = []
    if not meta.get("filter"):
        problems.append("UNSCOPED_CAPTURE_NO_FILTER")
    if not isinstance(meta.get("snaplen"), int) or not 0 < meta["snaplen"] <= b["snaplen"]:
        problems.append("SNAPLEN_EXCEEDS_HEADER_ONLY_BOUND")
    if (meta.get("packets") or 0) > b["packets"]:
        problems.append("PACKET_COUNT_EXCEEDS_BOUND")
    if (meta.get("duration_s") or 0) > b["seconds"]:
        problems.append("DURATION_EXCEEDS_BOUND")
    if (meta.get("bytes") or 0) > b["bytes"]:
        problems.append("BYTES_EXCEED_BOUND")
    return problems


def normalize_capture_metadata(meta: dict, *, device: str, evidence: dict, bounds: dict | None = None, now: datetime | None = None) -> dict:
    """Capture *metadata* observations.  Payload-bearing keys are dropped (reported in ``dropped_fields``), never forwarded; a capture
    that violates bounds is refused (``violations``) and yields a missing-data record instead of observations."""
    now = now or utcnow()
    dropped = sorted(k for k in meta if k.lower() in PAYLOAD_KEYS)
    violations = capture_bound_violations(meta, bounds)
    if violations:
        return {"observations": [], "dropped_fields": dropped, "violations": violations,
                "missing": [missing_record(Missing.UNAUTHORIZED_CAPTURE, source_type="PCAP_METADATA", device=device, detail=",".join(violations),
                                           evidence_id=evidence.get("evidence_id", ""), observed_at=now)]}
    started = to_utc(meta["started_at"]) if meta.get("started_at") else None
    parser = {"id": "pcap.metadata", "version": "1.0", "template": "capture-summary", "input_kind": "dict"}
    target = {"capture_id": meta.get("capture_id"), "capture_interface": meta.get("interface")}
    common = dict(device=device, evidence=evidence, observed_at=started, now=now, parser=parser, target=target)
    observations = [make_observation("capture.metadata", {"capture_id": meta.get("capture_id"), "interface": meta.get("interface"), "filter": meta["filter"],
                                                         "snaplen": meta["snaplen"], "packets": meta.get("packets", 0), "bytes": meta.get("bytes", 0),
                                                         "duration_s": meta.get("duration_s"), "pcap_ref": meta.get("pcap_ref"), "payload_included": False},
                                     flags=["PAYLOAD_EXCLUDED"] + (["PAYLOAD_FIELDS_DROPPED"] if dropped else []), **common)]
    for key in CAPTURE_SUMMARY_KEYS:
        value = (meta.get("summary") or {}).get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            observations.append(make_observation(f"capture.summary.{key}", value, unit="packets", flags=["FROM_CAPTURE_SUMMARY"], **common))
    return {"observations": observations, "dropped_fields": dropped, "violations": [], "missing": []}


# --------------------------------------------------------------------------------------------------------------------
# Snapshots and intent inputs
# --------------------------------------------------------------------------------------------------------------------
def normalize_snapshot(kind: str, content, *, device: str, evidence: dict, revision: str = "", url: str = "", now: datetime | None = None,
                       observed_at: datetime | None = None, evidence_class: str = EvidenceClass.SNAPSHOT) -> dict:
    """Config/state snapshot -> ``config.snapshot`` observation carrying only metadata (hash of the REDACTED text, size, line count,
    revision, operator-view URL).  The snapshot body never appears in the observation (UT-012).  A missing ``url`` is reported as
    ``None`` (never invented; UT-011)."""
    now = now or utcnow()
    text = content if isinstance(content, str) else json.dumps(content, sort_keys=True, default=str)
    redacted, count = redact_text(text)
    value = {"kind": kind, "revision": revision or None, "hash": sha256_text(redacted), "bytes": len(redacted.encode()), "lines": redacted.count("\n") + (1 if redacted else 0),
             "redactions": count, "operator_url": url or None}
    flags = ([] if url else ["NO_OPERATOR_URL"]) + (["SECRETS_REDACTED"] if count else [])
    return {"observations": [make_observation("config.snapshot", value, device=device, evidence=evidence, observed_at=observed_at or now, now=now,
                                              parser={"id": f"snapshot.{kind}", "version": "1.0", "template": kind, "input_kind": "text"},
                                              flags=flags, evidence_class=evidence_class)],
            "redacted_text": redacted}


def normalize_intent(device: str, intent: dict, *, evidence: dict, now: datetime | None = None, source: str = "netbox", revision: str = "",
                     url: str = "") -> dict:
    """NetBox / golden intent inputs -> ``intent.*`` observations, always ``evidence_class == 'intent'`` (intent is not proof of operational state).

    ``intent`` = ``{"interfaces": {name: {"mtu","speed_bps","admin","addresses":[..],"vrf"}}, "neighbors": [{"protocol","neighbor","interface"}]}``."""
    now = now or utcnow()
    at = to_utc(evidence["collected_at"]) if evidence.get("collected_at") else now
    parser = {"id": f"intent.{source}", "version": "1.0", "template": source, "input_kind": "dict"}
    extra = {"intent_source": source, "revision": revision or None, "operator_url": url or None}
    flags = [] if url else ["NO_OPERATOR_URL"]
    out = []
    for name, spec in sorted((intent.get("interfaces") or {}).items()):
        iface = canonical_interface(name)
        for field_name, key, unit in (("mtu", "intent.interface.mtu", "bytes"), ("speed_bps", "intent.interface.speed", "bps"), ("admin", "intent.interface.admin_state", ""),
                                      ("vrf", "intent.interface.vrf", "")):
            if spec.get(field_name) is not None:
                value = norm_admin_state(spec[field_name]) if field_name == "admin" else spec[field_name]
                out.append(make_observation(key, value, unit=unit, device=device, evidence=evidence, observed_at=at, interface=iface, now=now, parser=parser,
                                            evidence_class=EvidenceClass.INTENT, flags=flags, extra=extra, max_age_s=86400.0))
        for address in spec.get("addresses", []) or []:
            norm = normalize_address(address)
            if norm:
                out.append(make_observation("intent.interface.address", norm, device=device, evidence=evidence, observed_at=at, interface=iface, now=now, parser=parser,
                                            evidence_class=EvidenceClass.INTENT, flags=flags, extra=extra, max_age_s=86400.0))
    for nbr in intent.get("neighbors", []) or []:
        out.append(make_observation(f"intent.routing.{nbr['protocol']}.neighbor", "expected", device=device, evidence=evidence, observed_at=at,
                                    interface=canonical_interface(nbr.get("interface", "")), now=now, parser=parser, evidence_class=EvidenceClass.INTENT,
                                    target={"neighbor": nbr["neighbor"], "protocol": nbr["protocol"]}, flags=flags, extra=extra, max_age_s=86400.0))
    return {"observations": out}


# -- Independent forwarding-table (FIB) source: HC16 -------------------------------------------------------------------
# A FIB observation exists ONLY when an injected, structured, read-only operational document names an authoritative forwarding-plane source that is independent of the
# RIB.  ``route.table`` (RIB / Linux kernel routing table) is never accepted here, and nothing is inferred when the document is partial, mis-scoped or unsupported:
# every rejection is a missing record (UNKNOWN) bound to the asked ``route.fib@<prefix>`` keys.
FIB_SCHEMA = "nmas.troubleshooting.fib-source/1"
FIB_PARSER = {"id": "route.fib", "version": "fib-source-1.0", "template": "injected-structured", "input_kind": "structured"}
FIB_SOURCE_KINDS = frozenset({"hardware-fib", "cef", "fib-agent", "forwarding-agent", "gnmi-fib", "fib-api"})
FIB_COVERAGE = frozenset({"FULL_TABLE", "PREFIX_LOOKUP"})
FIB_MAX_ENTRIES = 20000
FIB_LABELS = ("SIMULATED", "RECORDED", "LIVE_GATEWAY_PINNED")


def _fib_reject(reason: str, detail: str, *, device: str, evidence: dict, request: dict, now, observed_at=None) -> dict:
    keys = [f"route.fib@{p}" for p in request.get("prefixes", ())] or ["route.fib"]
    recs = [missing_record(reason, source_type=evidence.get("source_type", "STATE_SNAPSHOT"), device=device, detail=detail[:200], evidence_id=evidence.get("evidence_id", ""),
                           command=evidence.get("command_or_api", ""), observed_at=observed_at or now, extra={"engine_key": k}) for k in keys]
    return {"observations": [], "missing": recs, "parser": dict(FIB_PARSER)}


def _fib_entry(raw, family: str):
    if not isinstance(raw, dict):
        raise ValueError("entry is not an object")
    net = ipaddress.ip_network(str(raw.get("prefix", "")).strip(), strict=True)
    if (net.version == 4) != (family == "ipv4"):
        raise ValueError("entry address family differs from the declared scope")
    hops = []
    for h in raw.get("next_hops") or []:
        if not isinstance(h, dict):
            raise ValueError("next hop is not an object")
        addr = h.get("address")
        if addr:
            addr = str(ipaddress.ip_address(str(addr)))
        res = h.get("resolved")
        hops.append({"address": addr or None, "interface": str(h.get("interface") or "") or None, "resolved": res if isinstance(res, bool) else None,
                     "adjacency": str(h.get("adjacency") or "")[:64] or None})
    prog = raw.get("programmed")
    if not isinstance(prog, bool):
        raise ValueError("entry lacks a boolean programmed flag")
    return {"prefix": str(net), "programmed": prog, "next_hops": hops, "action": str(raw.get("action") or "forward")[:16]}


def normalize_fib_state(doc, *, platform: str, os_version: str, device: str, evidence: dict, request: dict, now: datetime, observed_at=None) -> dict:
    """Injected FIB document -> ``route.fib.table`` observation (or explicit missing records).  ``request`` = ``{vrf, family, prefixes}`` asked of the source."""
    kw = dict(device=device, evidence=evidence, request=request, now=now, observed_at=observed_at)
    if not isinstance(doc, dict) or doc.get("schema") != FIB_SCHEMA:
        return _fib_reject(Missing.PARSE_FAILED, f"forwarding document is not {FIB_SCHEMA}", **kw)
    src = doc.get("source_identity") if isinstance(doc.get("source_identity"), dict) else {}
    kind = str(src.get("kind") or "").lower()
    if not src.get("id") or not kind:
        return _fib_reject(Missing.UNSUPPORTED_OPERATION, "source identity (id, kind) is absent: the origin of the forwarding data is unknown", **kw)
    if src.get("authoritative") is not True or src.get("derived_from_rib") is not False or kind not in FIB_SOURCE_KINDS:
        return _fib_reject(Missing.UNSUPPORTED_OPERATION, f"source {src.get('id')!r} (kind {kind!r}) is not an authoritative forwarding-plane source independent of the RIB: "
                           "a RIB / kernel routing table is never promoted to FIB evidence", **kw)
    if doc.get("device") != device or canonical_platform(str(doc.get("platform") or "")) != canonical_platform(platform) or not doc.get("os_version") \
            or (os_version and str(doc.get("os_version")) != str(os_version)):
        return _fib_reject(Missing.UNSUPPORTED_PLATFORM, "document device/platform/version does not match the admitted device", **kw)
    cap = doc.get("capability") if isinstance(doc.get("capability"), dict) else {}
    if str(cap.get("status", "")).upper() != "SUPPORTED" or not cap.get("api"):
        return _fib_reject(Missing.UNSUPPORTED_OPERATION, f"platform capability for forwarding-table reads is {cap.get('status') or 'UNKNOWN'}", **kw)
    scope = doc.get("scope") if isinstance(doc.get("scope"), dict) else {}
    vrf, family, coverage = scope.get("vrf"), scope.get("family"), scope.get("coverage")
    if not vrf or family not in ("ipv4", "ipv6") or coverage not in FIB_COVERAGE:
        return _fib_reject(Missing.SCOPE_MISMATCH, "document scope (vrf, family, coverage) is absent or invalid", **kw)
    if vrf != request.get("vrf") or family != request.get("family"):
        return _fib_reject(Missing.SCOPE_MISMATCH, f"document covers VRF {vrf}/{family}, not the asked {request.get('vrf')}/{request.get('family')}", **kw)
    prov = doc.get("provenance") if isinstance(doc.get("provenance"), dict) else {}
    if prov.get("label") not in FIB_LABELS or not prov.get("collected_at"):
        return _fib_reject(Missing.PARSE_FAILED, "provenance (label, collected_at) is absent: the evidence cannot be attributed", **kw)
    try:
        when = to_utc(prov["collected_at"])
    except (ValueError, TypeError):
        return _fib_reject(Missing.PARSE_FAILED, "provenance collected_at is not a timestamp", **kw)
    raw_entries = doc.get("entries")
    if not isinstance(raw_entries, list):
        return _fib_reject(Missing.PARSE_FAILED, "entries is not a list", **kw)
    notes, entries = [], []
    truncated = len(raw_entries) > FIB_MAX_ENTRIES
    if truncated:
        notes.append(f"truncated_at_{FIB_MAX_ENTRIES}_of_{len(raw_entries)}")
    bad = 0
    for raw in raw_entries[:FIB_MAX_ENTRIES]:
        try:
            entries.append(_fib_entry(raw, family))
        except (ValueError, TypeError) as exc:
            bad += 1
            notes.append(f"entry_rejected:{str(exc)[:60]}")
    queried = []
    for p in scope.get("queried") or []:
        try:
            queried.append(str(ipaddress.ip_network(str(p), strict=False)))
        except ValueError:
            notes.append("queried_prefix_invalid")
    restart = doc.get("restart") if isinstance(doc.get("restart"), dict) else {}
    converging = restart.get("converging") is not False if restart else True      # a source that does not state convergence is not trusted to be converged
    if restart.get("converging") is True:
        notes.append("device_restart_or_reconvergence_in_progress")
    elif not restart:
        notes.append("restart_state_not_reported")
    if bad:
        notes.append(f"{bad}_entries_rejected")
    if doc.get("complete") is not True:
        notes.append("source_reports_incomplete")
    complete = doc.get("complete") is True and not truncated and not bad and not converging and (coverage == "FULL_TABLE" or bool(queried))
    value = {"vrf": vrf, "family": family, "coverage": coverage, "complete": complete, "queried": queried, "entry_count": len(entries), "entries": entries, "uncertain": notes,
             "table_kind": "fib", "fib_evidence": True, "restart": {"converging": restart.get("converging"), "boot_id": restart.get("boot_id")},
             "source": {"id": str(src["id"])[:64], "kind": kind, "authoritative": True, "derived_from_rib": False, "api": str(cap["api"])[:120]},
             "platform": canonical_platform(platform), "os_version": str(doc["os_version"]), "provenance": {"label": prov["label"], "collected_at": iso(when)}}
    quality = Quality.OK if complete else Quality.PARTIAL
    obs = make_observation("route.fib.table", value, device=device, evidence=evidence, observed_at=observed_at or when, target={"vrf": vrf, "family": family}, quality=quality,
                           parser=dict(FIB_PARSER), now=now, flags=[] if complete else ["PARTIAL_PARSE"])
    return {"observations": [obs], "missing": [], "parser": dict(FIB_PARSER)}


# -- Injected read-only QoS source: HC19 ------------------------------------------------------------------------------------
# A ``qos.attachment`` observation exists ONLY for a structured, identity-bearing, read-only operational document of the admitted device.  Per attachment (interface +
# direction) every class carries its own ordered match criteria and cumulative drop counter samples.  Any pre-computed ``matches_flow`` claim is DISCARDED here: matching the
# production tuple is the runbook's job.  Counter samples are summarised into a status (OK / SHORT / STALE / RESET / MISSING); only OK yields a usable delta.
QOS_SCHEMA = "nmas.troubleshooting.qos-source/1"
QOS_PARSER = {"id": "qos.state", "version": "qos-source-1.0", "template": "injected-structured", "input_kind": "structured"}
QOS_SOURCE_KINDS = frozenset({"gnmi-qos", "qos-api", "qos-agent", "cli-structured"})
QOS_LABELS = ("SIMULATED", "RECORDED", "LIVE_GATEWAY_PINNED")
QOS_MAX_ATTACHMENTS = 128
QOS_MAX_CLASSES = 64
QOS_MAX_SAMPLES = 32
QOS_MIN_SPAN_S = 10.0          # a delta over a shorter window is not a rate
QOS_MAX_SAMPLE_AGE_S = 120.0   # newest sample must be this close to the document's collection time


def _qos_reject(reason: str, detail: str, *, device: str, evidence: dict, now, observed_at=None) -> dict:
    rec = missing_record(reason, source_type=evidence.get("source_type", "STATE_SNAPSHOT"), device=device, detail=detail[:200], evidence_id=evidence.get("evidence_id", ""),
                         command=evidence.get("command_or_api", ""), observed_at=observed_at or now, extra={"engine_key": "qos.state"})
    return {"observations": [], "missing": [rec], "parser": dict(QOS_PARSER)}


def _qos_str_list(v, conv=str):
    if v is None:
        return []
    if not isinstance(v, (list, tuple)):
        raise ValueError("expected a list")
    return [conv(x) for x in v]


def _qos_match(raw):
    if not isinstance(raw, dict) or not raw:
        return None
    out = {}
    if raw.get("any") is True:
        out["any"] = True
    if raw.get("protocol"):
        out["protocol"] = str(raw["protocol"]).lower()
    ports = _qos_str_list(raw.get("ports"), int)
    if ports:
        out["ports"] = ports
    for k in ("src", "dst"):
        nets = [str(ipaddress.ip_network(n, strict=False)) for n in _qos_str_list(raw.get(k))]
        if nets:
            out[k] = nets
    dscp = _qos_str_list(raw.get("dscp"), int)
    if dscp:
        out["dscp"] = dscp
    return out or None


def _qos_counters(raw, collected: datetime) -> dict:
    """-> ``{status, delta_dropped, span_s, samples, ...}``.  Only ``status == OK`` carries a usable delta."""
    if not isinstance(raw, dict) or not isinstance(raw.get("samples"), list):
        return {"status": "MISSING", "reason": "no counter samples", "samples": []}
    samples = []
    for s in raw["samples"][:QOS_MAX_SAMPLES]:
        try:
            at = to_utc(s["at"])
            dropped = s["dropped_pkts"]
            if isinstance(dropped, bool) or not isinstance(dropped, int) or dropped < 0:
                raise ValueError("dropped_pkts is not a non-negative integer")
            samples.append({"at": iso(at), "_t": at, "dropped": dropped, "boot_id": s.get("boot_id", raw.get("boot_id"))})
        except (KeyError, ValueError, TypeError):
            return {"status": "MISSING", "reason": "unparsable counter sample", "samples": []}
    public = [{"at": s["at"], "dropped": s["dropped"]} for s in samples]
    if len(samples) < 2:
        return {"status": "SHORT", "reason": "fewer than two counter samples", "samples": public}
    ordered = all(a["_t"] < b["_t"] for a, b in zip(samples, samples[1:]))
    if not ordered:
        return {"status": "MISSING", "reason": "samples are not strictly time-ordered", "samples": public}
    if any(not isinstance(s["boot_id"], str) or not s["boot_id"].strip() for s in samples):
        return {"status": "MISSING", "reason": "counter epoch (boot id) is absent or invalid: delta unusable", "samples": public}
    if len({s["boot_id"] for s in samples}) > 1 or any(b["dropped"] < a["dropped"] for a, b in zip(samples, samples[1:])):
        return {"status": "RESET", "reason": "counter decreased or its epoch (boot id) changed: delta unusable", "samples": public}
    span = (samples[-1]["_t"] - samples[0]["_t"]).total_seconds()
    if span < QOS_MIN_SPAN_S:
        return {"status": "SHORT", "reason": f"sample window {span:.0f}s < {QOS_MIN_SPAN_S:.0f}s", "samples": public, "span_s": span}
    age = (collected - samples[-1]["_t"]).total_seconds()
    if age > QOS_MAX_SAMPLE_AGE_S or age < -QOS_MAX_SAMPLE_AGE_S:
        return {"status": "STALE", "reason": f"newest sample is {age:.0f}s from the document collection time", "samples": public, "span_s": span}
    return {"status": "OK", "reason": "", "samples": public, "span_s": span, "delta_dropped": samples[-1]["dropped"] - samples[0]["dropped"]}


def _qos_class(raw, order: int, collected: datetime) -> dict:
    if not isinstance(raw, dict) or not raw.get("name"):
        raise ValueError("class lacks a name")
    notes = []
    try:
        match = _qos_match(raw.get("match"))
    except (ValueError, TypeError):
        match, notes = None, ["match_unparsable"]
    unsupported = str(raw["unsupported"])[:80] if raw.get("unsupported") else None
    pol = raw.get("policer_bps")
    return {"name": str(raw["name"])[:64], "order": raw["order"] if isinstance(raw.get("order"), int) else order, "match": match,
            "match_complete": raw.get("match_complete") is True and match is not None and not notes, "unsupported": unsupported,
            "action": str(raw.get("action") or "")[:32] or None, "policer_bps": pol if isinstance(pol, int) and not isinstance(pol, bool) else None,
            "counters": _qos_counters(raw.get("counters"), collected), "notes": notes}


def normalize_qos_state(doc, *, platform: str, os_version: str, device: str, evidence: dict, request: dict, now: datetime, observed_at=None) -> dict:
    """Injected QoS document -> one ``qos.attachment`` observation per (interface, direction), or an explicit missing record bound to ``qos.state``."""
    kw = dict(device=device, evidence=evidence, now=now, observed_at=observed_at)
    if not isinstance(doc, dict) or doc.get("schema") != QOS_SCHEMA:
        return _qos_reject(Missing.PARSE_FAILED, f"QoS document is not {QOS_SCHEMA}", **kw)
    src = doc.get("source_identity") if isinstance(doc.get("source_identity"), dict) else {}
    kind = str(src.get("kind") or "").lower()
    if not src.get("id") or kind not in QOS_SOURCE_KINDS or src.get("read_only") is not True:
        return _qos_reject(Missing.UNSUPPORTED_OPERATION, "source identity (id, kind in the QoS read set, read_only=true) is absent or not acceptable", **kw)
    if doc.get("device") != device or canonical_platform(str(doc.get("platform") or "")) != canonical_platform(platform) or not doc.get("os_version") \
            or (os_version and str(doc.get("os_version")) != str(os_version)):
        return _qos_reject(Missing.UNSUPPORTED_PLATFORM, "document device/platform/version does not match the admitted device", **kw)
    cap = doc.get("capability") if isinstance(doc.get("capability"), dict) else {}
    if str(cap.get("status", "")).upper() != "SUPPORTED" or not cap.get("api"):
        return _qos_reject(Missing.UNSUPPORTED_OPERATION, f"platform capability for QoS reads is {cap.get('status') or 'UNKNOWN'}", **kw)
    scope = doc.get("scope") if isinstance(doc.get("scope"), dict) else {}
    if not scope.get("vrf") or scope.get("vrf") != request.get("vrf"):
        return _qos_reject(Missing.SCOPE_MISMATCH, f"document VRF {scope.get('vrf')!r} differs from the asked {request.get('vrf')!r}", **kw)
    prov = doc.get("provenance") if isinstance(doc.get("provenance"), dict) else {}
    if prov.get("label") not in QOS_LABELS or not prov.get("collected_at"):
        return _qos_reject(Missing.PARSE_FAILED, "provenance (label, collected_at) is absent: the evidence cannot be attributed", **kw)
    try:
        when = to_utc(prov["collected_at"])
    except (ValueError, TypeError):
        return _qos_reject(Missing.PARSE_FAILED, "provenance collected_at is not a timestamp", **kw)
    atts = doc.get("attachments")
    if not isinstance(atts, list):
        return _qos_reject(Missing.PARSE_FAILED, "attachments is not a list", **kw)
    obs, notes = [], []
    if len(atts) > QOS_MAX_ATTACHMENTS:
        notes.append(f"truncated_at_{QOS_MAX_ATTACHMENTS}_of_{len(atts)}")
    seen = set()
    for a in atts[:QOS_MAX_ATTACHMENTS]:
        try:
            ifn, direction = canonical_interface(str(a["interface"])), a["direction"]
            if not ifn or direction not in ("in", "out"):
                raise ValueError("attachment interface/direction invalid")
            if (ifn, direction) in seen:
                raise ValueError("duplicate attachment")
            seen.add((ifn, direction))
            raw_classes = a.get("classes")
            if not isinstance(raw_classes, list) or len(raw_classes) > QOS_MAX_CLASSES:
                raise ValueError("classes missing or beyond the bound")
            classes = sorted((_qos_class(c, i, when) for i, c in enumerate(raw_classes)), key=lambda c: c["order"])
        except (KeyError, ValueError, TypeError) as exc:
            notes.append(f"attachment_rejected:{str(exc)[:60]}")
            continue
        unc = [f"class {c['name']}: {n}" for c in classes for n in c["notes"]]
        complete = a.get("complete") is True and not unc and doc.get("complete") is True and len(atts) <= QOS_MAX_ATTACHMENTS
        value = {"interface": ifn, "direction": direction, "policy": str(a.get("policy") or "")[:64] or None, "vrf": str(a.get("vrf") or scope["vrf"]), "af": a.get("af"),
                 "complete": complete, "uncertain": unc + notes, "classes": classes,
                 "source": {"id": str(src["id"])[:64], "kind": kind, "read_only": True, "api": str(cap["api"])[:120]},
                 "platform": canonical_platform(platform), "os_version": str(doc["os_version"]), "provenance": {"label": prov["label"], "collected_at": iso(when)}}
        obs.append(make_observation("qos.attachment", value, device=device, evidence=evidence, observed_at=observed_at or when, interface=ifn,
                                    target={"interface": ifn, "direction": direction}, quality=Quality.OK if complete else Quality.PARTIAL, parser=dict(QOS_PARSER), now=now,
                                    flags=[] if complete else ["PARTIAL_PARSE"]))
    if not obs:
        return _qos_reject(Missing.EMPTY, "no usable QoS attachment in the document: " + "; ".join(notes)[:150], **kw)
    return {"observations": obs, "missing": [], "parser": dict(QOS_PARSER)}


# -- Injected read-only physical-state source: RB01 / RB07 / HC04 / HC05 ---------------------------------------------------
# Per requested interface the document may carry optics (identity + DOM + thresholds), FEC (mode + counter samples), framing-counter samples and an L1 event history.
# Rules: every measurement needs its own timestamp; a DOM reading without BOTH of its warning thresholds is never a verdict input (the runbook would read "no threshold" as
# "within threshold"), so the whole ``interface.transceiver`` observation is UNTRUSTED; a cumulative counter is never a rate (only a same-epoch delta over >= PHY_MIN_SPAN_S is);
# a reset becomes ``interface.counter_event=reset``; virtual / absent optics is an explicit missing record, never a healthy default.  Nothing here issues a device command.
PHY_SCHEMA = "nmas.troubleshooting.physical-source/1"
PHY_PARSER = {"id": "phy.state", "version": "physical-source-1.0", "template": "injected-structured", "input_kind": "structured"}
PHY_SOURCE_KINDS = frozenset({"gnmi-physical", "snmp-entity", "phy-agent", "cli-structured"})
PHY_LABELS = ("SIMULATED", "RECORDED", "LIVE_GATEWAY_PINNED")
PHY_MAX_INTERFACES = 8
PHY_MAX_SAMPLES = 32
PHY_MAX_EVENTS = 64
PHY_MIN_SPAN_S = 10.0
PHY_MAX_AGE_S = 120.0          # a measurement older than this at document collection time is STALE
PHY_FUTURE_SKEW_S = 30.0
PHY_RATE_FIELDS = ("in_crc_errors", "in_fcs_errors", "in_align_errors", "in_runts", "in_giants", "in_los", "in_lof")
PHY_EVENT_KINDS = frozenset({"LOS", "LOF", "LINK_DOWN", "LINK_UP", "OPTIC_ALARM", "OPTIC_WARNING", "CRC_BURST", "FEC_DEGRADE", "ERRDISABLE"})
PHY_ENGINE_KEYS = ("interface.transceiver", "interface.fec", "interface.l1_events")


def _phy_missing(reason: str, detail: str, *, device: str, evidence: dict, now, key: str, subject: str = "", observed_at=None) -> dict:
    extra = {"engine_key": key}
    if subject:
        extra["subject"] = subject
    return missing_record(reason, source_type=evidence.get("source_type", "STATE_SNAPSHOT"), device=device, detail=detail[:200], evidence_id=evidence.get("evidence_id", ""),
                          command=evidence.get("command_or_api", ""), observed_at=observed_at or now, extra=extra)


def phy_reject_all(reason: str, detail: str, *, device: str, evidence: dict, now, interfaces: Iterable[str] = (), observed_at=None) -> dict:
    """A document-level refusal: every physical engine key of every requested interface becomes an explicit gap."""
    ifs = list(interfaces) or [""]
    recs = [_phy_missing(reason, detail, device=device, evidence=evidence, now=now, key=k, subject=i, observed_at=observed_at) for i in ifs for k in PHY_ENGINE_KEYS]
    return {"observations": [], "missing": recs, "parser": dict(PHY_PARSER)}


def _phy_num(v):
    """-> finite float, or None (bool / str / NaN / inf are malformed, never coerced)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    return float(v)


def _phy_ts(v, collected: datetime):
    """-> (datetime|None, state) with state in OK / STALE / FUTURE / BAD."""
    try:
        t = to_utc(v)
    except (ValueError, TypeError):
        return None, "BAD"
    age = (collected - t).total_seconds()
    if age < -PHY_FUTURE_SKEW_S:
        return t, "FUTURE"
    return t, "STALE" if age > PHY_MAX_AGE_S else "OK"


def _phy_series(raw, fields: Iterable[str], collected: datetime) -> dict:
    """Counter samples ``{boot_id, samples:[{at, <field>: int}]}`` -> ``{status, reason, deltas, span_s, last_at}``.  Only ``status == OK`` carries deltas."""
    if not isinstance(raw, dict) or not isinstance(raw.get("samples"), list) or not raw["samples"]:
        return {"status": "MISSING", "reason": "no counter samples"}
    fields = list(fields)
    samples = []
    for s in raw["samples"][:PHY_MAX_SAMPLES]:
        try:
            at = to_utc(s["at"])
        except (KeyError, ValueError, TypeError):
            return {"status": "MISSING", "reason": "unparsable counter sample time"}
        row = {"_t": at, "boot": s.get("boot_id", raw.get("boot_id"))}
        for f in fields:
            v = s.get(f)
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                row[f] = None
            else:
                row[f] = v
        samples.append(row)
    if len(samples) < 2:
        return {"status": "SHORT", "reason": "fewer than two counter samples"}
    if not all(a["_t"] < b["_t"] for a, b in zip(samples, samples[1:])):
        return {"status": "MISSING", "reason": "samples are not strictly time-ordered"}
    if any(not isinstance(s["boot"], str) or not s["boot"].strip() for s in samples):
        return {"status": "MISSING", "reason": "counter epoch (boot id) is absent or invalid"}
    usable = [f for f in fields if all(s[f] is not None for s in samples)]
    if len({s["boot"] for s in samples}) > 1 or any(b[f] < a[f] for f in usable for a, b in zip(samples, samples[1:])):
        return {"status": "RESET", "reason": "counter decreased or its epoch (boot id) changed: delta unusable", "last_at": samples[-1]["_t"]}
    if not usable:
        return {"status": "MISSING", "reason": "no counter field is present as a non-negative integer in every sample"}
    span = (samples[-1]["_t"] - samples[0]["_t"]).total_seconds()
    if span < PHY_MIN_SPAN_S:
        return {"status": "SHORT", "reason": f"sample window {span:.0f}s < {PHY_MIN_SPAN_S:.0f}s", "last_at": samples[-1]["_t"]}
    age = (collected - samples[-1]["_t"]).total_seconds()
    if age > PHY_MAX_AGE_S or age < -PHY_FUTURE_SKEW_S:
        return {"status": "STALE", "reason": f"newest sample is {age:.0f}s from the document collection time", "last_at": samples[-1]["_t"]}
    return {"status": "OK", "reason": "", "span_s": span, "last_at": samples[-1]["_t"], "deltas": {f: samples[-1][f] - samples[0][f] for f in usable}}


def _phy_optics(ifn: str, o, collected: datetime):
    """-> ``(value|None, quality, flags, missing_reason|None, missing_detail, measured_at)``."""
    if not isinstance(o, dict):
        return None, None, [], Missing.EMPTY, "no optics block", None
    if o.get("virtual") is True or o.get("present") is False:
        return None, None, [], Missing.UNSUPPORTED_OPERATION, "virtual or absent optics: DOM does not exist for this interface (UNKNOWN, not healthy)", None
    if o.get("present") is not True:
        return None, None, [], Missing.EMPTY, "optics presence is not stated", None
    at, state = _phy_ts(o.get("measured_at"), collected)
    if state == "BAD":
        return None, None, [], Missing.PARSE_FAILED, "optics measured_at is absent or not a timestamp", None
    bad = []
    part, typ = o.get("part"), o.get("type")
    if not isinstance(part, str) or not part.strip() or not isinstance(typ, str) or not typ.strip() or not isinstance(o.get("supported"), bool):
        bad.append("identity (part, type, supported) incomplete")
    th = o.get("thresholds") if isinstance(o.get("thresholds"), dict) else {}
    value = {"part": str(part)[:64] if isinstance(part, str) else None, "type": str(typ)[:32] if isinstance(typ, str) else None, "supported": o.get("supported") if isinstance(o.get("supported"), bool) else None,
             "wavelength_nm": _phy_num(o.get("wavelength_nm")), "reach_m": _phy_num(o.get("reach_m")), "speed_mbps": _phy_num(o.get("speed_mbps"))}
    for k, lo, hi in (("rx_dbm", "rx_low_warn", "rx_high_warn"), ("tx_dbm", "tx_low_warn", "tx_high_warn"), ("temp_c", None, "temp_high_warn")):
        v = _phy_num(o.get(k))
        need = [n for n in (lo, hi) if n]
        thv = {n: _phy_num(th.get(n)) for n in need}
        if v is None:
            bad.append(f"{k} measurement missing or malformed")
        if any(t is None for t in thv.values()):
            bad.append(f"{k} warning threshold(s) missing: {','.join(n for n, t in thv.items() if t is None)}")
        elif lo and thv[lo] >= thv[hi]:
            bad.append(f"{k} thresholds inconsistent")
        value[k] = v
        value.update({n: t for n, t in thv.items()})
    alarm = _phy_num(th.get("rx_low_alarm"))
    if alarm is not None:
        value["rx_low_alarm"] = alarm
    if bad:
        return value, Quality.UNTRUSTED_PARSE, ["PARTIAL_PARSE", "DOM_THRESHOLDS_OR_MEASUREMENT_MISSING"], None, "; ".join(bad), at
    if state == "FUTURE":
        return value, Quality.UNTRUSTED_PARSE, ["OBSERVED_IN_FUTURE_CLOCK_SUSPECT"], None, "", at
    return value, (Quality.STALE if state == "STALE" else Quality.OK), (["STALE_MEASUREMENT"] if state == "STALE" else []), None, "", at


def normalize_physical_state(doc, *, platform: str, os_version: str, device: str, evidence: dict, request: dict, now: datetime, observed_at=None) -> dict:  # pylint: disable=too-many-branches  # one flat validation per optic/PHY field; each branch records a distinct quality flag
    """Injected physical document -> ``interface.transceiver`` / ``interface.fec`` / ``interface.rate.*`` / ``interface.counter_event`` / ``interface.l1_events`` observations;
    everything not provable is an explicit missing record bound to the engine key (and interface subject)."""
    asked = []
    for i in (request.get("interfaces") or [])[:PHY_MAX_INTERFACES]:
        c_if = canonical_interface(str(i), platform=platform)
        if c_if and c_if not in asked:
            asked.append(c_if)
    kw = dict(device=device, evidence=evidence, now=now, observed_at=observed_at, interfaces=asked)
    if not asked:
        return phy_reject_all(Missing.SCOPE_MISMATCH, "no interface is in scope for this device", **kw)
    if not isinstance(doc, dict) or doc.get("schema") != PHY_SCHEMA:
        return phy_reject_all(Missing.PARSE_FAILED, f"physical document is not {PHY_SCHEMA}", **kw)
    src = doc.get("source_identity") if isinstance(doc.get("source_identity"), dict) else {}
    kind = str(src.get("kind") or "").lower()
    if not src.get("id") or kind not in PHY_SOURCE_KINDS or src.get("read_only") is not True:
        return phy_reject_all(Missing.UNSUPPORTED_OPERATION, "source identity (id, kind in the physical read set, read_only=true) is absent or not acceptable", **kw)
    if doc.get("device") != device or canonical_platform(str(doc.get("platform") or "")) != canonical_platform(platform) or not doc.get("os_version") \
            or (os_version and str(doc.get("os_version")) != str(os_version)):
        return phy_reject_all(Missing.UNSUPPORTED_PLATFORM, "document device/platform/version does not match the admitted device", **kw)
    cap = doc.get("capability") if isinstance(doc.get("capability"), dict) else {}
    if str(cap.get("status", "")).upper() != "SUPPORTED" or not cap.get("api"):
        return phy_reject_all(Missing.UNSUPPORTED_OPERATION, f"platform capability for physical reads is {cap.get('status') or 'UNKNOWN'}", **kw)
    scope = doc.get("scope") if isinstance(doc.get("scope"), dict) else {}
    scoped = scope.get("interfaces")
    if not isinstance(scoped, list) or {canonical_interface(str(s), platform=platform) for s in scoped} != set(asked):
        return phy_reject_all(Missing.SCOPE_MISMATCH, "document scope.interfaces differs from the asked interfaces (peer/other-port data is never attributed)", **kw)
    prov = doc.get("provenance") if isinstance(doc.get("provenance"), dict) else {}
    if prov.get("label") not in PHY_LABELS or not prov.get("collected_at"):
        return phy_reject_all(Missing.PARSE_FAILED, "provenance (label, collected_at) is absent: the evidence cannot be attributed", **kw)
    try:
        collected = to_utc(prov["collected_at"])
    except (ValueError, TypeError):
        return phy_reject_all(Missing.PARSE_FAILED, "provenance collected_at is not a timestamp", **kw)
    rows = doc.get("interfaces")
    if not isinstance(rows, list):
        return phy_reject_all(Missing.PARSE_FAILED, "interfaces is not a list", **kw)
    by_if, notes = {}, []
    for r in rows[:PHY_MAX_INTERFACES * 2]:
        name = canonical_interface(str(r.get("interface", "")), platform=platform) if isinstance(r, dict) else ""
        if name not in asked:
            notes.append("out_of_scope_or_unnamed_entry_ignored")
        elif name in by_if:
            notes.append(f"duplicate_entry_dropped:{name}")
            by_if[name] = None
        else:
            by_if[name] = r
    obs, missing = [], []
    source = {"id": str(src["id"])[:64], "kind": kind, "read_only": True, "api": str(cap["api"])[:120]}
    prov_out = {"label": prov["label"], "collected_at": iso(collected)}

    def miss(key, ifn, reason, detail):
        missing.append(_phy_missing(reason, detail, device=device, evidence=evidence, now=now, key=key, subject=ifn, observed_at=observed_at))

    for ifn in asked:
        r = by_if.get(ifn)
        if not isinstance(r, dict):
            for k in PHY_ENGINE_KEYS:
                miss(k, ifn, Missing.EMPTY, "interface absent from, or ambiguous in, the document")
            continue
        tgt = {"interface": ifn}
        stamp = {"source": source, "provenance": prov_out}
        # optics ------------------------------------------------------------------------------------------------
        val, q, flags, why, detail, at = _phy_optics(ifn, r.get("optics"), collected)
        if why:
            miss("interface.transceiver", ifn, why, detail)
        else:
            val = dict(val, **stamp)
            if q == Quality.UNTRUSTED_PARSE:
                val["uncertain"] = detail
            obs.append(make_observation("interface.transceiver", val, device=device, evidence=evidence, observed_at=at, interface=ifn, target=tgt, quality=q, flags=flags,
                                        parser=dict(PHY_PARSER), now=now))
        # FEC + counters ----------------------------------------------------------------------------------------
        fec = r.get("fec")
        reset_noted = False
        if not isinstance(fec, dict):
            miss("interface.fec", ifn, Missing.EMPTY, "no FEC block (not supported or not collected)")
        else:
            mode = fec.get("mode")
            ser = _phy_series(fec.get("counters"), ("uncorrected", "corrected"), collected)
            if not isinstance(mode, str) or not mode.strip():
                miss("interface.fec", ifn, Missing.PARSE_FAILED, "FEC mode is absent")
            elif ser["status"] != "OK" or "uncorrected" not in ser["deltas"]:
                miss("interface.fec", ifn, Missing.STALE_SOURCE if ser["status"] == "STALE" else Missing.EMPTY,
                     f"uncorrected-codeword delta unusable ({ser['status']}: {ser['reason'] or 'field absent'}); a lifetime counter is not a window")
                if ser["status"] == "RESET":
                    obs.append(make_observation("interface.counter_event", "reset", device=device, evidence=evidence, observed_at=ser["last_at"], interface=ifn, target=tgt,
                                                quality=Quality.PARTIAL, flags=["FEC_COUNTER_RESET"], parser=dict(PHY_PARSER), now=now, extra={"counter": "fec"}))
                    reset_noted = True
            else:
                v = {"mode": mode.strip().lower()[:32], "uncorrected": ser["deltas"]["uncorrected"], "corrected": ser["deltas"].get("corrected"), "window_s": round(ser["span_s"], 3), **stamp}
                obs.append(make_observation("interface.fec", v, device=device, evidence=evidence, observed_at=ser["last_at"], interface=ifn, target=tgt, quality=Quality.OK,
                                            parser=dict(PHY_PARSER), now=now))
        cser = _phy_series(r.get("counters"), PHY_RATE_FIELDS, collected) if r.get("counters") is not None else None
        if cser is not None:
            if cser["status"] == "RESET" and not reset_noted:
                obs.append(make_observation("interface.counter_event", "reset", device=device, evidence=evidence, observed_at=cser["last_at"], interface=ifn, target=tgt,
                                            quality=Quality.PARTIAL, flags=["PHYSICAL_COUNTER_RESET"], parser=dict(PHY_PARSER), now=now, extra={"counter": "framing"}))
            elif cser["status"] == "OK":
                for f, d in cser["deltas"].items():
                    obs.append(make_observation(f"interface.rate.{f}", round(d / cser["span_s"], 6), unit="/s", device=device, evidence=evidence, observed_at=cser["last_at"],
                                                interface=ifn, target=tgt, quality=Quality.OK, parser=dict(PHY_PARSER), now=now))
            else:
                notes.append(f"counters_{cser['status'].lower()}:{ifn}")
        # error history -----------------------------------------------------------------------------------------
        evs = r.get("events")
        if not isinstance(evs, list):
            miss("interface.l1_events", ifn, Missing.EMPTY, "no L1 event history was provided")
        else:
            clean, dropped = [], 0
            for e in evs[:PHY_MAX_EVENTS]:
                try:
                    et = to_utc(e["at"])
                    k = str(e["kind"]).upper()
                    if k not in PHY_EVENT_KINDS:
                        raise ValueError(k)
                    clean.append({"at": iso(et), "kind": k, "detail": str(e.get("detail", ""))[:120]})
                except (KeyError, ValueError, TypeError, AttributeError):
                    dropped += 1
            complete = r.get("events_complete") is True and dropped == 0 and len(evs) <= PHY_MAX_EVENTS
            if not complete:
                miss("interface.l1_events", ifn, Missing.EMPTY, f"event history incomplete (dropped={dropped}, bound={PHY_MAX_EVENTS}, events_complete={r.get('events_complete')!r}): absence of an event proves nothing")
            else:
                obs.append(make_observation("interface.l1_events", {"events": sorted(clean, key=lambda x: x["at"]), "window_s": request.get("window_s"), **stamp},
                                            device=device, evidence=evidence, observed_at=observed_at or collected, interface=ifn, target=tgt, quality=Quality.OK,
                                            parser=dict(PHY_PARSER), now=now))
    return {"observations": obs, "missing": missing, "parser": dict(PHY_PARSER), "notes": notes[:20]}


# -- Injected read-only routing-protocol source: RB03 (capability.protocol, protocol.config, routing.neighbor.detail) ----------------------------
# One document per admitted device and one explicit scope (protocol, AF, VRF, interface, peer).  Rules: identity/version/capability/scope/provenance are mandatory; a
# configuration is a verdict input only when it is complete (``config_complete`` true AND every field RB03 compares for that protocol is present and well-formed) -- an absent
# field is never "equal" to another absent field, so an incomplete configuration is UNTRUSTED_PARSE; authentication is carried ONLY as safe metadata (configured, key id,
# algorithm, hash fingerprint) and any secret-bearing field is scrubbed before the document is stored or parsed; unsupported protocols/AFs are explicit gaps.
PROTO_SCHEMA = "nmas.troubleshooting.protocol-source/1"
PROTO_PARSER = {"id": "proto.state", "version": "protocol-source-1.0", "template": "injected-structured", "input_kind": "structured"}
PROTO_SOURCE_KINDS = frozenset({"gnmi-protocol", "snmp-protocol", "proto-agent", "cli-structured"})
PROTO_LABELS = ("SIMULATED", "RECORDED", "LIVE_GATEWAY_PINNED")
PROTO_SUPPORTED = frozenset({"ospf", "ospfv3", "bgp", "isis", "rip", "ripng"})      # eigrp / anything else: unavailable (no field contract, no capability evidence)
PROTO_AFS = frozenset({"ipv4", "ipv6", "evpn"})
PROTO_ENGINE_KEYS = ("capability.protocol", "protocol.config", "routing.neighbor.detail")
PROTO_MAX_AGE_S = 300.0
PROTO_FUTURE_SKEW_S = 30.0
PROTO_MAX_STR = 64
PROTO_TIMERS = {"ospf": ("hello", "dead"), "ospfv3": ("hello", "dead"), "isis": ("hello", "hold")}
PROTO_STATES = {"full": "Full", "established": "Established", "up": "Up", "2-way": "2-Way", "two_way": "2-Way", "twoway": "2-Way", "exstart": "ExStart", "exchange": "Exchange",
                "loading": "Loading", "init": "Init", "attempt": "Attempt", "down": "Down", "idle": "Idle", "connect": "Connect", "active": "Active", "opensent": "OpenSent",
                "openconfirm": "OpenConfirm"}
_SECRET_KEY = re.compile(r"(?i)(secret|passw|passphrase|authentication[-_]?key|key[-_]?string|key[-_]?material|shared[-_]?key|pre[-_]?shared|psk|community|token|md5|hmac|cleartext|"
                         r"private|credential|auth[-_]?key|keychain[-_]?value)")
_SAFE_KEY = frozenset({"key_id", "key_chain", "key_ids", "fingerprint", "algorithm", "configured", "auth", "authentication"})
_FINGERPRINT = re.compile(r"^(?:[a-z0-9-]{3,12}:)?[0-9a-f]{32,128}$")


def scrub_protocol_secrets(node, _count=None):
    """Deep copy of ``node`` with every secret-bearing field replaced by ``<redacted>`` and free text passed through ``redact_text``.  -> (copy, number of redactions)."""
    count = _count if _count is not None else [0]
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if str(k).lower() not in _SAFE_KEY and _SECRET_KEY.search(str(k)):
                out[k] = REDACTED
                count[0] += 1
            else:
                out[k] = scrub_protocol_secrets(v, count)[0]
        return out, count[0]
    if isinstance(node, (list, tuple)):
        return [scrub_protocol_secrets(v, count)[0] for v in node], count[0]
    if isinstance(node, str):
        text, n = redact_text(node)
        count[0] += n
        return text, count[0]
    return node, count[0]


def _proto_missing(reason: str, detail: str, *, device: str, evidence: dict, now, key: str, subject: str = "", observed_at=None) -> dict:
    extra = {"engine_key": key}
    if subject:
        extra["subject"] = subject
    return missing_record(reason, source_type=evidence.get("source_type", "STATE_SNAPSHOT"), device=device, detail=detail[:200], evidence_id=evidence.get("evidence_id", ""),
                          command=evidence.get("command_or_api", ""), observed_at=observed_at or now, extra=extra)


def _proto_subjects(request: dict) -> dict:
    return {"capability.protocol": str(request.get("protocol") or ""), "protocol.config": str(request.get("protocol") or ""), "routing.neighbor.detail": str(request.get("peer") or "")}


def proto_reject_all(reason: str, detail: str, *, device: str, evidence: dict, now, request: dict, keys: Iterable[str] = PROTO_ENGINE_KEYS, observed_at=None) -> dict:
    subj = _proto_subjects(request)
    recs = [_proto_missing(reason, detail, device=device, evidence=evidence, now=now, key=k, subject=subj[k], observed_at=observed_at) for k in keys]
    return {"observations": [], "missing": recs, "parser": dict(PROTO_PARSER)}


def _pstr(v, n=PROTO_MAX_STR):
    return v.strip()[:n] if isinstance(v, str) and v.strip() else None


def _pint(v, lo=0, hi=4294967295):
    return v if isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi else None


def _proto_auth(a) -> tuple[dict | None, str]:
    """-> (safe auth metadata | None, problem).  Never carries key material; ``fingerprint`` must be a hash-shaped token."""
    if not isinstance(a, dict) or not isinstance(a.get("configured"), bool):
        return None, "auth.configured absent"
    if not a["configured"]:
        return {"configured": False, "key_id": None, "algorithm": None, "fingerprint": None}, ""
    fp = a.get("fingerprint")
    kid = a.get("key_id")
    kid = str(kid)[:32] if isinstance(kid, (str, int)) and not isinstance(kid, bool) and str(kid).strip() else None
    if not isinstance(fp, str) or not _FINGERPRINT.match(fp.lower()):
        return {"configured": True, "key_id": kid, "algorithm": _pstr(a.get("algorithm"), 16), "fingerprint": None}, "auth fingerprint absent or not hash-shaped (never accepted as a secret)"
    if kid is None:
        return {"configured": True, "key_id": None, "algorithm": _pstr(a.get("algorithm"), 16), "fingerprint": fp.lower()}, "auth key_id absent"
    return {"configured": True, "key_id": kid, "algorithm": _pstr(a.get("algorithm"), 16), "fingerprint": fp.lower()}, ""


def _proto_config(proto: str, cfg: dict, complete) -> tuple[dict, list[str]]:
    """Whitelisted RB03 comparison fields for ``proto`` + the list of problems (absent / malformed required fields, incomplete response)."""
    bad: list[str] = []
    if complete is not True:
        bad.append("config_complete is not true: the configuration response is partial")
    v: dict = {}

    def need(name, val):
        if val is None:
            bad.append(f"{name} absent or malformed")
        v[name] = val
    if proto in ("ospf", "ospfv3"):
        need("area", _pstr(cfg.get("area")))
        need("network_type", _pstr(cfg.get("network_type"), 32))
        need("stub", cfg.get("stub") if isinstance(cfg.get("stub"), bool) else None)
    elif proto == "bgp":
        need("local_as", _pint(cfg.get("local_as")))
        need("neighbor_remote_as", _pint(cfg.get("neighbor_remote_as")))
        need("neighbor_vrf", _pstr(cfg.get("neighbor_vrf")))
        afs = cfg.get("neighbor_afs")
        need("neighbor_afs", sorted({str(a).lower()[:16] for a in afs[:8]}) if isinstance(afs, list) and afs and all(isinstance(a, str) and a.strip() for a in afs) else None)
    elif proto == "isis":
        need("level", _pstr(cfg.get("level"), 16))
    elif proto in ("rip", "ripng"):
        ver = cfg.get("version")
        need("version", _pint(ver, 1, 2) if not isinstance(ver, str) else (_pint(int(ver), 1, 2) if ver.isdigit() else None))
    wanted_timers = PROTO_TIMERS.get(proto)
    t = cfg.get("timers")
    if wanted_timers:
        tv = {k: _pint(t.get(k), 1, 65535) for k in wanted_timers} if isinstance(t, dict) else {}
        if len(tv) != len(wanted_timers) or any(x is None for x in tv.values()):
            bad.append(f"timers ({','.join(wanted_timers)}) absent or malformed")
        v["timers"] = {k: x for k, x in tv.items() if x is not None} or None
    elif isinstance(t, dict):                                   # optional (bgp / rip): kept only when every present value is well-formed
        tv = {k: _pint(x, 0, 65535) for k, x in list(t.items())[:6] if isinstance(k, str)}
        if any(x is None for x in tv.values()):
            bad.append("timers malformed")
        v["timers"] = {k: x for k, x in tv.items() if x is not None} or None
    auth, why = _proto_auth(cfg.get("auth"))
    if why:
        bad.append(why)
    v["auth"] = auth
    return v, bad


def normalize_protocol_state(doc, *, platform: str, os_version: str, device: str, evidence: dict, request: dict, now: datetime, observed_at=None) -> dict:  # pylint: disable=too-many-branches  # one flat validation per protocol-neighbour field; each branch records a distinct quality flag
    """Injected protocol document -> ``capability.protocol`` / ``protocol.config`` / ``routing.neighbor.detail`` observations bound to the request scope; everything not provable
    is an explicit missing record bound to the engine key (and its subject: protocol, or peer for the neighbor detail)."""
    proto = str(request.get("protocol") or "").lower()
    af = str(request.get("af") or "").lower()
    vrf = str(request.get("vrf") or "")
    ifn = canonical_interface(str(request.get("interface") or ""), platform=platform) if request.get("interface") else ""
    peer = str(request.get("peer") or "")
    include = set(request.get("include") or ("capability", "config", "neighbor"))
    request = dict(request, protocol=proto)
    keys = tuple(k for k, inc in (("capability.protocol", "capability"), ("protocol.config", "config"), ("routing.neighbor.detail", "neighbor")) if inc in include) or PROTO_ENGINE_KEYS
    kw = dict(device=device, evidence=evidence, now=now, request=request, observed_at=observed_at)
    if proto not in PROTO_SUPPORTED or af not in PROTO_AFS or not vrf or not peer or (proto != "bgp" and not ifn):
        return proto_reject_all(Missing.UNSUPPORTED_OPERATION if proto not in PROTO_SUPPORTED else Missing.SCOPE_MISMATCH,
                                f"explicit supported protocol/AF/VRF/interface/peer scope required (protocol={proto!r} af={af!r} vrf={vrf!r} interface={ifn!r} peer={peer!r})", keys=keys, **kw)
    if not isinstance(doc, dict) or doc.get("schema") != PROTO_SCHEMA:
        return proto_reject_all(Missing.PARSE_FAILED, f"protocol document is not {PROTO_SCHEMA}", keys=keys, **kw)
    src = doc.get("source_identity") if isinstance(doc.get("source_identity"), dict) else {}
    kind = str(src.get("kind") or "").lower()
    if not src.get("id") or kind not in PROTO_SOURCE_KINDS or src.get("read_only") is not True:
        return proto_reject_all(Missing.UNSUPPORTED_OPERATION, "source identity (id, kind in the protocol read set, read_only=true) is absent or not acceptable", keys=keys, **kw)
    if doc.get("device") != device or canonical_platform(str(doc.get("platform") or "")) != canonical_platform(platform) or not doc.get("os_version") \
            or (os_version and str(doc.get("os_version")) != str(os_version)):
        return proto_reject_all(Missing.UNSUPPORTED_PLATFORM, "document device/platform/version does not match the admitted device", keys=keys, **kw)
    cap = doc.get("capability") if isinstance(doc.get("capability"), dict) else {}
    if str(cap.get("status", "")).upper() != "SUPPORTED" or not cap.get("api") or not isinstance(cap.get("protocols"), dict):
        return proto_reject_all(Missing.UNSUPPORTED_OPERATION, f"platform capability for protocol reads is {cap.get('status') or 'UNKNOWN'}", keys=keys, **kw)
    sc = doc.get("scope") if isinstance(doc.get("scope"), dict) else {}
    got = (str(sc.get("protocol") or "").lower(), str(sc.get("af") or "").lower(), str(sc.get("vrf") or ""),
           canonical_interface(str(sc.get("interface") or ""), platform=platform) if sc.get("interface") else "", str(sc.get("peer") or ""))
    if got != (proto, af, vrf, ifn, peer):
        return proto_reject_all(Missing.SCOPE_MISMATCH, "document scope (protocol/af/vrf/interface/peer) differs from the request: another instance is never attributed", keys=keys, **kw)
    prov = doc.get("provenance") if isinstance(doc.get("provenance"), dict) else {}
    if prov.get("label") not in PROTO_LABELS or not prov.get("collected_at"):
        return proto_reject_all(Missing.PARSE_FAILED, "provenance (label, collected_at) is absent: the evidence cannot be attributed", keys=keys, **kw)
    try:
        collected = to_utc(prov["collected_at"])
    except (ValueError, TypeError):
        return proto_reject_all(Missing.PARSE_FAILED, "provenance collected_at is not a timestamp", keys=keys, **kw)
    age = (now - collected).total_seconds()
    if age > PROTO_MAX_AGE_S:
        return proto_reject_all(Missing.STALE_SOURCE, f"document collected {age:.0f}s before this run (limit {PROTO_MAX_AGE_S:.0f}s)", keys=keys, **kw)
    if age < -PROTO_FUTURE_SKEW_S:
        return proto_reject_all(Missing.PARSE_FAILED, "document collected_at is in the future (clock suspect)", keys=keys, **kw)
    obs, missing, notes = [], [], []
    source = {"id": str(src["id"])[:64], "kind": kind, "read_only": True, "api": str(cap["api"])[:120]}
    stamp = {"source": source, "provenance": {"label": prov["label"], "collected_at": iso(collected)}}
    tgt_base = {"protocol": proto}

    def miss(key, reason, detail):
        missing.append(_proto_missing(reason, detail, device=device, evidence=evidence, now=now, key=key, subject=_proto_subjects(request)[key], observed_at=observed_at))

    protos = {str(k).lower(): v for k, v in cap["protocols"].items()}
    supported = af in {str(a).lower() for a in (protos.get(proto) or []) if isinstance(a, str)} if isinstance(protos.get(proto), list) else False
    if "capability.protocol" in keys:
        obs.append(make_observation("capability.protocol", {"supported": supported, "protocol": proto, "af": af, "vrf": vrf, "platform": canonical_platform(platform),
                                                             "note": "" if supported else f"{proto}/{af} is not listed by the platform capability evidence", **stamp},
                                    device=device, evidence=evidence, observed_at=collected, target=tgt_base, quality=Quality.OK, parser=dict(PROTO_PARSER), now=now, max_age_s=PROTO_MAX_AGE_S))
    if not supported:
        for k in keys:
            if k != "capability.protocol":
                miss(k, Missing.UNSUPPORTED_OPERATION, f"{proto}/{af} is not supported on this platform per capability evidence")
        return {"observations": obs, "missing": missing, "parser": dict(PROTO_PARSER), "notes": notes}
    # configuration -------------------------------------------------------------------------------------------------
    if "protocol.config" in keys:
        cfg = doc.get("config")
        if not isinstance(cfg, dict):
            miss("protocol.config", Missing.EMPTY, "no config block: absence is not a match")
        else:
            try:
                cat = to_utc(cfg.get("collected_at"))
            except (ValueError, TypeError):
                cat = None
            if cat is None:
                miss("protocol.config", Missing.PARSE_FAILED, "config.collected_at absent or not a timestamp")
            elif (now - cat).total_seconds() > PROTO_MAX_AGE_S:
                miss("protocol.config", Missing.STALE_SOURCE, "config section is older than the freshness limit")
            else:
                value, bad = _proto_config(proto, cfg, doc.get("config_complete"))
                value = dict(value, protocol=proto, af=af, vrf=vrf, interface=ifn or None, **stamp)
                if bad:
                    value["uncertain"] = "; ".join(bad)[:300]
                obs.append(make_observation("protocol.config", value, device=device, evidence=evidence, observed_at=cat, target=tgt_base,
                                            quality=Quality.UNTRUSTED_PARSE if bad else Quality.OK, flags=["PARTIAL_PARSE"] if bad else [], parser=dict(PROTO_PARSER), now=now,
                                            max_age_s=PROTO_MAX_AGE_S))
    # neighbor state ------------------------------------------------------------------------------------------------
    if "routing.neighbor.detail" in keys:
        nb = doc.get("neighbor")
        if not isinstance(nb, dict):
            miss("routing.neighbor.detail", Missing.EMPTY, "no neighbor block: absence is not evidence of absence")
        elif str(nb.get("peer") or "") != peer:
            miss("routing.neighbor.detail", Missing.SCOPE_MISMATCH, "neighbor block names another peer: never re-attributed")
        else:
            try:
                nat = to_utc(nb.get("observed_at"))
            except (ValueError, TypeError):
                nat = None
            state = PROTO_STATES.get(str(nb.get("state") or "").strip().lower().replace(" ", ""))
            if nat is None:
                miss("routing.neighbor.detail", Missing.PARSE_FAILED, "neighbor.observed_at absent or not a timestamp")
            elif state is None:
                miss("routing.neighbor.detail", Missing.PARSE_FAILED, "neighbor state is absent or not a known protocol state")
            elif (now - nat).total_seconds() > PROTO_MAX_AGE_S:
                miss("routing.neighbor.detail", Missing.STALE_SOURCE, "neighbor section is older than the freshness limit")
            else:
                since = _pint(nb.get("since_s"))
                err = nb.get("last_error")
                err = redact_text(err)[0][:200] if isinstance(err, str) and err.strip() else None
                value = {"state": state, "raw_state": str(nb.get("state"))[:32], "protocol": proto, "af": af, "vrf": vrf, "interface": ifn or None, "since_s": since,
                         "last_error": err, **stamp}
                partial = nb.get("complete") is not True or since is None
                if partial:
                    value["uncertain"] = "neighbor detail is partial (complete flag or since_s missing)"
                obs.append(make_observation("routing.neighbor.detail", value, device=device, evidence=evidence, observed_at=nat, target=dict(tgt_base, neighbor=peer),
                                            quality=Quality.UNTRUSTED_PARSE if partial else Quality.OK, flags=["PARTIAL_PARSE"] if partial else [], parser=dict(PROTO_PARSER),
                                            now=now, max_age_s=PROTO_MAX_AGE_S))
    return {"observations": obs, "missing": missing, "parser": dict(PROTO_PARSER), "notes": notes}
