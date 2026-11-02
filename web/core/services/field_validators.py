"""
Tier-1 FIELD validators for the Phase 9 Device Builder.

Tier 1 answers exactly one question: "is this individual value
structurally/syntactically possible?" Nothing here queries NetBox, Git,
GitHub, or a live device, and nothing here compares one field against
another (that would already be Tier-2 -- see docs/DEVICE_BUILDER_FOUNDATION.md
"Tier-1 field validation" for the exact boundary and Phase 13's ownership of
project/network-semantic checks: duplicate IP, NetBox collision, prefix
overlap, peer consistency, routing/VRF dependency, DHCP conflict, topology
impact, platform cross-feature validation).

Every validator has the same shape:

    validator(raw_value) -> (ok: bool, normalized_value, message: str)

`normalized_value` is only meaningfully different from `raw_value` when
`ok` is True (e.g. trimmed whitespace) -- on failure the caller keeps the
existing accepted_value rather than persisting anything from `raw_value`.
"""

from __future__ import annotations

import functools
import re
import ipaddress

from .. import models

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")

MAX_HOSTNAME_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 500
MAX_IMAGE_REFERENCE_LENGTH = 255
MAX_INTERFACE_NAME_LENGTH = 64
MAX_ROLE_LENGTH = 100
MIN_MTU = 576
MAX_MTU = 9216

_INTERFACE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,63}$")
_SAFE_LABEL_RE = re.compile(r"^[^\x00-\x1f\x7f]{0,100}$")


def _text_input(validator):
    """Text validators accept text (or None, which each validator already handles): any other JSON type -- a number, a
    boolean, a list, an object -- is an INVALID value with a fixed message, never an exception (Lab 7: the commit endpoint
    takes a JSON body, so ``{"value": 5}`` must become an INVALID field state, not an HTTP 500)."""

    @functools.wraps(validator)
    def guarded(raw_value, *args, **kwargs):
        if raw_value is not None and not isinstance(raw_value, str):
            return False, raw_value, f"A text value is required (got {type(raw_value).__name__})."
        return validator(raw_value, *args, **kwargs)

    return guarded


@_text_input
def validate_hostname(raw_value) -> tuple[bool, object, str]:
    value = (raw_value or "").strip()
    if not value:
        return False, raw_value, "Hostname is required."
    if len(value) > MAX_HOSTNAME_LENGTH:
        return False, raw_value, f"Hostname must be {MAX_HOSTNAME_LENGTH} characters or fewer."
    if not _HOSTNAME_RE.match(value):
        return (
            False,
            raw_value,
            "Hostname must contain only letters, digits, and hyphens, and cannot start or end with a hyphen.",
        )
    return True, value, ""


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@_text_input
def validate_description(raw_value) -> tuple[bool, object, str]:
    value = (raw_value or "").strip()
    if len(value) > MAX_DESCRIPTION_LENGTH:
        return False, raw_value, f"Description must be {MAX_DESCRIPTION_LENGTH} characters or fewer."
    # A description is rendered INSIDE one configuration line (``description {value}`` / a comment): a line break or any
    # other control character would end that line and inject the rest as configuration (Lab 7 finding F1).
    if _CONTROL_RE.search(value):
        return False, raw_value, "Description must be a single line without control characters."
    return True, value, ""


def validate_platform(raw_value) -> tuple[bool, object, str]:
    if raw_value not in models.Platform.values:
        return False, raw_value, f"Unknown platform identifier {raw_value!r}."
    return True, raw_value, ""


def validate_target_type(raw_value) -> tuple[bool, object, str]:
    if raw_value not in models.DeviceIntentTargetType.values:
        return False, raw_value, f"Unknown target type {raw_value!r}."
    return True, raw_value, ""


@_text_input
def validate_image_reference(raw_value) -> tuple[bool, object, str]:
    """
    Empty is always valid -- whether an image reference is *required* for a
    NEW_DEVICE intent is a cross-field/completeness concern, not a Tier-1
    syntax check, so it is left to the UI as a hint, never a hard rejection
    here (see docs/DEVICE_BUILDER_FOUNDATION.md "Existing vs New Device").
    """
    value = (raw_value or "").strip()
    if not value:
        return True, value, ""
    if len(value) > MAX_IMAGE_REFERENCE_LENGTH:
        return False, raw_value, f"Image reference must be {MAX_IMAGE_REFERENCE_LENGTH} characters or fewer."
    if not _IMAGE_REF_RE.match(value):
        return False, raw_value, "Image reference contains unsafe characters."
    return True, value, ""


@_text_input
def validate_interface_name(raw_value) -> tuple[bool, object, str]:
    value = (raw_value or "").strip()
    if not value:
        return False, raw_value, "Interface name is required."
    if len(value) > MAX_INTERFACE_NAME_LENGTH or not _INTERFACE_NAME_RE.fullmatch(value):
        return (
            False,
            raw_value,
            "Interface name must be 1-64 safe characters, begin with a letter, and contain only letters, digits, _ . : / or -.",
        )
    return True, value, "Syntax accepted; project validation pending."


@_text_input
def validate_bounded_label(raw_value, *, label: str = "Value", maximum: int = MAX_ROLE_LENGTH):
    value = (raw_value or "").strip()
    if len(value) > maximum or not _SAFE_LABEL_RE.fullmatch(value):
        return False, raw_value, f"{label} must be {maximum} characters or fewer and contain no control characters."
    return True, value, "Syntax accepted; project validation pending."


@_text_input
def validate_interface_description(raw_value):
    ok, value, message = validate_description(raw_value)
    return ok, value, ("Syntax accepted; project validation pending." if ok else message)


@_text_input
def validate_enum(raw_value, *, allowed: tuple[str, ...], label: str):
    if raw_value not in allowed:
        return False, raw_value, f"Unknown {label} {raw_value!r}."
    return True, raw_value, "Syntax accepted; project validation pending."


def validate_bool(raw_value, *, label: str = "Value"):
    if isinstance(raw_value, bool):
        return True, raw_value, "Syntax accepted; project validation pending."
    if isinstance(raw_value, str) and raw_value.strip().lower() in ("true", "false"):
        return True, raw_value.strip().lower() == "true", "Syntax accepted; project validation pending."
    return False, raw_value, f"{label} must be true or false."


def validate_optional_integer(raw_value, *, minimum: int, maximum: int, label: str):
    if raw_value in (None, ""):
        return True, None, "Syntax accepted; project validation pending."
    if isinstance(raw_value, bool):
        return False, raw_value, f"{label} must be an integer from {minimum} to {maximum}."
    try:
        value = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return False, raw_value, f"{label} must be an integer from {minimum} to {maximum}."
    if not minimum <= value <= maximum:
        return False, raw_value, f"{label} must be from {minimum} to {maximum}."
    return True, value, "Syntax accepted; project validation pending."


def validate_vlan_id(raw_value, *, optional: bool = False):
    if optional and raw_value in (None, ""):
        return True, None, "Syntax accepted; project validation pending."
    return validate_optional_integer(raw_value, minimum=1, maximum=4094, label="VLAN ID")


def validate_mtu(raw_value):
    return validate_optional_integer(raw_value, minimum=MIN_MTU, maximum=MAX_MTU, label="MTU")


def validate_vlan_set(raw_value):
    """Normalize ``10,20,30-32`` to a sorted list of unique VLAN IDs."""
    if raw_value in (None, "", []):
        return True, [], "Syntax accepted; project validation pending."
    if isinstance(raw_value, list):
        tokens = [str(item) for item in raw_value]
    else:
        tokens = [part.strip() for part in str(raw_value).split(",")]
    values: set[int] = set()
    try:
        for token in tokens:
            if not token:
                raise ValueError
            if "-" in token:
                start_raw, end_raw = token.split("-", 1)
                start, end = int(start_raw), int(end_raw)
                if start > end:
                    raise ValueError
                values.update(range(start, end + 1))
            else:
                values.add(int(token))
    except (TypeError, ValueError):
        return False, raw_value, "Allowed VLANs must be comma-separated IDs or ascending ranges (for example 10,20,30-32)."
    if not values or min(values) < 1 or max(values) > 4094:
        return False, raw_value, "Every allowed VLAN must be from 1 to 4094."
    if len(values) > 4094:
        return False, raw_value, "Allowed VLAN set is too large."
    return True, sorted(values), "Syntax accepted; project validation pending."


def vlan_set_display(value) -> str:
    """Deterministically compress a normalized VLAN list to range syntax."""
    if not value:
        return ""
    numbers = sorted({int(item) for item in value})
    ranges = []
    start = previous = numbers[0]
    for number in numbers[1:]:
        if number == previous + 1:
            previous = number
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = number
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


@_text_input
def validate_cidr(raw_value, *, family: int | None = None, optional: bool = True):
    value = (raw_value or "").strip()
    if not value and optional:
        return True, "", "Syntax accepted; project validation pending."
    try:
        parsed = ipaddress.ip_interface(value)
    except ValueError:
        return False, raw_value, "Enter a valid host address with prefix length (for example 192.0.2.1/31 or 2001:db8::1/64)."
    if family is not None and parsed.version != family:
        return False, raw_value, f"This address object requires IPv{family} syntax."
    # str(ip_interface) compresses IPv6 while preserving host bits.
    return True, str(parsed), "Syntax accepted; collision and project validation pending."


@_text_input
def validate_prefix(raw_value, *, family: int | None = None):
    value = (raw_value or "").strip()
    if not value:
        return True, "", "AUTO allocation will be resolved during Phase 13 validation."
    try:
        parsed = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False, raw_value, "Select or enter a valid network prefix (host bits are not permitted)."
    if family is not None and parsed.version != family:
        return False, raw_value, f"This AUTO address object requires an IPv{family} prefix."
    return True, str(parsed), "Prefix selected; allocation is unresolved and unreserved."


@_text_input
def validate_ip_host(raw_value, *, family: int, label: str):
    value = (raw_value or "").strip()
    if not value:
        return True, "", "Syntax accepted; project validation pending."
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False, raw_value, f"{label} must be a valid IPv{family} host address without a prefix length."
    if parsed.version != family:
        return False, raw_value, f"{label} must be IPv{family}."
    return True, str(parsed), "Syntax accepted; peer/topology validation pending."


MIN_ASN = 1
MAX_ASN = 4294967295


def validate_as_number(raw_value):
    """Plain numeric ASN only (1-4294967295). No asdot notation.

    Every ASN in this repository's verified evidence (R1-R5, AS65003-65005)
    is a plain integer, so asdot normalization is out of scope rather than
    guessed at (see docs/DEVICE_BUILDER_ROUTING.md "BGP ASN validation").
    """
    return validate_optional_integer(raw_value, minimum=MIN_ASN, maximum=MAX_ASN, label="AS number")


@_text_input
def validate_router_id(raw_value):
    """Optional dotted-decimal IPv4 syntax. Completeness (is one set at all)
    is a Phase-13 concern, not Tier-1."""
    value = (raw_value or "").strip()
    if not value:
        return True, "", "Syntax accepted; project validation pending."
    try:
        parsed = ipaddress.IPv4Address(value)
    except ValueError:
        return False, raw_value, "Router ID must be a dotted-decimal IPv4-shaped value (for example 192.0.2.1)."
    return True, str(parsed), "Syntax accepted; project validation pending."


def validate_area_id(raw_value):
    """Accept an OSPF area as an integer (0-4294967295) or dotted-decimal
    (a.b.c.d), normalized to canonical dotted-decimal (0 -> 0.0.0.0)."""
    value = str(raw_value if raw_value is not None else "").strip()
    if not value:
        return False, raw_value, "Area is required."
    try:
        if "." in value:
            parsed = ipaddress.IPv4Address(value)
        else:
            number = int(value)
            if not 0 <= number <= MAX_ASN:
                raise ValueError
            parsed = ipaddress.IPv4Address(number)
    except ValueError:
        return False, raw_value, "Area must be an integer (0-4294967295) or dotted-decimal (for example 0.0.0.0)."
    return True, str(parsed), "Syntax accepted; project validation pending."


_ISIS_NET_RE = re.compile(
    r"^[0-9A-Fa-f]{2}(?:\.[0-9A-Fa-f]{4}){3,9}\.[0-9A-Fa-f]{2}$"
)


@_text_input
def validate_isis_net(raw_value):
    """Syntax-only ISO NSAP NET check: area-id . system-id(6 bytes) . NSEL(1 byte),
    dot-separated nibble groups, 8-20 bytes total. Does not check network-wide
    uniqueness (Phase-13 scope)."""
    value = (raw_value or "").strip()
    if not value:
        return False, raw_value, "NET is required."
    if not _ISIS_NET_RE.fullmatch(value):
        return (
            False,
            raw_value,
            "NET must be dot-separated hex groups shaped like area.system-id.NSEL "
            "(for example 49.0001.0000.0000.0001.00).",
        )
    hex_digits = value.replace(".", "")
    if len(hex_digits) % 2 != 0 or not 16 <= len(hex_digits) <= 40:
        return False, raw_value, "NET must total 8-20 bytes (16-40 hex digits)."
    return True, value.lower(), "Syntax accepted; project validation pending."


def validate_distance(raw_value):
    return validate_optional_integer(raw_value, minimum=1, maximum=255, label="Administrative distance")


def validate_metric(raw_value, *, minimum: int, maximum: int, label: str):
    return validate_optional_integer(raw_value, minimum=minimum, maximum=maximum, label=label)


MAX_SECRET_REF_LENGTH = 200


@_text_input
def validate_secret_ref(raw_value):
    """A reference to an externally-stored secret only -- never the secret
    itself. Field names using this validator must end in ``_ref`` so
    secret_policy.py's denylist-with-``*_ref``-exemption treats them
    correctly; this validator only bounds/sanitizes the reference token."""
    return validate_bounded_label(raw_value, label="Secret reference", maximum=MAX_SECRET_REF_LENGTH)


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


@_text_input
def validate_domain_name(raw_value, *, required=False):
    value = (raw_value or "").strip().lower().rstrip(".")
    if not value and not required:
        return True, "", "Syntax accepted; project validation pending."
    if not value or not _DOMAIN_RE.fullmatch(value):
        return False, raw_value, "Enter a valid DNS domain name."
    return True, value, "Syntax accepted; resolver reachability and project validation pending."


@_text_input
def validate_acl_name(raw_value):
    value = (raw_value or "").strip()
    if not value or len(value) > 64 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", value):
        return False, raw_value, "ACL/policy name must start with a letter and contain only letters, digits, dot, underscore, or hyphen."
    return True, value, "Syntax accepted; project validation pending."


def validate_port_spec(raw_value):
    value = str(raw_value if raw_value is not None else "").strip()
    if not value:
        return True, "", "Syntax accepted; project validation pending."
    match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", value)
    if not match:
        return False, raw_value, "Port must be a number or numeric range such as 443 or 1024-65535."
    start = int(match.group(1))
    end = int(match.group(2) or start)
    if not 0 <= start <= end <= 65535:
        return False, raw_value, "Port values must be between 0 and 65535 and ranges must be ascending."
    return True, str(start) if start == end else f"{start}-{end}", "Syntax accepted; traffic-impact validation pending."


@_text_input
def validate_mac_address(raw_value, *, required=False):
    value = (raw_value or "").strip().lower()
    if not value and not required:
        return True, "", "Syntax accepted; project validation pending."
    compact = re.sub(r"[.:-]", "", value)
    if len(compact) != 12 or not re.fullmatch(r"[0-9a-f]{12}", compact):
        return False, raw_value, "Enter a 48-bit MAC address."
    normalized = f"{compact[:4]}.{compact[4:8]}.{compact[8:]}"
    return True, normalized, "Syntax accepted; project validation pending."


@_text_input
def validate_ip_or_prefix(raw_value, *, family: int, required=False, label="Address"):
    value = (raw_value or "").strip()
    if not value and not required:
        return True, "", "Syntax accepted; project validation pending."
    if "/" in value:
        return validate_prefix(value, family=family)
    return validate_ip_host(value, family=family, label=label)
