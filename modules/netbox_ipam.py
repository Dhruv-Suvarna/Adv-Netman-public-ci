"""NetBox API abstraction (Phase 1 foundation + Phase 2 modeling primitives
of the NetBox migration).

This module is the ONLY place in the repository that should ever speak the
NetBox REST API directly. The intended eventual architecture (see
docs/NETBOX_IPAM.md) is:

    NetBox
       |
       v
    modules/netbox_ipam.py
       |
       +--> addressing/provisioning   (future phase)
       +--> DHCP                      (future phase)
       +--> monitoring inventory      (future phase)
       +--> verification              (future phase)

Phase 1 implemented only foundational functionality: loading connection
configuration, constructing a client, testing connectivity, checking API
status, and validating authentication. Phase 2 adds generic, lab-agnostic
reconciliation primitives (`reconcile_object`, `ensure_tag`) used by
`netbox/scripts/populate_netbox.py` to idempotently model the existing lab in
NetBox. Nothing in this module or in `populate_netbox.py` renders device
configuration or is consumed by `master.py` -- see docs/NETBOX_IPAM.md for
the current migration status. In particular, this module must never be used
as a silent fallback source for addressing data; if NetBox is unavailable,
callers must see a raised exception, not empty data that could be confused
with "NetBox has no objects yet".

Error handling contract
------------------------
A failed NetBox request must never be mistaken for "NetBox successfully
returned zero objects". Every failure mode below raises a distinct,
documented exception type rather than returning None/[]/{} or swallowing the
error:

  * NetboxConfigurationError -- required configuration (NETBOX_URL, a
    malformed NETBOX_TIMEOUT/NETBOX_VERIFY_SSL, a missing NETBOX_TOKEN for an
    operation that requires authentication) is missing or invalid.
  * NetboxConnectionError    -- NetBox could not be reached at all: DNS
    failure, connection refused, or a request timeout.
  * NetboxAuthenticationError -- NetBox was reached, but authentication was
    required and either not supplied or rejected (HTTP 401/403).
  * NetboxResponseError      -- NetBox was reached, authentication (if any)
    succeeded, but the response was an unexpected HTTP error or could not be
    parsed as JSON.

No caller should ever catch a bare `Exception` around a call into this
module and treat the result as "no data" -- catch the specific NetboxError
subclasses that are actually recoverable for the situation.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

try:
    import pynetbox
except ImportError:  # pragma: no cover - exercised only if the dependency is missing
    pynetbox = None

BASE = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = BASE / "netbox" / ".env"
DEFAULT_TIMEOUT_SECONDS = 10.0
STATUS_PATH = "/api/status/"

_BOOL_TRUE = {"true", "1", "yes", "on"}
_BOOL_FALSE = {"false", "0", "no", "off"}


class NetboxError(RuntimeError):
    """Base class for every error this module raises."""


class NetboxConfigurationError(NetboxError):
    """Required NetBox connection configuration is missing or invalid."""


class NetboxConnectionError(NetboxError):
    """NetBox could not be reached at all (DNS failure/connection refused/timeout)."""


class NetboxAuthenticationError(NetboxError):
    """NetBox was reached but rejected, or is missing, the required credentials."""


class NetboxResponseError(NetboxError):
    """NetBox returned an HTTP error or a response that could not be parsed."""


@dataclass(frozen=True)
class NetboxConfig:
    url: str
    token: str | None
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    verify_ssl: bool = True

    @property
    def has_token(self) -> bool:
        return bool(self.token)


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE env file, matching the pattern already used
    throughout this repository (see modules/nmas.py, modules/snmp.py) rather
    than introducing a new dependency/format."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in _BOOL_TRUE:
        return True
    if normalized in _BOOL_FALSE:
        return False
    raise NetboxConfigurationError(f"{name} is not a valid boolean: {raw!r}")


def load_config(*, env: dict[str, str] | None = None, env_file: Path | None = None) -> NetboxConfig:
    """Resolve NetBox connection settings.

    Resolution order for each variable (first match wins): real process
    environment variables, then the repository's own gitignored
    `netbox/.env` runtime file (see netbox/.env.example). This mirrors how
    the rest of the repository's monitoring modules resolve runtime
    configuration -- it never falls back to inventory.yml/templates
    addressing data, deliberately: this phase introduces no dual-source-of-
    truth logic (see docs/NETBOX_IPAM.md).
    """
    process_env = os.environ if env is None else env
    file_values = _parse_env_file(env_file if env_file is not None else DEFAULT_ENV_FILE)

    def get(name: str) -> str | None:
        value = process_env.get(name)
        if value:
            return value
        return file_values.get(name) or None

    url = get("NETBOX_URL")
    if not url:
        raise NetboxConfigurationError(
            "NETBOX_URL is not set. Export it, or populate netbox/.env "
            "(see netbox/.env.example) before using the NetBox client."
        )
    url = url.rstrip("/")

    token = get("NETBOX_TOKEN") or None

    timeout_raw = get("NETBOX_TIMEOUT")
    if timeout_raw:
        try:
            timeout = float(timeout_raw)
        except ValueError as exc:
            raise NetboxConfigurationError(f"NETBOX_TIMEOUT is not a number: {timeout_raw!r}") from exc
        if timeout <= 0:
            raise NetboxConfigurationError("NETBOX_TIMEOUT must be a positive number of seconds")
    else:
        timeout = DEFAULT_TIMEOUT_SECONDS

    verify_raw = get("NETBOX_VERIFY_SSL")
    verify_ssl = _parse_bool("NETBOX_VERIFY_SSL", verify_raw) if verify_raw else True

    return NetboxConfig(url=url, token=token, timeout=timeout, verify_ssl=verify_ssl)


def build_client(config: NetboxConfig | None = None) -> "pynetbox.api":
    if pynetbox is None:
        raise NetboxError(
            "pynetbox is not installed. Add it to monitoring/requirements.txt "
            "(already done for this phase) and reinstall the NMAS virtual "
            "environment: monitoring/scripts/install_python_dependencies.sh"
        )
    config = config or load_config()
    client = pynetbox.api(config.url, token=config.token)
    client.http_session.verify = config.verify_ssl
    return client


def _is_v2_token(token: str) -> bool:
    """Mirrors pynetbox's own detection of NetBox's newer hashed (v2) API
    token format (`nbt_<key>.<secret>`) so the raw `requests` calls below
    build the same Authorization header pynetbox would for the same
    NETBOX_TOKEN value."""
    prefix = "nbt_"
    if not token.startswith(prefix):
        return False
    return "." in token[len(prefix):]


def _auth_header(token: str) -> dict[str, str]:
    if _is_v2_token(token):
        return {"Authorization": f"Bearer {token}"}
    return {"Authorization": f"Token {token}"}


def _request(config: NetboxConfig, path: str, *, authenticated: bool) -> requests.Response:
    headers = {"Accept": "application/json"}
    if authenticated:
        if not config.has_token:
            raise NetboxConfigurationError("NETBOX_TOKEN is required for an authenticated request but is not set")
        headers.update(_auth_header(config.token))
    url = f"{config.url}{path}"
    try:
        return requests.get(url, headers=headers, timeout=config.timeout, verify=config.verify_ssl)
    except requests.exceptions.Timeout as exc:
        raise NetboxConnectionError(f"NetBox at {config.url} timed out after {config.timeout}s") from exc
    except requests.exceptions.ConnectionError as exc:
        raise NetboxConnectionError(f"NetBox at {config.url} is unreachable: {exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise NetboxConnectionError(f"NetBox request to {config.url} failed: {exc}") from exc


def _json(response: requests.Response, *, context: str) -> Any:
    try:
        return response.json()
    except ValueError as exc:
        raise NetboxResponseError(
            f"{context}: NetBox returned a non-JSON response (HTTP {response.status_code})"
        ) from exc


def check_status(config: NetboxConfig | None = None) -> dict:
    """Call NetBox's /api/status/ endpoint and return its parsed JSON body.

    This is the connectivity/API-health check: a successful call proves
    NetBox is up and returned a real status document. It never touches
    IPAM/DCIM data, so there is no ambiguity here between "unreachable" and
    "empty" -- that distinction matters starting in later phases, once this
    module grows data-reading functions.
    """
    config = config or load_config()
    response = _request(config, STATUS_PATH, authenticated=False)
    if response.status_code in (401, 403):
        if not config.has_token:
            raise NetboxAuthenticationError(
                f"NetBox at {config.url} requires authentication to read {STATUS_PATH} and NETBOX_TOKEN is not set"
            )
        response = _request(config, STATUS_PATH, authenticated=True)
        if response.status_code in (401, 403):
            raise NetboxAuthenticationError(
                f"NetBox rejected the configured API token (HTTP {response.status_code})"
            )
    if not response.ok:
        raise NetboxResponseError(
            f"NetBox {STATUS_PATH} returned HTTP {response.status_code}: {response.text[:300]}"
        )
    return _json(response, context=STATUS_PATH)


def verify_authentication(config: NetboxConfig | None = None) -> dict:
    """Prove the configured NETBOX_TOKEN is accepted by NetBox.

    Raises NetboxConfigurationError if no token is configured,
    NetboxAuthenticationError if NetBox rejects it, NetboxConnectionError if
    NetBox is unreachable, or NetboxResponseError for any other unexpected
    HTTP/JSON failure. Returns the authenticated status document on success.
    """
    config = config or load_config()
    if not config.has_token:
        raise NetboxConfigurationError("NETBOX_TOKEN is not set; cannot validate authentication")
    response = _request(config, STATUS_PATH, authenticated=True)
    if response.status_code in (401, 403):
        raise NetboxAuthenticationError(f"NetBox rejected the configured API token (HTTP {response.status_code})")
    if not response.ok:
        raise NetboxResponseError(
            f"Authenticated {STATUS_PATH} returned HTTP {response.status_code}: {response.text[:300]}"
        )
    return _json(response, context=f"authenticated {STATUS_PATH}")


def run_diagnostics(config: NetboxConfig | None = None) -> dict:
    """Run every foundational check and return one structured, printable
    result. This function itself never raises for an *expected* runtime
    failure (NetBox down, bad token) -- each check's outcome is captured
    individually so a caller (e.g. the CLI below) can report a clear
    per-check PASS/FAIL/SKIPPED without losing the distinction between them.
    A configuration error (e.g. missing NETBOX_URL) still raises immediately,
    since no check can meaningfully proceed without it.
    """
    config = config or load_config()
    result: dict[str, Any] = {"url": config.url, "checks": []}

    def record(name: str, fn) -> Any:
        try:
            value = fn()
            result["checks"].append({"name": name, "status": "PASS", "detail": None})
            return value
        except NetboxError as exc:
            result["checks"].append({"name": name, "status": "FAIL", "detail": str(exc)})
            return None

    status = record("connectivity/status", lambda: check_status(config))
    if status is not None:
        result["netbox_version"] = status.get("netbox-version")

    if config.has_token:
        record("authentication", lambda: verify_authentication(config))
    else:
        result["checks"].append({"name": "authentication", "status": "SKIPPED", "detail": "NETBOX_TOKEN not set"})

    result["all_passed"] = all(item["status"] in ("PASS", "SKIPPED") for item in result["checks"])
    return result


# ---------------------------------------------------------------------------
# Phase 2: generic, lab-agnostic reconciliation primitives.
#
# Everything below is deliberately ignorant of what a "device", "prefix", or
# "VLAN" means in THIS lab -- that knowledge (the manifest schema, which
# fields matter for which NetBox object type, R5/WebServer's unmanaged
# status, etc.) lives entirely in netbox/scripts/populate_netbox.py. This
# module only knows how to talk to NetBox and how to reconcile one object
# against one desired-state dict safely. That separation is what lets this
# module stay "the only place that speaks the NetBox REST API" while the
# lab-specific modeling logic lives in a dedicated, clearly-scoped script.
# ---------------------------------------------------------------------------

OWNERSHIP_TAG = "csci5840-iac"
MANAGED_TAG = "managed"
UNMANAGED_TAG = "unmanaged"

#: Reconciliation outcomes. CHECK-* are only ever returned when apply=False;
#: they describe what CREATE/UPDATE *would* do without changing NetBox.
CREATE = "CREATE"
UNCHANGED = "UNCHANGED"
UPDATE = "UPDATE"
CONFLICT = "CONFLICT"
CHECK_CREATE = "CHECK-CREATE"
CHECK_UPDATE = "CHECK-UPDATE"


@dataclass
class ReconcileResult:
    action: str
    obj: Any = None
    changes: dict = None
    conflicts: dict = None

    def __post_init__(self):
        if self.changes is None:
            self.changes = {}
        if self.conflicts is None:
            self.conflicts = {}

    @property
    def ok(self) -> bool:
        return self.action != CONFLICT


def _normalize(value: Any) -> Any:
    """Reduce a value to something comparable across BOTH directions this
    module deals with: a related object READ BACK from NetBox (a pynetbox
    Record with `.slug`/`.id` attributes) and a related object reference
    WRITTEN by a caller's `desired` dict (a plain `{"slug": ...}` or
    `{"id": ...}` dict -- see e.g. populate_netbox.py's `{"role": {"slug":
    ...}}`). Both reduce to the same slug/id value so they compare equal
    when they refer to the same NetBox object. A list becomes a sorted list
    of normalized items; everything else passes through unchanged."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        if "slug" in value:
            return value["slug"]
        if "id" in value:
            return value["id"]
        return value
    if isinstance(value, (list, tuple)):
        return sorted((str(_normalize(item)) for item in value))
    slug = getattr(value, "slug", None)
    if slug is not None:
        return slug
    # NetBox choice fields (e.g. a custom field's "type", an IP address's
    # "status"/"role") come back as a Record whose *machine* value lives in
    # `.value` -- its `str()`/`repr()` is the human label ("Boolean"), which
    # would otherwise never match the plain string ("boolean") a caller's
    # `desired` dict uses.
    choice_value = getattr(value, "value", None)
    if choice_value is not None and not hasattr(value, "id"):
        return choice_value
    obj_id = getattr(value, "id", None)
    if obj_id is not None:
        return obj_id
    return value


def _values_equal(existing: Any, desired: Any) -> bool:
    # A desired reference dict ({"id": ...} or {"slug": ...}) must be
    # compared against the SAME attribute on the existing object -- not
    # each side reduced independently to whatever _normalize happens to
    # prefer (which defaults to slug-over-id for existing objects and would
    # otherwise wrongly compare, e.g., an existing object's slug against a
    # desired id and call them unequal even when they name the same object).
    if isinstance(desired, dict) and hasattr(existing, "id"):
        if "id" in desired:
            return getattr(existing, "id", None) == desired["id"]
        if "slug" in desired:
            return getattr(existing, "slug", None) == desired["slug"]
    left, right = _normalize(existing), _normalize(desired)
    if isinstance(left, list) or isinstance(right, list):
        return left == right
    if left is None and right is None:
        return True
    return str(left) == str(right)


def _diff_custom_fields(
    existing_cf: dict | None, desired_cf: dict, safe_keys: frozenset[str] = frozenset(),
) -> tuple[dict, dict]:
    """Compare only the keys THIS repository manages (the keys present in
    `desired_cf`); a custom field key present on the object but absent from
    `desired_cf` belongs to someone/something else and is left untouched.

    A key already holding a DIFFERENT value than desired is normally a
    CONFLICT (never silently overwritten) -- except for a key listed in
    `safe_keys`, which is this repository's own explicit declaration that
    the key represents revisable POLICY/planning state it owns outright
    (e.g. an assignment-mode decision that a later phase deliberately
    changed), not identity data a human or another tool might have set out
    of band. See `reconcile_object`'s `safe_update_custom_fields` param."""
    existing_cf = existing_cf or {}
    changes, conflicts = {}, {}
    for key, desired_value in desired_cf.items():
        existing_value = existing_cf.get(key)
        if existing_value is None or existing_value == "":
            if desired_value is None or desired_value == "":
                continue  # already effectively unset -- nothing to change
            changes[key] = desired_value
        elif not _values_equal(existing_value, desired_value):
            if key in safe_keys:
                changes[key] = desired_value
            else:
                conflicts[key] = {"existing": existing_value, "desired": desired_value}
    return changes, conflicts


def _wrap_pynetbox_errors(action: str, fn):
    try:
        return fn()
    except requests.exceptions.Timeout as exc:
        raise NetboxConnectionError(f"NetBox timed out while attempting to {action}") from exc
    except requests.exceptions.ConnectionError as exc:
        raise NetboxConnectionError(f"NetBox was unreachable while attempting to {action}: {exc}") from exc
    except Exception as exc:  # pynetbox.RequestError and friends -- see module docstring
        if pynetbox is not None and isinstance(exc, pynetbox.RequestError):
            raise NetboxResponseError(f"NetBox rejected an attempt to {action}: {exc.error}") from exc  # pylint: disable=no-member  # pynetbox.RequestError carries .error; isinstance-guarded on the line above
        raise


def _to_wire(fields: dict) -> dict:
    """Translate this module's plain-Python `desired`/`changes` dict into
    exactly what NetBox's write API expects on the wire. Only `tags` needs
    translation: NetBox's serializer requires each tag to be referenced by
    numeric id or by an attribute dict (e.g. {"slug": ...}), not a bare
    string, even though bare strings are what reads naturally in a manifest
    and in this module's own comparison/reporting logic (see `_normalize`,
    which reduces a tag object back down to its slug for exactly that
    reason)."""
    if "tags" not in fields:
        return fields
    wire = dict(fields)
    wire["tags"] = [{"slug": tag} if isinstance(tag, str) else tag for tag in fields["tags"]]
    return wire


def reconcile_object(
    endpoint,
    *,
    lookup: dict,
    desired: dict,
    safe_update_fields: frozenset[str] = frozenset(),
    safe_update_custom_fields: frozenset[str] = frozenset(),
    apply: bool = True,
) -> ReconcileResult:
    """Idempotently reconcile ONE NetBox object against desired state.

    `lookup` must uniquely identify the object (e.g. {"name": "R1", "site_id": 3}).
    `desired` is every field this repository cares about for this object,
    INCLUDING a `"tags"` entry when relevant (see below) and/or a
    `"custom_fields"` dict (see `_diff_custom_fields`).

    Behavior:
      * No match                          -> CREATE (or CHECK-CREATE if not apply)
      * Match, every desired field equal  -> UNCHANGED
      * Match, only `safe_update_fields`
        (plus tags/custom_fields, which
        are always additive/safe) differ  -> UPDATE (or CHECK-UPDATE)
      * Match, some OTHER field differs   -> CONFLICT (nothing is changed;
                                              the caller must report this to
                                              a human rather than overwrite it)

    `tags` are handled additively: an existing object keeps every tag it
    already has, and this repository's desired tags are unioned in. Tags are
    therefore never a source of CONFLICT. `custom_fields` are merged key by
    key (see `_diff_custom_fields`): an existing custom field this repository
    does not mention is left alone; one it does mention that already holds a
    different value is a CONFLICT, exactly like any other field -- UNLESS
    that key is listed in `safe_update_custom_fields`, this repository's
    explicit declaration that the key is revisable policy/planning state it
    owns outright (e.g. an assignment-mode decision a later phase
    deliberately revised), in which case a differing value is an UPDATE
    instead. Defaults to empty (strict conflict) for every existing caller.
    """
    matches = _wrap_pynetbox_errors("look up", lambda: list(endpoint.filter(**lookup)))
    if len(matches) > 1:
        raise NetboxResponseError(f"Ambiguous NetBox lookup on {lookup!r}: {len(matches)} objects matched")

    if not matches:
        if not apply:
            return ReconcileResult(CHECK_CREATE, None, changes=dict(desired))
        payload = {**lookup, **_to_wire(desired)}
        created = _wrap_pynetbox_errors("create", lambda: endpoint.create(**payload))
        return ReconcileResult(CREATE, created, changes=dict(desired))

    existing = matches[0]
    changes: dict = {}
    conflicts: dict = {}

    for field_name, desired_value in desired.items():
        if field_name == "tags":
            existing_tags = set(_normalize(getattr(existing, "tags", None)) or [])
            desired_tags = set(desired_value)
            if not desired_tags <= existing_tags:
                changes["tags"] = sorted(existing_tags | desired_tags)
            continue
        if field_name == "custom_fields":
            cf_changes, cf_conflicts = _diff_custom_fields(
                getattr(existing, "custom_fields", None), desired_value, safe_update_custom_fields,
            )
            if cf_conflicts:
                conflicts["custom_fields"] = cf_conflicts
            if cf_changes:
                changes["custom_fields"] = {**(getattr(existing, "custom_fields", None) or {}), **cf_changes}
            continue

        existing_value = getattr(existing, field_name, None)
        if _values_equal(existing_value, desired_value):
            continue
        if field_name in safe_update_fields:
            changes[field_name] = desired_value
        else:
            conflicts[field_name] = {"existing": _normalize(existing_value), "desired": _normalize(desired_value)}

    if conflicts:
        return ReconcileResult(CONFLICT, existing, conflicts=conflicts)
    if not changes:
        return ReconcileResult(UNCHANGED, existing)
    if not apply:
        return ReconcileResult(CHECK_UPDATE, existing, changes=changes)
    wire_changes = _to_wire(changes)
    _wrap_pynetbox_errors("update", lambda: (existing.update(wire_changes), existing.save()))
    return ReconcileResult(UPDATE, existing, changes=changes)


def ensure_tag(client, name: str, *, color: str | None = None, description: str = "", apply: bool = True) -> ReconcileResult:
    """Ensure one NetBox tag exists (tags have no meaningful "safe update"
    fields beyond color/description, which are cosmetic)."""
    slug = name.lower().replace(" ", "-")
    desired = {"description": description}
    if color:
        desired["color"] = color
    return reconcile_object(
        client.extras.tags,
        lookup={"slug": slug},
        desired={"name": name, **desired},
        safe_update_fields=frozenset({"color", "description", "name"}),
        apply=apply,
    )


def ensure_custom_field(
    client,
    name: str,
    *,
    field_type: str,
    content_types: list[str],
    label: str = "",
    description: str = "",
    apply: bool = True,
) -> ReconcileResult:
    """Ensure one NetBox custom-field DEFINITION exists (this is the schema,
    not a value -- values are set per-object via each object's own
    `custom_fields` dict, reconciled by `reconcile_object`).

    `content_types` is this function's stable public parameter name (the
    term used across NetBox's own documentation and older releases); NetBox
    4.x renamed the actual wire/API field to `object_types` (still the same
    "app_label.model" string list), so the translation happens here rather
    than leaking that version detail to every caller.
    """
    return reconcile_object(
        client.extras.custom_fields,
        lookup={"name": name},
        desired={
            "type": field_type,
            "object_types": sorted(content_types),
            "label": label or name,
            "description": description,
        },
        safe_update_fields=frozenset({"label", "description", "object_types"}),
        apply=apply,
    )


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Foundational NetBox connectivity/authentication verification (Phase 1 of the NetBox migration)."
    )
    parser.parse_args(argv)

    try:
        config = load_config()
    except NetboxConfigurationError as exc:
        print(f"NetBox configuration: FAIL ({exc})", file=sys.stderr)
        return 1

    print(f"NetBox URL: {config.url}")
    try:
        result = run_diagnostics(config)
    except NetboxConfigurationError as exc:
        print(f"NetBox configuration: FAIL ({exc})", file=sys.stderr)
        return 1

    for check in result["checks"]:
        line = f"{check['name']:.<30} {check['status']}"
        if check["status"] == "FAIL":
            line += f"  ({check['detail']})"
        print(line)
    if "netbox_version" in result and result["netbox_version"]:
        print(f"NetBox version: {result['netbox_version']}")
    print("Overall: " + ("PASS" if result["all_passed"] else "FAIL"))
    return 0 if result["all_passed"] else 1


# ---------------------------------------------------------------------------
# Phase 3A: normalized, provisioning-facing READ API.
#
# Everything below returns plain Python dicts/lists/None -- never a raw
# pynetbox Record. This is deliberate: modules/ipam_context.py and every
# future provisioning caller should never need to know pynetbox's response
# shapes, and should never be able to accidentally mutate/`.save()` a
# NetBox object through a value returned from here (these functions are
# read-only by construction: they never call `.save()`/`.update()`).
#
# Fail-closed contract (Step 12/13 of Phase 3A): a NetBox connectivity/auth
# failure raises the same NetboxError subclasses as everywhere else in this
# module. A required object that is simply ABSENT from NetBox (e.g. a
# device that was never populated, a VLAN with no matching prefix) raises
# NetboxModelError -- distinct from "NetBox is down" -- so a caller building
# a provisioning context can never mistake "NetBox has no such data" for
# "empty/optional" and silently proceed with incomplete addressing.
# ---------------------------------------------------------------------------

MANAGED_TAG_NAME = "managed"
UNMANAGED_TAG_NAME = "unmanaged"
MANAGED_CUSTOM_FIELD = "iac_managed"
OWNERSHIP_TAG_FILTER = "csci5840-iac"
# Phase 3C: distinguishes a primary (NMAS) DHCP pool boundary from a
# secondary (R2) one on the same ipam.IPRange objects -- see
# docs/NETBOX_IPAM.md "Phase 3C".
DHCP_PRIMARY_TAG = "dhcp-primary"
DHCP_SECONDARY_TAG = "dhcp-secondary"
DHCP_SERVER_TAGS = {DHCP_PRIMARY_TAG: "primary", DHCP_SECONDARY_TAG: "secondary"}


class NetboxModelError(NetboxError):
    """NetBox was reached and answered normally, but the specific object a
    caller needs (device, interface, prefix, VLAN, address, ...) does not
    exist, or the model is internally inconsistent (e.g. a device tagged
    both "managed" and "unmanaged"). Distinct from NetboxConnectionError/
    NetboxAuthenticationError/NetboxResponseError, which mean NetBox itself
    could not be reached or answered abnormally -- this means NetBox was
    reached fine but the DATA a caller asked for isn't there. Never
    conflate this with "the object legitimately has zero of something"
    (e.g. a device with no IPv4 primary address returns None, not this)."""


def _list(endpoint, **filters) -> list:
    return _wrap_pynetbox_errors("list", lambda: list(endpoint.filter(**filters)))


def _get_one(endpoint, **filters):
    matches = _list(endpoint, **filters)
    if len(matches) > 1:
        raise NetboxResponseError(f"Ambiguous NetBox lookup on {filters!r}: {len(matches)} objects matched")
    return matches[0] if matches else None


def _normalized_ip(record) -> dict:
    iface = ipaddress.ip_interface(record.address)
    role = getattr(record, "role", None)
    return {
        "address": str(iface.ip),
        "prefix_length": iface.network.prefixlen,
        "cidr": str(iface),
        "family": iface.version,
        "role": _normalize(role),
        "description": record.description or None,
    }


def get_managed_devices(client=None) -> list[str]:
    """Return the names of every device NetBox marks as managed for this
    IaC, using NetBox's own authoritative scope metadata -- never a
    hard-coded exclusion list. Both signals Phase 2 wrote (the `managed`
    tag and the `iac_managed` custom field) must agree; disagreement is a
    data-integrity problem reported as NetboxModelError, not silently
    resolved one way. A device tagged both `managed` and `unmanaged` is
    likewise a data-integrity error.

    R5 and WebServer are excluded by this NetBox-authoritative check, not
    because this function happens to know their names.
    """
    client = client or build_client()
    all_devices = _list(client.dcim.devices, tag=OWNERSHIP_TAG_FILTER)
    tagged_managed = {d.name for d in all_devices if MANAGED_TAG_NAME in (_normalize(d.tags) or [])}
    tagged_unmanaged = {d.name for d in all_devices if UNMANAGED_TAG_NAME in (_normalize(d.tags) or [])}
    both = tagged_managed & tagged_unmanaged
    if both:
        raise NetboxModelError(f"Device(s) tagged BOTH managed and unmanaged (data integrity error): {sorted(both)}")
    flagged_managed = {d.name for d in all_devices if d.custom_fields.get(MANAGED_CUSTOM_FIELD) is True}
    if tagged_managed != flagged_managed:
        raise NetboxModelError(
            "The 'managed' tag and the iac_managed custom field disagree for: "
            f"{sorted(tagged_managed ^ flagged_managed)}"
        )
    return sorted(tagged_managed)


def is_device_managed(name: str, client=None) -> bool:
    """Defense-in-depth membership check -- prefer this (or
    `require_managed_device`) at the top of any function that is about to
    do something provisioning-shaped with a device name, even though
    `get_managed_devices()` is already the authoritative source."""
    return name in get_managed_devices(client)


def require_managed_device(name: str, client=None) -> None:
    """Raise NetboxModelError if `name` is not (or is not YET known to be)
    a managed device. Callers building provisioning contexts should call
    this before doing anything else with a device name."""
    if not is_device_managed(name, client):
        raise NetboxModelError(f"{name!r} is not a managed device in NetBox; refusing to treat it as a provisioning target")


def get_device(name: str, client=None) -> dict:
    """Normalized device summary. Works for ANY device NetBox knows about
    (including R5/WebServer) -- callers that must never touch an unmanaged
    device should check `managed` themselves or call
    `require_managed_device()` first; this function does not gate access,
    it only reports the truth NetBox holds."""
    client = client or build_client()
    device = _get_one(client.dcim.devices, name=name, tag=OWNERSHIP_TAG_FILTER)
    if device is None:
        raise NetboxModelError(f"No IaC-owned device named {name!r} exists in NetBox")
    tags = set(_normalize(device.tags) or [])
    return {
        "name": device.name,
        "role": _normalize(device.role),
        "device_type": _normalize(device.device_type),
        "managed": device.custom_fields.get(MANAGED_CUSTOM_FIELD),
        "tags": sorted(tags),
        "primary_ipv4": _normalized_ip(device.primary_ip4) if device.primary_ip4 else None,
        "primary_ipv6": _normalized_ip(device.primary_ip6) if device.primary_ip6 else None,
    }


def get_primary_address(name: str, family: int, client=None) -> dict | None:
    """The device's primary_ip4/primary_ip6 (the dedicated-management-VLAN
    address for the 9 managed devices; see docs/NETBOX_IPAM.md "Primary
    address convention" for R5/WebServer). Returns None if the device has
    no primary address of that family -- that is a legitimate empty
    result, not an error, so it is never confused with the device not
    existing at all (which still raises NetboxModelError)."""
    if family not in (4, 6):
        raise NetboxConfigurationError(f"family must be 4 or 6, got {family!r}")
    device = get_device(name, client)
    return device[f"primary_ipv{family}"]


def get_interface_addresses(device: str, interface: str, client=None) -> list[dict]:
    """Every IP address assigned to one interface, normalized. Returns an
    empty list if the interface exists but carries no addresses (a
    legitimate result for a pure L2 port, though this repository does not
    model those); raises NetboxModelError if the interface itself does not
    exist for that device."""
    client = client or build_client()
    iface = _get_one(client.dcim.interfaces, device=device, name=interface)
    if iface is None:
        raise NetboxModelError(f"{device}/{interface}: no such interface in NetBox")
    addresses = _list(client.ipam.ip_addresses, interface_id=iface.id)
    return sorted((_normalized_ip(a) for a in addresses), key=lambda a: (a["family"], a["address"]))


def get_interface_address(device: str, interface: str, family: int, client=None) -> dict | None:
    """Convenience single-address accessor for the common case of one
    address per family per interface. Returns None if the interface has no
    address of that family (e.g. VLAN30's SVI has no IPv4) -- raises
    NetboxModelError only if MULTIPLE addresses of the same family exist
    (an ambiguous request, not a "just pick one" situation)."""
    if family not in (4, 6):
        raise NetboxConfigurationError(f"family must be 4 or 6, got {family!r}")
    matches = [a for a in get_interface_addresses(device, interface, client) if a["family"] == family]
    if len(matches) > 1:
        raise NetboxModelError(f"{device}/{interface}: {len(matches)} IPv{family} addresses exist; ambiguous single-address request")
    return matches[0] if matches else None


def get_peer_addresses(device: str, interface: str, family: int | None = None, client=None) -> list[dict]:
    """Derive the OTHER end(s) of a point-to-point link by finding every
    other IP address that shares the same containing prefix as `device`'s
    own address on `interface` -- never a hard-coded peer identity. Used
    for BGP neighbor addresses and static-route next hops (see
    docs/NETBOX_IPAM.md "Deriving relationships instead of hard-coding
    them"). Works across the managed/unmanaged boundary (e.g. finding R5's
    address from R3's side) because it queries by shared prefix, not by
    device scope.

    Raises NetboxModelError if `device`/`interface` itself has no address
    of the requested family to anchor the search from.
    """
    client = client or build_client()
    own_addresses = get_interface_addresses(device, interface, client)
    if family is not None:
        own_addresses = [a for a in own_addresses if a["family"] == family]
    if not own_addresses:
        raise NetboxModelError(f"{device}/{interface}: no address to derive a peer from (family={family})")
    peers = []
    for own in own_addresses:
        candidates = _list(client.ipam.ip_addresses, parent=own["cidr"])
        for candidate in candidates:
            normalized = _normalized_ip(candidate)
            if normalized["address"] != own["address"]:
                peers.append(normalized)
    return peers


def get_peer_address(device: str, interface: str, family: int, client=None) -> dict | None:
    """Single-peer convenience wrapper around `get_peer_addresses` for the
    normal point-to-point (/31 or /127, exactly two hosts) case. Raises
    NetboxModelError if more than one peer address of that family exists
    (this repository's model never has that for a real point-to-point
    link -- more than one match means the prefix is not actually
    point-to-point, which is worth failing loudly on rather than guessing)."""
    peers = get_peer_addresses(device, interface, family, client)
    if len(peers) > 1:
        raise NetboxModelError(f"{device}/{interface}: {len(peers)} IPv{family} peer addresses found; not a simple point-to-point link")
    return peers[0] if peers else None


def get_prefix(prefix: str, client=None) -> dict:
    """Normalized prefix summary. Raises NetboxModelError if the exact
    prefix (address + mask) does not exist -- callers should pass the
    fully-specified CIDR, matching how netbox/ipam.yml declares it."""
    client = client or build_client()
    obj = _get_one(client.ipam.prefixes, prefix=prefix)
    if obj is None:
        raise NetboxModelError(f"No such prefix in NetBox: {prefix}")
    network = ipaddress.ip_network(obj.prefix)
    return {
        "prefix": str(network),
        "family": network.version,
        "prefix_length": network.prefixlen,
        "vlan_vid": obj.vlan.vid if obj.vlan else None,
        "role": _normalize(obj.role),
        "managed": obj.custom_fields.get(MANAGED_CUSTOM_FIELD),
        "description": obj.description or None,
    }


def get_vlan(vid: int, client=None) -> dict:
    """Normalized VLAN summary, including both its IPv4 and IPv6 prefixes
    where they exist (either may legitimately be None -- see VLAN30)."""
    client = client or build_client()
    obj = _get_one(client.ipam.vlans, vid=vid)
    if obj is None:
        raise NetboxModelError(f"No such VLAN in NetBox: {vid}")
    prefixes = _list(client.ipam.prefixes, vlan_id=obj.id)
    by_family = {p["family"]: p for p in (get_prefix(str(ipaddress.ip_network(p.prefix)), client) for p in prefixes)}
    return {
        "vid": obj.vid,
        "name": obj.name,
        "role": _normalize(obj.role),
        "prefix_ipv4": by_family.get(4),
        "prefix_ipv6": by_family.get(6),
    }


def get_shared_gateway(vid: int, family: int, client=None) -> dict | None:
    """The shared VRRP-role gateway address for a client VLAN (Step 6):
    never a specific device's own interface address, and intentionally NOT
    assigned to any single interface in NetBox (see docs/NETBOX_IPAM.md).
    Returns None when the VLAN legitimately has no gateway of that family
    (e.g. VLAN30 has no IPv4 gateway) -- raises NetboxModelError only if
    more than one VRRP address of that family exists for the VLAN's
    prefix, which would mean the model is ambiguous, not that there is no
    gateway."""
    if family not in (4, 6):
        raise NetboxConfigurationError(f"family must be 4 or 6, got {family!r}")
    vlan = get_vlan(vid, client)
    prefix_entry = vlan[f"prefix_ipv{family}"]
    if prefix_entry is None:
        return None
    client = client or build_client()
    candidates = [
        _normalized_ip(a) for a in _list(client.ipam.ip_addresses, parent=prefix_entry["prefix"])
        if _normalize(getattr(a, "role", None)) == "vrrp"
    ]
    if len(candidates) > 1:
        raise NetboxModelError(f"VLAN{vid}: {len(candidates)} IPv{family} VRRP addresses found; ambiguous shared gateway")
    return candidates[0] if candidates else None


def get_dhcp_ranges(vid: int | None = None, server: str | None = None, client=None) -> list[dict]:
    """Every modeled DHCP allocation range (Step 16 metadata), optionally
    filtered to those matching one VLAN's prefix and/or one server
    ("primary"/"secondary", Phase 3C -- see `DHCP_SERVER_TAGS`). Status is
    `reserved`, not `dhcp` -- see docs/NETBOX_IPAM.md for why this NetBox
    release's ipam.IPRange model doesn't support a `dhcp` status.

    `server` in the returned entry is `None` for a range NetBox holds that
    predates the primary/secondary tagging convention (never fabricated);
    raises NetboxConfigurationError if `server` is passed but is not one
    of "primary"/"secondary"."""
    if server is not None and server not in DHCP_SERVER_TAGS.values():
        raise NetboxConfigurationError(f"server must be one of {sorted(DHCP_SERVER_TAGS.values())}, got {server!r}")
    client = client or build_client()
    ranges = _list(client.ipam.ip_ranges, tag=OWNERSHIP_TAG_FILTER)
    result = []
    for item in ranges:
        start, end = ipaddress.ip_address(item.start_address.split("/")[0]), ipaddress.ip_address(item.end_address.split("/")[0])
        tag_slugs = set(_normalize(getattr(item, "tags", None)) or [])
        item_server = next((label for tag, label in DHCP_SERVER_TAGS.items() if tag in tag_slugs), None)
        if server is not None and item_server != server:
            continue
        entry = {
            "start": str(start), "end": str(end), "family": start.version,
            "server": item_server,
            "description": item.description or None,
        }
        if vid is not None:
            vlan_entry = get_vlan(vid, client)
            prefix_entry = vlan_entry[f"prefix_ipv{start.version}"]
            if prefix_entry is None or start not in ipaddress.ip_network(prefix_entry["prefix"]):
                continue
        result.append(entry)
    return sorted(result, key=lambda r: (r["family"], r["start"]))


def get_dhcp_relay_targets(prefix: str, client=None) -> list[str]:
    """The `dhcp_relay_targets` custom field on a client prefix (Step 16),
    parsed into a plain list of address strings. Returns an empty list
    (not an error) for a prefix that legitimately has no relay targets
    recorded (e.g. a transit prefix); raises NetboxModelError if the
    prefix itself does not exist."""
    client = client or build_client()
    obj = _get_one(client.ipam.prefixes, prefix=prefix)
    if obj is None:
        raise NetboxModelError(f"No such prefix in NetBox: {prefix}")
    raw = obj.custom_fields.get("dhcp_relay_targets") or ""
    return [item.strip() for item in raw.split(",") if item.strip()]


def get_device_interface_names(device: str, client=None) -> list[str]:
    """Every interface NetBox knows about for `device`, by name -- lets a
    caller enumerate a device's addressing without hard-coding which
    interfaces it has."""
    client = client or build_client()
    nb_device = get_device(device, client)  # raises NetboxModelError if absent
    del nb_device
    return sorted(record.name for record in _list(client.dcim.interfaces, device=device))


def list_all_prefix_cidrs(client=None) -> set[str]:
    """Every prefix (any status/scope) NetBox currently holds, as exact
    CIDR strings. Used to validate that an address value extracted from
    elsewhere is a real, NetBox-known prefix -- not to decide routing/NAT
    policy."""
    client = client or build_client()
    return {str(ipaddress.ip_network(p.prefix)) for p in _list(client.ipam.prefixes)}


# ---------------------------------------------------------------------------
# Phase 3B: deterministic dynamic-assignment metadata.
#
# NetBox 4.7 models MAC addresses as their own first-class object
# (dcim.MACAddress, polymorphically assigned to an interface, with an
# `is_primary` flag and a matching `Interface.primary_mac_address` FK) --
# NOT a plain string field on Interface. This is used here instead of a
# custom field, per Step 8's instruction to prefer a native representation
# when NetBox has one.
#
# DUID/IAID have no NetBox-native representation at all, so those (and the
# assignment-mode policy itself, which is forward-looking design intent
# this repository owns -- see docs/NETBOX_IPAM.md "Why a custom field, not
# NetBox's own IP-address `status=dhcp`") use custom fields:
# `ipv4_assignment_mode`/`ipv6_assignment_mode` on dcim.interface,
# `dhcpv6_duid`/`dhcpv6_iaid` on dcim.interface.
# ---------------------------------------------------------------------------

ASSIGNMENT_MODES = ("static", "dhcp-reserved", "dhcpv6-reserved", "none")


def get_interface_mac(device: str, interface: str, client=None) -> dict | None:
    """The primary MAC address recorded against one interface, or None if
    none is recorded yet. Never fabricates a value -- returns exactly what
    NetBox holds, including its `identity_status` (Phase 3B.1: `None` if
    never explicitly decided, `IDENTITY_OBSERVED`/`IDENTITY_AUTHORITATIVE`/
    `IDENTITY_BLOCKED` otherwise -- see mark_mac_authoritative()). A nested
    interface->MAC reference from NetBox does not reliably include custom
    fields, so this re-fetches the full MAC object by id rather than
    trusting the nested one.
    """
    client = client or build_client()
    iface = _get_one(client.dcim.interfaces, device=device, name=interface)
    if iface is None:
        raise NetboxModelError(f"{device}/{interface}: no such interface in NetBox")
    mac_ref = getattr(iface, "primary_mac_address", None)
    if mac_ref is None:
        return None
    full = _get_one(client.dcim.mac_addresses, id=mac_ref.id) or mac_ref
    custom_fields = getattr(full, "custom_fields", None) or {}
    return {
        "mac_address": full.mac_address,
        "description": full.description or None,
        "identity_status": custom_fields.get("identity_status") or None,
    }


def ensure_interface_mac(device: str, interface: str, mac_address: str, client=None, apply: bool = True) -> ReconcileResult:
    """Reconcile ONE observed MAC address onto ONE interface, and mark it
    that interface's primary MAC. This is explicitly for LIVE-OBSERVED,
    re-derivable data (see modules/ipam_context.py's MAC-discovery
    function and docs/NETBOX_IPAM.md's MAC-stability findings) -- it is
    reconciled the same idempotent way as everything else, so a MAC that
    changes on a future redeploy is detected as an UPDATE here, never
    silently masked.
    """
    client = client or build_client()
    iface = _get_one(client.dcim.interfaces, device=device, name=interface)
    if iface is None:
        raise NetboxModelError(f"{device}/{interface}: no such interface in NetBox")
    lookup = {
        "mac_address": mac_address,
        "assigned_object_id": iface.id,
        "assigned_object_type": "dcim.interface",
    }
    existing = _get_one(client.dcim.mac_addresses, **lookup)
    desired = {
        "assigned_object_type": "dcim.interface", "assigned_object_id": iface.id,
        "is_primary": True, "tags": [OWNERSHIP_TAG_FILTER],
    }
    # A live sync is observation, never authority. Seed that explicit state
    # only for a new/previously-unclassified record; preserve an existing
    # authoritative or blocked decision instead of trying to demote it on
    # every observational rerun.
    if existing is None or not (getattr(existing, "custom_fields", None) or {}).get("identity_status"):
        desired["custom_fields"] = {"identity_status": IDENTITY_OBSERVED}
    result = reconcile_object(
        client.dcim.mac_addresses,
        lookup=lookup,
        desired=desired,
        safe_update_fields=frozenset({"is_primary"}),
        apply=apply,
    )
    if apply and result.obj is not None:
        current_primary = getattr(iface, "primary_mac_address", None)
        if current_primary is None or current_primary.id != result.obj.id:
            # Pass the full record (not just its id): pynetbox serializes a
            # nested Record to its id automatically on write, and passing
            # the object means `iface.primary_mac_address` is immediately
            # the correct, fully-populated value in memory too, with no
            # separate re-fetch required.
            iface.update({"primary_mac_address": result.obj})
            iface.save()
    return result


def get_assignment_modes(device: str, interface: str, client=None) -> dict:
    """The Phase 3B/3B.1 assignment-policy metadata recorded for one
    interface: `ipv4_mode`/`ipv6_mode` (one of ASSIGNMENT_MODES), the
    DHCPv6 identity fields when present, and `dhcpv6_identity_status`.
    Fields simply absent from NetBox (not yet set) come back as None -- a
    caller must not treat that as "static" or "ready" by default; see
    modules/ipam_context.py's reservation view for how this is combined
    with the recorded mode."""
    client = client or build_client()
    iface = _get_one(client.dcim.interfaces, device=device, name=interface)
    if iface is None:
        raise NetboxModelError(f"{device}/{interface}: no such interface in NetBox")
    cf = iface.custom_fields or {}
    return {
        "ipv4_mode": cf.get("ipv4_assignment_mode"),
        "ipv6_mode": cf.get("ipv6_assignment_mode"),
        "dhcpv6_duid": cf.get("dhcpv6_duid") or None,
        "dhcpv6_iaid": cf.get("dhcpv6_iaid") or None,
        "dhcpv6_identity_status": cf.get("dhcpv6_identity_status") or None,
    }


# ---------------------------------------------------------------------------
# Phase 3B.1: distinguishing OBSERVED from AUTHORITATIVE/PLANNED identity.
#
# `sync_interface_macs.py` (Phase 3B) only ever records what is currently,
# transiently true on the running lab -- it never asserts durability. The
# functions below are the ONLY place that marks an identity as the
# deliberate, mechanism-verified, to-be-pinned-at-cutover plan (Step 6/12).
# Nothing here touches a live device; they only annotate NetBox records
# that some earlier sync/observation step already created.
# ---------------------------------------------------------------------------

IDENTITY_OBSERVED = "observed"
IDENTITY_AUTHORITATIVE = "authoritative-planned"
IDENTITY_BLOCKED = "blocked"
IDENTITY_STATUSES = (IDENTITY_OBSERVED, IDENTITY_AUTHORITATIVE, IDENTITY_BLOCKED)


def mark_mac_authoritative(device: str, interface: str, *, description: str, client=None, apply: bool = True) -> ReconcileResult:
    """Promote the MAC address ALREADY recorded (by sync_interface_macs.py)
    for `device`/`interface` from merely "observed" to
    "authoritative-planned": the deliberate, platform-mechanism-verified
    decision that this exact value is what will be pinned at cutover.
    Never introduces a new MAC value -- raises NetboxModelError if no MAC
    is on file yet (observe it first)."""
    client = client or build_client()
    current = get_interface_mac(device, interface, client)
    if current is None:
        raise NetboxModelError(f"{device}/{interface}: no MAC address recorded yet -- run sync_interface_macs.py first")
    iface = _get_one(client.dcim.interfaces, device=device, name=interface)
    mac_obj = _get_one(
        client.dcim.mac_addresses,
        mac_address=current["mac_address"], assigned_object_id=iface.id, assigned_object_type="dcim.interface",
    )
    if current["identity_status"] == IDENTITY_OBSERVED:
        changes = {
            "custom_fields": {
                **(getattr(mac_obj, "custom_fields", None) or {}),
                "identity_status": IDENTITY_AUTHORITATIVE,
            },
            "description": description,
        }
        if not apply:
            return ReconcileResult(CHECK_UPDATE, mac_obj, changes=changes)
        _wrap_pynetbox_errors("promote observed MAC identity", lambda: (mac_obj.update(changes), mac_obj.save()))
        return ReconcileResult(UPDATE, mac_obj, changes=changes)
    return reconcile_object(
        client.dcim.mac_addresses,
        lookup={"id": mac_obj.id},
        desired={"custom_fields": {"identity_status": IDENTITY_AUTHORITATIVE}, "description": description},
        safe_update_fields=frozenset({"description"}),
        apply=apply,
    )




def set_dhcpv6_identity(
    device: str, interface: str, *, status: str, duid: str | None = None, iaid: str | None = None,
    description: str | None = None, client=None, apply: bool = True,
) -> ReconcileResult:
    """Record the DHCPv6 identity decision for one interface: either
    `status=IDENTITY_AUTHORITATIVE` with a computed, deterministic
    `duid` (and, non-bindingly, a predicted `iaid` -- see
    docs/NETBOX_IPAM.md for why ISC dhcpd's fixed-address6 matching does
    not require IAID at all), or `status=IDENTITY_BLOCKED` (with `duid`/
    `iaid` left None) when no viable platform mechanism was found. Never
    call this with a fabricated DUID -- `duid` must be mathematically
    DERIVED from an already-authoritative MAC (DUID-LL) or otherwise
    genuinely established, never guessed. `description`, when given,
    records the mechanism/rationale on the interface itself.
    """
    if status not in IDENTITY_STATUSES:
        raise NetboxConfigurationError(f"status must be one of {IDENTITY_STATUSES}, got {status!r}")
    if status == IDENTITY_AUTHORITATIVE and not duid:
        raise NetboxConfigurationError("status=authoritative-planned requires a computed duid")
    if status == IDENTITY_BLOCKED and (duid or iaid):
        raise NetboxConfigurationError("status=blocked must not carry a DUID or IAID")
    client = client or build_client()
    iface = _get_one(client.dcim.interfaces, device=device, name=interface)
    if iface is None:
        raise NetboxModelError(f"{device}/{interface}: no such interface in NetBox")
    custom_fields = {"dhcpv6_identity_status": status}
    if duid:
        custom_fields["dhcpv6_duid"] = duid
    if iaid:
        custom_fields["dhcpv6_iaid"] = iaid
    desired = {"custom_fields": custom_fields}
    safe_fields = frozenset()
    if description is not None:
        desired["description"] = description
        safe_fields = frozenset({"description"})
    return reconcile_object(
        client.dcim.interfaces,
        lookup={"id": iface.id},
        desired=desired,
        safe_update_fields=safe_fields,
        apply=apply,
    )


# ---------------------------------------------------------------------------
# Phase 3B.3: management-VLAN policy correction.
#
# The user's architecture decision established that Vlan200 (the dedicated
# management VLAN on all 9 managed devices) stays STATICALLY addressed --
# superseding Phase 3B/3B.1's assumption that it would eventually become a
# DHCP/DHCPv6-reserved dynamic target (see docs/NETBOX_IPAM.md "Phase
# 3B.3"). `netbox/scripts/populate_netbox.py` no longer classifies any
# interface as dhcp-reserved/dhcpv6-reserved by name (see its
# `_assignment_mode()`), but NetBox may still hold DHCP-identity-planning
# metadata a PREVIOUS run wrote before that correction (a MAC's
# `identity_status=authoritative-planned`, or an interface's
# `dhcpv6_duid`/`dhcpv6_iaid`/`dhcpv6_identity_status`). The two functions
# below clear exactly that stale metadata, driven by the interface's CURRENT
# assignment-mode policy (never a hard-coded interface name) -- so they stay
# correct if some other interface is ever deliberately made dynamic later,
# and are a safe no-op for anything that never had this metadata at all.
# ---------------------------------------------------------------------------


# Substring marker left in a MAC's `description` by mark_mac_authoritative()
# (via pin_stable_identities.py's CEOS_MAC_MECHANISM/LINUX_MAC_MECHANISM)
# when Vlan200 was still classified dhcp-reserved (Phase 3B/3B.1). Used only
# to detect that specific stale text below -- never to fabricate one.
_STALE_MAC_DESCRIPTION_MARKER = "Not yet applied"


def clear_stale_mac_identity_status(device: str, interface: str, client=None, apply: bool = True) -> ReconcileResult | None:
    """If `interface`'s CURRENT ipv4 assignment-mode policy is not
    `dhcp-reserved`, any earlier `identity_status` recorded on its MAC is a
    stale claim about a DHCPv4-reservation cutover that is no longer
    planned -- clear it back to unset. A MAC promoted by
    `mark_mac_authoritative()` before that correction also carries a
    `description` naming the (now-abandoned) pinning mechanism (e.g. "Pin
    via EOS 'interface Vlan200/mac-address ...' ... Not yet applied"); that
    text is replaced with a neutral inventory note in the same pass, driven
    only by detecting the known stale marker -- never overwriting a
    description this repository did not itself write. Never touches a
    genuinely still-dynamic interface's decision, never invents a value, and
    never removes the MAC address itself (it remains legitimate inventory
    data). Returns None (no-op) when there is nothing to clear."""
    modes = get_assignment_modes(device, interface, client)
    if modes["ipv4_mode"] == "dhcp-reserved":
        return None  # still a legitimate dynamic target -- not stale
    current = get_interface_mac(device, interface, client)
    if current is None:
        return None  # nothing recorded, nothing to clear
    stale_description = bool(current["description"]) and _STALE_MAC_DESCRIPTION_MARKER in current["description"]
    if not current["identity_status"] and not stale_description:
        return None  # nothing recorded, nothing to clear
    client = client or build_client()
    iface = _get_one(client.dcim.interfaces, device=device, name=interface)
    mac_obj = _get_one(
        client.dcim.mac_addresses,
        mac_address=current["mac_address"], assigned_object_id=iface.id, assigned_object_type="dcim.interface",
    )
    desired: dict = {"custom_fields": {"identity_status": ""}}
    safe_fields = frozenset()
    if stale_description:
        desired["description"] = f"Observed {interface} interface/system MAC retained for inventory."
        safe_fields = frozenset({"description"})
    return reconcile_object(
        client.dcim.mac_addresses,
        lookup={"id": mac_obj.id},
        desired=desired,
        safe_update_fields=safe_fields,
        safe_update_custom_fields=frozenset({"identity_status"}),
        apply=apply,
    )


def clear_stale_dhcpv6_identity(device: str, interface: str, client=None, apply: bool = True) -> ReconcileResult | None:
    """If `interface`'s CURRENT ipv6 assignment-mode policy is not
    `dhcpv6-reserved`, any earlier `dhcpv6_duid`/`dhcpv6_iaid`/
    `dhcpv6_identity_status` is stale DHCPv6-reservation planning metadata
    that is no longer relevant (e.g. a static management SVI) -- clear all
    three back to unset. Returns None (no-op) when the interface is still a
    genuine dhcpv6-reserved target, or when nothing is recorded to clear."""
    modes = get_assignment_modes(device, interface, client)
    if modes["ipv6_mode"] == "dhcpv6-reserved":
        return None  # still a legitimate dynamic target -- not stale
    if not (modes["dhcpv6_duid"] or modes["dhcpv6_iaid"] or modes["dhcpv6_identity_status"]):
        return None  # nothing recorded, nothing to clear
    client = client or build_client()
    iface = _get_one(client.dcim.interfaces, device=device, name=interface)
    if iface is None:
        raise NetboxModelError(f"{device}/{interface}: no such interface in NetBox")
    return reconcile_object(
        client.dcim.interfaces,
        lookup={"id": iface.id},
        desired={"custom_fields": {"dhcpv6_duid": "", "dhcpv6_iaid": "", "dhcpv6_identity_status": ""}},
        safe_update_custom_fields=frozenset({"dhcpv6_duid", "dhcpv6_iaid", "dhcpv6_identity_status"}),
        apply=apply,
    )


if __name__ == "__main__":
    raise SystemExit(_cli())
