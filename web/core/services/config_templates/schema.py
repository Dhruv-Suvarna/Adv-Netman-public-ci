"""The portable template intent: the importer's vendor-neutral records as plain YAML-safe data, plus typed parameters.

``intent`` mirrors ``config_import.schema.ParsedConfig`` field for field (name-keyed, no database ids, no raw CLI):

    device:        {hostname}
    interfaces:    [{name, kind, description, mtu, admin_state, access_vlan, trunk_allowed_vlans, native_vlan, parent_name,
                     encapsulation_vlan, vlan_id, addresses[], dhcp_relays[], fhrp[], acl_attachments[]}]
    static_routes: [{family, destination, next_hop_address, next_hop_interface, distance, tag}]
    routing:       [{family, fields{}, bindings[], neighbors[], networks[]}]
    acls:          [{name, family, acl_type, entries[]}]
    nat_rules:     [{family, mode, original_source, outside_interface}]
    host:          {...}   end-device profile only (never applied to a managed device)

A string value may be exactly ``{{ name }}`` (replaced by the TYPED parameter value) or contain such placeholders
(rendered by a sandboxed Jinja2 environment).  No other Jinja2 syntax is accepted, so a package cannot carry template
logic.  Any object may carry ``_when: <boolean parameter>``: it is part of the intent only when that parameter is true.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from copy import deepcopy

from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

from ..config_import.schema import (
    ParsedAcl,
    ParsedConfig,
    ParsedInterface,
    ParsedNatRule,
    ParsedRoutingInstance,
    ParsedStaticRoute,
)

SCHEMA_VERSION = 1
SUPPORTED_SCHEMA_VERSIONS = frozenset({1})
WHEN = "_when"

TOP_LEVEL_KEYS = ("device", "interfaces", "static_routes", "routing", "acls", "nat_rules", "host")
_RAW_LINE_FIELDS = frozenset({"preserved_lines", "lines"})          # raw CLI never enters a template
_INTERFACE_FIELDS = tuple(f.name for f in dataclasses.fields(ParsedInterface) if f.name not in _RAW_LINE_FIELDS)
_ROUTE_FIELDS = tuple(f.name for f in dataclasses.fields(ParsedStaticRoute) if f.name not in _RAW_LINE_FIELDS)
_INSTANCE_FIELDS = tuple(f.name for f in dataclasses.fields(ParsedRoutingInstance) if f.name not in _RAW_LINE_FIELDS)
_ACL_FIELDS = tuple(f.name for f in dataclasses.fields(ParsedAcl) if f.name not in _RAW_LINE_FIELDS)
_NAT_FIELDS = tuple(f.name for f in dataclasses.fields(ParsedNatRule) if f.name not in _RAW_LINE_FIELDS)
OBJECT_FIELDS = {"interfaces": _INTERFACE_FIELDS, "static_routes": _ROUTE_FIELDS, "routing": _INSTANCE_FIELDS,
                 "acls": _ACL_FIELDS, "nat_rules": _NAT_FIELDS}

MAX_NODES = 20000
MAX_STRING = 300
MAX_DEPTH = 8

PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-z][a-z0-9_]{0,63})\s*\}\}")
_FULL_PLACEHOLDER_RE = re.compile(r"^\{\{\s*([a-z][a-z0-9_]{0,63})\s*\}\}$")
_PARAM_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_JINJA_SYNTAX_RE = re.compile(r"\{\{|\}\}|\{%|%\}|\{#|#\}")
_JINJA = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False)


class TemplateSchemaError(ValueError):
    """Structural problems of a template (operator-facing messages; never contains a secret value)."""

    def __init__(self, problems):
        self.problems = [str(p) for p in problems]
        super().__init__("; ".join(self.problems))


# --- ParsedConfig <-> intent -------------------------------------------------------------------------------------------
def _prune(value):
    """Drop empty optional values so the YAML shows intent, not the dataclass defaults."""
    if isinstance(value, dict):
        return {k: _prune(v) for k, v in value.items() if v not in (None, "", [], {}) and k not in _RAW_LINE_FIELDS}
    if isinstance(value, list):
        return [_prune(v) for v in value]
    return value


def from_parsed(parsed: ParsedConfig) -> tuple[dict, list[dict]]:
    """-> (intent, exclusions).  Raw CLI the importer could not model is recorded BY LABEL ONLY -- its text never enters a template."""
    intent = {
        "device": {"hostname": parsed.hostname},
        "interfaces": [_prune({k: v for k, v in dataclasses.asdict(i).items() if k in _INTERFACE_FIELDS}) for i in parsed.interfaces],
        "static_routes": [_prune({k: v for k, v in dataclasses.asdict(r).items() if k in _ROUTE_FIELDS}) for r in parsed.static_routes],
        "routing": [_prune({k: v for k, v in dataclasses.asdict(r).items() if k in _INSTANCE_FIELDS}) for r in parsed.routing_instances],
        "acls": [_prune({k: v for k, v in dataclasses.asdict(a).items() if k in _ACL_FIELDS}) for a in parsed.acls],
        "nat_rules": [_prune({k: v for k, v in dataclasses.asdict(n).items() if k in _NAT_FIELDS}) for n in parsed.nat_rules],
    }
    for interface in intent["interfaces"]:
        interface.pop("ospf_bindings", None)      # duplicated on the routing instance's own bindings, which is what is applied
    counted: dict[tuple, int] = {}
    for block in parsed.unmanaged_blocks:
        key = (block.label[:120], block.classification)
        counted[key] = counted.get(key, 0) + len(block.lines)
    for owner, items in (("interface", parsed.interfaces), ("routing", parsed.routing_instances), ("acl", parsed.acls)):
        for item in items:
            if item.preserved_lines:
                label = f"Additional {owner} configuration ({getattr(item, 'name', '') or getattr(item, 'family', '')})"
                counted[(label, "RECOGNIZED_UNSUPPORTED")] = counted.get((label, "RECOGNIZED_UNSUPPORTED"), 0) + len(item.preserved_lines)
    exclusions = [{"category": "UNMODELLED_CONFIGURATION", "label": label, "classification": classification, "lines": lines,
                   "reason": "Not representable as semantic intent; the raw text is deliberately not carried by the template."}
                  for (label, classification), lines in sorted(counted.items())]
    return {k: v for k, v in intent.items() if v not in ([], {})}, exclusions


def to_parsed(intent: dict) -> ParsedConfig:
    """A RESOLVED intent (no placeholders left) back into the importer records the Device Builder apply pipeline consumes."""
    def build(cls, row, fields):
        return cls(**{k: deepcopy(v) for k, v in row.items() if k in fields})

    return ParsedConfig(
        hostname=str((intent.get("device") or {}).get("hostname") or ""),
        interfaces=[build(ParsedInterface, r, _INTERFACE_FIELDS) for r in intent.get("interfaces") or []],
        static_routes=[build(ParsedStaticRoute, r, _ROUTE_FIELDS) for r in intent.get("static_routes") or []],
        routing_instances=[build(ParsedRoutingInstance, {"fields": {}, **r}, _INSTANCE_FIELDS) for r in intent.get("routing") or []],
        acls=[build(ParsedAcl, r, _ACL_FIELDS) for r in intent.get("acls") or []],
        nat_rules=[build(ParsedNatRule, r, _NAT_FIELDS) for r in intent.get("nat_rules") or []],
        parser_version="nmas-template-1",
    )


# --- parameters --------------------------------------------------------------------------------------------------------
def _ip(kind, version=None):
    def check(value):
        parsed = kind(str(value))
        if version and parsed.version != version:
            raise ValueError(f"an IPv{version} value is required")
        return str(parsed)
    return check


def _integer(low, high):
    def check(value):
        if isinstance(value, bool) or not re.fullmatch(r"-?\d+", str(value).strip()):
            raise ValueError("an integer is required")
        number = int(value)
        if not low <= number <= high:
            raise ValueError(f"must be between {low} and {high}")
        return number
    return check


def _pattern(regex, message):
    def check(value):
        if not isinstance(value, str) or not re.fullmatch(regex, value):
            raise ValueError(message)
        return value
    return check


def _boolean(value):
    if isinstance(value, bool):
        return value
    if str(value).strip().lower() in ("true", "yes", "on", "1"):
        return True
    if str(value).strip().lower() in ("false", "no", "off", "0", ""):
        return False
    raise ValueError("true or false is required")


def _vlan_list(value):
    items = value if isinstance(value, (list, tuple)) else [v for v in re.split(r"[,\s]+", str(value).strip()) if v]
    return sorted({_integer(1, 4094)(item) for item in items})


def _text(value):
    if not isinstance(value, str) or len(value) > 200 or re.search(r"[\x00-\x1f\x7f]", value) or _JINJA_SYNTAX_RE.search(value):
        raise ValueError("plain text up to 200 characters is required")
    return value


PARAMETER_TYPES = {
    "hostname": _pattern(r"[A-Za-z0-9_-]{1,64}", "1-64 letters, digits, underscore or hyphen"),
    "interface_name": _pattern(r"[A-Za-z][A-Za-z0-9_./:-]{0,63}", "an interface name is required"),
    "ipv4_interface": _ip(ipaddress.ip_interface, 4), "ipv6_interface": _ip(ipaddress.ip_interface, 6),
    "ip_interface": _ip(ipaddress.ip_interface),
    "ipv4_address": _ip(ipaddress.ip_address, 4), "ipv6_address": _ip(ipaddress.ip_address, 6), "ip_address": _ip(ipaddress.ip_address),
    "ip_prefix": _ip(lambda v: ipaddress.ip_network(v, strict=True)),
    "vlan_id": _integer(1, 4094), "vlan_list": _vlan_list, "asn": _integer(1, 4294967295),
    "integer": _integer(-2147483648, 4294967295), "boolean": _boolean, "string": _text,
}


def infer_type(key: str, value) -> str:
    """The parameter type for a leaf that is being parameterized (by field name first, then by the observed value)."""
    if isinstance(value, bool):
        return "boolean"
    if key == "trunk_allowed_vlans":
        return "vlan_list"
    if key in ("access_vlan", "native_vlan", "vlan_id", "encapsulation_vlan"):
        return "vlan_id"
    if key.endswith("_asn"):
        return "asn"
    if isinstance(value, int):
        return "integer"
    text = str(value)
    if key == "hostname":
        return "hostname"
    if key in ("interface_name", "parent_name", "next_hop_interface", "outside_interface", "update_source_interface"):
        return "interface_name"
    for name, parser in (("ip_address", ipaddress.ip_address), ("ip_interface", ipaddress.ip_interface)):
        try:
            parsed = parser(text)
        except ValueError:
            continue
        if name == "ip_interface" and key in ("destination", "original_source", "prefix"):
            return "ip_prefix" if parsed.network.network_address == parsed.ip else "ip_interface"
        return name.replace("ip_", f"ipv{parsed.version}_")
    return "string"


def validate_parameter_definitions(parameters) -> list[str]:
    problems = []
    if not isinstance(parameters, dict):
        return ["parameters must be a mapping."]
    for name, spec in parameters.items():
        if not isinstance(name, str) or not _PARAM_NAME_RE.fullmatch(name):
            problems.append(f"Parameter name {str(name)[:40]!r} is not a valid identifier.")
            continue
        if not isinstance(spec, dict) or spec.get("type") not in PARAMETER_TYPES:
            problems.append(f"Parameter {name}: unknown or missing type.")
            continue
        unknown = set(spec) - {"type", "description", "required", "default"}
        if unknown:
            problems.append(f"Parameter {name}: unknown attribute(s) {sorted(unknown)}.")
        if spec.get("default") is not None:
            try:
                PARAMETER_TYPES[spec["type"]](spec["default"])
            except ValueError as exc:
                problems.append(f"Parameter {name}: default is invalid ({exc}).")
    return problems


def resolve_parameters(parameters: dict, supplied: dict | None, *, needed=None) -> tuple[dict, list[str]]:
    """-> (typed values, problems).  ``needed`` limits the REQUIRED check to placeholders the resolved intent actually uses."""
    supplied = supplied or {}
    values, problems = {}, []
    for name in sorted(set(supplied) - set(parameters)):
        problems.append(f"Unknown parameter {str(name)[:40]!r}.")
    for name, spec in parameters.items():
        raw = supplied.get(name)
        if raw is None or (isinstance(raw, str) and raw.strip() == "" and spec["type"] not in ("string", "boolean")):
            raw = spec.get("default")
        if raw is None:
            if spec["type"] == "boolean":
                values[name] = False
            elif needed is None or name in needed:
                problems.append(f"Parameter {name} is required.")
            continue
        try:
            values[name] = PARAMETER_TYPES[spec["type"]](raw.strip() if isinstance(raw, str) and spec["type"] != "string" else raw)
        except ValueError as exc:
            problems.append(f"Parameter {name}: {exc}.")
    return values, problems


# --- placeholders ------------------------------------------------------------------------------------------------------
def _walk_strings(value, path=""):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_strings(child, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_strings(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def placeholders(value) -> set[str]:
    return {name for _path, text in _walk_strings(value) for name in PLACEHOLDER_RE.findall(text)}


def when_flags(value) -> set[str]:
    found = set()
    if isinstance(value, dict):
        if isinstance(value.get(WHEN), str):
            found.add(value[WHEN])
        for child in value.values():
            found |= when_flags(child)
    elif isinstance(value, list):
        for child in value:
            found |= when_flags(child)
    return found


def _prune_disabled(value, flags: dict):
    if isinstance(value, dict):
        return {k: _prune_disabled(v, flags) for k, v in value.items() if k != WHEN}
    if isinstance(value, list):
        return [_prune_disabled(v, flags) for v in value if not (isinstance(v, dict) and WHEN in v and not flags.get(v[WHEN]))]
    return value


def _substitute(value, values: dict):
    if isinstance(value, dict):
        return {k: _substitute(v, values) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, values) for v in value]
    if isinstance(value, str) and "{{" in value:
        full = _FULL_PLACEHOLDER_RE.match(value)
        if full:
            return deepcopy(values[full.group(1)])
        return _JINJA.from_string(value).render(**values)
    return value


def resolve(intent: dict, parameters: dict, supplied: dict | None) -> tuple[dict, dict, list[str]]:
    """Validate the supplied parameter values and produce the concrete intent.  -> (intent, values, problems)."""
    flags, problems = resolve_parameters({k: v for k, v in parameters.items() if v.get("type") == "boolean"},
                                         {k: v for k, v in (supplied or {}).items() if (parameters.get(k) or {}).get("type") == "boolean"})
    enabled = _prune_disabled(intent, flags)
    values, more = resolve_parameters(parameters, supplied, needed=placeholders(enabled))
    problems = sorted(set(problems + more))
    if problems:
        return {}, values, problems
    return _substitute(enabled, values), values, []


# --- structure ---------------------------------------------------------------------------------------------------------
def validate_intent(intent, parameters) -> list[str]:
    """Structural / placeholder integrity of a template intent.  Pure; no database, no device."""
    problems: list[str] = []
    if not isinstance(intent, dict):
        return ["intent must be a mapping."]
    for key in intent:
        if key not in TOP_LEVEL_KEYS:
            problems.append(f"Unknown intent section {str(key)[:40]!r}.")
    if not isinstance(intent.get("device") or {}, dict) or not (intent.get("device") or {}).get("hostname"):
        problems.append("intent.device.hostname is required.")
    nodes = 0

    def check(value, path, depth):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise TemplateSchemaError(["The intent is too large or too deeply nested."])
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key):
                    problems.append(f"{path}: invalid key.")
                    continue
                check(child, f"{path}.{key}", depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                check(child, f"{path}[{index}]", depth + 1)
        elif isinstance(value, str):
            if len(value) > MAX_STRING or re.search(r"[\x00-\x08\x0a-\x1f\x7f]", value):
                problems.append(f"{path}: text is too long or contains control characters.")
            elif _JINJA_SYNTAX_RE.search(PLACEHOLDER_RE.sub("", value)):
                problems.append(f"{path}: only '{{{{ parameter }}}}' placeholders are allowed (no other template syntax).")
        elif value is not None and not isinstance(value, (bool, int)):
            problems.append(f"{path}: unsupported value type {type(value).__name__}.")

    try:
        check(intent, "intent", 0)
    except TemplateSchemaError as exc:
        return exc.problems
    for section, fields in OBJECT_FIELDS.items():
        rows = intent.get(section, [])
        if not isinstance(rows, list):
            problems.append(f"intent.{section} must be a list.")
            continue
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                problems.append(f"intent.{section}[{index}] must be a mapping.")
                continue
            unknown = set(row) - set(fields) - {WHEN}
            if unknown:
                problems.append(f"intent.{section}[{index}]: unknown field(s) {sorted(unknown)}.")
    names = [row.get("name") for row in intent.get("interfaces", []) if isinstance(row, dict)] if isinstance(intent.get("interfaces", []), list) else []
    if any(not n or not isinstance(n, str) for n in names):
        problems.append("Every interface needs a name.")
    duplicates = sorted({n for n in names if isinstance(n, str) and names.count(n) > 1})
    if duplicates:
        problems.append(f"Duplicate interface name(s): {', '.join(duplicates)}.")
    problems.extend(validate_parameter_definitions(parameters))
    if isinstance(parameters, dict):
        for name in sorted(placeholders(intent) - set(parameters)):
            problems.append(f"Placeholder {{{{ {name} }}}} has no parameter definition.")
        for name in sorted(when_flags(intent)):
            if (parameters.get(name) or {}).get("type") != "boolean":
                problems.append(f"_when flag {name!r} must be a boolean parameter.")
    return problems
