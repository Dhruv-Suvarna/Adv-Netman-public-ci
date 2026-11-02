"""Validating loaders for the two deployed monitoring inputs: ``monitoring/config/snmp_oids.yml`` and
``monitoring/config/gnmi_paths.yml``.

Both files drive live polling / streaming (`modules/snmp.py`, `modules/gnmi.py` and, as JSON, the gNMI collector on the
host).  A typo used to surface only as a KeyError or a silently wrong OID in the middle of a poll; these loaders refuse a
bad file at import time with an NmasError that names the key at fault:

  snmp_oids.yml   every OID the collectors reference is present and a numeric dotted OID; ``cpu`` maps each monitored
                  platform (ceos, linux) and nothing else; no two scalar names share one OID; no duplicate YAML key.
  gnmi_paths.yml  ``sample_interval_ns`` is an integer between 1 s and 1 h; ``streams`` is a non-empty list whose entries
                  carry an absolute path, a known ``kind``, an InfluxDB-safe measurement and field name(s); no path and no
                  field is declared twice; no duplicate YAML key.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from modules.nmas import MONITORING, NmasError

SNMP_OIDS_FILE = MONITORING / "config/snmp_oids.yml"
GNMI_PATHS_FILE = MONITORING / "config/gnmi_paths.yml"

SNMP_REQUIRED = ("sysName", "sysUpTime", "ifIndex", "ifDescr", "ifName", "ifAdminStatus", "ifOperStatus", "engineID",
                 "linkDown", "linkUp", "coldStart", "snmpTrapOID", "ceosTestNotification")
MONITORED_PLATFORMS = ("ceos", "linux")
GNMI_KINDS = ("string", "int")
GNMI_INTERVAL_NS = (1_000_000_000, 3_600_000_000_000)
_OID = re.compile(r"[0-2](?:\.(?:0|[1-9][0-9]*))+")
_IDENT = re.compile(r"[a-z][a-z0-9_]*")


class _UniqueKeyLoader(yaml.SafeLoader):
    """safe_load that refuses a mapping with the same key twice (PyYAML silently keeps the last one)."""


def _unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    seen = set()
    for key_node, _value in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise NmasError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _read(path: Path, label: str) -> dict:
    try:
        document = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)  # nosec B506 - SafeLoader subclass
    except FileNotFoundError:
        raise NmasError(f"{label}: file not found ({path})") from None
    except NmasError as exc:
        raise NmasError(f"{label}: {exc}") from None
    except yaml.YAMLError as exc:
        raise NmasError(f"{label}: malformed YAML ({exc.__class__.__name__})") from None
    if not isinstance(document, dict):
        raise NmasError(f"{label}: the document must be a mapping")
    return document


def _oid(value, where: str, label: str) -> str:
    if not isinstance(value, str) or not _OID.fullmatch(value):
        raise NmasError(f"{label}: {where} must be a numeric dotted OID string, got {type(value).__name__}")
    return value


def validate_snmp_oids(document: dict, label: str = "snmp_oids.yml") -> dict:
    missing = [key for key in SNMP_REQUIRED if key not in document]
    if missing or "cpu" not in document:
        raise NmasError(f"{label}: missing required OID(s): {', '.join(missing + ([] if 'cpu' in document else ['cpu']))}")
    scalars = {}
    for key, value in document.items():
        if not isinstance(key, str):
            raise NmasError(f"{label}: OID names must be strings, got {type(key).__name__}")
        if key == "cpu":
            continue
        oid = _oid(value, key, label)
        if oid in scalars:
            raise NmasError(f"{label}: {key} and {scalars[oid]} declare the same OID {oid}")
        scalars[oid] = key
    cpu = document["cpu"]
    if not isinstance(cpu, dict) or sorted(cpu) != sorted(MONITORED_PLATFORMS):
        raise NmasError(f"{label}: cpu must map exactly the monitored platforms {', '.join(MONITORED_PLATFORMS)}")
    for platform, value in cpu.items():
        _oid(value, f"cpu.{platform}", label)
    return document


def _names(value, where: str, label: str) -> list[str]:
    names = value if isinstance(value, list) else [value]
    if not names or not all(isinstance(name, str) and _IDENT.fullmatch(name) for name in names):
        raise NmasError(f"{label}: {where} must be a lower-case identifier or a non-empty list of them")
    return names


def validate_gnmi_paths(document: dict, label: str = "gnmi_paths.yml") -> dict:
    interval = document.get("sample_interval_ns")
    if isinstance(interval, bool) or not isinstance(interval, int) or not GNMI_INTERVAL_NS[0] <= interval <= GNMI_INTERVAL_NS[1]:
        raise NmasError(f"{label}: sample_interval_ns must be an integer between {GNMI_INTERVAL_NS[0]} and {GNMI_INTERVAL_NS[1]}")
    streams = document.get("streams")
    if not isinstance(streams, list) or not streams:
        raise NmasError(f"{label}: streams must be a non-empty list")
    paths, fields = set(), set()
    for index, stream in enumerate(streams):
        where = f"streams[{index}]"
        if not isinstance(stream, dict):
            raise NmasError(f"{label}: {where} must be a mapping")
        path = stream.get("path")
        if not isinstance(path, str) or not path.startswith("/") or any(ch.isspace() for ch in path):
            raise NmasError(f"{label}: {where}.path must be an absolute gNMI path without whitespace")
        if path in paths:
            raise NmasError(f"{label}: {where}.path {path} is declared twice")
        paths.add(path)
        if stream.get("kind") not in GNMI_KINDS:
            raise NmasError(f"{label}: {where}.kind must be one of {', '.join(GNMI_KINDS)}")
        for key in ("category", "measurement"):
            _names(stream.get(key), f"{where}.{key}", label)
            if isinstance(stream.get(key), list):
                raise NmasError(f"{label}: {where}.{key} must be a single identifier")
        for name in _names(stream.get("field"), f"{where}.field", label):
            if name in fields:
                raise NmasError(f"{label}: {where}.field {name} is already produced by another stream")
            fields.add(name)
        if "tags" in stream:
            _names(stream["tags"], f"{where}.tags", label)
        for key in ("model", "description"):
            if not isinstance(stream.get(key), str) or not stream[key].strip():
                raise NmasError(f"{label}: {where}.{key} must be a non-empty string")
    limitations = document.get("limitations", [])
    if not isinstance(limitations, list) or not all(isinstance(item, str) for item in limitations):
        raise NmasError(f"{label}: limitations must be a list of strings")
    return document


def load_snmp_oids(path: Path = SNMP_OIDS_FILE) -> dict:
    """The validated SNMP OID map used by modules/snmp.py."""
    return validate_snmp_oids(_read(path, "snmp_oids.yml"))


def load_gnmi_paths(path: Path = GNMI_PATHS_FILE) -> dict:
    """The validated gNMI stream inventory used by modules/gnmi.py (and shipped to the collector as JSON)."""
    return validate_gnmi_paths(_read(path, "gnmi_paths.yml"))
