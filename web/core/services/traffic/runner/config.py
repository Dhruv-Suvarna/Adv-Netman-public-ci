"""The runner's root-owned configuration: what the endpoint IDS mean on THIS host.

Rendered by the installer from the tracked inventory and installed as ``/etc/nmas/traffic-runner.json`` (root:root, not writable by
anyone else).  The website can read it but cannot change it, so an endpoint id can only ever resolve to the container the operator who
installed the runner intended.  It holds no secret.

    {"instance": "nmas", "lab": "srlceos01", "tools_image": "sha256:<64 hex>", "allowed_peer_uids": [1001],
     "endpoints": {"H1": {"container": "clab-srlceos01-H1", "families": ["IPV4", "IPV6"]}, ...}}
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass

from .policy import ADDRESS_FAMILIES

_NAME = re.compile(r"^[A-Za-z0-9_]{1,32}$")
_INSTANCE = re.compile(r"^[a-z0-9]{1,16}$")
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")           # an image ID: immutable content, never a tag that can be re-pointed


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Endpoint:
    name: str
    container: str
    families: tuple


@dataclass(frozen=True)
class Config:
    instance: str
    lab: str
    tools_image: str
    allowed_peer_uids: frozenset
    endpoints: dict


def parse(document) -> Config:
    if not isinstance(document, dict) or set(document) != {"instance", "lab", "tools_image", "allowed_peer_uids", "endpoints"}:
        raise ConfigError("configuration keys")
    instance, lab, image = document["instance"], document["lab"], document["tools_image"]
    if not isinstance(instance, str) or not _INSTANCE.fullmatch(instance):
        raise ConfigError("instance")
    if not isinstance(lab, str) or not _NAME.fullmatch(lab):
        raise ConfigError("lab")
    if not isinstance(image, str) or not _IMAGE.fullmatch(image):
        raise ConfigError("tools_image must be an image ID (sha256:...)")
    uids = document["allowed_peer_uids"]
    if not isinstance(uids, list) or not uids or any(type(u) is not int or u < 0 for u in uids):
        raise ConfigError("allowed_peer_uids")
    raw = document["endpoints"]
    if not isinstance(raw, dict) or not raw:
        raise ConfigError("endpoints")
    endpoints = {}
    for name, entry in raw.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name) or not isinstance(entry, dict) or set(entry) != {"container", "families"}:
            raise ConfigError(f"endpoint {name!r}")
        families = entry["families"]
        if entry["container"] != f"clab-{lab}-{name}":     # an endpoint is a node of the lab: never an arbitrary container
            raise ConfigError(f"endpoint {name!r} container")
        if not isinstance(families, list) or not families or any(f not in ADDRESS_FAMILIES for f in families):
            raise ConfigError(f"endpoint {name!r} families")
        endpoints[name] = Endpoint(name, entry["container"], tuple(families))
    return Config(instance, lab, image, frozenset(uids), endpoints)


def load(path: str) -> Config:
    """Read the configuration, refusing a file that anyone but root (or the runner's own account) could have written."""
    try:
        info = os.stat(path)
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ConfigError("configuration unreadable") from exc
    if info.st_uid not in (0, os.geteuid()) or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError("configuration must be owned by root and not group/world writable")
    return parse(document)
