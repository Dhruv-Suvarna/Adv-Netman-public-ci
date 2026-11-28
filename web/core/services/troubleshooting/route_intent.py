"""Strict, versioned per-prefix expectations for routing acceptance.

This module never learns intent from an observed RIB.  It validates a reviewed
source file, then compares independently collected RIBs with the declared
prefix, source protocol, and acceptable next hops.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import routing

SCHEMA = "nmas.troubleshooting.route-intent/1"
_REVISION = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DEVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SOURCES = frozenset({
    "bgp", "connected", "isis", "ospf", "ospf3", "ospf_external",
    "ospf3_external", "ra", "rip", "static",
})


class IntentError(ValueError):
    """The reviewed intent source is malformed or ambiguous."""


@dataclass(frozen=True)
class PrefixExpectation:
    target_id: str
    direction: str
    target_prefix: str
    device: str
    af: str
    route_prefix: str
    source: str
    next_hops: tuple[str, ...]

    def rib_entry(self) -> routing.RibEntry:
        return routing.RibEntry(
            prefix=self.route_prefix,
            source=self.source,
            raw_type=self.source,
            next_hops=tuple((address, "") for address in self.next_hops),
            af=self.af,
        )


@dataclass(frozen=True)
class RouteIntent:
    revision: str
    topology_revision: str
    provenance: tuple[str, ...]
    expectations: tuple[PrefixExpectation, ...]


def _exact(obj: dict, required: set[str], where: str) -> None:
    if not isinstance(obj, dict) or set(obj) != required:
        raise IntentError(f"{where} keys must be exactly {sorted(required)}")


def load(path: str | Path) -> RouteIntent:
    """Load a strict reviewed JSON source; unknown fields fail closed."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntentError("route intent is unreadable") from exc
    _exact(data, {"schema", "revision", "topology_revision", "provenance", "targets"}, "root")
    if data["schema"] != SCHEMA:
        raise IntentError("unsupported route-intent schema")
    if not isinstance(data["revision"], str) or not _REVISION.fullmatch(data["revision"]):
        raise IntentError("invalid intent revision")
    if not isinstance(data["topology_revision"], str) or not _SHA1.fullmatch(data["topology_revision"]):
        raise IntentError("invalid topology revision")
    if not isinstance(data["provenance"], list) or not data["provenance"] or not all(
        isinstance(value, str) and value for value in data["provenance"]
    ):
        raise IntentError("provenance must be a non-empty string list")
    if not isinstance(data["targets"], list) or not data["targets"]:
        raise IntentError("targets must be a non-empty list")

    expectations: list[PrefixExpectation] = []
    target_ids: set[str] = set()
    identities: set[tuple[str, str, str]] = set()
    for index, target in enumerate(data["targets"]):
        where = f"targets[{index}]"
        _exact(target, {"id", "direction", "target_prefix", "expectations"}, where)
        target_id, direction = target["id"], target["direction"]
        if not isinstance(target_id, str) or not _REVISION.fullmatch(target_id) or target_id in target_ids:
            raise IntentError(f"{where} has an invalid or duplicate id")
        target_ids.add(target_id)
        if direction not in ("forward", "return"):
            raise IntentError(f"{where} direction must be forward or return")
        try:
            target_prefix = str(ipaddress.ip_network(target["target_prefix"], strict=False))
        except (TypeError, ValueError) as exc:
            raise IntentError(f"{where} target_prefix is invalid") from exc
        if not isinstance(target["expectations"], list) or not target["expectations"]:
            raise IntentError(f"{where} expectations must be non-empty")
        for offset, item in enumerate(target["expectations"]):
            item_where = f"{where}.expectations[{offset}]"
            _exact(item, {"device", "af", "route_prefix", "source", "next_hops"}, item_where)
            device, af, source = item["device"], item["af"], item["source"]
            if not isinstance(device, str) or not _DEVICE.fullmatch(device):
                raise IntentError(f"{item_where} device is invalid")
            if af not in ("ipv4", "ipv6") or source not in _SOURCES:
                raise IntentError(f"{item_where} has an unsupported AF or source")
            try:
                target_net = ipaddress.ip_network(target_prefix)
                route_net = ipaddress.ip_network(item["route_prefix"], strict=False)
            except (TypeError, ValueError) as exc:
                raise IntentError(f"{item_where} route_prefix is invalid") from exc
            version = 4 if af == "ipv4" else 6
            if target_net.version != version or route_net.version != version or not target_net.subnet_of(route_net):
                raise IntentError(f"{item_where} route does not cover its target in the declared AF")
            if not isinstance(item["next_hops"], list) or not all(isinstance(v, str) for v in item["next_hops"]):
                raise IntentError(f"{item_where} next_hops must be a string list")
            try:
                next_hops = tuple(sorted({str(ipaddress.ip_address(v)) for v in item["next_hops"]}))
            except ValueError as exc:
                raise IntentError(f"{item_where} next_hop is invalid") from exc
            if any(ipaddress.ip_address(v).version != version for v in next_hops):
                raise IntentError(f"{item_where} next_hop family mismatch")
            identity = (target_id, device, str(route_net))
            if identity in identities:
                raise IntentError(f"{item_where} duplicates an expectation")
            identities.add(identity)
            expectations.append(PrefixExpectation(
                target_id, direction, target_prefix, device, af, str(route_net), source, next_hops,
            ))
    return RouteIntent(data["revision"], data["topology_revision"], tuple(data["provenance"]), tuple(expectations))


def evaluate(intent: RouteIntent, ribs: dict[str, dict[str, dict[str, routing.RibEntry] | None]], *, now: datetime):
    """Evaluate every expectation. ``ribs`` is keyed by AF, then device."""
    results = []
    source = f"VERSIONED_INTENT {intent.revision} topology={intent.topology_revision}"
    for expectation in intent.expectations:
        observed = (ribs.get(expectation.af) or {}).get(expectation.device)
        result = routing.classify_route_change(
            expectation.device,
            expectation.route_prefix,
            expectation.rib_entry(),
            observed,
            now=now,
            expectation_source=source,
        )
        result.scope.update({"target_id": expectation.target_id, "direction": expectation.direction,
                             "target_prefix": expectation.target_prefix})
        result.evidence.update({"intent_revision": intent.revision, "topology_revision": intent.topology_revision,
                                "route_prefix": expectation.route_prefix})
        results.append(result)
    return results
