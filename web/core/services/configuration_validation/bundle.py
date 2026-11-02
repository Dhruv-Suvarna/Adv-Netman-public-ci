"""The Configuration Validation bundle: what NMAS sends to GitHub Actions for one immutable Tier-2 validation run.

Compact, deterministic and safe to appear in a workflow log or artifact: the accepted Change snapshot is secret-free by
construction (``validation.snapshot`` redacts secret-shaped keys), every candidate text passes the project's
configuration sanitizer (``bundles.legacy_sanitize``), and ``assert_safe`` refuses a bundle in which a credential format
is still recognisable.  Three hashes bind it: ``snapshot_hash`` (the Tier-2 input hash), ``candidate_hash`` (the
sanitized candidate of every device) and the SHA-256 of the bundle itself, which travels beside it.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json

SCHEMA_VERSION = 1
KIND = "nmas_configuration_validation"
EVENT_TYPE = "nmas_configuration_validation"
# GitHub accepts about 64 KiB for a repository_dispatch payload.  The encoded bundle must fit with room for the envelope.
MAX_ENCODED_BYTES = 56_000
TOO_LARGE = "CONFIG_VALIDATION_BUNDLE_TOO_LARGE"
UNSAFE = "CONFIG_VALIDATION_BUNDLE_NOT_SANITIZED"
REQUIRED = ("schema_version", "kind", "correlation_id", "change", "validation", "snapshot_hash", "candidate_hash", "targets", "devices",
            "removals", "intent", "dependencies", "matrix", "scope")


class BundleError(ValueError):
    """The bundle cannot be sent or cannot be trusted.  ``code`` is stable."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def digest(value) -> str:
    return hashlib.sha256((value if isinstance(value, str) else canonical(value)).encode()).hexdigest()


def candidate_hash(devices, removals) -> str:
    """One hash over the sanitized candidate of every device and the content hash of every removal."""
    return digest({"devices": sorted([d["device"], d["platform"], d["candidate_sha256"]] for d in devices),
                   "removals": sorted([r["device"], r["platform"], r["content_hash"]] for r in removals)})


# The capability-matrix leaf of a routing instance: the family alone does not name it.  A RIP or EIGRP instance is one
# protocol per address family, OSPF one per version (as ``routing_intent_service._routing_protocol_for`` decides).
_LEAF_BY = {"rip": "address_family", "eigrp": "address_family", "ospf": "version"}
_LEAVES = {("rip", "IPV4"): "RIPV2", ("rip", "IPV6"): "RIPNG", ("eigrp", "IPV4"): "EIGRP_IPV4", ("eigrp", "IPV6"): "EIGRP_IPV6",
           ("ospf", "OSPFV2"): "OSPFV2", ("ospf", "OSPFV3"): "OSPFV3"}
_BGP_LEAVES = {"IPV4": "BGP_IPV4", "IPV6": "BGP_IPV6"}


def routing_leaves(family: str, instance: dict) -> set[str]:
    """The matrix features one routing instance requests.  A value this table does not know is returned under a name
    that is in no matrix (``RIP:IPX``), so that the platform-support check fails closed on it instead of skipping it."""
    if family == "isis":
        return {"ISIS"}
    if family == "bgp":             # BGP has no protocol of its own: each neighbour and each network is IPv4 or IPv6 BGP
        rows = [*(instance.get("neighbors") or {}).values(), *(instance.get("networks") or {}).values()]
        return {_BGP_LEAVES.get(str(row.get("family")), f"BGP:{row.get('family')}") for row in rows if isinstance(row, dict)}
    key = instance.get(_LEAF_BY.get(family, ""))
    return {_LEAVES.get((family, key), f"{family.upper()}:{key}")}


def features_of(device: dict) -> list[str]:
    """The capability-matrix features a snapshot device entry requests: one per interface kind, static-route family and
    routing instance, each named as the matrix names its leaves."""
    found = set()
    for interface in (device.get("interfaces") or {}).values():
        if interface.get("kind"):
            found.add(f"interface.{interface['kind']}")
    routing = device.get("routing") or {}
    for route in (routing.get("static_routes") or {}).values():
        found.add("routing.STATIC_IPV6" if route.get("family") == "IPV6" else "routing.STATIC_IPV4")
    for family, instances in routing.items():
        if family == "static_routes" or not isinstance(instances, dict):
            continue
        for instance in instances.values():
            if isinstance(instance, dict):
                found |= {f"routing.{leaf}" for leaf in routing_leaves(family, instance)}
    return sorted(found)


def assert_safe(bundle: dict) -> None:
    """Refuse a bundle in which a credential format is recognisable.  Second line: the inputs are already sanitized."""
    from ..ci import redact

    def walk(value, path):
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")
        elif isinstance(value, str):
            for line in value.splitlines():
                names = redact.scan_line(line)
                if names:
                    raise BundleError(UNSAFE, f"{path}: {names[0]}")

    walk(bundle, "bundle")


def encode(bundle: dict) -> dict:
    """The repository_dispatch ``client_payload``.  Never truncates: a bundle that does not fit is refused."""
    assert_safe(bundle)
    body = canonical(bundle)
    packed = base64.b64encode(gzip.compress(body.encode(), mtime=0)).decode()
    if len(packed) > MAX_ENCODED_BYTES:
        raise BundleError(TOO_LARGE, f"{len(packed)} bytes encoded, the limit is {MAX_ENCODED_BYTES}")
    return {"correlation_id": bundle["correlation_id"], "change_id": bundle["change"]["change_id"], "snapshot_hash": bundle["snapshot_hash"],
            "candidate_hash": bundle["candidate_hash"], "bundle_sha256": digest(body), "bundle": packed}


def decode(payload: dict) -> dict:
    """The bundle of a ``client_payload``, verified against the SHA-256 that travelled with it."""
    try:
        body = gzip.decompress(base64.b64decode(payload["bundle"], validate=True)).decode()
        bundle = json.loads(body)
    except (KeyError, ValueError, OSError, TypeError) as exc:
        raise BundleError("CONFIG_VALIDATION_BUNDLE_UNREADABLE", type(exc).__name__) from None
    if digest(body) != payload.get("bundle_sha256") or not isinstance(bundle, dict):
        raise BundleError("CONFIG_VALIDATION_BUNDLE_HASH_MISMATCH", "the bundle is not the one NMAS hashed")
    return bundle
