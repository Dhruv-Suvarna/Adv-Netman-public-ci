"""Read-only adapter for the existing NetworkX topology service.

This module consumes the already-authoritative ``GET /api/topology`` API.  It
does not inspect Containerlab, query devices, access NetBox, or construct a
graph.  Views call this boundary and never know the upstream service address.
"""

from __future__ import annotations

import json
import math
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from django.conf import settings

UNAVAILABLE_MESSAGE = "Topology service temporarily unavailable."
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
NODE_STATES = {"HEALTHY", "STALE", "OFFLINE", "UNKNOWN"}
EDGE_STATES = {"UP", "DOWN", "DEGRADED", "UNKNOWN"}
FORBIDDEN_KEY_PARTS = {
    "password",
    "passwd",
    "secret",
    "token",
    "webhook",
    "credential",
    "apikey",
    "api_key",
    "private_key",
}


class TopologyResponseError(ValueError):
    """The upstream response was unsafe or did not match schema version 1."""


def _contains_forbidden_key(value) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower()
            if any(part in normalized for part in FORBIDDEN_KEY_PARTS):
                return True
            if _contains_forbidden_key(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False


def _validate_upstream_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TopologyResponseError("Configured topology service URL is invalid")
    if parsed.query or parsed.fragment or parsed.path != "/api/topology":
        raise TopologyResponseError("Configured topology service URL must target /api/topology")


def _validate_payload(payload) -> dict:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise TopologyResponseError("Unexpected topology schema version")
    graph = payload.get("graph")
    if not isinstance(graph, dict):
        raise TopologyResponseError("Topology graph is missing")
    nodes, edges = graph.get("nodes"), graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise TopologyResponseError("Topology nodes or edges are invalid")
    if not all(isinstance(item, dict) for item in [*nodes, *edges]):
        raise TopologyResponseError("Topology members must be objects")

    node_ids = [item.get("id") for item in nodes]
    edge_ids = [item.get("id") for item in edges]
    if not all(isinstance(item, str) and item for item in node_ids):
        raise TopologyResponseError("Topology node identities are invalid")
    if not all(isinstance(item, str) and item for item in edge_ids):
        raise TopologyResponseError("Topology edge identities are invalid")
    if len(node_ids) != len(set(node_ids)):
        raise TopologyResponseError("Topology node identities are invalid")
    if len(edge_ids) != len(set(edge_ids)):
        raise TopologyResponseError("Topology edge identities are invalid")
    if not all(item.get("health") in NODE_STATES for item in nodes):
        raise TopologyResponseError("Topology node health is invalid")
    if not all(item.get("status") in EDGE_STATES for item in edges):
        raise TopologyResponseError("Topology edge state is invalid")
    node_id_set = set(node_ids)
    if not all(
        isinstance(item.get("source"), str)
        and isinstance(item.get("target"), str)
        and item["source"] in node_id_set
        and item["target"] in node_id_set
        for item in edges
    ):
        raise TopologyResponseError("Topology edge endpoint is invalid")
    try:
        coordinates_valid = all(
            math.isfinite(float(item[axis])) for item in nodes for axis in ("x", "y")
        )
    except (KeyError, TypeError, ValueError):
        coordinates_valid = False
    if not coordinates_valid:
        raise TopologyResponseError("Topology layout coordinates are invalid")
    if _contains_forbidden_key(payload):
        raise TopologyResponseError("Topology response contains a forbidden field")

    # The upstream deliberately degrades graph health when InfluxDB cannot be
    # read.  Preserve that state, but never relay its raw internal exception.
    backend = payload.get("backend")
    if not isinstance(backend, dict):
        raise TopologyResponseError("Topology backend status is invalid")
    if isinstance(backend, dict) and backend.get("error"):
        backend["error"] = "Monitoring evidence temporarily unavailable."
    return payload


def _fetch_payload() -> dict:
    url = settings.TOPOLOGY_SERVICE_URL
    _validate_upstream_url(url)
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "NMAS-Django/1"},
        method="GET",
    )
    with urlopen(request, timeout=settings.TOPOLOGY_SERVICE_TIMEOUT_SECONDS) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise TopologyResponseError("Topology response is too large")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TopologyResponseError("Topology response is not valid JSON") from exc
    return _validate_payload(payload)


def get_topology_summary() -> dict:
    """Return safe presentation data or an explicit degraded-state result."""
    try:
        payload = _fetch_payload()
    except (
        HTTPError,
        URLError,
        socket.timeout,
        TimeoutError,
        OSError,
        TypeError,
        ValueError,
        AttributeError,
        RecursionError,
    ):
        return {
            "status": "unavailable",
            "message": UNAVAILABLE_MESSAGE,
            "data": None,
            "node_count": 0,
            "edge_count": 0,
        }
    nodes = payload["graph"]["nodes"]
    edges = payload["graph"]["edges"]
    return {
        "status": "available",
        "message": "Live read-only topology loaded.",
        "data": payload,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "generated_at": payload.get("generated_at"),
        "backend_status": payload["backend"].get("status", "UNKNOWN"),
    }
