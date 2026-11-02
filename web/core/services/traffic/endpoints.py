"""The traffic endpoint catalogue: which lab endpoints may source or sink a test.

The catalogue is the tracked inventory (``hosts`` plus the optional WebServer) -- never browser input.  An endpoint here is an UNMANAGED
traffic endpoint: being listed does not make it a managed device, a registry entry or a NetBox identity, and nothing in this module writes
anywhere.  The website only ever sends an endpoint ID to the traffic runner; the runner resolves it against its OWN root-owned copy of
this catalogue (``runner_config`` renders that copy at install time) and discovers the addresses inside the endpoint's namespace, so an
operator never types an address and a test can only target an address a catalogued endpoint really holds.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..health import inventory

V4, V6 = "IPV4", "IPV6"


@dataclass(frozen=True)
class Endpoint:
    name: str
    container: str
    lab: str
    families: tuple[str, ...]      # address families the lab design gives this endpoint (H4 is IPv6-only)


def catalogue() -> dict[str, Endpoint]:
    document = inventory.load_inventory()
    lab = str(document.get("lab_name") or "")
    found = {}
    for name, flags in sorted((document.get("hosts") or {}).items()):
        flags = flags or {}
        families = tuple(f for f, on in ((V4, flags.get("ipv4", True)), (V6, flags.get("ipv6", True))) if on)
        found[name] = Endpoint(name, f"clab-{lab}-{name}", lab, families)
    if (document.get("toggles") or {}).get("include_webserver"):
        found["WebServer"] = Endpoint("WebServer", f"clab-{lab}-WebServer", lab, (V4, V6))
    return found


def get(name: str) -> Endpoint | None:
    return catalogue().get(str(name or ""))


def runner_config(*, tools_image: str, allowed_peer_uids, instance: str = "nmas") -> dict:
    """The traffic runner's configuration document for this inventory (installed root-owned; see ``runner/config.py``)."""
    found = catalogue()
    labs = {endpoint.lab for endpoint in found.values()}
    return {
        "instance": instance, "lab": labs.pop() if len(labs) == 1 else "", "tools_image": tools_image,
        "allowed_peer_uids": sorted(int(uid) for uid in allowed_peer_uids),
        "endpoints": {name: {"container": endpoint.container, "families": list(endpoint.families)} for name, endpoint in found.items()},
    }
