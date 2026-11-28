"""Routing-protocol evidence source adapter (RB03 NB01/NB04/NB05/NB06/NB09): request building for the injected read-only ``protocol-source/1`` reader.

Flow: ``RuntimeDeps.proto_source`` -> ``collectors.ProtocolCollector`` -> ``normalization.normalize_protocol_state`` (parser ``proto.state``) -> observations
``capability.protocol`` / ``protocol.config`` / ``routing.neighbor.detail`` -> ``runtime.map_observations`` -> the engine keys ``capability.protocol@<protocol>``,
``protocol.config@<protocol>`` and ``routing.neighbor.detail@<peer>`` that RB03 reads.

Scope: one bounded read per admitted device, with an explicit (protocol, AF, VRF, interface, peer) scope taken from the case target.  The TARGET end is read on the target device
(capability + config + neighbor detail, peer = neighbor device, interface = target interface); the NEIGHBOR end is read on the neighbor device (capability + config only; peer =
target device, interface = ``neighbor_interface``) and only if that device is admitted and in the case scope.  Unsupported protocols / AFs, a missing VRF/peer/interface or a
device that is neither end produce no request: the keys stay explicit gaps.  Nothing here issues a device command or changes configuration.
"""

from __future__ import annotations

from .. import normalization as nz

SOURCE_VERSION = "1.0.0"
PROTOCOL_KEYS = frozenset(nz.PROTO_ENGINE_KEYS)
PROTO_GAP_REASON = ("NOT_CONFIGURED: no injected read-only routing-protocol source is available; protocol capability, configuration and neighbor state are UNKNOWN "
                    "(no command is invented and a missing configuration is never treated as matching)")


def wanted_here(wanted) -> bool:
    return any(w in PROTOCOL_KEYS for w in wanted)


def scope_of(target: dict | None) -> dict | None:
    """Validated explicit scope or None."""
    t = target or {}
    proto = str(t.get("protocol") or "").lower()
    af = str(t.get("af") or "ipv4").lower()
    vrf = str(t.get("vrf") or "default")
    if proto not in nz.PROTO_SUPPORTED or af not in nz.PROTO_AFS or not t.get("device") or not t.get("neighbor_device"):
        return None
    if proto != "bgp" and not (t.get("interface") and t.get("neighbor_interface")):
        return None
    return {"protocol": proto, "af": af, "vrf": vrf}


def requests_for_device(target: dict | None, device: str, wanted, scope_devices=()) -> list[dict]:
    """-> ``[]`` or one request for ``device``."""
    t = target or {}
    sc = scope_of(t)
    if sc is None or not wanted_here(wanted):
        return []
    if t["device"] == device:
        include = [n for n, k in (("capability", "capability.protocol"), ("config", "protocol.config"), ("neighbor", "routing.neighbor.detail")) if k in wanted]
        return [dict(sc, interface=t.get("interface") or None, peer=t["neighbor_device"], include=include)] if include else []
    if t["neighbor_device"] == device and (not scope_devices or device in scope_devices):
        include = [n for n, k in (("capability", "capability.protocol"), ("config", "protocol.config")) if k in wanted]
        return [dict(sc, interface=t.get("neighbor_interface") or None, peer=t["device"], include=include)] if include else []
    return []


def served_keys(requests) -> set:
    names = {"capability": "capability.protocol", "config": "protocol.config", "neighbor": "routing.neighbor.detail"}
    return {names[i] for r in requests for i in r.get("include", ()) if i in names}


def gap_reason(target: dict | None, source_configured: bool, has_request: bool) -> str:
    sc = scope_of(target)
    if sc is None:
        proto = str((target or {}).get("protocol") or "").lower()
        if proto and proto not in nz.PROTO_SUPPORTED:
            return f"UNSUPPORTED_OPERATION: protocol {proto!r} has no protocol-source contract (supported: {sorted(nz.PROTO_SUPPORTED)}); no test is invented"
        return "SCOPE_MISMATCH: protocol/AF/VRF/interface/peer scope is not explicit or not supported; the protocol source is not read"
    if not source_configured:
        return PROTO_GAP_REASON
    if not has_request:
        return "SCOPE_MISMATCH: this device is neither the target end nor the neighbor end of the adjacency; protocol state is not read"
    return "UNKNOWN: the injected protocol source produced no usable evidence for this key (see the collector run)"
