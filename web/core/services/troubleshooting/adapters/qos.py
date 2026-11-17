"""QoS evidence source adapter (HC19): request building and flow-tuple classification for the injected read-only ``qos-source/1`` reader.

Flow: ``RuntimeDeps.qos_source`` -> ``collectors.QosCollector`` -> ``normalization.normalize_qos_state`` (parser ``qos.state``) -> ``qos.attachment`` observations ->
``runtime.map_observations`` -> engine key ``qos.state@<interface>-<direction>`` -> ``runbooks.hc.hc19``.

Rules enforced by the layers (none of them trusts a pre-computed ``matches_flow`` flag, which normalization discards):
* the attachment (interface + direction) is reported by the source and compared with the production path hop (``in_if`` / ``out_if``) by HC19;
* a class is "the flow's class" only when ``classify`` proves it from the production tuple (protocol, port, src/dst, DSCP when the class matches on it) against
  the class's own ordered match criteria; an unsupported/incomplete class before a proven match, or a class that matches on a field the flow does not state, is UNKNOWN;
* drop evidence is a counter DELTA between two ordered samples of one counter epoch; reset, short, stale or missing samples are never a delta.

Nothing here issues a device command.  No default reader exists: without ``RuntimeDeps.qos_source`` the key is an explicit gap.
"""

from __future__ import annotations

import ipaddress

SOURCE_VERSION = "1.0.0"
QOS_GAP_REASON = ("NOT_CONFIGURED: no injected read-only QoS source is available; QoS classification and queue drops are UNKNOWN "
                  "(no command is invented for platforms without a validated QoS read)")


def qos_request(flow: dict | None) -> dict:
    """One bounded read per device: the production tuple the source may use to narrow its answer (the source's answer is still re-classified locally)."""
    flow = flow or {}
    return {"vrf": str(flow.get("vrf") or "default"), "directions": ["in", "out"],
            "flow": {k: flow.get(k) for k in ("protocol", "port", "src_ip", "dst_ip", "af", "dscp") if flow.get(k) is not None}}


def _in_net(ip, net):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except (ValueError, TypeError):
        return None


def classify(cls: dict, flow: dict):
    """-> ``(True|False|None, reason)``: does ``cls`` provably match (True) / provably not match (False) / cannot be decided (None) for the production tuple."""
    if cls.get("unsupported"):
        return None, f"class {cls.get('name')} uses unsupported match syntax ({cls['unsupported']})"
    if cls.get("match_complete") is not True:
        return None, f"class {cls.get('name')} match criteria are not completely collected"
    match = cls.get("match")
    if not isinstance(match, dict) or not match:
        return None, f"class {cls.get('name')} has no collected match criteria"
    if match.get("any") is True and len(match) == 1:
        return True, "match-any (default) class"
    verdict = True
    proto = match.get("protocol")
    if proto not in (None, "ip", "any"):
        if not flow.get("protocol"):
            return None, "flow protocol unknown"
        if proto != flow["protocol"]:
            return False, f"protocol {proto} differs from flow {flow['protocol']}"
    ports = match.get("ports")
    if ports:
        if flow.get("port") is None:
            return None, "flow port unknown"
        if flow["port"] not in ports:
            return False, f"port {flow['port']} not in {ports}"
    for fld, key in (("src", "src_ip"), ("dst", "dst_ip")):
        nets = match.get(fld)
        if nets:
            if not flow.get(key):
                return None, f"flow {key} unknown"
            hits = [_in_net(flow[key], n) for n in nets]
            if any(h is None for h in hits):
                return None, f"class {fld} network unparsable"
            if not any(hits):
                return False, f"{key} {flow[key]} not in {nets}"
    dscp = match.get("dscp")
    if dscp:
        if flow.get("dscp") is None:
            return None, "class matches on DSCP but the production packets' DSCP is not stated"
        if flow["dscp"] not in dscp:
            return False, f"dscp {flow['dscp']} not in {dscp}"
    return verdict, "all match criteria hold for the production tuple"
