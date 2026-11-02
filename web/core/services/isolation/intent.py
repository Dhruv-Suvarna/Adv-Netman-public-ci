"""The isolation intent of one bootstrap port, derived from the upstream's own running configuration.  Pure: text in, intent out.

The intent names every element separately so each is verified on its own:

    L2               the port is a dedicated routed port (no switchport, no subinterface, no port-channel member)
    IPV4 / IPV6      what the device may send (ingress) and what may be forwarded to it (egress)
    CONTROL_PLANE    routing processes that would form an adjacency on the port are made passive
    MANAGEMENT_PLANE the upstream's own SSH service refuses the bootstrap side; other enabled services block the policy

Anything the builder cannot prove safe becomes a blocker with a stable code; nothing is guessed.  Operations already present
on the upstream are never "adopted": a fresh policy plans only into a port that holds none of NMAS's statements.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json

from ..config_workbench.structure import config_paths
from . import eos

SCHEMA = 1


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _problem(code: str, detail: str = "") -> dict:
    return {"code": code, "detail": str(detail)[:200]}


def build(*, device_id: str, upstream: str, interface: str, network, config_text: str, nmas_sources=()) -> tuple[dict, list, list, dict]:
    """-> (intent, apply operations, problems, facts).  ``network`` is the device's BootstrapNetwork; ``nmas_sources`` are the
    addresses NMAS manages the upstream from (the management ACL must never refuse them)."""
    problems: list[dict] = []
    port = eos.interface_facts(config_text, interface)
    facts = {"port": {k: port[k] for k in ("exists", "routed", "ipv4", "ipv6", "access_groups", "helpers", "vrf", "channel_group",
                                           "shutdown", "subinterfaces")}}
    if not port["exists"]:
        return {}, [], [_problem("ISOLATION_PORT_NOT_FOUND", interface)], facts
    if not port["routed"]:
        problems.append(_problem("ISOLATION_PORT_NOT_ROUTED", "only a dedicated routed port is enforced (no switchport)"))
    if port["channel_group"] or port["subinterfaces"]:
        problems.append(_problem("ISOLATION_PORT_SHARED", "port-channel member or subinterfaces present"))
    if not port["ipv4"]:
        problems.append(_problem("ISOLATION_PORT_NO_ADDRESS", interface))

    prefix = str(ipaddress.ip_network(network.ipv4_prefix, strict=False))
    on_port = {str(ipaddress.ip_interface(a).network) for a in port["ipv4"]}
    gateways = {str(ipaddress.ip_interface(a).ip) for a in port["ipv4"]}
    if prefix not in on_port or network.gateway not in gateways:
        problems.append(_problem("ISOLATION_BOOTSTRAP_NETWORK_MISMATCH", f"{interface} is not {network.gateway} on {prefix}"))
    if network.service_address not in port["helpers"]:
        problems.append(_problem("ISOLATION_BOOTSTRAP_NETWORK_MISMATCH", f"{interface} does not relay DHCP to {network.service_address}"))

    names = eos.acl_names(device_id)
    foreign = {k: v for k, v in port["access_groups"].items() if not v.startswith(eos.ACL_PREFIX)}
    if foreign:
        problems.append(_problem("ISOLATION_FOREIGN_ACL", f"{interface} already filters with {sorted(foreign.values())}"))

    routing = eos.routing_facts(config_text, interface)
    facts["routing"] = routing
    for item in routing["unsupported"]:
        problems.append(_problem("ISOLATION_ROUTING_UNSUPPORTED", f"{item['protocol']}: {item['reason']}"))

    denied = eos.management_denied(port["ipv4"], port["ipv6"])
    management = eos.management_plan(config_text, denied, port["vrf"], names)
    facts["management"] = {"denied": denied, "blocked": management["blocked"]}
    for reason in management["blocked"]:
        problems.append(_problem("ISOLATION_MGMT_PLANE_EXPOSED", reason))
    for source in nmas_sources:
        if eos.locks_out(source, denied):
            problems.append(_problem("ISOLATION_MGMT_PLANE_EXPOSED", f"the management ACL would refuse NMAS's own source {source}"))

    bootstrap = {"prefix": prefix, "service_address": network.service_address, "http_port": int(network.http_port)}
    intent = {
        "schema": SCHEMA, "device": device_id,
        "upstream": {"device": upstream, "interface": interface, "platform": "arista_ceos", "vrf": port["vrf"]},
        "bootstrap": bootstrap,
        "elements": {
            "L2": {"mode": "VERIFY", "routed_port": True},
            "IPV4": {"acl": names["in4"], "entries": eos.ipv4_entries(bootstrap),
                     "out_acl": names["out4"], "out_entries": eos.ipv4_egress_entries(bootstrap)},
            "IPV6": {"acl": names["in6"], "entries": eos.ipv6_entries(),
                     "out_acl": names["out6"], "out_entries": eos.ipv6_egress_entries()},
            "CONTROL_PLANE": {"ospf_passive": routing["ospf"], "already_passive": routing["already_passive"],
                              # OSPFv3 keys only when the port runs OSPFv3: an IPv4-only policy keeps its earlier intent hash
                              **({"ospf6_passive": routing["ospf6"], "already_passive6": routing["already_passive6"]}
                                 if routing["ospf6"] or routing["already_passive6"] else {})},
            "MANAGEMENT_PLANE": {"V4": management["V4"], "V6": management["V6"]},
        },
    }
    if problems:
        return intent, [], problems, facts
    try:
        ops = eos.render_apply(intent)
    except eos.RenderError as exc:
        return intent, [], [_problem(exc.code if exc.code.startswith("ISOLATION_") else "ISOLATION_PLATFORM_NOT_IMPLEMENTED", exc.detail)], facts
    present = config_paths(config_text)
    for op in ops:
        found = [path for path in op["paths"] if path in present]
        if found:
            problems.append(_problem("ISOLATION_NAME_COLLISION", f"{op['key']}: the upstream already holds {found[0][:120]}"))
    for name, keyword in ((names["in4"], "ip"), (names["out4"], "ip"), (names["mgmt4"], "ip"),
                          (names["in6"], "ipv6"), (names["out6"], "ipv6"), (names["mgmt6"], "ipv6")):
        if eos.acl_entries(config_text, name, keyword) is not None and not any(p["code"] == "ISOLATION_NAME_COLLISION" for p in problems):
            problems.append(_problem("ISOLATION_NAME_COLLISION", f"{keyword} access-list {name} already exists"))
    return intent, ([] if problems else ops), problems, facts


def presence(config_text: str, ops) -> dict:
    """{operation key: PRESENT | ABSENT | PARTIAL} of rendered operations in a configuration."""
    present = config_paths(config_text)
    found = {}
    for op in ops:
        hits = sum(1 for path in op["paths"] if path in present)
        found[op["key"]] = "PRESENT" if hits == len(op["paths"]) else "ABSENT" if hits == 0 else "PARTIAL"
    return found


def acl_exact(config_text: str, intent: dict) -> list[str]:
    """ACLs of the intent whose configured entries differ from the intended ones (extra entries included)."""
    wrong = []
    elements = intent["elements"]
    wanted = [(elements["IPV4"]["acl"], "ip", elements["IPV4"]["entries"]), (elements["IPV4"]["out_acl"], "ip", elements["IPV4"]["out_entries"]),
              (elements["IPV6"]["acl"], "ipv6", elements["IPV6"]["entries"]), (elements["IPV6"]["out_acl"], "ipv6", elements["IPV6"]["out_entries"])]
    for family, keyword in (("V4", "ip"), ("V6", "ipv6")):
        element = elements["MANAGEMENT_PLANE"].get(family)
        if element and element["mode"] == "ADD":
            wanted.append((element["acl"], keyword, element["entries"]))
    for name, keyword, entries in wanted:
        configured = eos.acl_entries(config_text, name, keyword)
        if configured is None or [e for e in configured if e != "counters per-entry"] != list(entries):
            wrong.append(name)
    return wrong
