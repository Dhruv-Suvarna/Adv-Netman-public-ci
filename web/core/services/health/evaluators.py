"""Requirement evaluators and the reusable plan-verification engine (``evaluate_plan_requirements``).

PRECHECK vs POSTCHECK (the distinction the whole phase turns on):

* POSTCHECK  "did the intended state appear?"  -- the requirement's expected state is compared with observed evidence.
  Missing evidence is UNKNOWN (=> INCOMPLETE), never PASS; a demonstrated deviation is FAIL.
* PRECHECK   "is the current state acceptable BEFORE the change?"  Two classes:
  - FUTURE_STATE requirements (an interface, address, BGP peer, ACL definition the plan creates): their absence before
    deployment is EXPECTED, so they evaluate to NOT_APPLICABLE (or an informational PASS when already satisfied --
    idempotent).  They can never FAIL, WARN or block a precheck.
  - PREREQUISITE requirements (the base interface a route / binding / attachment relies on, unless the plan creates it):
    evaluated against the current state, because they must already hold.

The engine performs NO I/O: evidence is gathered once by the caller (Deep-Health live reads, telemetry, the DHCP
verifier) and handed in as an ``EvidenceSet``, so a later deployment phase can call the exact same evaluator after a push.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .codes import CheckStatus, Freshness, Phase, Role
from .evidence import EvidenceSet, FactGroup
from .live import norm_cidr, norm_ip, norm_prefix
from .requirements import NOT_IMPLEMENTED, UNKNOWN_TYPE, Requirement, normalize_plan, plan_interfaces
from .results import CheckResult, count_by_status, iso, postcheck_result, precheck_result
from .routing_config import normalized_area

DATA_UNAVAILABLE = "DATA_UNAVAILABLE"  # placeholder mapped to the phase-specific code by the engine
S = CheckStatus


@dataclass
class Outcome:
    status: str
    code: str
    message: str
    observed: object = None
    expected: object = None
    group: FactGroup | None = None


@dataclass
class EvalContext:
    evidence: EvidenceSet
    created_interfaces: dict = field(default_factory=dict)   # device -> interface names the plan creates
    one_sided_ospf: frozenset = frozenset()                  # {(device, interface)} the validation flagged OSPF_ONE_SIDED
    roles: dict = field(default_factory=dict)                # device -> Role
    isolated_ports: frozenset = frozenset()                  # {(device, interface)} held by an enforced trusted-isolation policy


ISOLATED_PORT = ("The link to the trusted upstream is isolated until production admission (passive and filtered there by design); "
                 "the production admission verifies this adjacency.")


def _isolated(req, ctx, interface, code, expected):
    """NOT_APPLICABLE while ``interface`` is a port held by trusted isolation (V2 Phase 5): no adjacency can form there yet."""
    if (req.device, interface) in ctx.isolated_ports:
        return Outcome(S.NOT_APPLICABLE, code, ISOLATED_PORT, expected={**expected, "isolated_until_admission": True})
    return None


@dataclass
class RequirementEvaluation:
    phase: str
    result: str
    results: list
    counts: dict
    summary: dict


# --- evidence access ---------------------------------------------------------------------------------------------
def _need(ctx: EvalContext, device: str, group_name: str):
    """(FactGroup, None) when usable evidence exists; else (None, UNKNOWN outcome).  Expired evidence is never used."""
    evidence = ctx.evidence.device(device)
    if evidence is None:
        return None, Outcome(S.UNKNOWN, DATA_UNAVAILABLE, f"No evidence was collected for {device}.", {"reason": "NO_DEVICE_EVIDENCE"})
    group = evidence.group(group_name)
    if group is None or not group.available:
        reason = (group.error if group is not None else "") or evidence.live_error or "GROUP_UNAVAILABLE"
        return None, Outcome(S.UNKNOWN, DATA_UNAVAILABLE, f"{group_name.replace('_', ' ').capitalize()} evidence is unavailable for {device}.",
                             {"reason": reason}, group=group)
    if group.freshness(ctx.evidence.now, ctx.evidence.thresholds) == Freshness.EXPIRED:
        return None, Outcome(S.UNKNOWN, DATA_UNAVAILABLE, f"{group_name.replace('_', ' ').capitalize()} evidence for {device} is too old to use.",
                             {"reason": "EVIDENCE_EXPIRED"}, group=group)
    return group, None


def _facts(req: Requirement) -> dict:
    return req.expected or {}


# --- POSTCHECK evaluators: (requirement, context) -> Outcome ------------------------------------------------------
def _interface_present(req, ctx):
    group, missing = _need(ctx, req.device, "interfaces")
    if missing:
        return missing
    name = _facts(req)["interface"]
    if name in group.data:
        return Outcome(S.PASS, "INTERFACE_EXPECTED_PRESENT", f"Interface {name} exists.", {"interface": name}, {"interface": name}, group)
    if group.complete:
        return Outcome(S.FAIL, "INTERFACE_MISSING", f"Interface {name} does not exist.", {"interfaces": sorted(group.data)}, {"interface": name}, group)
    return Outcome(S.UNKNOWN, DATA_UNAVAILABLE, f"Interface evidence is partial; {name} could not be confirmed absent.", {"partial": True}, {"interface": name}, group)


def _interface_row(req, ctx):
    group, missing = _need(ctx, req.device, "interfaces")
    if missing:
        return None, None, missing
    row = group.data.get(_facts(req)["interface"])
    if row is None:
        status = S.NOT_APPLICABLE if group.complete else S.UNKNOWN
        code = "INTERFACE_MISSING" if group.complete else DATA_UNAVAILABLE
        return None, group, Outcome(status, code, "The interface is absent; reported by INTERFACE_PRESENT.", group=group)
    return row, group, None


def _interface_admin(req, ctx):
    row, group, problem = _interface_row(req, ctx)
    if problem:
        return problem
    want_up = bool(_facts(req).get("admin_enabled", True))
    actual = row.get("admin")
    if actual is None:
        return Outcome(S.UNKNOWN, DATA_UNAVAILABLE, "Administrative state is not reported.", {"admin": None}, {"admin": "UP" if want_up else "DOWN"}, group)
    if (actual == "UP") == want_up:
        return Outcome(S.PASS, "INTERFACE_EXPECTED_UP" if want_up else "INTERFACE_ADMIN_DOWN",
                       f"Administrative state is {actual}, as required.", {"admin": actual}, {"admin": "UP" if want_up else "DOWN"}, group)
    return Outcome(S.FAIL, "INTERFACE_STATE_MISMATCH", f"Administrative state is {actual}, required {'UP' if want_up else 'DOWN'}.",
                   {"admin": actual}, {"admin": "UP" if want_up else "DOWN"}, group)


def _interface_oper(req, ctx):
    if not _facts(req).get("admin_enabled", True):
        return Outcome(S.NOT_APPLICABLE, "INTERFACE_ADMIN_DOWN", "The interface is intentionally shut down; no operational state is expected.")
    row, group, problem = _interface_row(req, ctx)
    if problem:
        return problem
    actual = row.get("oper")
    if actual is None:
        return Outcome(S.UNKNOWN, DATA_UNAVAILABLE, "Operational state is not reported.", {"oper": None}, {"oper": "UP"}, group)
    if actual == "UP":
        return Outcome(S.PASS, "INTERFACE_EXPECTED_UP", "Operational state is UP.", {"oper": actual}, {"oper": "UP"}, group)
    # Operational state depends on the far end and the link, so a mismatch is a WARN, not a FAIL (a false FAIL could
    # drive a rollback); a definite configuration deviation is reported by INTERFACE_ADMIN_STATE / INTERFACE_PRESENT.
    return Outcome(S.WARN, "INTERFACE_OPER_DOWN", f"Operational state is {actual}.", {"oper": actual}, {"oper": "UP"}, group)


def _address(req, ctx):
    group, missing = _need(ctx, req.device, "addresses")
    if missing:
        return missing
    facts = _facts(req)
    want, name = norm_cidr(facts.get("address")), facts.get("interface")
    have = list(group.data.get(name, []))
    if want and want in have:
        return Outcome(S.PASS, "ADDRESS_EXPECTED_PRESENT", f"{want} is configured on {name}.", {"addresses": have}, {"address": want, "interface": name}, group)
    return Outcome(S.FAIL, "ADDRESS_MISSING", f"{facts.get('address')} is not configured on {name}.", {"addresses": have},
                   {"address": want or facts.get("address"), "interface": name}, group)


def _static_route(req, ctx):
    group, missing = _need(ctx, req.device, "routes")
    if missing:
        return missing
    facts = _facts(req)
    prefix = norm_prefix(facts.get("prefix"))
    hop = norm_ip(facts["next_hop"]) if facts.get("next_hop") else None
    exit_interface = facts.get("exit_interface") or None
    candidates = [route for route in group.data if route["prefix"] == prefix]
    expected = {"prefix": prefix, "next_hop": hop, "exit_interface": exit_interface}
    for route in candidates:
        if (hop is None or hop in route["next_hops"]) and (exit_interface is None or exit_interface in route["interfaces"]):
            return Outcome(S.PASS, "ROUTE_EXPECTED_PRESENT", f"Route {prefix} is present.", {"route": route}, expected, group)
    return Outcome(S.FAIL, "ROUTE_MISSING", f"Route {prefix} is not present with the expected next hop.", {"routes_for_prefix": candidates[:5]}, expected, group)


def _ospf(req, ctx):
    group, missing = _need(ctx, req.device, "ospf")
    if missing:
        return missing
    facts = _facts(req)
    if facts.get("passive"):
        return Outcome(S.NOT_APPLICABLE, "OSPF_EXPECTED_FULL", "The interface is passive; no adjacency is expected.")
    interface, family = facts.get("interface"), str(facts.get("version") or "OSPFV2").upper()
    neighbors = [n for n in group.data if n["interface"] == interface and n["family"] == family]
    expected = {"interface": interface, "family": family, "state": "FULL"}
    if any(n["state"] == "FULL" for n in neighbors):
        return Outcome(S.PASS, "OSPF_EXPECTED_FULL", f"An OSPF adjacency is FULL on {interface}.", {"neighbors": neighbors}, expected, group)
    held = _isolated(req, ctx, interface, "OSPF_EXPECTED_FULL", expected)
    if held is not None:
        return held
    if neighbors:
        return Outcome(S.FAIL, "OSPF_ADJACENCY_DOWN", f"OSPF neighbors on {interface} are not FULL.", {"neighbors": neighbors}, expected, group)
    if (req.device, interface) in ctx.one_sided_ospf:
        return Outcome(S.NOT_APPLICABLE, "OSPF_EXPECTED_FULL",
                       "Validation found no OSPF binding on the far end of this link (OSPF_ONE_SIDED); no adjacency is expected.", expected=expected, group=group)
    return Outcome(S.FAIL, "OSPF_ADJACENCY_DOWN", f"No OSPF neighbor was observed on {interface}.", {"neighbors": []}, expected, group)


def _isis(req, ctx):
    group, missing = _need(ctx, req.device, "isis")
    if missing:
        return missing
    facts = _facts(req)
    if facts.get("passive"):
        return Outcome(S.NOT_APPLICABLE, "ISIS_EXPECTED_UP", "The interface is passive; no adjacency is expected.")
    interface = facts.get("interface")
    neighbors = [n for n in group.data if n["interface"] == interface]
    expected = {"interface": interface, "state": "UP"}
    if any(n["state"] == "UP" for n in neighbors):
        return Outcome(S.PASS, "ISIS_EXPECTED_UP", f"An IS-IS adjacency is UP on {interface}.", {"neighbors": neighbors}, expected, group)
    held = _isolated(req, ctx, interface, "ISIS_EXPECTED_UP", expected)
    if held is not None:
        return held
    if neighbors:
        return Outcome(S.FAIL, "ISIS_ADJACENCY_DOWN", f"IS-IS neighbors on {interface} are not UP.", {"neighbors": neighbors}, expected, group)
    return Outcome(S.FAIL, "ISIS_ADJACENCY_DOWN", f"No IS-IS neighbor was observed on {interface}.", {"neighbors": []}, expected, group)


def _protocol_route(req, ctx, *, protocol: str, label: str, code: str):
    """A route of ONE protocol is present with EXACTLY the expected paths, or absent.  ``present`` False asserts absence."""
    group, missing = _need(ctx, req.device, "routes")
    if missing:
        return missing
    facts = _facts(req)
    prefix = norm_prefix(facts.get("prefix"))
    wanted = sorted(str(name) for name in facts.get("interfaces") or [])
    found = [route for route in group.data if route["prefix"] == prefix and str(route["type"]).lower().startswith(protocol)]
    paths = sorted({name for route in found for name in route["interfaces"]})
    observed = {"paths": paths, "next_hops": sorted({hop for route in found for hop in route["next_hops"]}),
                "other_sources": sorted({str(route["type"]) for route in group.data if route["prefix"] == prefix and route not in found})}
    if facts.get("present") is False:
        expected = {"prefix": prefix, "present": False}
        if found:
            return Outcome(S.FAIL, f"{code}_ROUTE_UNEXPECTED", f"{label} route {prefix} is present but must be absent.", observed, expected, group)
        return Outcome(S.PASS, f"{code}_ROUTE_ABSENT", f"No {label} route {prefix} is installed.", observed, expected, group)
    expected = {"prefix": prefix, "present": True, "paths": wanted}
    if not found:
        return Outcome(S.FAIL, f"{code}_ROUTE_MISSING", f"{label} route {prefix} is not installed.", observed, expected, group)
    if wanted and paths != wanted:
        return Outcome(S.FAIL, f"{code}_ROUTE_PATH_MISMATCH", f"{label} route {prefix} uses {', '.join(paths) or 'no path'}, not {', '.join(wanted)}.",
                       observed, expected, group)
    return Outcome(S.PASS, f"{code}_ROUTE_PRESENT", f"{label} route {prefix} is installed via {', '.join(paths)}.", observed, expected, group)


def _isis_route(req, ctx):
    return _protocol_route(req, ctx, protocol="isis", label="IS-IS", code="ISIS")


def _rip_route(req, ctx):
    return _protocol_route(req, ctx, protocol="rip", label="RIP", code="RIP")


def _rip_neighbor(req, ctx):
    """A RIP peer exists on an interface, or (``present`` False) no peer exists there.  Peers, never advertised prefixes."""
    group, missing = _need(ctx, req.device, "rip_neighbors")
    if missing:
        return missing
    facts = _facts(req)
    interface = facts.get("interface")
    peers = [n for n in group.data if n["interface"] == interface and n["accepted"]]
    observed = {"peers": [n["peer"] for n in peers]}
    if facts.get("present") is False:
        expected = {"interface": interface, "present": False}
        if peers:
            return Outcome(S.FAIL, "RIP_NEIGHBOR_UNEXPECTED", f"A RIP peer exists on {interface} but none is intended.", observed, expected, group)
        return Outcome(S.PASS, "RIP_NEIGHBOR_ABSENT", f"No RIP peer exists on {interface}.", observed, expected, group)
    expected = {"interface": interface, "present": True, **({"peer": facts["peer"]} if facts.get("peer") else {})}
    if facts.get("peer") and norm_ip(facts["peer"]) not in observed["peers"]:
        return Outcome(S.FAIL, "RIP_NEIGHBOR_MISSING", f"RIP peer {facts['peer']} was not observed on {interface}.", observed, expected, group)
    if not peers:
        held = _isolated(req, ctx, interface, "RIP_NEIGHBOR_PRESENT", expected)
        if held is not None:
            return held
        return Outcome(S.FAIL, "RIP_NEIGHBOR_MISSING", f"No RIP peer was observed on {interface}.", observed, expected, group)
    return Outcome(S.PASS, "RIP_NEIGHBOR_PRESENT", f"A RIP peer is present on {interface}.", observed, expected, group)


def _bgp(req, ctx):
    group, missing = _need(ctx, req.device, "bgp")
    if missing:
        return missing
    facts = _facts(req)
    if facts.get("shutdown"):
        return Outcome(S.NOT_APPLICABLE, "BGP_EXPECTED_ESTABLISHED", "The neighbor is administratively shut down; no session is expected.")
    peer = norm_ip(facts.get("peer"))
    expected = {"peer": peer, "state": "ESTABLISHED"}
    found = next((p for p in group.data if p["peer"] == peer), None)
    if found is None:
        return Outcome(S.FAIL, "BGP_SESSION_DOWN", f"BGP peer {peer} is not present.", {"peers": [p["peer"] for p in group.data]}, expected, group)
    if found["state"] == "ESTABLISHED":
        return Outcome(S.PASS, "BGP_EXPECTED_ESTABLISHED", f"BGP peer {peer} is Established.", {"state": found["state"]}, expected, group)
    return Outcome(S.FAIL, "BGP_SESSION_DOWN", f"BGP peer {peer} is {found['state'] or 'not established'}.", {"state": found["state"]}, expected, group)


def _routing_rows(req, ctx):
    group, missing = _need(ctx, req.device, "routing_config")
    return (group.data, group, None) if not missing else (None, None, missing)


def _routing_result(group, expected, found, label):
    if found:
        return Outcome(S.PASS, "ROUTING_CONFIG_PRESENT", f"{label} matches running configuration.",
                       expected=expected, group=group)
    return Outcome(S.FAIL, "ROUTING_CONFIG_MISMATCH", f"{label} does not match running configuration.",
                   {"matching_objects": 0}, expected, group)


def _routing_process(req, ctx):
    rows, group, missing = _routing_rows(req, ctx)
    if missing:
        return missing
    facts = _facts(req)
    protocol = str(facts["protocol"]).lower()
    version = facts.get("version") or ""
    if protocol == "rip":
        version = "IPV6" if version == "RIPNG" else "IPV4"
    for row in rows:
        if row["protocol"] != protocol:
            continue
        if protocol == "ospf" and version and row["version"] != version:
            continue
        if protocol == "rip" and row["version"] != version:
            continue
        if facts.get("process_id") is not None and row["process_id"] != facts["process_id"]:
            # FRR has one default-VRF OSPF/OSPF6 process per protocol, without
            # a numeric process ID in its CLI.  The modeled ID is not rendered.
            device = ctx.evidence.device(req.device)
            if not (protocol == "ospf" and row["process_id"] is None and device and device.platform == "linux"):
                continue
        if facts.get("local_asn") is not None and row["local_asn"] != facts["local_asn"]:
            continue
        if facts.get("router_id") and row["router_id"] != facts["router_id"]:
            continue
        if not row["enabled"]:
            continue
        if any(want not in row["networks"] for want in facts.get("networks") or []):
            continue
        return _routing_result(group, facts, True, "Routing process")
    return _routing_result(group, facts, False, "Routing process")


def _routing_binding(req, ctx):
    rows, group, missing = _routing_rows(req, ctx)
    if missing:
        return missing
    facts = _facts(req)
    # the running-configuration rows carry normalized areas ("0.0.0.0" and "0" are the same area): compare like with like
    area = facts.get("area") if facts.get("area") in (None, "") else normalized_area(facts["area"])
    for row in rows:
        if row["protocol"] != facts["protocol"]:
            continue
        if facts.get("version") and row["protocol"] == "ospf" and row["version"] != facts["version"]:
            continue
        if any(binding.get("interface_name") == facts["interface"] and
               (area in (None, "") or binding.get("area") == area) and
               bool(binding.get("passive")) == bool(facts.get("passive")) and
               (facts.get("metric") is None or binding.get("metric") == facts["metric"]) for binding in row["bindings"]):
            return _routing_result(group, facts, True, "Routing interface binding")
        # OSPFv2 also enables an interface through a process ``network`` statement covering its address.  The running
        # configuration then holds no per-interface binding, and no passive flag is modeled for that form, so it can
        # only confirm a non-passive expectation.
        if not facts.get("passive") and any(
                binding.get("interface_name") == facts["interface"] and
                (area in (None, "") or binding.get("area") == area)
                for binding in row.get("network_bindings") or []):
            return _routing_result(group, facts, True, "Routing interface binding")
    return _routing_result(group, facts, False, "Routing interface binding")


def _bgp_config(req, ctx):
    rows, group, missing = _routing_rows(req, ctx)
    if missing:
        return missing
    facts = _facts(req)
    family = str(facts.get("address_family") or facts.get("family") or "").upper()
    for row in rows:
        if row["protocol"] != "bgp" or (facts.get("local_asn") and row["local_asn"] != facts["local_asn"]):
            continue
        for neighbor in row["neighbors"]:
            if norm_ip(neighbor.get("peer_address")) != norm_ip(facts["peer"]):
                continue
            if facts.get("remote_asn") is not None and neighbor.get("remote_asn") != facts["remote_asn"]:
                continue
            if family in {"IPV4", "IPV6"} and not neighbor.get(f"activate_{family.lower()}"):
                continue
            return _routing_result(group, facts, True, "BGP neighbor and address family")
    return _routing_result(group, facts, False, "BGP neighbor and address family")


def family_label(value) -> str:
    """A family fact as the routing rows spell it: the planner records 4 / 6, hand-written descriptors IPV4 / IPV6."""
    text = str(value or "").upper()
    return {"4": "IPV4", "6": "IPV6"}.get(text, text)


def _bgp_network(req, ctx):
    rows, group, missing = _routing_rows(req, ctx)
    if missing:
        return missing
    facts = _facts(req)
    wanted = {"family": family_label(facts.get("family")), "cidr": norm_prefix(facts["prefix"])}
    found = any(row["protocol"] == "bgp" and any(
        net.get("family") == wanted["family"] and norm_prefix(net.get("cidr")) == wanted["cidr"]
        for net in row["networks"]) for row in rows)
    return _routing_result(group, wanted, found, "BGP network")


def _fhrp(req, ctx):
    group, missing = _need(ctx, req.device, "virtual_addresses")
    if missing:
        return missing
    facts = _facts(req)
    have = set(group.data.get(facts.get("interface"), []))
    want = sorted(norm_ip(a) or str(a) for a in facts.get("virtual_addresses", []))
    absent = [a for a in want if a not in have]
    if want and not absent:
        return Outcome(S.PASS, "FHRP_VIP_EXPECTED_PRESENT", "Virtual address(es) configured.", {"virtual_addresses": sorted(have)}, {"virtual_addresses": want}, group)
    return Outcome(S.FAIL, "FHRP_VIP_MISSING", "Virtual address(es) missing: " + ", ".join(absent or ["none configured"]),
                   {"virtual_addresses": sorted(have)}, {"virtual_addresses": want}, group)


def _dhcp_relay(req, ctx):
    group, missing = _need(ctx, req.device, "config")
    if missing:
        return missing
    facts = _facts(req)
    wanted = {"interface": facts.get("interface"), "destination": norm_ip(facts.get("destination"))}
    if "dhcp_relays" not in group.data:      # a platform whose configuration read has no DHCP relay facts (Linux)
        return Outcome(S.UNKNOWN, DATA_UNAVAILABLE, "This platform's configuration read does not report DHCP relays.",
                       expected=wanted, group=group)
    if wanted in group.data["dhcp_relays"]:
        return Outcome(S.PASS, "DHCP_RELAY_EXPECTED_PRESENT", f"DHCP relay {wanted['destination']} configured on {wanted['interface']}.", expected=wanted, group=group)
    return Outcome(S.FAIL, "DHCP_RELAY_MISSING", f"DHCP relay {wanted['destination']} is not configured on {wanted['interface']}.",
                   {"relays": [r for r in group.data["dhcp_relays"] if r["interface"] == wanted["interface"]]}, wanted, group)


def _acl_definition(req, ctx):
    group, missing = _need(ctx, req.device, "config")
    if missing:
        return missing
    name = _facts(req).get("name")
    if name in group.data["acl_definitions"]:
        return Outcome(S.PASS, "ACL_DEFINITION_EXPECTED_PRESENT", f"ACL {name} is defined.", expected={"acl": name}, group=group)
    return Outcome(S.FAIL, "ACL_DEFINITION_MISSING", f"ACL {name} is not defined.", {"acls": group.data["acl_definitions"]}, {"acl": name}, group)


def _acl_attachment(req, ctx):
    group, missing = _need(ctx, req.device, "config")
    if missing:
        return missing
    facts = _facts(req)
    wanted = {"interface": facts.get("interface"), "acl": facts.get("acl_name"), "direction": str(facts.get("direction") or "").upper()}
    if wanted in group.data["acl_attachments"]:
        return Outcome(S.PASS, "ACL_ATTACHMENT_EXPECTED_PRESENT", f"ACL {wanted['acl']} is attached {wanted['direction'].lower()} on {wanted['interface']}.", expected=wanted, group=group)
    return Outcome(S.FAIL, "ACL_ATTACHMENT_MISSING", f"ACL {wanted['acl']} is not attached {wanted['direction'].lower()} on {wanted['interface']}.",
                   {"attachments": [a for a in group.data["acl_attachments"] if a["interface"] == wanted["interface"]]}, wanted, group)


def _pbr_sequence(row) -> tuple:
    """A PBR sequence in comparable form: (sequence, source, destination, next hop); "" for an absent match."""
    return (int(row.get("sequence") or 0), norm_prefix(row.get("source_prefix")) if row.get("source_prefix") else "",
            norm_prefix(row.get("destination_prefix")) if row.get("destination_prefix") else "", norm_ip(row.get("next_hop")) or "")


def _pbr_policy(req, ctx):
    group, missing = _need(ctx, req.device, "pbr")
    if missing:
        return missing
    facts = _facts(req)
    name = facts.get("name")
    wanted = sorted(_pbr_sequence(row) for row in facts.get("sequences") or [])
    observed = (group.data.get("policies") or {}).get(name)
    installed = sorted((int(row["sequence"]), row.get("source_prefix") or "", row.get("destination_prefix") or "", hop)
                       for row in (observed or {}).get("sequences", []) if row.get("installed")
                       for hop in row.get("next_hops") or [""])
    expected = {"policy": name, "sequences": [list(row) for row in wanted]}
    if observed and observed.get("valid") and wanted and all(row in installed for row in wanted):
        return Outcome(S.PASS, "PBR_POLICY_EXPECTED_PRESENT", f"PBR policy {name} is valid and its {len(wanted)} sequence(s) are installed.",
                       expected=expected, group=group)
    return Outcome(S.FAIL, "PBR_POLICY_MISSING", f"PBR policy {name} is not defined, not valid, or a sequence is not installed.",
                   {"policy": observed}, expected, group)


def _pbr_attachment(req, ctx):
    group, missing = _need(ctx, req.device, "pbr")
    if missing:
        return missing
    facts = _facts(req)
    wanted = {"interface": facts.get("interface"), "policy": facts.get("policy_name")}
    if str(facts.get("direction") or "IN").upper() == "IN" and {**wanted, "valid": True} in (group.data.get("attachments") or []):
        return Outcome(S.PASS, "PBR_ATTACHMENT_EXPECTED_PRESENT", f"PBR policy {wanted['policy']} is applied on {wanted['interface']}.",
                       expected=wanted, group=group)
    return Outcome(S.FAIL, "PBR_ATTACHMENT_MISSING", f"PBR policy {wanted['policy']} is not applied on {wanted['interface']}.",
                   {"attachments": [a for a in group.data.get("attachments") or [] if a.get("interface") == wanted["interface"]]},
                   wanted, group)


def _nft_host(value) -> str:
    """A host address as nft lists it (without /32)."""
    return str(value or "").removesuffix("/32")


def _nat_rule(req, ctx):
    group, missing = _need(ctx, req.device, "nat")
    if missing:
        return missing
    facts = _facts(req)
    outside = facts.get("outside_interface")
    if facts.get("mode") == "STATIC":
        # a static mapping is proven only by both directions of exactly this 1:1 pair on the outside interface
        expected = {"outside_interface": outside, "inside": _nft_host(facts.get("original_source")),
                    "global": _nft_host(facts.get("translated_source"))}
        mappings = group.data.get("static") or []
        if any({"outside_interface": m["oif"], "inside": m["inside"], "global": m["global"]} == expected for m in mappings):
            return Outcome(S.PASS, "NAT_RULE_EXPECTED_PRESENT",
                           f"{expected['inside']} is statically translated to {expected['global']} (both directions) on {outside}.",
                           {"static": mappings}, expected, group)
        return Outcome(S.FAIL, "NAT_RULE_MISSING",
                       f"No static NAT maps {expected['inside']} to {expected['global']} in both directions on {outside}.",
                       {"static": mappings}, expected, group)
    expected = {"outside_interface": outside, "action": "masquerade|snat"}
    if any(rule["oif"] == outside for rule in group.data["rules"]):
        return Outcome(S.PASS, "NAT_RULE_EXPECTED_PRESENT", f"A NAT rule translates traffic leaving {outside}.", {"rules": group.data["rules"]}, expected, group)
    return Outcome(S.FAIL, "NAT_RULE_MISSING", f"No NAT rule translates traffic leaving {outside}.", {"rules": group.data["rules"]}, expected, group)


# --- PRECHECK prerequisite: the base interface must already exist and be up, unless the plan creates it ---------------
def _interface_prerequisite(req, ctx, interfaces):
    interfaces = [name for name in interfaces if name]
    outcomes = []
    for name in interfaces:
        if name in ctx.created_interfaces.get(req.device, set()):
            outcomes.append(Outcome(S.NOT_APPLICABLE, "INTERFACE_EXPECTED_PRESENT", f"{name} is created earlier in this plan.", expected={"interface": name}))
            continue
        group, missing = _need(ctx, req.device, "interfaces")
        if missing:
            outcomes.append(missing)
            continue
        row = group.data.get(name)
        if row is None:
            outcomes.append(Outcome(S.FAIL, "INTERFACE_MISSING", f"Prerequisite interface {name} does not exist and the plan does not create it.",
                                    {"interfaces": sorted(group.data)}, {"interface": name}, group) if group.complete
                            else Outcome(S.UNKNOWN, DATA_UNAVAILABLE, f"Interface evidence is partial; prerequisite {name} could not be confirmed.", group=group))
        elif row.get("admin") == "DOWN":
            outcomes.append(Outcome(S.WARN, "INTERFACE_ADMIN_DOWN", f"Prerequisite interface {name} is administratively down.", row, {"interface": name}, group))
        elif row.get("oper") == "DOWN":
            outcomes.append(Outcome(S.FAIL, "INTERFACE_OPER_DOWN", f"Prerequisite interface {name} is operationally down.", row, {"interface": name}, group))
        else:
            outcomes.append(Outcome(S.PASS, "INTERFACE_EXPECTED_UP", f"Prerequisite interface {name} is up.", row, {"interface": name}, group))
    if not outcomes:
        return Outcome(S.NOT_APPLICABLE, "INTERFACE_EXPECTED_UP", "No pre-existing interface prerequisite.")
    rank = {S.FAIL: 0, S.UNKNOWN: 1, S.WARN: 2, S.PASS: 3, S.NOT_APPLICABLE: 4}
    return sorted(outcomes, key=lambda o: rank[o.status])[0]


def _pre_static_route(req, ctx):
    return _interface_prerequisite(req, ctx, [_facts(req).get("exit_interface")])


def _pre_ospf(req, ctx):
    return _interface_prerequisite(req, ctx, [_facts(req).get("interface")])


def _pre_fhrp(req, ctx):
    return _interface_prerequisite(req, ctx, [_facts(req).get("interface")])


def _pre_dhcp_relay(req, ctx):
    return _interface_prerequisite(req, ctx, [_facts(req).get("interface")])


def _pre_acl_attachment(req, ctx):
    return _interface_prerequisite(req, ctx, [_facts(req).get("interface")])


def _pre_pbr_attachment(req, ctx):
    return _interface_prerequisite(req, ctx, [_facts(req).get("interface")])


def _pre_nat_rule(req, ctx):
    facts = _facts(req)
    return _interface_prerequisite(req, ctx, [facts.get("inside_interface"), facts.get("outside_interface")])


# check type -> (postcheck evaluator, precheck prerequisite evaluator | None).  ``None`` marks a FUTURE_STATE
# requirement: its pre-change absence is expected, so a precheck never fails on it.
def _removal_paths(req, ctx):
    group, missing = _need(ctx, req.device, "config_paths")
    if missing:
        return None, None, missing
    wanted = list(_facts(req).get("absent_paths") or [])
    present = set(group.data)
    return group, (wanted, [path for path in wanted if path in present]), None


def _config_absent(req, ctx):
    group, result, missing = _removal_paths(req, ctx)
    if missing:
        return missing
    wanted, still = result
    expected = {"absent": wanted}
    if not still:
        return Outcome(S.PASS, "CONFIG_REMOVED_CONFIRMED", "The removed configuration is absent from the running configuration.",
                       {"still_present": []}, expected, group)
    return Outcome(S.FAIL, "CONFIG_STILL_PRESENT", "Configuration selected for removal is still present: " + "; ".join(still[:3]),
                   {"still_present": still[:10]}, expected, group)


def _pre_config_absent(req, ctx):
    group, result, missing = _removal_paths(req, ctx)
    if missing:
        return missing
    wanted, present = result
    if len(present) == len(wanted):
        return Outcome(S.PASS, "REMOVAL_TARGET_PRESENT", "The configuration selected for removal is present.", {"present": present[:10]},
                       {"present": wanted}, group)
    if not present:
        return Outcome(S.WARN, "REMOVAL_TARGET_ALREADY_ABSENT", "The configuration selected for removal is already absent; nothing will be sent.",
                       {"present": []}, {"present": wanted}, group)
    return Outcome(S.FAIL, "REMOVAL_TARGET_DRIFTED", "Only part of the configuration selected for removal is present; rebuild the removal.",
                   {"present": present[:10]}, {"present": wanted}, group)


def _management_paths(req):
    """Exact, secret-free EOS running-config signatures for one management-VRF descriptor."""
    facts = _facts(req)
    vrf = facts["vrf"]
    if req.kind == "MGMT_VRF_PRESENT":
        return [f"vrf instance {vrf}"]
    if req.kind == "MGMT_VRF_BOUND":
        header = f"interface {facts['interface']}"
        addresses = []
        for address in facts.get("addresses") or []:
            normalized = norm_cidr(address)
            if not normalized:
                return None
            addresses.append(f"{header} > {'ipv6' if ':' in normalized else 'ip'} address {normalized}")
        return [f"{header} > vrf {vrf}", *addresses]
    if req.kind == "MGMT_VRF_ROUTE_PRESENT":
        verb = "ipv6 route" if str(facts.get("family")).upper() in ("6", "IPV6") else "ip route"
        prefix, hop = norm_prefix(facts["prefix"]), norm_ip(facts["next_hop"])
        return [f"{verb} vrf {vrf} {prefix} {hop}"] if prefix and hop else None
    service = str(facts["service"]).upper()
    if service == "SYSLOG":
        return [f"logging vrf {vrf} host {facts['host']}"] if facts.get("host") else None
    if service == "NTP":
        return [f"ntp server vrf {vrf} {facts['host']}"] if facts.get("host") else None
    if service == "SNMP":
        return [f"snmp-server vrf {vrf}"]
    return None


def _management_config(req, ctx):
    service = str(_facts(req).get("service", "")).upper()
    service_keys = {"SSH": "ssh", "EAPI": "http-commands", "GNMI": "gnmi"}
    if req.kind == "MGMT_SERVICE_IN_VRF" and service in service_keys:
        # Consume normalized booleans from the read-only collector.  A health
        # result never constructs device enable/disable commands.
        group, missing = _need(ctx, req.device, "management_services")
        if missing:
            return missing
        vrf = _facts(req)["vrf"]
        enabled = (group.data.get(service_keys[service]) or {}).get(vrf)
        observed, expected_state = {"service": service, "vrf": vrf, "enabled": enabled}, {"enabled": True}
        if enabled is True:
            return Outcome(S.PASS, "MGMT_CONFIG_PRESENT", "Management service is enabled in the intended VRF.",
                           observed, expected_state, group)
        if not group.complete:
            return Outcome(S.UNKNOWN, DATA_UNAVAILABLE, "Management service evidence is partial.", observed, expected_state, group)
        return Outcome(S.FAIL, "MGMT_CONFIG_MISSING", "Management service is absent or disabled in the intended VRF.",
                       observed, expected_state, group)
    expected = _management_paths(req)
    if expected is None:
        return Outcome(S.UNKNOWN, "REQUIREMENT_NOT_IMPLEMENTED", f"{req.kind} service has no verified EOS read-back.")
    group, missing = _need(ctx, req.device, "config_paths")
    if missing:
        return missing
    present = set(group.data)
    absent = [path for path in expected if path not in present]
    if not absent:
        return Outcome(S.PASS, "MGMT_CONFIG_PRESENT", "Management VRF configuration matches the plan.",
                       {"present": expected}, {"paths": expected}, group)
    if not group.complete:
        return Outcome(S.UNKNOWN, DATA_UNAVAILABLE, "Running-configuration evidence is partial.",
                       {"missing": absent}, {"paths": expected}, group)
    return Outcome(S.FAIL, "MGMT_CONFIG_MISSING", "Management VRF configuration differs from the plan.",
                   {"missing": absent}, {"paths": expected}, group)


EVALUATORS = {
    "INTERFACE_PRESENT": (_interface_present, None),
    "INTERFACE_ADMIN_STATE": (_interface_admin, None),
    "INTERFACE_OPER_STATE": (_interface_oper, None),
    "ADDRESS_PRESENT": (_address, None),
    "STATIC_ROUTE_PRESENT": (_static_route, _pre_static_route),
    "OSPF_NEIGHBOR_EXPECTED": (_ospf, _pre_ospf),
    "ISIS_NEIGHBOR_EXPECTED": (_isis, _pre_ospf),
    "ISIS_ROUTE_EXPECTED": (_isis_route, None),
    "RIP_NEIGHBOR_EXPECTED": (_rip_neighbor, None),
    "RIP_ROUTE_EXPECTED": (_rip_route, None),
    "BGP_NEIGHBOR_EXPECTED": (_bgp, None),
    "ROUTING_PROCESS_CONFIG": (_routing_process, None),
    "ROUTING_BINDING_CONFIG": (_routing_binding, None),
    "BGP_NEIGHBOR_CONFIG": (_bgp_config, None),
    "BGP_NETWORK_CONFIG": (_bgp_network, None),
    "FHRP_VIRTUAL_ADDRESS_PRESENT": (_fhrp, _pre_fhrp),
    "DHCP_RELAY_CONFIG_PRESENT": (_dhcp_relay, _pre_dhcp_relay),
    "ACL_DEFINITION_PRESENT": (_acl_definition, None),
    "ACL_ATTACHMENT_PRESENT": (_acl_attachment, _pre_acl_attachment),
    "NAT_RULE_PRESENT": (_nat_rule, _pre_nat_rule),
    "PBR_POLICY_PRESENT": (_pbr_policy, None),
    "PBR_ATTACHMENT_PRESENT": (_pbr_attachment, _pre_pbr_attachment),
    "CONFIG_OBJECT_ABSENT": (_config_absent, _pre_config_absent),
    "MGMT_VRF_PRESENT": (_management_config, None),
    "MGMT_VRF_BOUND": (_management_config, None),
    "MGMT_VRF_ROUTE_PRESENT": (_management_config, None),
    "MGMT_SERVICE_IN_VRF": (_management_config, None),
}
# the PASS-spelling code of each FUTURE_STATE check type (used for its NOT_APPLICABLE precheck result)
FUTURE_STATE_CODE = {
    "INTERFACE_PRESENT": "INTERFACE_EXPECTED_PRESENT", "INTERFACE_ADMIN_STATE": "INTERFACE_EXPECTED_UP",
    "INTERFACE_OPER_STATE": "INTERFACE_EXPECTED_UP", "ADDRESS_PRESENT": "ADDRESS_EXPECTED_PRESENT",
    "BGP_NEIGHBOR_EXPECTED": "BGP_EXPECTED_ESTABLISHED", "ACL_DEFINITION_PRESENT": "ACL_DEFINITION_EXPECTED_PRESENT",
    "PBR_POLICY_PRESENT": "PBR_POLICY_EXPECTED_PRESENT",
    "ROUTING_PROCESS_CONFIG": "ROUTING_CONFIG_PRESENT", "ROUTING_BINDING_CONFIG": "ROUTING_CONFIG_PRESENT",
    "BGP_NEIGHBOR_CONFIG": "ROUTING_CONFIG_PRESENT", "BGP_NETWORK_CONFIG": "ROUTING_CONFIG_PRESENT",
    "MGMT_VRF_PRESENT": "MGMT_CONFIG_PRESENT", "MGMT_VRF_BOUND": "MGMT_CONFIG_PRESENT",
    "MGMT_VRF_ROUTE_PRESENT": "MGMT_CONFIG_PRESENT", "MGMT_SERVICE_IN_VRF": "MGMT_CONFIG_PRESENT",
}
# facts each check type needs in the descriptor; a descriptor without them (an older plan) is INCOMPLETE, never guessed
REQUIRED_FACTS = {
    "INTERFACE_PRESENT": ("interface",), "INTERFACE_ADMIN_STATE": ("interface",), "INTERFACE_OPER_STATE": ("interface",),
    "ADDRESS_PRESENT": ("interface", "address"), "STATIC_ROUTE_PRESENT": ("prefix",), "OSPF_NEIGHBOR_EXPECTED": ("interface",),
    "ISIS_NEIGHBOR_EXPECTED": ("interface",), "ISIS_ROUTE_EXPECTED": ("prefix",), "RIP_NEIGHBOR_EXPECTED": ("interface",),
    "RIP_ROUTE_EXPECTED": ("prefix",),
    "BGP_NEIGHBOR_EXPECTED": ("peer",), "FHRP_VIRTUAL_ADDRESS_PRESENT": ("interface", "virtual_addresses"),
    "DHCP_RELAY_CONFIG_PRESENT": ("interface", "destination"), "ACL_DEFINITION_PRESENT": ("name",),
    "ACL_ATTACHMENT_PRESENT": ("interface", "acl_name", "direction"), "NAT_RULE_PRESENT": ("outside_interface",),
    "PBR_POLICY_PRESENT": ("name", "sequences"), "PBR_ATTACHMENT_PRESENT": ("interface", "policy_name"),
    "CONFIG_OBJECT_ABSENT": ("absent_paths",),
    "ROUTING_PROCESS_CONFIG": ("protocol",), "ROUTING_BINDING_CONFIG": ("protocol", "interface"),
    "BGP_NEIGHBOR_CONFIG": ("peer",), "BGP_NETWORK_CONFIG": ("prefix", "family"),
    "MGMT_VRF_PRESENT": ("vrf",), "MGMT_VRF_BOUND": ("vrf", "interface"),
    "MGMT_VRF_ROUTE_PRESENT": ("vrf", "prefix", "next_hop", "family"),
    "MGMT_SERVICE_IN_VRF": ("vrf", "service"),
}


# --- the engine --------------------------------------------------------------------------------------------------
def _evaluate_one(req: Requirement, check_type: str, phase: str, ctx: EvalContext) -> Outcome:
    if check_type == UNKNOWN_TYPE:
        return Outcome(S.UNKNOWN, "REQUIREMENT_UNKNOWN_TYPE", f"Requirement type {req.kind or '(none)'} is not known to the health engine; it was NOT verified.")
    if check_type == NOT_IMPLEMENTED:
        if phase == Phase.PRECHECK:
            return Outcome(S.NOT_APPLICABLE, "REQUIREMENT_NOT_IMPLEMENTED", f"{req.kind} has no prerequisite to check before deployment.")
        return Outcome(S.UNKNOWN, "REQUIREMENT_NOT_IMPLEMENTED", f"No evaluator exists for {req.kind}; it was NOT verified.")
    facts = req.expected
    if facts is None or any(facts.get(key) in (None, "") for key in REQUIRED_FACTS[check_type]):
        return Outcome(S.UNKNOWN, "REQUIREMENT_DESCRIPTOR_INCOMPLETE", "The plan's descriptor carries no expected facts for this requirement (an older plan); rebuild the plan.")
    post, pre = EVALUATORS[check_type]
    if phase == Phase.POSTCHECK:
        return post(req, ctx)
    if pre is not None:
        return pre(req, ctx)
    # FUTURE_STATE: absence before deployment is expected -- never a failure.
    informational = post(req, ctx)
    if informational.status == S.PASS:
        return Outcome(S.PASS, informational.code, informational.message + " (already satisfied before deployment; idempotent)",
                       informational.observed, informational.expected, informational.group)
    return Outcome(S.NOT_APPLICABLE, FUTURE_STATE_CODE[check_type],
                   "Future-state requirement: it is not required before deployment and is verified afterwards.", expected=informational.expected)


def _to_result(req: Requirement, check_type: str, outcome: Outcome, phase: str, ctx: EvalContext) -> CheckResult:
    code = outcome.code
    if code == DATA_UNAVAILABLE:
        code = "PRECHECK_DATA_UNAVAILABLE" if phase == Phase.PRECHECK else "POSTCHECK_DATA_UNAVAILABLE"
    group = outcome.group
    return CheckResult(
        code, outcome.status, req.device, outcome.message, group.source if group is not None else "PLAN",
        observed=outcome.observed, expected=outcome.expected, observed_at=iso(group.observed_at) if group is not None else None,
        freshness=group.freshness(ctx.evidence.now, ctx.evidence.thresholds) if group is not None else Freshness.UNKNOWN,
        role=ctx.roles.get(req.device, Role.TARGET), phase=phase, requirement=check_type if check_type not in (NOT_IMPLEMENTED, UNKNOWN_TYPE) else req.kind,
        cfg_id=req.cfg_id, subject=req.subject,
    )


def evaluate_requirements(requirements, phase: str, evidence: EvidenceSet, *, roles: dict | None = None,
                          one_sided_ospf=frozenset(), isolated_ports=frozenset()) -> RequirementEvaluation:
    """Evaluate normalized requirements against collected evidence.  Deterministic; performs no I/O."""
    if phase not in Phase.ALL:
        raise ValueError(f"Unknown verification phase {phase!r}")
    requirements = list(requirements)
    ctx = EvalContext(evidence=evidence, created_interfaces=plan_interfaces(requirements), one_sided_ospf=frozenset(one_sided_ospf), roles=dict(roles or {}),
                      isolated_ports=frozenset(isolated_ports))
    results = []
    for req in requirements:
        for check_type in req.check_types:
            results.append(_to_result(req, check_type, _evaluate_one(req, check_type, phase, ctx), phase, ctx))
    verdict = postcheck_result(results) if phase == Phase.POSTCHECK else precheck_result(results)
    unverified = sorted({(r.cfg_id, r.requirement, r.check_code) for r in results
                         if r.check_code in ("REQUIREMENT_NOT_IMPLEMENTED", "REQUIREMENT_UNKNOWN_TYPE", "REQUIREMENT_DESCRIPTOR_INCOMPLETE")
                         and r.status == S.UNKNOWN})
    summary = {"requirements": len(requirements), "checks": len(results),
               "unverified": [{"cfg_id": c, "requirement": q, "code": k} for c, q, k in unverified]}
    return RequirementEvaluation(phase=phase, result=verdict, results=results, counts=count_by_status(results), summary=summary)


def _one_sided_ospf(plan) -> frozenset:
    """{(device, interface)} the pinned validation flagged OSPF_ONE_SIDED (a peer relationship was NOT validated)."""
    found = set()
    for finding in ((plan.validation_run.report or {}).get("findings") or []):
        if finding.get("code") == "OSPF_ONE_SIDED":
            end = str((finding.get("evidence") or {}).get("participating_end", ""))
            device, _, interface = end.partition(":")
            if device and interface:
                found.add((device, interface))
    return frozenset(found)


def isolated_ports(plan) -> frozenset:
    """{(device, interface)} of the plan's devices whose link to a trusted upstream is held by an ENFORCED / VERIFIED isolation
    policy (V2 Phase 5): the upstream keeps that port passive and filtered until production admission releases it."""
    from ... import models

    devices = set(plan.configlets.values_list("target_device", flat=True))
    if not devices:
        return frozenset()
    rows = models.IsolationPolicy.objects.filter(device__name__in=devices, state__in=(models.IsolationState.ENFORCED, models.IsolationState.VERIFIED))
    return frozenset((row.device.name, row.attachment.local_interface) for row in rows.select_related("device", "attachment")
                     if row.attachment.local_interface)


def evaluate_plan_requirements(plan, phase: str, evidence: EvidenceSet, *, roles: dict | None = None) -> RequirementEvaluation:
    """THE reusable verification engine: a plan's Phase-14 requirements vs supplied evidence, for PRECHECK or POSTCHECK.

    Pure with respect to the outside world (only reads the plan's own frozen rows); the caller supplies ``evidence``.
    A later deployment phase calls this after a push with fresh live evidence and gets the same evaluation the precheck
    used, with the POSTCHECK expectations.
    """
    return evaluate_requirements(normalize_plan(plan), phase, evidence, roles=roles, one_sided_ospf=_one_sided_ospf(plan),
                                 isolated_ports=isolated_ports(plan))
