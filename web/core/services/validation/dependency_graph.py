"""Semantic dependency graph of accepted intent (NOT a deployment plan).

Nodes are stable objects (interface, address, routing instance/binding, FHRP
instance, NAT pool/rule, DHCP relay/client, ACL/attachment, PBR
policy/attachment ...).  An edge ``A -> B`` reads "A depends on B".  Edge
types are explicit:

    REQUIRES                 the dependent cannot exist without the target
                             (address -> interface, binding -> instance)
    REFERENCES               a soft reference (PBR output interface)
    DEFINE_BEFORE_ATTACH     an attachment/use needs its definition first
                             (ACL attachment -> ACL, NAT rule -> pool)
    PARENT_BEFORE_CHILD      subinterface -> parent interface
    ADDRESS_BEFORE_ROUTING   routing object -> a candidate address it relies on
    INTERFACE_BEFORE_SERVICE service/protocol object -> the interface it binds

A reference to a missing object is kept as an edge with status MISSING (and
becomes DEPENDENCY_MISSING) -- it is never silently dropped.  Cycles among
RESOLVED edges become DEPENDENCY_CYCLE with the full path as evidence.

This module deliberately produces NO execution order, device order,
transaction stage, rollback order, or Configlet: that is Phase 14.
"""

from __future__ import annotations

import ipaddress

from .findings import Code

GRAPH_SCHEMA_VERSION = 1
MAX_NODES = 2000
MAX_EDGES = 4000

REQUIRES = "REQUIRES"
REFERENCES = "REFERENCES"
DEFINE_BEFORE_ATTACH = "DEFINE_BEFORE_ATTACH"
PARENT_BEFORE_CHILD = "PARENT_BEFORE_CHILD"
ADDRESS_BEFORE_ROUTING = "ADDRESS_BEFORE_ROUTING"
INTERFACE_BEFORE_SERVICE = "INTERFACE_BEFORE_SERVICE"
EDGE_TYPES = (
    REQUIRES, REFERENCES, DEFINE_BEFORE_ATTACH, PARENT_BEFORE_CHILD,
    ADDRESS_BEFORE_ROUTING, INTERFACE_BEFORE_SERVICE,
)


def node_id(device: str, node_type: str, object_id: str) -> str:
    return f"{device}/{node_type}/{object_id}"


class GraphBuilder:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}

    def node(self, device: str, node_type: str, object_id: str, label: str) -> str:
        nid = node_id(device, node_type, object_id)
        self.nodes.setdefault(nid, {
            "id": nid, "device": device, "type": node_type, "object_id": object_id, "label": label,
        })
        return nid

    def edge(self, source: str, target: str, edge_type: str, *, status: str = "RESOLVED", reason: str = "") -> None:
        if edge_type not in EDGE_TYPES:
            raise ValueError(f"Unknown edge type {edge_type!r}")
        self.edges[(source, target, edge_type)] = {
            "from": source, "to": target, "type": edge_type, "status": status, "reason": reason,
        }


def _family_of(value) -> int | None:
    return {"IPV4": 4, "IPV6": 6, "OSPFV2": 4, "OSPFV3": 6}.get(value)


def _add_ref(builder, source, device, ref_type, ref_id, edge_type, exists: bool, *, required: bool, reason: str):
    """Add an edge to `ref_id`, MISSING when it does not resolve."""
    if not ref_id:
        if required:
            builder.edge(source, node_id(device, ref_type, "<unset>"), edge_type, status="MISSING", reason=f"{reason} (unset)")
        return
    target = node_id(device, ref_type, ref_id)
    builder.edge(source, target, edge_type, status="RESOLVED" if exists else "MISSING", reason=reason)


def build_graph(model) -> dict:
    builder = GraphBuilder()
    for name in sorted(model.devices):
        device = model.devices[name]
        interfaces = device.interfaces

        def iface_exists(iid, _i=interfaces):
            return iid in _i

        # interfaces + addresses ------------------------------------------------
        for interface in device.ordered(interfaces):
            iid = interface["id"]
            inode = builder.node(name, "interface", iid, f"{name} {interface.get('name')}")
            parent = interface.get("parent_id") or ""
            if parent:
                _add_ref(builder, inode, name, "interface", parent, PARENT_BEFORE_CHILD, iface_exists(parent),
                         required=False, reason="parent interface")
            for address in sorted((interface.get("addresses") or {}).values(), key=lambda a: a.get("id", "")):
                anode = builder.node(name, "address", address["id"],
                                     f"{name} {interface.get('name')} {address.get('cidr') or address.get('ipam_prefix') or 'AUTO'}")
                builder.edge(anode, inode, REQUIRES, reason="address on interface")

        def address_nodes(interface_id, family):
            return [
                node_id(name, "address", a.address_id)
                for a in model.addresses_of(name, interface_id)
                if family is None or a.family == family
            ]

        # routing ---------------------------------------------------------------
        routing = device.routing
        for route in sorted((routing.get("static_routes") or {}).values(), key=lambda r: r.get("id", "")):
            rnode = builder.node(name, "static_route", route["id"], f"{name} static {route.get('destination') or route['id']}")
            if route.get("next_hop_type") == "INTERFACE":
                ref = route.get("next_hop_interface_id") or ""
                _add_ref(builder, rnode, name, "interface", ref, INTERFACE_BEFORE_SERVICE, iface_exists(ref),
                         required=True, reason="static route exit interface")
                if iface_exists(ref):
                    for target in address_nodes(ref, _family_of(route.get("family"))):
                        builder.edge(rnode, target, ADDRESS_BEFORE_ROUTING, reason="exit interface address")
            elif route.get("next_hop_address"):
                try:
                    hop = ipaddress.ip_address(route["next_hop_address"])
                except ValueError:
                    hop = None
                for record in model.device_addresses(name):
                    if hop is not None and hop.version == record.family and hop in record.network:
                        builder.edge(rnode, node_id(name, "address", record.address_id), ADDRESS_BEFORE_ROUTING,
                                     reason="next hop in connected network")
        for family in ("rip", "ospf", "isis", "eigrp"):
            for instance in sorted((routing.get(family) or {}).values(), key=lambda r: r.get("id", "")):
                inode = builder.node(name, f"routing_{family}", instance["id"], f"{name} {family.upper()} {instance['id']}")
                if family == "ospf":
                    fam = _family_of(instance.get("version"))
                elif family in ("rip", "eigrp"):
                    fam = _family_of(instance.get("address_family"))
                else:
                    fam = None
                for binding in sorted((instance.get("interfaces") or {}).values(), key=lambda b: b.get("id", "")):
                    bnode = builder.node(name, "routing_binding", binding["id"], f"{name} {family.upper()} binding")
                    builder.edge(bnode, inode, REQUIRES, reason="binding belongs to instance")
                    ref = binding.get("interface_id") or ""
                    _add_ref(builder, bnode, name, "interface", ref, INTERFACE_BEFORE_SERVICE, iface_exists(ref),
                             required=True, reason=f"{family.upper()} interface binding")
                    if iface_exists(ref):
                        for target in address_nodes(ref, fam):
                            builder.edge(bnode, target, ADDRESS_BEFORE_ROUTING, reason="interface address")
        for instance in sorted((routing.get("bgp") or {}).values(), key=lambda r: r.get("id", "")):
            inode = builder.node(name, "routing_bgp", instance["id"], f"{name} BGP AS{instance.get('local_asn')}")
            for neighbor in sorted((instance.get("neighbors") or {}).values(), key=lambda n: n.get("id", "")):
                nnode = builder.node(name, "bgp_neighbor", neighbor["id"], f"{name} BGP peer {neighbor.get('peer_address')}")
                builder.edge(nnode, inode, REQUIRES, reason="neighbor belongs to instance")
                ref = neighbor.get("update_source_interface_id") or ""
                if ref:
                    _add_ref(builder, nnode, name, "interface", ref, INTERFACE_BEFORE_SERVICE, iface_exists(ref),
                             required=False, reason="BGP update source")
                    if iface_exists(ref):
                        for target in address_nodes(ref, _family_of(neighbor.get("family"))):
                            builder.edge(nnode, target, ADDRESS_BEFORE_ROUTING, reason="update-source address")
            for network in sorted((instance.get("networks") or {}).values(), key=lambda n: n.get("id", "")):
                wnode = builder.node(name, "bgp_network", network["id"], f"{name} BGP network {network.get('cidr')}")
                builder.edge(wnode, inode, REQUIRES, reason="network belongs to instance")

        # FHRP ------------------------------------------------------------------
        for instance in sorted(device.fhrp_instances.values(), key=lambda r: r.get("id", "")):
            fnode = builder.node(name, "fhrp", instance["id"], f"{name} {instance.get('protocol')} {instance['id']}")
            ref = instance.get("interface_id") or ""
            _add_ref(builder, fnode, name, "interface", ref, INTERFACE_BEFORE_SERVICE, iface_exists(ref),
                     required=True, reason="FHRP interface")

        # NAT -------------------------------------------------------------------
        pools = device.nat.get("pools") or {}
        for pool in sorted(pools.values(), key=lambda r: r.get("id", "")):
            builder.node(name, "nat_pool", pool["id"], f"{name} NAT pool {pool.get('name') or pool['id']}")
        for rule in sorted((device.nat.get("rules") or {}).values(), key=lambda r: r.get("id", "")):
            nnode = builder.node(name, "nat_rule", rule["id"], f"{name} NAT rule {rule['id']}")
            pool_ref = rule.get("pool_id") or ""
            if pool_ref:
                _add_ref(builder, nnode, name, "nat_pool", pool_ref, DEFINE_BEFORE_ATTACH, pool_ref in pools,
                         required=False, reason="NAT pool")
            for field_name, label in (("inside_interface_id", "NAT inside interface"), ("outside_interface_id", "NAT outside interface")):
                ref = rule.get(field_name) or ""
                if ref:
                    _add_ref(builder, nnode, name, "interface", ref, INTERFACE_BEFORE_SERVICE, iface_exists(ref),
                             required=False, reason=label)

        # DHCP ------------------------------------------------------------------
        for kind, collection in (("dhcp_relay", device.dhcp.get("relays") or {}), ("dhcp_client", device.dhcp.get("clients") or {})):
            for obj in sorted(collection.values(), key=lambda r: r.get("id", "")):
                dnode = builder.node(name, kind, obj["id"], f"{name} {kind.replace('_', ' ')} {obj['id']}")
                ref = obj.get("interface_id") or ""
                _add_ref(builder, dnode, name, "interface", ref, INTERFACE_BEFORE_SERVICE, iface_exists(ref),
                         required=True, reason=f"{kind.replace('_', ' ')} interface")

        # ACL -------------------------------------------------------------------
        acls = device.acls
        for acl in sorted(acls.values(), key=lambda r: r.get("id", "")):
            builder.node(name, "acl", acl["id"], f"{name} ACL {acl.get('name') or acl['id']}")
        for attachment in sorted(device.acl_attachments.values(), key=lambda r: r.get("id", "")):
            anode = builder.node(name, "acl_attachment", attachment["id"], f"{name} ACL attachment {attachment['id']}")
            acl_ref = attachment.get("acl_id") or ""
            _add_ref(builder, anode, name, "acl", acl_ref, DEFINE_BEFORE_ATTACH, acl_ref in acls,
                     required=True, reason="ACL definition")
            ref = attachment.get("interface_id") or ""
            _add_ref(builder, anode, name, "interface", ref, INTERFACE_BEFORE_SERVICE, iface_exists(ref),
                     required=True, reason="ACL attachment interface")

        # PBR -------------------------------------------------------------------
        policies = device.pbr.get("policies") or {}
        for policy in sorted(policies.values(), key=lambda r: r.get("id", "")):
            pnode = builder.node(name, "pbr_policy", policy["id"], f"{name} PBR policy {policy.get('name') or policy['id']}")
            for seq in sorted((policy.get("sequences") or {}).values(), key=lambda r: r.get("id", "")):
                snode = builder.node(name, "pbr_sequence", seq["id"], f"{name} PBR sequence {seq['id']}")
                builder.edge(snode, pnode, REQUIRES, reason="sequence belongs to policy")
                ref = seq.get("output_interface_id") or ""
                if ref:
                    _add_ref(builder, snode, name, "interface", ref, REFERENCES, iface_exists(ref),
                             required=False, reason="PBR output interface")
        for attachment in sorted((device.pbr.get("attachments") or {}).values(), key=lambda r: r.get("id", "")):
            anode = builder.node(name, "pbr_attachment", attachment["id"], f"{name} PBR attachment {attachment['id']}")
            pol_ref = attachment.get("policy_id") or ""
            _add_ref(builder, anode, name, "pbr_policy", pol_ref, DEFINE_BEFORE_ATTACH, pol_ref in policies,
                     required=True, reason="PBR policy definition")
            ref = attachment.get("interface_id") or ""
            _add_ref(builder, anode, name, "interface", ref, INTERFACE_BEFORE_SERVICE, iface_exists(ref),
                     required=True, reason="PBR attachment interface")

        # Management VRF (V2 Phase 4) ------------------------------------------------
        # binding -> VRF definition, the interface and its addresses (the binding re-applies them inside the VRF);
        # a route / service -> its VRF and every binding of that VRF (a VRF route or service needs a bound interface).
        management = device.management
        vrfs = management.get("vrfs") or {}
        bindings_by_vrf: dict = {}
        for vrf in sorted(vrfs.values(), key=lambda r: r.get("id", "")):
            builder.node(name, "mgmt_vrf", vrf["id"], f"{name} management VRF {vrf.get('name') or vrf['id']}")
        for binding in sorted((management.get("bindings") or {}).values(), key=lambda r: r.get("id", "")):
            bnode = builder.node(name, "mgmt_vrf_binding", binding["id"], f"{name} management VRF binding {binding['id']}")
            vrf_ref = binding.get("vrf_id") or ""
            _add_ref(builder, bnode, name, "mgmt_vrf", vrf_ref, DEFINE_BEFORE_ATTACH, vrf_ref in vrfs, required=True,
                     reason="management VRF definition")
            ref = binding.get("interface_id") or ""
            _add_ref(builder, bnode, name, "interface", ref, INTERFACE_BEFORE_SERVICE, iface_exists(ref), required=True,
                     reason="management VRF interface")
            for address in sorted(((interfaces.get(ref) or {}).get("addresses") or {}).values(), key=lambda a: a.get("id", "")):
                builder.edge(bnode, node_id(name, "address", address["id"]), REQUIRES, reason="binding re-applies the interface addresses")
            bindings_by_vrf.setdefault(vrf_ref, []).append(bnode)
        for collection, node_type, label in (("routes", "mgmt_vrf_route", "route"), ("services", "mgmt_vrf_service", "service")):
            for obj in sorted((management.get(collection) or {}).values(), key=lambda r: r.get("id", "")):
                onode = builder.node(name, node_type, obj["id"], f"{name} management VRF {label} {obj['id']}")
                vrf_ref = obj.get("vrf_id") or ""
                _add_ref(builder, onode, name, "mgmt_vrf", vrf_ref, DEFINE_BEFORE_ATTACH, vrf_ref in vrfs, required=True,
                         reason="management VRF definition")
                for bnode in bindings_by_vrf.get(vrf_ref, []):
                    builder.edge(onode, bnode, REQUIRES, reason=f"a management VRF {label} needs the VRF's interface")
                source = obj.get("source_interface_id") or ""
                if source:
                    _add_ref(builder, onode, name, "interface", source, INTERFACE_BEFORE_SERVICE, iface_exists(source), required=False,
                             reason="management service source interface")

    # Raw Configlets (Phase 18) are OPAQUE nodes.  Their dependencies are the operator's EXPLICIT stable node references (never
    # inferred from CLI text); an unresolvable reference stays a MISSING edge and a cycle is found like any other.
    raw_items = ((model.snapshot.get("raw_configlets") or {}).get("items")) or []
    for item in raw_items:
        builder.node(item["device"], "raw_configlet", item["raw_id"], f"{item['device']} raw Configlet {item['raw_id']} ({item['name']})")
    for item in raw_items:
        for ref in item["dependencies"]:
            builder.edge(item["node_id"], ref, REQUIRES, status="RESOLVED" if ref in builder.nodes else "MISSING",
                         reason="declared raw Configlet dependency")

    # Remove Configuration: one node per resolved removal item; "X requires Y" means Y is removed FIRST (whatever still
    # references an object is detached / deleted before the object itself).  Only a READY analysis produces nodes.
    from .removals import analysis_for
    for entry in ((model.snapshot.get("config_removals") or {}).get("items")) or []:
        result = analysis_for(entry)
        if result["status"] != "READY":
            continue
        ids = {item["id"]: removal_node_object_id(item["id"]) for item in result["items"]}
        for item in result["items"]:
            builder.node(entry["device"], "config_removal", ids[item["id"]], f"{entry['device']} remove {item['label']}")
        for item in result["items"]:
            for dep in item["depends_on"]:
                builder.edge(node_id(entry["device"], "config_removal", ids[item["id"]]), node_id(entry["device"], "config_removal", ids[dep]),
                             REQUIRES, reason="a referrer is removed before what it references")
    return _finalize(builder)


def removal_node_object_id(item_id: str) -> str:
    """Stable, path-safe graph object id for one removal item (its text id may contain spaces and slashes)."""
    import hashlib

    return "RM-" + hashlib.sha256(item_id.encode()).hexdigest()[:12]


def find_cycles(edges: list[dict]) -> list[list[str]]:
    """Deterministic cycle detection over RESOLVED edges (iterative DFS)."""
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        if edge["status"] != "RESOLVED":
            continue
        adjacency.setdefault(edge["from"], []).append(edge["to"])
        adjacency.setdefault(edge["to"], [])
    for targets in adjacency.values():
        targets.sort()
    color: dict[str, int] = {}  # 0/absent white, 1 grey, 2 black
    cycles: list[list[str]] = []
    seen: set[tuple] = set()
    for start in sorted(adjacency):
        if color.get(start):
            continue
        stack = [(start, iter(adjacency[start]))]
        path = [start]
        color[start] = 1
        while stack:
            current, children = stack[-1]
            advanced = False
            for child in children:
                state = color.get(child, 0)
                if state == 0:
                    color[child] = 1
                    path.append(child)
                    stack.append((child, iter(adjacency[child])))
                    advanced = True
                    break
                if state == 1:
                    cycle = path[path.index(child):] + [child]
                    body = cycle[:-1]
                    pivot = body.index(min(body))
                    canonical = tuple(body[pivot:] + body[:pivot])
                    if canonical not in seen:
                        seen.add(canonical)
                        cycles.append(list(canonical) + [canonical[0]])
            if not advanced:
                color[current] = 2
                stack.pop()
                path.pop()
    return sorted(cycles)


def _finalize(builder: GraphBuilder) -> dict:
    nodes = [builder.nodes[key] for key in sorted(builder.nodes)][:MAX_NODES]
    edges = [builder.edges[key] for key in sorted(builder.edges)][:MAX_EDGES]
    cycles = find_cycles(edges)
    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "kind": "semantic_dependency_graph",
        "note": "Semantic dependencies of accepted intent only. This is NOT a deployment plan: "
                "no execution order, device order, stage, or Configlet is derived here (Phase 14).",
        "nodes": nodes,
        "edges": edges,
        "cycles": cycles,
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "missing": sum(1 for e in edges if e["status"] == "MISSING"),
            "cycles": len(cycles),
            "truncated": len(builder.nodes) > MAX_NODES or len(builder.edges) > MAX_EDGES,
        },
    }


def validate_dependencies(ctx) -> None:
    graph = build_graph(ctx.model)
    ctx.graph = graph
    nodes = {n["id"]: n for n in graph["nodes"]}
    for edge in graph["edges"]:
        if edge["status"] != "MISSING":
            continue
        source = nodes.get(edge["from"], {})
        ctx.add(
            Code.DEPENDENCY_MISSING,
            f"{source.get('label', edge['from'])} depends on a missing object ({edge['reason']}).",
            device=source.get("device"), object_type=source.get("type"), object_id=source.get("object_id"),
            related_objects=[edge["to"]], source="DEPENDENCY_GRAPH",
            evidence={"edge_type": edge["type"], "from": edge["from"], "to": edge["to"], "reason": edge["reason"]},
            remediation="Re-select an existing object or remove the dangling reference.",
        )
    for cycle in graph["cycles"]:
        first = nodes.get(cycle[0], {})
        ctx.add(
            Code.DEPENDENCY_CYCLE,
            "Dependency cycle: " + " -> ".join(cycle),
            device=first.get("device"), object_type=first.get("type"), object_id=first.get("object_id"),
            related_objects=cycle[:-1], source="DEPENDENCY_GRAPH",
            evidence={"cycle": cycle},
            remediation="Break the cycle by removing or re-pointing one of the listed references.",
        )
    ctx.checked["graph_nodes"] = graph["summary"]["nodes"]
    ctx.checked["graph_edges"] = graph["summary"]["edges"]
