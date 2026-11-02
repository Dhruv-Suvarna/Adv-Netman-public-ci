"""Turn validated Phase-13 graph nodes into Configlet specs.  Pure: no DB writes, no network.

Each graph node (interface, address, static route, routing process / binding, BGP
neighbor / network, FHRP, DHCP relay, NAT rule, ACL / attachment ...) becomes ONE
meaningful atomic Configlet -- except a BGP neighbor, which is decomposed into its
*definition* (DEFINE) and one *address-family activation* (ACTIVATE_ATTACH) per
activated family, because those deploy, verify and roll back independently.

The snippet text is never composed here.  It comes from the platform driver via
``snippets`` (context slice without / with the object).  Behavior depends only on
``platform`` and structured intent -- never on a device name.
"""

from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass, field

from ... import models
from .. import candidate_renderer, platform_drivers
from ..raw_configlets import assertions as raw_assertions
from . import priorities, snippets
from .errors import PlanGenerationError

ROUTING_FAMILIES = ("rip", "ospf", "isis", "eigrp")


@dataclass
class ConfigletSpec:
    key: str                      # stable identity within the plan: "<node id>" or "<node id>#<sub>"
    node_id: str                  # the graph node this Configlet realizes ("<device>/<type>/<object id>")
    device: str
    platform: str
    object_type: str              # priorities.CATALOGUE key
    object_id: str
    source_type: str              # the graph node type
    label: str
    lines: list[str]
    intent: object = None
    derived: dict | None = None   # validation-derived value metadata (AUTO addresses)
    parent_key: str | None = None  # an internal dependency on another Configlet of the same object
    facts: dict = field(default_factory=dict)  # secret-free EXPECTED facts for Phase-15 verification (never rendered)
    origin: str = "STRUCTURED"                 # Phase 18: STRUCTURED (planner-generated) or RAW (operator-authored, opaque)
    raw: dict | None = None                    # RAW only: the pinned revision / verification facts and declared assertions
    priority_override: int | None = None       # RAW only: the operator's explicit, declared priority
    removal: dict | None = None                # REMOVAL only: restore lines, verification paths, snapshot provenance
    capability_feature: str = ""               # exact Phase-4 feature key; never inferred from a broad object type

    @property
    def object_class(self) -> priorities.ObjectClass:
        cls = priorities.CATALOGUE[self.object_type]
        if self.priority_override is not None:
            return dataclasses.replace(cls, priority=models.DeploymentPriority(self.priority_override))
        return cls

    @property
    def sort_key(self) -> tuple:
        cls = self.object_class
        return (int(cls.priority), self.device, priorities.OPERATION_RANK[cls.operation], self.key)


class DeviceContext:
    """One device's ACCEPTED, fully hydrated intent (the same state the candidate renderer uses)."""

    def __init__(self, intent, revision, derived_addresses: dict):
        state = candidate_renderer.hydrate_state(intent, revision, use_draft=False)
        self.intent = intent
        self.name = intent.device_name
        self.platform = intent.platform
        self.driver = platform_drivers.get_driver(intent.platform)
        self.hostname = state["field_values"].get("device.hostname") or intent.device_name
        self.field_values = {"device.hostname": self.hostname, "device.description": ""}
        self.interfaces = copy.deepcopy(state["interfaces"])
        self.routing = copy.deepcopy(state["routing"])
        self.phase12 = copy.deepcopy(state["phase12"])
        self.auto: dict[str, dict] = {}
        self._apply_derived_auto_addresses(derived_addresses)

    def _apply_derived_auto_addresses(self, derived_addresses: dict) -> None:
        """Use the Phase-13 PROPOSED address for an AUTO address, on a COPY (accepted intent is untouched)."""
        for interface in self.interfaces:
            for address in (interface.get("addresses") or {}).values():
                if address.get("source") != "AUTO":
                    continue
                fact = derived_addresses.get((self.name, address["id"]))
                if fact is None or not fact.get("proposed_address"):
                    raise PlanGenerationError("AUTO_VALUE_MISSING", device=self.name, address_id=address["id"])
                self.auto[address["id"]] = fact
                address["source"] = "MANUAL"
                address["cidr"] = fact["proposed_address"]

    # -- state lookup ------------------------------------------------------------------------
    def iface(self, interface_id: str):
        return next((row for row in self.interfaces if row.get("id") == interface_id), None)

    def ifaces(self, interface_ids) -> list[dict]:
        wanted = {i for i in interface_ids if i}
        return [row for row in self.interfaces if row.get("id") in wanted]

    @staticmethod
    def stripped(interface: dict) -> dict:
        return {**interface, "addresses": {}}

    def shell(self, family: str, instance: dict) -> dict:
        """A routing process without its children (bindings / neighbors / networks)."""
        if family == "bgp":
            return {**instance, "neighbors": {}, "networks": {}}
        if family == "ospf" and self.platform == "ubuntu_frr":
            # FRR rejects a network statement overlapping an interface's
            # explicit `ip ospf area` binding.  Preserve this render-only
            # context while omitting the binding Configlet itself.
            import ipaddress

            bound = set()
            for binding in (instance.get("interfaces") or {}).values():
                interface = self.iface(binding.get("interface_id"))
                for address in (interface or {}).get("addresses", {}).values():
                    try:
                        network = ipaddress.ip_network(address["cidr"], strict=False)
                    except (KeyError, ValueError):
                        continue
                    if network.version == 4:
                        bound.add(str(network))
            return {**instance, "interfaces": {}, "_bound_networks": sorted(bound)}
        return {**instance, "interfaces": {}}

    # -- rendering through the ONE renderer --------------------------------------------------
    def render(self, *, interfaces=None, routing=None, phase12=None) -> list[str]:
        return snippets.render_lines(self.driver, self.field_values, interfaces=interfaces, routing=routing, phase12=phase12)

    def added(self, before: dict, after: dict) -> list[str]:
        return snippets.added_lines(self.render(**before), self.render(**after))


# --- handlers ----------------------------------------------------------------------------------
def _missing(ctx: DeviceContext, node: dict):
    return PlanGenerationError("DEPENDENCY_MISSING", device=ctx.name, node=node["id"])


def _spec(ctx, node, object_type, lines, *, suffix="", label="", derived=None, parent_key=None, facts=None,
          capability_feature="") -> ConfigletSpec:
    return ConfigletSpec(
        key=node["id"] + (f"#{suffix}" if suffix else ""), node_id=node["id"], device=ctx.name, platform=ctx.platform,
        object_type=object_type, object_id=node["object_id"], source_type=node["type"],
        label=label or node.get("label") or node["id"], lines=lines, intent=ctx.intent, derived=derived, parent_key=parent_key,
        facts=dict(facts or {}), capability_feature=capability_feature,
    )


def _family(text) -> int:
    return 6 if ":" in str(text or "") else 4


def _iface_name(ctx, interface_id) -> str:
    row = ctx.iface(interface_id or "")
    return (row or {}).get("name") or ""


def _interface(ctx, node):
    iface = ctx.iface(node["object_id"])
    if iface is None:
        raise _missing(ctx, node)
    parent = ctx.iface(iface.get("parent_id") or "")
    base = [ctx.stripped(parent)] if parent else []
    lines = ctx.added(dict(interfaces=base), dict(interfaces=[*base, ctx.stripped(iface)]))
    facts = {"interface": iface.get("name"), "admin_enabled": iface.get("admin_state", "ENABLED") == "ENABLED"}
    return [_spec(ctx, node, "interface", lines, facts=facts, capability_feature=f"interface.{iface.get('kind')}")]


def _address(ctx, node):
    for iface in ctx.interfaces:
        address = (iface.get("addresses") or {}).get(node["object_id"])
        if address is not None:
            break
    else:
        raise _missing(ctx, node)
    parent = ctx.iface(iface.get("parent_id") or "")
    context = [ctx.stripped(parent)] if parent else []
    lines = ctx.added(
        dict(interfaces=[*context, ctx.stripped(iface)]),
        dict(interfaces=[*context, {**iface, "addresses": {address["id"]: address}}]),
    )
    derived = None
    if address["id"] in ctx.auto:
        fact = ctx.auto[address["id"]]
        derived = {
            "kind": "AUTO_ADDRESS", "source": "VALIDATION_DERIVED", "proposed_address": fact["proposed_address"],
            "selected_prefix": fact.get("selected_prefix"), "algorithm": fact.get("algorithm"),
            "reserved": False, "recheck_required": True,
        }
    facts = {"interface": iface.get("name"), "address": address.get("cidr"), "family": _family(address.get("cidr"))}
    return [_spec(ctx, node, "address", lines, derived=derived, facts=facts, capability_feature=f"interface.{iface.get('kind')}")]


def _static_route(ctx, node):
    route = (ctx.routing.get("static_routes") or {}).get(node["object_id"])
    if route is None:
        raise _missing(ctx, node)
    ref = ctx.ifaces([route.get("next_hop_interface_id")])
    lines = ctx.added(dict(interfaces=ref), dict(interfaces=ref, routing={"static_routes": {route["id"]: route}}))
    facts = {"prefix": route.get("destination"), "family": _family(route.get("destination")),
             "next_hop": route.get("next_hop_address") or "", "exit_interface": _iface_name(ctx, route.get("next_hop_interface_id"))}
    return [_spec(ctx, node, "static_route", lines, facts=facts,
                  capability_feature=f"routing.STATIC_{route.get('family') or 'IPV4'}")]


# V2 Phase 6: a natively onboarded cEOS boots with the ZTP bootstrap's explicit ``no ip routing``, and an IPv4 routing process forms
# no adjacency without ``ip routing`` (observed on cEOS 4.36.2F; the isolated OSPF capability procedure enables it the same way
# before the process).  A NEW_DEVICE cEOS candidate therefore carries ``ip routing`` in each IPv4 routing-process Configlet.  The
# executor's captured-config inverse undoes it with the configured negation, and leaves it alone where routing is already on.
# V2 Phase 9: the same holds for IPv6.  The bootstrapped cEOS has IPv6 routing off; ``ipv6 router ospf N`` is accepted with
# "IPv6 routing not enabled in VRF default" and no OSPFv3 adjacency forms until ``ipv6 unicast-routing`` is configured (observed
# live: docs/evidence/v2-phase9-closure/ipv6-admission/platform-probe).  An OSPFv3 / RIPng process carries ``ipv6 unicast-routing``.
_IPV4_PROCESSES = {"ospf": ("OSPFV2",), "rip": ("IPV4",), "isis": None, "bgp": None}
_IPV6_PROCESSES = {"ospf": ("OSPFV3",), "rip": ("IPV6",)}


def _routing_prerequisite(ctx, family: str, instance: dict) -> str:
    if ctx.platform != "arista_ceos" or getattr(ctx.intent, "target_type", "") != "NEW_DEVICE" or family not in _IPV4_PROCESSES:
        return ""
    wanted = _IPV4_PROCESSES[family]
    selector = instance.get("version") if family == "ospf" else instance.get("address_family")
    if wanted is None or (selector or wanted[0]) in wanted:
        return "ip routing"
    return "ipv6 unicast-routing" if selector in _IPV6_PROCESSES.get(family, ()) else ""


# V2 Phase 6: the exact Phase-4 feature of a routing process / binding, from the declared version or address family only (never
# from the broad object type).  BGP and IS-IS processes stay unclassified, so provisioning keeps refusing them (fail closed).
_ROUTING_FEATURES = {"ospf": ("version", {"OSPFV2": "routing.OSPFV2", "OSPFV3": "routing.OSPFV3"}),
                     "rip": ("address_family", {"IPV4": "routing.RIPV2", "IPV6": "routing.RIPNG"})}


def routing_feature(family: str, instance: dict) -> str:
    selector, table = _ROUTING_FEATURES.get(family, ("", {}))
    return table.get(str((instance or {}).get(selector) or ""), "")


def _routing_instance(ctx, node):
    family = node["type"].removeprefix("routing_")
    instance = (ctx.routing.get(family) or {}).get(node["object_id"])
    if instance is None:
        raise _missing(ctx, node)
    shell = ctx.shell(family, instance)
    lines = ctx.added(dict(), dict(routing={family: {instance["id"]: shell}}))
    prerequisite = _routing_prerequisite(ctx, family, instance)
    if prerequisite and prerequisite not in lines:
        lines = [prerequisite, *lines]
    facts = {"protocol": family, "version": instance.get("version"), "process_id": instance.get("process_id"),
             "local_asn": instance.get("local_asn"), "router_id": instance.get("router_id"),
             "address_family": instance.get("address_family"),
             "networks": [{"prefix": row.get("prefix"), "area": row.get("area")} for row in
                          (instance.get("networks") or {}).values()
                          if row.get("prefix") not in set(shell.get("_bound_networks") or [])] if family == "ospf" else []}
    return [_spec(ctx, node, node["type"], lines, facts=facts, capability_feature=routing_feature(family, instance))]


def _binding(ctx, node):
    for family in ROUTING_FAMILIES:
        for instance in (ctx.routing.get(family) or {}).values():
            binding = (instance.get("interfaces") or {}).get(node["object_id"])
            if binding is not None:
                ref = ctx.ifaces([binding.get("interface_id")])
                shell = ctx.shell(family, instance)
                with_binding = {**shell, "interfaces": {binding["id"]: binding}}
                lines = ctx.added(
                    dict(interfaces=ref, routing={family: {instance["id"]: shell}}),
                    dict(interfaces=ref, routing={family: {instance["id"]: with_binding}}),
                )
                facts = {"protocol": family, "version": instance.get("version"),
                         "interface": _iface_name(ctx, binding.get("interface_id")),
                         "area": binding.get("area"), "passive": bool(binding.get("passive")),
                         **({"metric": binding["metric"]} if family == "isis" and binding.get("metric") is not None else {})}
                return [_spec(ctx, node, "routing_binding", lines, facts=facts, capability_feature=routing_feature(family, instance))]
    raise _missing(ctx, node)


def _bgp_child(ctx, node, collection: str):
    for instance in (ctx.routing.get("bgp") or {}).values():
        child = (instance.get(collection) or {}).get(node["object_id"])
        if child is not None:
            return instance, child
    raise _missing(ctx, node)


def _bgp_neighbor(ctx, node):
    instance, neighbor = _bgp_child(ctx, node, "neighbors")
    ref = ctx.ifaces([neighbor.get("update_source_interface_id")])
    shell = ctx.shell("bgp", instance)
    definition = {**neighbor, "activate_ipv4": False, "activate_ipv6": False,
                  "next_hop_self": False, "route_reflector_client": False}

    def routing(row):
        return {"bgp": {instance["id"]: {**shell, "neighbors": {neighbor["id"]: row}}}}

    after_definition = dict(interfaces=ref, routing=routing(definition))
    facts = {"peer": neighbor.get("peer_address"), "family": _family(neighbor.get("peer_address")),
             "remote_asn": neighbor.get("remote_asn"), "local_asn": instance.get("local_asn"), "shutdown": bool(neighbor.get("shutdown"))}
    specs = [_spec(ctx, node, "bgp_neighbor", ctx.added(dict(interfaces=ref, routing={"bgp": {instance["id"]: shell}}), after_definition),
                   facts=facts)]
    for suffix, flag in (("af-ipv4", "activate_ipv4"), ("af-ipv6", "activate_ipv6")):
        if not neighbor.get(flag):
            continue
        activated = {**definition, flag: True, "next_hop_self": neighbor.get("next_hop_self"),
                     "route_reflector_client": neighbor.get("route_reflector_client")}
        lines = ctx.added(after_definition, dict(interfaces=ref, routing=routing(activated)))
        family = "IPv4" if suffix.endswith("ipv4") else "IPv6"
        specs.append(_spec(
            ctx, node, "bgp_neighbor_af", lines, suffix=suffix, parent_key=specs[0].key,
            label=f"{node.get('label') or node['id']} {family} address-family activation",
            facts={**facts, "address_family": family.upper()},
        ))
    return specs


def _bgp_network(ctx, node):
    instance, network = _bgp_child(ctx, node, "networks")
    shell = ctx.shell("bgp", instance)
    lines = ctx.added(
        dict(routing={"bgp": {instance["id"]: shell}}),
        dict(routing={"bgp": {instance["id"]: {**shell, "networks": {network["id"]: network}}}}),
    )
    return [_spec(ctx, node, "bgp_network", lines, facts={"prefix": network.get("cidr"), "family": _family(network.get("cidr"))})]


def _fhrp(ctx, node):
    instance = ((ctx.phase12.get("fhrp") or {}).get("instances") or {}).get(node["object_id"])
    if instance is None:
        raise _missing(ctx, node)
    ref = ctx.ifaces([instance.get("interface_id")])
    lines = ctx.added(dict(interfaces=ref), dict(interfaces=ref, phase12={"fhrp": {"instances": {instance["id"]: instance}}}))
    facts = {"interface": _iface_name(ctx, instance.get("interface_id")), "protocol": instance.get("protocol"),
             "virtual_addresses": sorted(str(v.get("address")) for v in (instance.get("virtual_ips") or {}).values() if v.get("address"))}
    return [_spec(ctx, node, "fhrp", lines, facts=facts)]


def _dhcp_relay(ctx, node):
    dhcp = (ctx.phase12.get("services") or {}).get("dhcp") or {}
    relay = (dhcp.get("relays") or {}).get(node["object_id"])
    if relay is None:
        raise _missing(ctx, node)
    ref = ctx.ifaces([relay.get("interface_id")])
    override = {"mode": "OVERRIDE"}
    lines = ctx.added(
        dict(interfaces=ref, phase12={"services": {"dhcp": dict(override)}}),
        dict(interfaces=ref, phase12={"services": {"dhcp": {**override, "relays": {relay["id"]: relay}}}}),
    )
    facts = {"interface": _iface_name(ctx, relay.get("interface_id")), "destination": relay.get("destination"),
             "family": _family(relay.get("destination"))}
    return [_spec(ctx, node, "dhcp_relay", lines, facts=facts, capability_feature=f"service_policy.DHCP_RELAY_IPV{facts['family']}")]


def _nat_pool(ctx, node):
    pool = ((ctx.phase12.get("nat") or {}).get("pools") or {}).get(node["object_id"])
    if pool is None:
        raise _missing(ctx, node)
    lines = ctx.added(dict(), dict(phase12={"nat": {"pools": {pool["id"]: pool}}}))
    return [_spec(ctx, node, "nat_pool", lines)]


def _nat_rule(ctx, node):
    rule = ((ctx.phase12.get("nat") or {}).get("rules") or {}).get(node["object_id"])
    if rule is None:
        raise _missing(ctx, node)
    ref = ctx.ifaces([rule.get("inside_interface_id"), rule.get("outside_interface_id")])
    lines = ctx.added(dict(interfaces=ref), dict(interfaces=ref, phase12={"nat": {"rules": {rule["id"]: rule}}}))
    facts = {"inside_interface": _iface_name(ctx, rule.get("inside_interface_id")),
             "outside_interface": _iface_name(ctx, rule.get("outside_interface_id")),
             "mode": rule.get("mode"), "original_source": rule.get("original_source") or ""}
    return [_spec(ctx, node, "nat_rule", lines, facts=facts)]


def _acl(ctx, node):
    acl = ((ctx.phase12.get("security") or {}).get("acls") or {}).get(node["object_id"])
    if acl is None:
        raise _missing(ctx, node)
    lines = ctx.added(dict(), dict(phase12={"security": {"acls": {acl["id"]: acl}}}))
    return [_spec(ctx, node, "acl", lines, facts={"name": acl.get("name"), "family": acl.get("family")})]


def _acl_attachment(ctx, node):
    security = ctx.phase12.get("security") or {}
    attachment = (security.get("attachments") or {}).get(node["object_id"])
    acl = (security.get("acls") or {}).get((attachment or {}).get("acl_id") or "")
    if attachment is None or acl is None:
        raise _missing(ctx, node)
    ref = ctx.ifaces([attachment.get("interface_id")])
    acls = {acl["id"]: {**acl, "entries": {}}}  # the definition is its own Configlet; only its name is needed here
    lines = ctx.added(
        dict(interfaces=ref, phase12={"security": {"acls": acls}}),
        dict(interfaces=ref, phase12={"security": {"acls": acls, "attachments": {attachment["id"]: attachment}}}),
    )
    facts = {"acl_name": acl.get("name"), "interface": _iface_name(ctx, attachment.get("interface_id")),
             "direction": attachment.get("direction")}
    return [_spec(ctx, node, "acl_attachment", lines, facts=facts)]


def _pbr_policy(ctx, node):
    policy = (((ctx.phase12.get("policy") or {}).get("pbr") or {}).get("policies") or {}).get(node["object_id"])
    if policy is None:
        raise _missing(ctx, node)
    lines = ctx.added(dict(), dict(phase12={"policy": {"pbr": {"policies": {policy["id"]: policy}}}}))
    return [_spec(ctx, node, "pbr_policy", lines)]


def _pbr_attachment(ctx, node):
    pbr = ((ctx.phase12.get("policy") or {}).get("pbr")) or {}
    attachment = (pbr.get("attachments") or {}).get(node["object_id"])
    policy = (pbr.get("policies") or {}).get((attachment or {}).get("policy_id") or "")
    if attachment is None or policy is None:
        raise _missing(ctx, node)
    ref = ctx.ifaces([attachment.get("interface_id")])
    policies = {policy["id"]: {**policy, "sequences": {}}}
    lines = ctx.added(
        dict(interfaces=ref, phase12={"policy": {"pbr": {"policies": policies}}}),
        dict(interfaces=ref, phase12={"policy": {"pbr": {"policies": policies, "attachments": {attachment["id"]: attachment}}}}),
    )
    return [_spec(ctx, node, "pbr_attachment", lines)]


# --- V2 Phase 4: management VRF ------------------------------------------------------------------------------------------
def _management(ctx) -> dict:
    found = ctx.phase12.get("management") or {}
    return {key: dict(found.get(key) or {}) for key in ("vrfs", "bindings", "routes", "services")}


def _mgmt_slice(management: dict, **collections) -> dict:
    return {"management": {"vrfs": {}, "bindings": {}, "routes": {}, "services": {}, **collections}}


def _mgmt_vrf_for(ctx, node, collection):
    management = _management(ctx)
    obj = management[collection].get(node["object_id"])
    vrf = management["vrfs"].get((obj or {}).get("vrf_id") or "") if collection != "vrfs" else obj
    if obj is None or vrf is None:
        raise _missing(ctx, node)
    return management, obj, vrf


def _mgmt_vrf(ctx, node):
    _management_doc, vrf, _vrf = _mgmt_vrf_for(ctx, node, "vrfs")
    lines = ctx.added(dict(), dict(phase12=_mgmt_slice({}, vrfs={vrf["id"]: vrf})))
    return [_spec(ctx, node, "mgmt_vrf", lines, facts={"vrf": vrf["name"]}, capability_feature="management.VRF_DEFINE")]


def _address_children(lines: list[str], header: str) -> list[str]:
    """The address lines of ``header``'s block in a rendered slice (re-applied after a VRF change discards them)."""
    out, inside = [], False
    for line in lines:
        if line == header:
            inside = True
            continue
        if inside and line[:1] not in (" ", "\t"):
            break
        if inside and " address " in f" {line.strip()} " and not line.strip().startswith(("!", "#", "no ")):
            out.append(line)
    return out


def _mgmt_vrf_binding(ctx, node):
    management, binding, vrf = _mgmt_vrf_for(ctx, node, "bindings")
    iface = ctx.iface(binding.get("interface_id"))
    if iface is None:
        raise _missing(ctx, node)
    before = ctx.render(interfaces=[iface], phase12=_mgmt_slice(management, vrfs={vrf["id"]: vrf}))
    after = ctx.render(interfaces=[iface], phase12=_mgmt_slice(management, vrfs={vrf["id"]: vrf}, bindings={binding["id"]: binding}))
    lines = snippets.added_lines(before, after)
    if lines and ctx.platform in ("arista_ceos", "cisco_c8000v_iosxe", "cisco_iosxr"):
        # The platform discards the interface's addresses when its VRF changes: re-apply them in the same Configlet.
        lines = [*lines, *[line for line in _address_children(after, lines[0]) if line not in lines]]
    facts = {"vrf": vrf["name"], "interface": iface.get("name"),
             "addresses": [a.get("cidr") for a in (iface.get("addresses") or {}).values() if a.get("cidr")]}
    return [_spec(ctx, node, "mgmt_vrf_binding", lines, facts=facts, capability_feature="management.INTERFACE_BINDING")]


def _mgmt_vrf_route(ctx, node):
    management, route, vrf = _mgmt_vrf_for(ctx, node, "routes")
    base = _mgmt_slice(management, vrfs={vrf["id"]: vrf})
    lines = ctx.added(dict(phase12=base), dict(phase12=_mgmt_slice(management, vrfs={vrf["id"]: vrf}, routes={route["id"]: route})))
    facts = {"vrf": vrf["name"], "prefix": route.get("destination"), "next_hop": route.get("next_hop"), "family": _family(route.get("destination"))}
    return [_spec(ctx, node, "mgmt_vrf_route", lines, facts=facts, capability_feature="management.STATIC_ROUTE")]


def _mgmt_vrf_service(ctx, node):
    management, service, vrf = _mgmt_vrf_for(ctx, node, "services")
    ref = ctx.ifaces([service.get("source_interface_id")])
    base = _mgmt_slice(management, vrfs={vrf["id"]: vrf})
    lines = ctx.added(dict(interfaces=ref, phase12=base),
                      dict(interfaces=ref, phase12=_mgmt_slice(management, vrfs={vrf["id"]: vrf}, services={service["id"]: service})))
    facts = {"vrf": vrf["name"], "service": service.get("service"), "host": service.get("host") or ""}
    return [_spec(ctx, node, "mgmt_vrf_service", lines, facts=facts, capability_feature=f"management.{service.get('service')}")]


HANDLERS = {
    "mgmt_vrf": _mgmt_vrf,
    "mgmt_vrf_binding": _mgmt_vrf_binding,
    "mgmt_vrf_route": _mgmt_vrf_route,
    "mgmt_vrf_service": _mgmt_vrf_service,
    "interface": _interface,
    "address": _address,
    "static_route": _static_route,
    "routing_rip": _routing_instance,
    "routing_ospf": _routing_instance,
    "routing_isis": _routing_instance,
    "routing_eigrp": _routing_instance,
    "routing_bgp": _routing_instance,
    "routing_binding": _binding,
    "bgp_neighbor": _bgp_neighbor,
    "bgp_network": _bgp_network,
    "fhrp": _fhrp,
    "dhcp_relay": _dhcp_relay,
    "nat_pool": _nat_pool,
    "nat_rule": _nat_rule,
    "acl": _acl,
    "acl_attachment": _acl_attachment,
    "pbr_policy": _pbr_policy,
    "pbr_attachment": _pbr_attachment,
}


def _identity_spec(ctx: DeviceContext):
    """A FOUNDATION configlet ONLY for a real rename (accepted hostname != device name); never invented."""
    if ctx.hostname == ctx.name:
        return None
    lines = [
        text for descriptor in ctx.driver.identity_descriptors(ctx.field_values)
        if (text := candidate_renderer.descriptor_text(descriptor)) and not text.strip().startswith("!")
    ]
    if not snippets.deployable(lines) or snippets.has_unsupported_marker(lines) or lines == [platform_drivers.NOT_IMPLEMENTED_LINE["text"]]:
        return None
    node = {"id": f"{ctx.name}/device_identity/hostname", "object_id": "device.hostname", "type": "device_identity",
            "label": f"{ctx.name} hostname {ctx.hostname}"}
    return _spec(ctx, node, "device_identity", lines, facts={"hostname": ctx.hostname})


def raw_spec(item: dict, revision, run) -> ConfigletSpec:
    """One OPAQUE Configlet from a verified Raw Configlet revision.  The text is the pinned, immutable revision text; nothing is rendered,
    parsed or inferred, and the priority is exactly what the operator declared."""
    pins = {
        "raw_id": item["raw_id"], "revision": revision.revision, "content_hash": revision.content_hash,
        "verification_run_id": str(run.run_id), "verification_result": run.result, "policy_version": run.policy_version,
        "verifier": f"{run.adapter_id}@{run.adapter_version}", "backend": run.backend, "priority": int(revision.priority),
        "assertions": list(revision.assertions),
    }
    return ConfigletSpec(
        key=item["node_id"], node_id=item["node_id"], device=item["device"], platform=item["platform"], object_type="raw_configlet",
        object_id=item["raw_id"], source_type="raw_configlet", label=f"{item['raw_id']} {revision.name}",
        lines=revision.content.splitlines(), origin="RAW", raw=pins, priority_override=int(revision.priority),
    )


def removal_spec(node: dict, entry: dict, item: dict) -> ConfigletSpec:
    """One Configlet for one intentional removal item.  The lines are the deterministic, parser-validated removal rendering
    re-derived from the persisted snapshot -- never browser text."""
    object_type = "config_removal_detach" if item["operation"] == models.ConfigletOperationType.DEACTIVATE_DETACH else "config_removal_delete"
    return ConfigletSpec(
        key=node["id"], node_id=node["id"], device=entry["device"], platform=entry["platform"], object_type=object_type,
        object_id=node["object_id"], source_type="config_removal", label=f"remove {item['label']}", lines=list(item["removal_lines"]),
        origin="REMOVAL",
        facts={"kind": item["kind"], "absent_paths": list(item["absent_paths"]), "object": item["id"]},
        removal={"item": item["id"], "kind": item["kind"], "restore_lines": list(item["restore_lines"]), "restorable": bool(item["restorable"]),
                 "absent_paths": list(item["absent_paths"]), "snapshot_id": entry["snapshot_id"], "snapshot_digest": entry["snapshot_digest"],
                 "lines": list(item["lines"])},
    )


def build_specs(contexts: dict, graph: dict, raw_inputs: dict | None = None, removal_inputs: dict | None = None) -> tuple[list[ConfigletSpec], dict, list[dict]]:
    """-> (specs, node_id -> primary spec key, plan warnings).  Raises PlanGenerationError.

    ``raw_inputs`` maps a raw graph node id to ``(snapshot item, pinned revision, pinned verification run)``;
    ``removal_inputs`` maps a removal graph node id to ``(snapshot removal entry, re-derived removal item)``."""
    specs: list[ConfigletSpec] = []
    node_to_key: dict[str, str] = {}
    warnings: list[dict] = []

    pbr_policy_of_sequence: dict[str, str] = {}
    for name, ctx in contexts.items():
        pbr = ((ctx.phase12.get("policy") or {}).get("pbr")) or {}
        for policy in (pbr.get("policies") or {}).values():
            for sequence_id in (policy.get("sequences") or {}):
                pbr_policy_of_sequence[f"{name}/pbr_sequence/{sequence_id}"] = f"{name}/pbr_policy/{policy['id']}"

    for node in sorted(graph.get("nodes", []), key=lambda n: n["id"]):
        node_type = node["type"]
        if node_type in priorities.FOLDED_NODE_TYPES:
            continue  # resolved to its owning Configlet after all specs exist
        if node_type == "raw_configlet":
            found = (raw_inputs or {}).get(node["id"])
            if found is None:
                raise PlanGenerationError("RAW_REVISION_MISMATCH", node=node["id"])
            specs.append(raw_spec(*found))
            node_to_key.setdefault(node["id"], node["id"])
            continue
        if node_type == "config_removal":
            found = (removal_inputs or {}).get(node["id"])
            if found is None:
                raise PlanGenerationError("DEPENDENCY_MISSING", node=node["id"])
            specs.append(removal_spec(node, *found))
            node_to_key.setdefault(node["id"], node["id"])
            continue
        handler = HANDLERS.get(node_type)
        if handler is None:
            raise PlanGenerationError("UNKNOWN_OBJECT_TYPE", node=node["id"], type=node_type)
        ctx = contexts.get(node["device"])
        if ctx is None:
            raise PlanGenerationError("DEPENDENCY_MISSING", node=node["id"], device=node["device"])
        for spec in handler(ctx, node):
            if snippets.has_unsupported_marker(spec.lines):
                raise PlanGenerationError("UNSUPPORTED_OBJECT", node=node["id"], device=ctx.name, type=node_type)
            if not spec.lines:
                raise PlanGenerationError("RENDERER_INCONSISTENT", node=node["id"], device=ctx.name, type=node_type)
            unresolved = snippets.placeholders(spec.lines)
            if unresolved:
                raise PlanGenerationError("UNRESOLVED_PLACEHOLDER", node=node["id"], device=ctx.name, placeholders=unresolved)
            if not snippets.deployable(spec.lines):
                warnings.append({
                    "code": "NO_DEPLOYABLE_CONFIG",
                    "message": f"{spec.label} renders no deployable configuration (for example a disabled object) and was skipped.",
                    "details": {"node": node["id"], "device": ctx.name},
                })
                continue
            specs.append(spec)
            node_to_key.setdefault(node["id"], spec.key)

    for name in sorted(contexts):
        identity = _identity_spec(contexts[name])
        if identity is not None:
            specs.append(identity)
            node_to_key[identity.node_id] = identity.key

    for sequence_node, policy_node in pbr_policy_of_sequence.items():
        if policy_node in node_to_key:
            node_to_key[sequence_node] = node_to_key[policy_node]
    return specs, node_to_key, warnings


def verification_requirements(spec: ConfigletSpec) -> list[dict]:
    """Declarative requirement descriptors ONLY.  Phase 15 (``health/``) evaluates them; nothing runs here.

    A RAW Configlet's descriptors come from its declared, closed-catalogue ASSERTIONS -- or, with none, the single honestly-unverifiable
    ``RAW_CONFIG_APPLIED`` marker (see ``raw_configlets.assertions``).

    Descriptor schema 2 adds ``expected``: the secret-free facts of the accepted object (interface name, address,
    prefix, peer, ...), captured at plan-build time so a later precheck/postcheck never re-derives intent.  Plans
    built before this field existed carry no ``expected`` and are evaluated as INCOMPLETE, never guessed.
    """
    if spec.origin == "RAW":
        return raw_assertions.descriptors((spec.raw or {}).get("assertions") or [], device=spec.device, label=spec.label, raw_id=spec.object_id)
    return [{
        "schema_version": 2,
        "requirement": spec.object_class.requirement,
        "device": spec.device,
        "subject": {"object_type": spec.source_type, "object_id": spec.object_id, "label": spec.label},
        "expected": dict(spec.facts),
        "status": "DEFERRED",
        "owner": "PHASE_15",
    }]
