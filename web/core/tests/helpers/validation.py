"""Multi-device Change fixtures (Phase-13 validation): synthetic multi-device Changes and fake sources.

Everything here is application-state only.  Sources are injected as
SourceBundle objects so no test ever contacts NetBox, a device, or Git.
"""

from __future__ import annotations

from types import SimpleNamespace

from core import models
from core.services import (
    change_service,
    change_validation_service as cvs,
    field_commit_service,
    intent_service,
    interface_intent_service,
    routing_intent_service,
    service_policy_intent_service as spis,
)
from core.services.validation import sources as sources_module
from core.services.validation.findings import sha256_of
from core.services.validation.sources import SourceBundle, SourceResult

DEFAULT_MANAGEMENT = {
    "nmas_ipv4": "192.168.200.100", "nmas_ipv6": "2001:db8:200::100",
    "primary_dhcp_ipv4": "192.168.200.100", "primary_dhcp_ipv6": "2001:db8:200::100",
    "backup_dhcp_ipv4": "192.168.200.2", "backup_dhcp_ipv6": "2001:db8:200::2",
}


def netbox_data(**overrides) -> dict:
    data = {
        "ip_addresses": [], "prefixes": [], "vlans": [1, 10, 20, 30, 100, 200], "dhcp_ranges": [],
        "interface_modes": [], "devices": [],
    }
    data.update(overrides)
    return data


def nb_ip(cidr, device=None, interface=None, role=None) -> dict:
    ip, _, length = cidr.partition("/")
    return {"cidr": cidr, "ip": ip, "prefix_length": int(length), "family": 6 if ":" in ip else 4,
            "device": device, "interface": interface, "role": role}


def nb_prefix(prefix, vlan=None, relay_targets=()) -> dict:
    return {"prefix": prefix, "family": 6 if ":" in prefix else 4, "vlan": vlan, "relay_targets": list(relay_targets)}


def topology_data(links=(), nodes=None) -> dict:
    names = set(nodes or ())
    for (a, _), (z, _) in links:
        names.update((a, z))
    kinds = {n: ("linux" if n in ("R3", "R4") or n.startswith("H") else "arista_ceos") for n in names}
    return {
        "lab_name": "srlceos01",
        "nodes": {n: {"kind": kinds[n], "image": "x"} for n in sorted(names)},
        "links": [
            {"a": {"device": a, "interface": ai, "raw_interface": ai}, "z": {"device": z, "interface": zi, "raw_interface": zi}}
            for (a, ai), (z, zi) in links
        ],
    }


DEFAULT_NODES = ("R1", "R2", "R3", "R4", "S1", "S2")


def inventory_data(devices=DEFAULT_NODES) -> dict:
    return {
        "management": dict(DEFAULT_MANAGEMENT),
        "network_devices": {
            n: {"platform": "ubuntu_frr" if n in ("R3", "R4") else "arista_ceos",
                "monitoring_address": f"192.168.200.{i + 1}", "monitoring_address_v6": "", "edge": False}
            for i, n in enumerate(devices)
        },
        "hosts": ["H1", "H2"],
    }


def _result(name, data, *, fingerprint=None):
    if data is None:
        return SourceResult(name=name, status="unavailable", message=f"{name} unavailable (test)")
    return SourceResult(name=name, status="available", data=data, fingerprint=fingerprint or sha256_of(data))


def make_sources(*, netbox="default", topology="default", inventory="default", head="test-head") -> SourceBundle:
    nb = netbox_data() if netbox == "default" else netbox
    tp = topology_data(nodes=DEFAULT_NODES) if topology == "default" else topology
    inv = inventory_data() if inventory == "default" else inventory
    return SourceBundle(
        netbox=_result("NETBOX", nb), topology=_result("TOPOLOGY", tp), inventory=_result("INVENTORY", inv),
        capability=sources_module.collect_capability(), repository_head=head,
    )


class Dev:
    """One DeviceIntent + candidate revision inside a Change, with terse builders."""

    def __init__(self, change, name, *, platform=models.Platform.ARISTA_CEOS, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE):
        self.change, self.name = change, name
        self.intent, _ = intent_service.create_or_get_device_intent(
            change=change, device_name=name, platform=platform, target_type=target_type)
        self.revision = intent_service.create_candidate_revision(device_intent=self.intent)
        field_commit_service.seed_device_identity_field_states(intent=self.intent, revision=self.revision)

    # -- generic accepted commit ------------------------------------------------
    def set(self, path, value):
        state = field_commit_service.commit_field(
            change=self.change, intent=self.intent, revision=self.revision, path=path, raw_value=value)
        assert state.validation_state == models.FieldValidationState.VALID, (path, value, state.validation_message)
        return state

    def draft(self, path, value):
        """A DRAFT-only edit (never accepted) -- exercises the accepted-only contract."""
        return intent_service.set_draft_field(revision=self.revision, path=path, draft_value=value)

    def force(self, path, value):
        """Persist a value the Tier-1 validators would refuse (malformed / historical / manually edited data)."""
        revision = self.refresh()
        node = revision.sections
        parts = path.split(".")
        for key in parts[:-1]:
            node = node[key]
        node[parts[-1]] = value
        revision.save(update_fields=["sections"])
        models.IntentFieldState.objects.filter(revision=revision, path=path).update(accepted_value=value, draft_value=value)

    def inject(self, fn):
        """Mutate persisted sections directly (simulates historical / manually edited / migrated data)."""
        revision = self.refresh()
        sections = spis._sections(revision)  # deep copy with every Phase-12 namespace defaulted
        fn(sections)
        revision.sections = sections
        revision.save(update_fields=["sections"])

    def refresh(self):
        self.revision.refresh_from_db()
        return self.revision

    # -- interfaces ----------------------------------------------------------------
    def iface(self, name, kind="ROUTED_PHYSICAL", **fields):
        row = interface_intent_service.add_interface(revision=self.revision, kind=kind, name=name)
        for key, value in fields.items():
            self.set(f"interfaces.{row['id']}.{key}", value)
        return self.current_iface(row["id"])

    def current_iface(self, iid):
        return interface_intent_service.get_interface(self.refresh(), iid)

    def address(self, iface, cidr):
        family = "IPV6" if ":" in cidr else "IPV4"
        row = interface_intent_service.add_address(revision=self.revision, interface_id=iface["id"], family=family, source="MANUAL")
        self.set(f"interfaces.{iface['id']}.addresses.{row['id']}.cidr", cidr)
        return row

    def auto_address(self, iface, prefix="", family="IPV4"):
        row = interface_intent_service.add_address(revision=self.revision, interface_id=iface["id"], family=family, source="AUTO")
        if prefix:
            self.set(f"interfaces.{iface['id']}.addresses.{row['id']}.ipam_prefix", prefix)
        return row

    # -- routing -------------------------------------------------------------------
    def static_route(self, destination, next_hop="", family="IPV4", interface=None):
        route = routing_intent_service.add_static_route(revision=self.revision, family=family)
        self.set(f"routing.static_routes.{route['id']}.destination", destination)
        if interface is not None:
            self.set(f"routing.static_routes.{route['id']}.next_hop_type", "INTERFACE")
            self.set(f"routing.static_routes.{route['id']}.next_hop_interface_id", interface["id"])
        else:
            self.set(f"routing.static_routes.{route['id']}.next_hop_address", next_hop)
        return route

    def ospf(self, version="OSPFV2", router_id="", process_id=1):
        instance = routing_intent_service.add_protocol_instance(revision=self.revision, family="ospf", version=version)
        if self.intent.platform == models.Platform.ARISTA_CEOS and process_id is not None:
            self.set(f"routing.ospf.{instance['id']}.process_id", process_id)
        if router_id:
            self.set(f"routing.ospf.{instance['id']}.router_id", router_id)
        return instance

    def bind(self, family, instance, iface, **fields):
        binding = routing_intent_service.add_interface_binding(
            revision=self.revision, family=family, instance_id=instance["id"], interface_id=iface["id"])
        for key, value in fields.items():
            self.set(f"routing.{family}.{instance['id']}.interfaces.{binding['id']}.{key}", value)
        return binding

    def rip(self, address_family="IPV4"):
        return routing_intent_service.add_protocol_instance(revision=self.revision, family="rip", address_family=address_family)

    def bgp(self, asn, router_id=""):
        instance = routing_intent_service.add_protocol_instance(revision=self.revision, family="bgp", local_asn=asn)
        if router_id:
            self.set(f"routing.bgp.{instance['id']}.router_id", router_id)
        return instance

    def neighbor(self, instance, peer, remote_asn, **fields):
        row = routing_intent_service.add_bgp_neighbor(
            revision=self.revision, instance_id=instance["id"], peer_address=peer, remote_asn=remote_asn)
        for key, value in fields.items():
            self.set(f"routing.bgp.{instance['id']}.neighbors.{row['id']}.{key}", value)
        return row

    def bgp_network(self, instance, cidr, family="IPV4"):
        return routing_intent_service.add_bgp_network(revision=self.revision, instance_id=instance["id"], family=family, cidr=cidr)

    # -- Phase 12 ----------------------------------------------------------------
    def fhrp(self, iface, *, family="IPV4", vips=(), virtual_mac="", protocol="VARP", **fields):
        instance = spis.add_fhrp_instance(revision=self.revision, protocol=protocol, interface_id=iface["id"], address_family=family)
        if virtual_mac:
            self.set(f"fhrp.instances.{instance['id']}.virtual_mac", virtual_mac)
        for key, value in fields.items():
            self.set(f"fhrp.instances.{instance['id']}.{key}", value)
        for vip in vips:
            spis.add_fhrp_vip(revision=self.revision, instance_id=instance["id"], address=vip)
        return instance

    def nat_pool(self, name, start, end, family="NAT44"):
        pool = spis.add_nat_pool(revision=self.revision, family=family, name=name)
        self.set(f"nat.pools.{pool['id']}.start_address", start)
        self.set(f"nat.pools.{pool['id']}.end_address", end)
        return pool

    def nat_rule(self, *, inside=None, outside=None, source="", mode="PAT", pool=None, family="NAT44"):
        rule = spis.add_nat_rule(revision=self.revision, family=family, mode=mode)
        if source:
            self.set(f"nat.rules.{rule['id']}.original_source", source)
        if inside is not None:
            self.set(f"nat.rules.{rule['id']}.inside_interface_id", inside["id"])
        if outside is not None:
            self.set(f"nat.rules.{rule['id']}.outside_interface_id", outside["id"])
        if pool is not None:
            self.set(f"nat.rules.{rule['id']}.pool_id", pool["id"])
        return rule

    def relay(self, iface, destination, family="IPV4"):
        return spis.add_dhcp_relay(revision=self.revision, family=family, interface_id=iface["id"], destination=destination)

    def acl(self, name="EDGE-IN", family="IPV4", acl_type="EXTENDED"):
        return spis.add_acl(revision=self.revision, name=name, family=family, acl_type=acl_type)

    def ace(self, acl, action="PERMIT", protocol="IP", **fields):
        entry = spis.add_ace(revision=self.revision, acl_id=acl["id"], action=action, protocol=protocol)
        for key, value in fields.items():
            self.set(f"security.acls.{acl['id']}.entries.{entry['id']}.{key}", value)
        return entry

    def attach_acl(self, acl, iface, direction="IN"):
        return spis.add_acl_attachment(revision=self.revision, acl_id=acl["id"], interface_id=iface["id"], direction=direction)

    def switch_platform(self, platform):
        """Preserve intent but change the platform (how unsupported intent arises)."""
        self.intent.platform = platform
        self.intent.save(update_fields=["platform"])


def new_change(title="Phase 13 fixture") -> models.Change:
    return change_service.create_change(title=title)


def codes(run_or_report) -> list[str]:
    report = run_or_report.report if hasattr(run_or_report, "report") else run_or_report
    return [f["code"] for f in report["findings"]]


def findings(run_or_report, code=None):
    report = run_or_report.report if hasattr(run_or_report, "report") else run_or_report
    return [f for f in report["findings"] if code is None or f["code"] == code]


def validate(change, sources=None, actor="tester"):
    return cvs.validate_change(change, actor=actor, sources=sources or make_sources())


def link(a, ai, z, zi):
    return ((a, ai), (z, zi))


# --- Phase-14 plan fixtures -------------------------------------------------------------------------
def rich_change(*, ospf_process_id: bool = True):
    """A deterministic Change covering every plannable object family.

    R1 (cEOS): interfaces, manual + AUTO addresses, static route, OSPF (+binding), BGP (process, neighbor with an
    activated IPv4 family, network), FHRP, DHCP relay, ACL (+attachment).  R2 (cEOS): the peer.  R3 (Ubuntu/FRR):
    NAT44/PAT.  Validation of it is PASS_WITH_WARNINGS (BGP peer / network evidence warnings).
    """
    change = new_change("Plan fixture")
    r1, r2, r3 = Dev(change, "R1"), Dev(change, "R2"), Dev(change, "R3", platform=models.Platform.UBUNTU_FRR)
    e1 = r1.iface("Ethernet1"); r1.address(e1, "192.0.2.0/31")
    e2 = r1.iface("Ethernet2"); r1.auto_address(e2, "198.51.100.0/29")
    z1 = r2.iface("Ethernet1"); r2.address(z1, "192.0.2.1/31")
    ospf = r1.ospf(router_id="10.0.0.1", process_id=None)
    if ospf_process_id:
        r1.set(f"routing.ospf.{ospf['id']}.process_id", 10)
    r1.bind("ospf", ospf, e1)
    bgp = r1.bgp(65001, router_id="10.0.0.1")
    neighbor = r1.neighbor(bgp, "192.0.2.1", 65002, activate_ipv4=True, next_hop_self=True)
    r1.bgp_network(bgp, "203.0.113.0/24")
    r1.static_route("10.9.0.0/24", next_hop="192.0.2.1")
    svi = r1.iface("Vlan10", kind="SVI", vlan_id=10); r1.address(svi, "192.168.10.11/24"); r1.fhrp(svi, vips=["192.168.10.1"])
    r1.relay(svi, "192.168.200.100")
    acl = r1.acl("EDGE-IN"); r1.ace(acl, "PERMIT", "IP"); r1.attach_acl(acl, svi)
    inside, outside = r3.iface("eth1"), r3.iface("eth2")
    r3.nat_rule(inside=inside, outside=outside, source="10.0.0.0/8")
    sources = make_sources(netbox=netbox_data(prefixes=[nb_prefix("198.51.100.0/29")]))
    return SimpleNamespace(change=change, r1=r1, r2=r2, r3=r3, ospf=ospf, bgp=bgp, neighbor=neighbor, svi=svi, e1=e1, sources=sources)


def simple_pass_change():
    """The smallest Change that validates PASS (a matching /31 pair)."""
    change = new_change("Simple plan fixture")
    r1, r2 = Dev(change, "R1"), Dev(change, "R2")
    a = r1.iface("Ethernet1"); r1.address(a, "192.0.2.0/31")
    z = r2.iface("Ethernet1"); r2.address(z, "192.0.2.1/31")
    return SimpleNamespace(change=change, r1=r1, r2=r2, a=a, sources=make_sources())


def clone_run(run, **overrides):
    """A NEW append-only validation run copying ``run`` (used to inject a synthetic graph / status)."""
    fields = dict(
        change=run.change, status=run.status, engine_version=run.engine_version, input_hash=run.input_hash,
        source_hash=run.source_hash, repository_head=run.repository_head, created_by="test", summary=run.summary,
        report=run.report, derived_facts=run.derived_facts, dependency_graph=run.dependency_graph,
        intent_revision_map=run.intent_revision_map, source_provenance=run.source_provenance,
    )
    fields.update(overrides)
    return models.ChangeValidationRun.objects.create(**fields)


def graph_node(run, device, node_type, contains=""):
    """The id of the first graph node of ``device``/``node_type`` whose label contains ``contains``."""
    return next(
        n["id"] for n in run.dependency_graph["nodes"]
        if n["device"] == device and n["type"] == node_type and contains in n["label"]
    )


def graph_with_edges(run, *edges, status="RESOLVED"):
    """A deep copy of the run's graph plus synthetic ``(dependent, dependency, type)`` edges."""
    import copy

    graph = copy.deepcopy(run.dependency_graph)
    for source, target, edge_type in edges:
        graph["edges"].append({"from": source, "to": target, "type": edge_type, "status": status, "reason": "synthetic test edge"})
    return graph


def change_in_state(state: str):
    """(change, sources) for each validation state a plan must handle.

    NEVER_RUN | PASS | PASS_WITH_WARNINGS | BLOCKED | INCOMPLETE | STALE (a PASS whose accepted intent then changed).
    """
    f = simple_pass_change()
    if state == "NEVER_RUN":
        return f.change, f.sources
    if state == "PASS_WITH_WARNINGS":
        f.r1.static_route("10.9.0.0/24", next_hop="172.16.9.9")  # ROUTE_NEXT_HOP_UNRESOLVED (warning)
    if state == "BLOCKED":
        f.r2.address(f.r2.iface("Ethernet2"), "192.0.2.0/31")  # the same host address as R1 -> IP_DUPLICATE
    sources = make_sources(netbox=None) if state == "INCOMPLETE" else f.sources
    validate(f.change, sources)
    if state == "STALE":
        f.r1.set(f"interfaces.{f.a['id']}.description", "changed after validation")
    return f.change, sources
