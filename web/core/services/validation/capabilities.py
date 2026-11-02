"""Capability + renderer-consistency + platform-identity validation.

There is ONE capability truth: platform_drivers' three registries
(PLATFORM_CAPABILITIES, ROUTING_CAPABILITIES, SERVICE_POLICY_CAPABILITIES).
This module only ENUMERATES accepted objects and looks each one up through
the registry's own public functions -- it holds no capability table.

Planning eligibility
    SUPPORTED       -> nothing to report
    NOT_IMPLEMENTED -> PLATFORM_FEATURE_NOT_IMPLEMENTED  (blocking)
    UNSUPPORTED     -> PLATFORM_FEATURE_UNSUPPORTED      (blocking)
    UNKNOWN         -> PLATFORM_FEATURE_UNKNOWN          (incomplete)

Renderer consistency (per object, via the driver's own descriptor API):
    registry SUPPORTED but the authoritative renderer raises, emits the
    unsupported-object marker, or emits nothing        -> PLATFORM_RENDERER_INCONSISTENT
    registry NOT supported but deployable-looking (non-comment) output is
    emitted for the object                             -> PLATFORM_RENDERER_INCONSISTENT
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .. import candidate_renderer, platform_drivers
from ..platform_drivers import CapabilityStatus, PlatformCapability, RoutingProtocol
from .findings import Code

_STATUS_CODE = {
    CapabilityStatus.NOT_IMPLEMENTED: Code.PLATFORM_FEATURE_NOT_IMPLEMENTED,
    CapabilityStatus.UNSUPPORTED: Code.PLATFORM_FEATURE_UNSUPPORTED,
    CapabilityStatus.UNKNOWN: Code.PLATFORM_FEATURE_UNKNOWN,
}
_UNKNOWN_CAP = PlatformCapability(CapabilityStatus.UNKNOWN, "No registry row exists for this platform/feature.")


@dataclass
class ObjectCapability:
    device: str
    object_type: str
    object_id: str
    label: str
    feature: str
    status: CapabilityStatus
    evidence: str
    field_path: str = ""
    probe: dict | None = None  # {"with": kwargs, "without": kwargs} for the renderer probe
    extra: dict = field(default_factory=dict)


def _lookup(fn, *args) -> PlatformCapability:
    try:
        return fn(*args)
    except ValueError:
        return _UNKNOWN_CAP


def _interface_kwargs(device, *, only=None):
    rows = [row for row in device.interfaces.values() if only is None or row.get("id") in only]
    return sorted(rows, key=lambda r: (int(r.get("sequence") or 0), r.get("name") or "", r.get("id", "")))


def _slice(device, *, routing=None, phase12=None, interfaces=None):
    return {
        "interfaces": _interface_kwargs(device) if interfaces is None else interfaces,
        "routing": routing or {},
        "phase12": phase12 or {},
    }


def enumerate_object_capabilities(device) -> list[ObjectCapability]:
    """Every accepted object of one device with its registry capability."""
    name, platform = device.name, device.platform
    result: list[ObjectCapability] = []

    def add(object_type, object_id, label, feature, capability, *, path="", probe=None, **extra):
        result.append(ObjectCapability(
            device=name, object_type=object_type, object_id=object_id, label=label, feature=str(feature),
            status=capability.status, evidence=capability.evidence, field_path=path, probe=probe, extra=extra,
        ))

    # ---- interfaces ------------------------------------------------------
    for interface in device.ordered(device.interfaces):
        iid = interface["id"]
        cap = _lookup(platform_drivers.capability_for, platform, interface.get("kind", ""))
        parent = device.interfaces.get(interface.get("parent_id") or "")
        base = [parent] if parent else []
        probe = {
            "without": _slice(device, interfaces=list(base)),
            "with": _slice(device, interfaces=[*base, interface]),
        }
        add("interface", iid, f"interface {interface.get('name')} ({interface.get('kind')})",
            interface.get("kind", ""), cap, path=f"interfaces.{iid}", probe=probe)

    # ---- routing ---------------------------------------------------------
    routing = device.routing
    for route in sorted((routing.get("static_routes") or {}).values(), key=lambda r: r.get("id", "")):
        protocol = platform_drivers.routing_object_protocol("static_routes", route)
        add("static_route", route["id"], f"static route {route.get('destination') or route['id']}", protocol,
            _lookup(platform_drivers.capability_for_routing, platform, protocol),
            path=f"routing.static_routes.{route['id']}",
            probe={"without": _slice(device), "with": _slice(device, routing={"static_routes": {route["id"]: route}})})
    for family in ("rip", "ospf", "isis", "eigrp"):
        for instance in sorted((routing.get(family) or {}).values(), key=lambda r: r.get("id", "")):
            protocol = platform_drivers.routing_object_protocol(family, instance)
            add(f"routing_{family}", instance["id"], f"{family.upper()} instance {instance['id']}", protocol,
                _lookup(platform_drivers.capability_for_routing, platform, protocol),
                path=f"routing.{family}.{instance['id']}",
                probe={"without": _slice(device), "with": _slice(device, routing={family: {instance["id"]: instance}})})
    for instance in sorted((routing.get("bgp") or {}).values(), key=lambda r: r.get("id", "")):
        v4 = _lookup(platform_drivers.capability_for_routing, platform, RoutingProtocol.BGP_IPV4)
        v6 = _lookup(platform_drivers.capability_for_routing, platform, RoutingProtocol.BGP_IPV6)
        cap = v4 if v4.status == CapabilityStatus.SUPPORTED else (v6 if v6.status == CapabilityStatus.SUPPORTED else v4)
        add("routing_bgp", instance["id"], f"BGP AS{instance.get('local_asn')} ({instance['id']})", "BGP", cap,
            path=f"routing.bgp.{instance['id']}",
            probe={"without": _slice(device), "with": _slice(device, routing={"bgp": {instance["id"]: instance}})})
        for neighbor in sorted((instance.get("neighbors") or {}).values(), key=lambda r: r.get("id", "")):
            protocol = RoutingProtocol.BGP_IPV4 if neighbor.get("family") == "IPV4" else RoutingProtocol.BGP_IPV6
            add("bgp_neighbor", neighbor["id"], f"BGP neighbor {neighbor.get('peer_address')}", protocol,
                _lookup(platform_drivers.capability_for_routing, platform, protocol),
                path=f"routing.bgp.{instance['id']}.neighbors.{neighbor['id']}")
        for network in sorted((instance.get("networks") or {}).values(), key=lambda r: r.get("id", "")):
            protocol = RoutingProtocol.BGP_IPV4 if network.get("family") == "IPV4" else RoutingProtocol.BGP_IPV6
            add("bgp_network", network["id"], f"BGP network {network.get('cidr')}", protocol,
                _lookup(platform_drivers.capability_for_routing, platform, protocol),
                path=f"routing.bgp.{instance['id']}.networks.{network['id']}")

    # ---- Phase-12 services / security / policy ---------------------------
    def sp(feature):
        return _lookup(platform_drivers.resolve_service_policy_capability, platform, feature)

    for instance in sorted(device.fhrp_instances.values(), key=lambda r: r.get("id", "")):
        feature = platform_drivers.fhrp_feature_name(instance)
        add("fhrp", instance["id"], f"{instance.get('protocol')} instance {instance['id']}", feature, sp(feature),
            path=f"fhrp.instances.{instance['id']}",
            probe={"without": _slice(device), "with": _slice(device, phase12={"fhrp": {"instances": {instance["id"]: instance}}})})

    nat = device.nat
    for pool in sorted((nat.get("pools") or {}).values(), key=lambda r: r.get("id", "")):
        feature = f"NAT_POOL_{pool.get('family')}"
        add("nat_pool", pool["id"], f"NAT pool {pool.get('name') or pool['id']}", feature, sp(feature),
            path=f"nat.pools.{pool['id']}",
            probe={"without": _slice(device), "with": _slice(device, phase12={"nat": {"pools": {pool["id"]: pool}}})})
    for rule in sorted((nat.get("rules") or {}).values(), key=lambda r: r.get("id", "")):
        feature = f"NAT_{rule.get('family')}_{rule.get('mode')}"
        add("nat_rule", rule["id"], f"NAT {rule.get('family')} {rule.get('mode')} rule {rule['id']}", feature, sp(feature),
            path=f"nat.rules.{rule['id']}",
            probe={"without": _slice(device), "with": _slice(device, phase12={"nat": {"rules": {rule["id"]: rule}}})})

    dhcp = device.dhcp
    override = {"mode": "OVERRIDE"}
    for relay in sorted((dhcp.get("relays") or {}).values(), key=lambda r: r.get("id", "")):
        feature = f"DHCP_RELAY_{relay.get('family')}"
        add("dhcp_relay", relay["id"], f"DHCP relay {relay['id']}", feature, sp(feature),
            path=f"services.dhcp.relays.{relay['id']}",
            probe={"without": _slice(device, phase12={"services": {"dhcp": dict(override)}}),
                   "with": _slice(device, phase12={"services": {"dhcp": {**override, "relays": {relay["id"]: relay}}}})})
    for client in sorted((dhcp.get("clients") or {}).values(), key=lambda r: r.get("id", "")):
        feature = f"DHCP_CLIENT_{client.get('family')}"
        add("dhcp_client", client["id"], f"DHCP client {client['id']}", feature, sp(feature),
            path=f"services.dhcp.clients.{client['id']}",
            probe={"without": _slice(device, phase12={"services": {"dhcp": dict(override)}}),
                   "with": _slice(device, phase12={"services": {"dhcp": {**override, "clients": {client["id"]: client}}}})})
    if dhcp.get("local_server_override"):
        add("dhcp_local_server", "services.dhcp", "local DHCP server override", "DHCP_LOCAL_SERVER", sp("DHCP_LOCAL_SERVER"),
            path="services.dhcp.local_server_override",
            probe={"without": _slice(device, phase12={"services": {"dhcp": dict(override)}}),
                   "with": _slice(device, phase12={"services": {"dhcp": {**override, "local_server_override": True}}})})
    if device.dns.get("mode") == "OVERRIDE":
        add("dns_override", "services.dns", "DNS resolver override", "DNS_OVERRIDE", sp("DNS_OVERRIDE"),
            path="services.dns.mode",
            probe={"without": _slice(device, phase12={"services": {"dns": {"mode": "INHERIT"}}}),
                   "with": _slice(device, phase12={"services": {"dns": {"mode": "OVERRIDE"}}})})
    monitoring = ((device.entry.get("services") or {}).get("monitoring")) or {}
    if monitoring.get("mode") == "OVERRIDE":
        add("monitoring_override", "services.monitoring", "monitoring override", "MONITORING_OVERRIDE",
            sp("MONITORING_OVERRIDE"), path="services.monitoring.mode")

    for acl in sorted(device.acls.values(), key=lambda r: r.get("id", "")):
        feature = f"ACL_{acl.get('family')}_{acl.get('acl_type')}"
        add("acl", acl["id"], f"ACL {acl.get('name') or acl['id']}", feature, sp(feature),
            path=f"security.acls.{acl['id']}",
            probe={"without": _slice(device), "with": _slice(device, phase12={"security": {"acls": {acl["id"]: acl}}})})
    for attachment in sorted(device.acl_attachments.values(), key=lambda r: r.get("id", "")):
        acl = device.acls.get(attachment.get("acl_id") or "") or {}
        feature = f"ACL_ATTACH_{acl.get('family', 'IPV4')}"
        acls = {acl["id"]: acl} if acl else {}
        add("acl_attachment", attachment["id"], f"ACL attachment {attachment['id']}", feature, sp(feature),
            path=f"security.attachments.{attachment['id']}",
            probe={"without": _slice(device, phase12={"security": {"acls": acls}}),
                   "with": _slice(device, phase12={"security": {"acls": acls, "attachments": {attachment["id"]: attachment}}})})

    pbr = device.pbr
    for policy in sorted((pbr.get("policies") or {}).values(), key=lambda r: r.get("id", "")):
        feature = f"PBR_{policy.get('family')}"
        add("pbr_policy", policy["id"], f"PBR policy {policy.get('name') or policy['id']}", feature, sp(feature),
            path=f"policy.pbr.policies.{policy['id']}",
            probe={"without": _slice(device), "with": _slice(device, phase12={"policy": {"pbr": {"policies": {policy["id"]: policy}}}})})
    for attachment in sorted((pbr.get("attachments") or {}).values(), key=lambda r: r.get("id", "")):
        policy = (pbr.get("policies") or {}).get(attachment.get("policy_id") or "") or {}
        feature = f"PBR_ATTACH_{policy.get('family', 'IPV4')}"
        pols = {policy["id"]: policy} if policy else {}
        add("pbr_attachment", attachment["id"], f"PBR attachment {attachment['id']}", feature, sp(feature),
            path=f"policy.pbr.attachments.{attachment['id']}",
            probe={"without": _slice(device, phase12={"policy": {"pbr": {"policies": pols}}}),
                   "with": _slice(device, phase12={"policy": {"pbr": {"policies": pols, "attachments": {attachment["id"]: attachment}}}})})
    return result


# --- renderer probe -----------------------------------------------------------

def _render_lines(driver, device, kwargs) -> list[str]:
    descriptors = driver.render_candidate(
        field_values={"device.hostname": device.name, "device.description": ""},
        interfaces=kwargs["interfaces"], routing=kwargs["routing"], phase12=kwargs["phase12"],
    )
    lines = []
    for descriptor in descriptors:
        text = candidate_renderer.descriptor_text(descriptor)
        if text is not None and text.strip():
            lines.append(text)
    return lines


def probe_object(device, entry: ObjectCapability) -> dict:
    """{"markers": n, "deployable": [...], "emitted": n} for exactly one object."""
    driver = platform_drivers.get_driver(device.platform)
    with_lines = Counter(_render_lines(driver, device, entry.probe["with"]))
    without_lines = Counter(_render_lines(driver, device, entry.probe["without"]))
    added = with_lines - without_lines
    markers = sum(n for text, n in added.items() if text.startswith(platform_drivers.UNSUPPORTED_OBJECT_MARKER))
    deployable = sorted(text for text in added if not text.strip().startswith("!"))
    return {"markers": markers, "deployable": deployable, "emitted": sum(added.values())}


def validate_capabilities(ctx) -> None:
    checked = 0
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        for entry in enumerate_object_capabilities(device):
            checked += 1
            if entry.status != CapabilityStatus.SUPPORTED:
                code = _STATUS_CODE[entry.status]
                ctx.add(
                    code,
                    f"{entry.label} is {entry.status.value} for platform {device.platform}; "
                    "the Change cannot proceed to deployment planning as represented.",
                    device=name, object_type=entry.object_type, object_id=entry.object_id,
                    field_path=entry.field_path, source="CAPABILITY_REGISTRY",
                    evidence={"feature": entry.feature, "status": entry.status.value,
                              "platform": device.platform, "registry_evidence": entry.evidence},
                    remediation="Remove or replace the object, or choose a platform whose registry marks it SUPPORTED.",
                )
            if entry.probe is None:
                continue
            try:
                probe = probe_object(device, entry)
            except Exception as exc:  # noqa: BLE001 - "renderer cannot render" is itself the finding
                if entry.status == CapabilityStatus.SUPPORTED:
                    ctx.add(
                        Code.PLATFORM_RENDERER_INCONSISTENT,
                        f"Registry marks {entry.label} SUPPORTED but the authoritative renderer failed to render it.",
                        device=name, object_type=entry.object_type, object_id=entry.object_id,
                        field_path=entry.field_path, source="RENDERER",
                        evidence={"feature": entry.feature, "renderer_error": exc.__class__.__name__},
                        remediation="Fix the renderer/template or correct the capability registry row.",
                    )
                continue
            if entry.status == CapabilityStatus.SUPPORTED and (probe["markers"] or not probe["emitted"]):
                ctx.add(
                    Code.PLATFORM_RENDERER_INCONSISTENT,
                    f"Registry marks {entry.label} SUPPORTED but the authoritative renderer "
                    + ("reports it unsupported." if probe["markers"] else "emits no configuration for it."),
                    device=name, object_type=entry.object_type, object_id=entry.object_id,
                    field_path=entry.field_path, source="RENDERER",
                    evidence={"feature": entry.feature, "unsupported_markers": probe["markers"], "emitted_lines": probe["emitted"]},
                    remediation="Reconcile platform_drivers capability rows with the driver's renderer.",
                )
            elif entry.status != CapabilityStatus.SUPPORTED and probe["deployable"]:
                ctx.add(
                    Code.PLATFORM_RENDERER_INCONSISTENT,
                    f"Registry marks {entry.label} {entry.status.value} but the renderer emitted deployable-looking output.",
                    device=name, object_type=entry.object_type, object_id=entry.object_id,
                    field_path=entry.field_path, source="RENDERER",
                    evidence={"feature": entry.feature, "status": entry.status.value, "deployable_lines": probe["deployable"][:5]},
                    remediation="Reconcile platform_drivers capability rows with the driver's renderer.",
                )
    ctx.checked["capability_objects"] = checked


def validate_platform_identity(ctx) -> None:
    """Revision presence + intent platform vs fixed inventory/topology identity."""
    inventory, topology = ctx.inventory, ctx.topology
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        if not device.entry.get("has_revision"):
            ctx.add(
                Code.INTENT_REVISION_MISSING,
                f"DeviceIntent {name} has no candidate revision; there is no accepted intent to validate.",
                device=name, object_type="DeviceIntent", object_id=name, source="INTENT",
                remediation="Open the Device Builder for this device to create its candidate revision.",
            )
        if device.target_type != "EXISTING_DEVICE":
            continue
        known_in_inventory = inventory is not None and (
            name in inventory["network_devices"] or name in inventory["hosts"]
            or name == "WebServer"
        )
        known_in_topology = topology is not None and name in topology["nodes"]
        if inventory is not None:
            declared = inventory["network_devices"].get(name, {}).get("platform")
            if declared and declared != device.platform:
                ctx.add(
                    Code.PLATFORM_INVENTORY_MISMATCH,
                    f"Intent platform {device.platform} differs from inventory platform {declared} for {name}.",
                    device=name, object_type="DeviceIntent", object_id=name, source="INVENTORY",
                    evidence={"intent_platform": device.platform, "inventory_platform": declared},
                    remediation="Correct the DeviceIntent platform or the target device.",
                )
                continue
        if inventory is not None and topology is not None and not (known_in_inventory or known_in_topology):
            ctx.add(
                Code.DEVICE_NOT_IN_INVENTORY,
                f"Existing-device intent {name} is not present in project inventory or topology.",
                device=name, object_type="DeviceIntent", object_id=name, source="INVENTORY",
                remediation="Confirm the device name, or mark the intent as a NEW_DEVICE.",
            )
