"""Management VRF: intent, per-platform rendering, Tier-1 validation and the honest capability classification.

Intent lives in the candidate revision's ``sections["management"]`` (the same versioned JSON document every other Device
Builder namespace uses) and travels through hydration as ``phase12["management"]`` ONLY when it holds an object, so every
existing candidate, snapshot hash and plan is byte-identical:

    vrfs      {id: {id, name, description}}
    bindings  {id: {id, vrf_id, interface_id}}                     -- moves an L3 interface into the VRF
    routes    {id: {id, vrf_id, family, destination, next_hop}}     -- VRF static routes (the management default route)
    services  {id: {id, vrf_id, service, host, source_interface_id}} -- SSH / EAPI / GNMI / SYSLOG / NTP / SNMP in the VRF

Objects are created complete and validated at creation (there is no per-field draft state for them); a change is a remove
and an add.  Mutations are DRAFT-only, like every Device Builder collection.

Rendering: one function per platform returns line descriptors for four insertion points of ``PlatformDriver
.render_composed``: ``definitions`` (before interfaces), ``binding`` (inside one interface block, before its addresses --
EOS / IOS XE / IOS XR discard an interface's addresses when its VRF changes, so the binding must precede them), ``routes``
(after routing) and ``services`` (after service policy).  Anything a platform renderer cannot express is emitted as the
standard UNSUPPORTED marker, which validation and planning refuse -- nothing is silently dropped.
"""

from __future__ import annotations

import ipaddress
import re
from copy import deepcopy
from uuid import uuid4

from django.db import transaction

from ... import models

SERVICES = ("SSH", "EAPI", "GNMI", "NETCONF", "SYSLOG", "NTP", "SNMP")
HOST_SERVICES = frozenset({"SYSLOG", "NTP"})
FAMILIES = ("IPV4", "IPV6")
MAX_VRFS, MAX_BINDINGS, MAX_ROUTES, MAX_SERVICES = 2, 16, 16, 16
RESERVED = frozenset({"default", "global", "mgmt-default"})
L3_KINDS = frozenset({"ROUTED_PHYSICAL", "SVI", "LOOPBACK", "SUBINTERFACE", "MANAGEMENT"})
UNSUPPORTED = "! UNSUPPORTED:"     # platform_drivers.UNSUPPORTED_OBJECT_MARKER (kept literal: no import cycle)
SRL_VRF_ROUTE_GROUP = "nmas-mgmt"


class ManagementIntentError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def empty() -> dict:
    return {"vrfs": {}, "bindings": {}, "routes": {}, "services": {}}


def section(revision) -> dict:
    found = deepcopy((revision.sections or {}).get("management") or {})
    base = empty()
    for key in base:
        if isinstance(found.get(key), dict):
            base[key] = found[key]
    return base


def present(management: dict | None) -> bool:
    return any((management or {}).get(key) for key in ("vrfs", "bindings", "routes", "services"))


# --- intent mutation -----------------------------------------------------------------------------------------------------------
def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


def _save(revision, management: dict) -> None:
    from .. import interface_intent_service

    interface_intent_service.require_draft(revision)
    sections = deepcopy(revision.sections or {})
    if present(management):
        sections["management"] = management
    else:
        sections.pop("management", None)        # an emptied namespace leaves the document exactly as before
    revision.sections = sections
    revision.save(update_fields=["sections"])


def _vrf(management: dict, vrf_id: str) -> dict:
    vrf = management["vrfs"].get(str(vrf_id or ""))
    if not vrf:
        raise ManagementIntentError("MGMT_VRF_REFERENCE_INVALID", "The VRF does not belong to this candidate revision.")
    return vrf


def _interface(revision, interface_id: str) -> dict:
    from .. import interface_intent_service

    try:
        return interface_intent_service.get_interface(revision, str(interface_id or ""))
    except interface_intent_service.CollectionOwnershipError:
        raise ManagementIntentError("MGMT_INTERFACE_REFERENCE_INVALID", "The interface does not belong to this candidate revision.") from None


def add_vrf(revision, *, name: str, description: str = "") -> dict:
    name, description = str(name or "").strip(), str(description or "").strip()
    if not models.MGMT_VRF_NAME_RE.fullmatch(name) or name.lower() in RESERVED:
        raise ManagementIntentError("MGMT_VRF_INVALID", "Use 1-32 letters, digits, '_' or '-', starting with a letter (not 'default').")
    if len(description) > 80 or re.search(r"[\x00-\x1f]", description):
        raise ManagementIntentError("MGMT_VRF_INVALID", "The description is too long or has control characters.")
    with transaction.atomic():
        management = section(revision)
        if len(management["vrfs"]) >= MAX_VRFS:
            raise ManagementIntentError("MGMT_LIMIT", f"At most {MAX_VRFS} management VRFs.")
        if any(v["name"].lower() == name.lower() for v in management["vrfs"].values()):
            raise ManagementIntentError("MGMT_VRF_DUPLICATE", "A management VRF with this name exists.")
        obj = {"id": _new_id("mvrf"), "name": name, "description": description}
        management["vrfs"][obj["id"]] = obj
        _save(revision, management)
    return obj


def add_binding(revision, *, vrf_id: str, interface_id: str) -> dict:
    with transaction.atomic():
        management = section(revision)
        _vrf(management, vrf_id)
        interface = _interface(revision, interface_id)
        if interface.get("kind") not in L3_KINDS:
            raise ManagementIntentError("MGMT_BINDING_INVALID", "Only a layer-3 interface can be placed in a management VRF.")
        if any(b["interface_id"] == interface["id"] for b in management["bindings"].values()):
            raise ManagementIntentError("MGMT_BINDING_DUPLICATE", "The interface is already bound to a management VRF.")
        if len(management["bindings"]) >= MAX_BINDINGS:
            raise ManagementIntentError("MGMT_LIMIT", "Too many management VRF bindings.")
        obj = {"id": _new_id("mbind"), "vrf_id": str(vrf_id), "interface_id": interface["id"]}
        management["bindings"][obj["id"]] = obj
        _save(revision, management)
    return obj


def add_route(revision, *, vrf_id: str, destination: str, next_hop: str) -> dict:
    try:
        prefix = ipaddress.ip_network(str(destination).strip(), strict=True)
        hop = ipaddress.ip_address(str(next_hop).strip())
    except ValueError:
        raise ManagementIntentError("MGMT_ROUTE_INVALID", "Give a destination prefix and a next-hop address.") from None
    if prefix.version != hop.version or hop.is_loopback or hop.is_multicast or hop.is_unspecified:
        raise ManagementIntentError("MGMT_ROUTE_INVALID", "The next hop must be a unicast address of the destination's family.")
    with transaction.atomic():
        management = section(revision)
        _vrf(management, vrf_id)
        if len(management["routes"]) >= MAX_ROUTES:
            raise ManagementIntentError("MGMT_LIMIT", "Too many management VRF routes.")
        if any(r["vrf_id"] == vrf_id and r["destination"] == str(prefix) for r in management["routes"].values()):
            raise ManagementIntentError("MGMT_ROUTE_DUPLICATE", "The VRF already has a route to this destination.")
        obj = {"id": _new_id("mroute"), "vrf_id": str(vrf_id), "family": "IPV6" if prefix.version == 6 else "IPV4",
               "destination": str(prefix), "next_hop": str(hop)}
        management["routes"][obj["id"]] = obj
        _save(revision, management)
    return obj


def add_service(revision, *, vrf_id: str, service: str, host: str = "", source_interface_id: str = "") -> dict:
    service = str(service or "").upper()
    if service not in SERVICES:
        raise ManagementIntentError("MGMT_SERVICE_INVALID", "Unknown management service.")
    host = str(host or "").strip()
    if service in HOST_SERVICES:
        try:
            parsed = ipaddress.ip_address(host)
        except ValueError:
            raise ManagementIntentError("MGMT_SERVICE_INVALID", f"{service} needs a server address.") from None
        if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
            raise ManagementIntentError("MGMT_SERVICE_INVALID", "The server must be a unicast address.")
        host = str(parsed)
    elif host:
        raise ManagementIntentError("MGMT_SERVICE_INVALID", f"{service} takes no server address.")
    with transaction.atomic():
        management = section(revision)
        _vrf(management, vrf_id)
        if source_interface_id:
            _interface(revision, source_interface_id)
        if len(management["services"]) >= MAX_SERVICES:
            raise ManagementIntentError("MGMT_LIMIT", "Too many management VRF services.")
        if any(s["vrf_id"] == vrf_id and s["service"] == service and s.get("host", "") == host for s in management["services"].values()):
            raise ManagementIntentError("MGMT_SERVICE_DUPLICATE", "This service is already enabled in the VRF.")
        obj = {"id": _new_id("msvc"), "vrf_id": str(vrf_id), "service": service, "host": host,
               "source_interface_id": str(source_interface_id or "")}
        management["services"][obj["id"]] = obj
        _save(revision, management)
    return obj


def remove(revision, *, collection: str, object_id: str) -> dict:
    """Remove one object.  Removing a VRF that still has bindings / routes / services is refused (no dangling reference)."""
    if collection not in ("vrfs", "bindings", "routes", "services"):
        raise ManagementIntentError("MGMT_REFERENCE_INVALID", "Unknown management collection.")
    with transaction.atomic():
        management = section(revision)
        obj = management[collection].get(str(object_id or ""))
        if obj is None:
            raise ManagementIntentError("MGMT_REFERENCE_INVALID", "The object does not belong to this candidate revision.")
        if collection == "vrfs" and any(child.get("vrf_id") == obj["id"] for key in ("bindings", "routes", "services")
                                        for child in management[key].values()):
            raise ManagementIntentError("MGMT_VRF_IN_USE", "Remove the VRF's bindings, routes and services first.")
        del management[collection][obj["id"]]
        _save(revision, management)
    return obj


# --- rendering -----------------------------------------------------------------------------------------------------------------
def _s(text: str) -> dict:
    return {"kind": "static", "text": text}


def _names(management: dict) -> dict:
    return {vrf_id: vrf["name"] for vrf_id, vrf in (management.get("vrfs") or {}).items()}


def _families(management: dict, vrf_id: str) -> set:
    return {r.get("family") for r in (management.get("routes") or {}).values() if r.get("vrf_id") == vrf_id}


def binding_for(management: dict, interface_id: str) -> str:
    """-> the VRF name ``interface_id`` is bound to ('' when none)."""
    names = _names(management)
    for binding in (management.get("bindings") or {}).values():
        if binding.get("interface_id") == interface_id and binding.get("vrf_id") in names:
            return names[binding["vrf_id"]]
    return ""


def _iface_name(interfaces_by_id: dict, interface_id: str) -> str:
    return (interfaces_by_id.get(interface_id or "") or {}).get("name") or ""


def _mask(prefix: str) -> tuple[str, str]:
    network = ipaddress.ip_network(prefix)
    return str(network.network_address), str(network.netmask)


# EOS -------------------------------------------------------------------------------------------------------------------------------
def _eos(part: str, management: dict, interfaces_by_id: dict, interface=None) -> list[dict]:
    names = _names(management)
    if part == "definitions":
        lines = []
        for vrf_id, vrf in sorted(management.get("vrfs", {}).items(), key=lambda kv: kv[1]["name"]):
            lines += [_s("!"), _s(f"vrf instance {vrf['name']}")]
            if vrf.get("description"):
                lines.append(_s(f"   description {vrf['description']}"))
            lines += [_s("!"), _s(f"ip routing vrf {vrf['name']}")]
            if "IPV6" in _families(management, vrf_id):
                lines.append(_s(f"ipv6 unicast-routing vrf {vrf['name']}"))
        return lines
    if part == "binding":
        name = binding_for(management, interface["id"])
        return [_s(f"   vrf {name}")] if name else []
    if part == "routes":
        lines = []
        for route in sorted(management.get("routes", {}).values(), key=lambda r: (names.get(r["vrf_id"], ""), r["destination"])):
            if route["vrf_id"] not in names:
                continue
            verb = "ipv6 route" if route["family"] == "IPV6" else "ip route"
            lines.append(_s(f"{verb} vrf {names[route['vrf_id']]} {route['destination']} {route['next_hop']}"))
        return ([_s("!")] + lines) if lines else []
    blocks: dict[str, list[str]] = {}
    flat: list[str] = []
    for service in sorted(management.get("services", {}).values(), key=lambda s: (names.get(s["vrf_id"], ""), s["service"], s.get("host", ""))):
        vrf = names.get(service["vrf_id"])
        if not vrf:
            continue
        kind = service["service"]
        if kind == "SSH":
            blocks.setdefault("management ssh", []).extend([f"   vrf {vrf}", "      no shutdown"])
        elif kind == "EAPI":
            blocks.setdefault("management api http-commands", []).extend([f"   vrf {vrf}", "      no shutdown"])
        elif kind == "GNMI":
            blocks.setdefault("management api gnmi", []).extend([f"   transport grpc {vrf}", f"      vrf {vrf}"])
        elif kind == "SYSLOG":
            flat.append(f"logging vrf {vrf} host {service['host']}")
            source = _iface_name(interfaces_by_id, service.get("source_interface_id"))
            if source:
                flat.append(f"logging vrf {vrf} source-interface {source}")
        elif kind == "NTP":
            flat.append(f"ntp server vrf {vrf} {service['host']}")
        elif kind == "SNMP":
            flat.append(f"snmp-server vrf {vrf}")
        else:
            flat.append(f"{UNSUPPORTED} management VRF service {kind} is NOT_IMPLEMENTED for Arista cEOS; intent preserved")
    lines = []
    for header, children in blocks.items():
        lines += [_s("!"), _s(header), *(_s(child) for child in children)]
    if flat:
        lines += [_s("!"), *(_s(text) for text in flat)]
    return lines


# IOS XE ----------------------------------------------------------------------------------------------------------------------------
def _iosxe(part: str, management: dict, interfaces_by_id: dict, interface=None) -> list[dict]:
    names = _names(management)
    if part == "definitions":
        lines = []
        for vrf_id, vrf in sorted(management.get("vrfs", {}).items(), key=lambda kv: kv[1]["name"]):
            lines += [_s("!"), _s(f"vrf definition {vrf['name']}")]
            if vrf.get("description"):
                lines.append(_s(f" description {vrf['description']}"))
            lines += [_s(" address-family ipv4"), _s(" exit-address-family")]
            if "IPV6" in _families(management, vrf_id):
                lines += [_s(" address-family ipv6"), _s(" exit-address-family")]
        return lines
    if part == "binding":
        name = binding_for(management, interface["id"])
        return [_s(f" vrf forwarding {name}")] if name else []
    if part == "routes":
        lines = []
        for route in sorted(management.get("routes", {}).values(), key=lambda r: (names.get(r["vrf_id"], ""), r["destination"])):
            if route["vrf_id"] not in names:
                continue
            if route["family"] == "IPV6":
                lines.append(_s(f"ipv6 route vrf {names[route['vrf_id']]} {route['destination']} {route['next_hop']}"))
            else:
                network, mask = _mask(route["destination"])
                lines.append(_s(f"ip route vrf {names[route['vrf_id']]} {network} {mask} {route['next_hop']}"))
        return ([_s("!")] + lines) if lines else []
    lines = []
    for service in sorted(management.get("services", {}).values(), key=lambda s: (names.get(s["vrf_id"], ""), s["service"], s.get("host", ""))):
        vrf = names.get(service["vrf_id"])
        if not vrf:
            continue
        if service["service"] == "SYSLOG":
            lines.append(_s(f"logging host {service['host']} vrf {vrf}"))
        elif service["service"] == "NTP":
            lines.append(_s(f"ntp server vrf {vrf} {service['host']}"))
        else:
            # SSH in a VRF needs the VTY access-class 'vrf-also' policy; SNMP needs a community / user: neither is modelled.
            lines.append(_s(f"{UNSUPPORTED} management VRF service {service['service']} is NOT_IMPLEMENTED for Cisco IOS XE; intent preserved"))
    return ([_s("!")] + lines) if lines else []


# IOS XR ----------------------------------------------------------------------------------------------------------------------------
def _iosxr(part: str, management: dict, interfaces_by_id: dict, interface=None) -> list[dict]:
    names = _names(management)
    if part == "definitions":
        lines = []
        for vrf_id, vrf in sorted(management.get("vrfs", {}).items(), key=lambda kv: kv[1]["name"]):
            lines += [_s("!"), _s(f"vrf {vrf['name']}")]
            if vrf.get("description"):
                lines.append(_s(f" description {vrf['description']}"))
            lines += [_s(" address-family ipv4 unicast"), _s(" !")]
            if "IPV6" in _families(management, vrf_id):
                lines += [_s(" address-family ipv6 unicast"), _s(" !")]
        return lines
    if part == "binding":
        name = binding_for(management, interface["id"])
        return [_s(f" vrf {name}")] if name else []
    if part == "routes":
        by_vrf: dict = {}
        for route in management.get("routes", {}).values():
            if route["vrf_id"] in names:
                by_vrf.setdefault(names[route["vrf_id"]], {}).setdefault(route["family"], []).append(route)
        if not by_vrf:
            return []
        lines = [_s("!"), _s("router static")]
        for vrf in sorted(by_vrf):
            lines.append(_s(f" vrf {vrf}"))
            for family in ("IPV4", "IPV6"):
                rows = sorted(by_vrf[vrf].get(family, []), key=lambda r: r["destination"])
                if rows:
                    lines.append(_s(f"  address-family {'ipv6' if family == 'IPV6' else 'ipv4'} unicast"))
                    lines += [_s(f"   {r['destination']} {r['next_hop']}") for r in rows]
        return lines
    lines = []
    for service in sorted(management.get("services", {}).values(), key=lambda s: (names.get(s["vrf_id"], ""), s["service"], s.get("host", ""))):
        vrf = names.get(service["vrf_id"])
        if not vrf:
            continue
        kind = service["service"]
        if kind == "SSH":
            lines.append(_s(f"ssh server vrf {vrf}"))
        elif kind == "SYSLOG":
            lines.append(_s(f"logging {service['host']} vrf {vrf}"))
        elif kind == "NTP":
            lines += [_s("ntp"), _s(f" server vrf {vrf} {service['host']}")]
        elif kind == "GNMI":
            lines += [_s("grpc"), _s(f" vrf {vrf}")]
        else:
            lines.append(_s(f"{UNSUPPORTED} management VRF service {kind} is NOT_IMPLEMENTED for Cisco IOS XR; intent preserved"))
    return ([_s("!")] + lines) if lines else []


# SR Linux --------------------------------------------------------------------------------------------------------------------------
def _srl_subif(name: str) -> str:
    return name if "." in name else f"{name}.0"


def _srlinux(part: str, management: dict, interfaces_by_id: dict, interface=None) -> list[dict]:
    names = _names(management)
    if part == "definitions":
        lines = []
        for vrf in sorted(management.get("vrfs", {}).values(), key=lambda v: v["name"]):
            if vrf["name"] == "mgmt":
                lines.append(_s("! the built-in 'mgmt' network-instance already exists (bound to mgmt0)"))
                continue
            lines += [_s(f"set network-instance {vrf['name']} type ip-vrf"), _s(f"set network-instance {vrf['name']} admin-state enable")]
            if vrf.get("description"):
                lines.append(_s(f'set network-instance {vrf["name"]} description "{vrf["description"]}"'))
        return lines
    if part == "binding":
        name = binding_for(management, interface["id"])
        if not name:
            return []
        subif = _srl_subif(interface.get("name") or "")
        # The interface template binds the subinterface to "default"; an interface belongs to ONE network-instance.
        return [_s(f"delete network-instance default interface {subif}"), _s(f"set network-instance {name} interface {subif}")]
    if part == "routes":
        lines = []
        for route in sorted(management.get("routes", {}).values(), key=lambda r: (names.get(r["vrf_id"], ""), r["destination"])):
            vrf = names.get(route["vrf_id"])
            if not vrf:
                continue
            group = f"{SRL_VRF_ROUTE_GROUP}-{route['id'][-8:]}"
            lines += [_s(f"set network-instance {vrf} next-hop-groups group {group} nexthop 1 ip-address {route['next_hop']}"),
                      _s(f"set network-instance {vrf} static-routes route {route['destination']} next-hop-group {group}"),
                      _s(f"set network-instance {vrf} static-routes route {route['destination']} admin-state enable")]
        return lines
    lines = []
    for service in sorted(management.get("services", {}).values(), key=lambda s: (names.get(s["vrf_id"], ""), s["service"], s.get("host", ""))):
        vrf = names.get(service["vrf_id"])
        if not vrf:
            continue
        kind = service["service"]
        if kind == "SSH":
            lines += [_s(f"set system ssh-server nmas-{vrf} admin-state enable"), _s(f"set system ssh-server nmas-{vrf} network-instance {vrf}")]
        elif kind == "GNMI":
            lines += [_s(f"set system grpc-server nmas-{vrf} admin-state enable"), _s(f"set system grpc-server nmas-{vrf} network-instance {vrf}"),
                      _s(f"set system grpc-server nmas-{vrf} services [ gnmi ]")]
        elif kind == "SYSLOG":
            lines.append(_s(f"set system logging remote-server {service['host']} network-instance {vrf}"))
        elif kind == "NTP":
            lines += [_s(f"set system ntp network-instance {vrf}"), _s(f"set system ntp server {service['host']}")]
        else:
            lines.append(_s(f"{UNSUPPORTED} management VRF service {kind} is NOT_IMPLEMENTED for Nokia SR Linux; intent preserved"))
    return lines


# Ubuntu / FRR ------------------------------------------------------------------------------------------------------------------------
def _vrf_table(vrf_id: str, names: dict) -> int:
    return 1000 + sorted(names).index(vrf_id) + 1


def _ubuntu(part: str, management: dict, interfaces_by_id: dict, interface=None) -> list[dict]:
    names = _names(management)
    if part == "definitions":
        lines = []
        for vrf_id in sorted(names, key=lambda k: names[k]):
            name = names[vrf_id]
            lines += [_s(f"ip link add {name} type vrf table {_vrf_table(vrf_id, names)}"), _s(f"ip link set dev {name} up")]
        if lines:
            # sshd / gNMI listening in the default VRF accept connections arriving through an l3mdev (VRF) device
            lines.append(_s("sysctl -w net.ipv4.tcp_l3mdev_accept=1"))
        return lines
    if part == "binding":
        name = binding_for(management, interface["id"])
        return [_s(f"ip link set dev {interface.get('name')} master {name}")] if name else []
    if part == "routes":
        by_vrf: dict = {}
        for route in management.get("routes", {}).values():
            if route["vrf_id"] in names:
                by_vrf.setdefault(names[route["vrf_id"]], []).append(route)
        lines = []
        for vrf in sorted(by_vrf):
            lines.append(_s(f"vrf {vrf}"))
            for route in sorted(by_vrf[vrf], key=lambda r: r["destination"]):
                verb = "ipv6 route" if route["family"] == "IPV6" else "ip route"
                lines.append(_s(f" {verb} {route['destination']} {route['next_hop']}"))
            lines.append(_s("exit-vrf"))
        return lines
    lines = []
    for service in management.get("services", {}).values():
        if service["vrf_id"] in names and service["service"] not in ("SSH", "GNMI"):
            lines.append(_s(f"{UNSUPPORTED} management VRF service {service['service']} is NOT_IMPLEMENTED for Ubuntu / FRR; intent preserved"))
    return lines


RENDERERS = {
    models.Platform.ARISTA_CEOS.value: _eos,
    models.Platform.CISCO_C8000V_IOSXE.value: _iosxe,
    models.Platform.CISCO_IOSXR.value: _iosxr,
    models.Platform.NOKIA_SRLINUX.value: _srlinux,
    models.Platform.UBUNTU_FRR.value: _ubuntu,
}


def render(platform: str, part: str, management: dict | None, interfaces_by_id: dict | None = None, interface: dict | None = None) -> list[dict]:
    """Descriptors for one insertion point.  An unknown platform renders the UNSUPPORTED marker once (definitions only)."""
    if not present(management):
        return []
    renderer = RENDERERS.get(platform)
    if renderer is None:
        if part != "definitions":
            return []
        return [_s(f"{UNSUPPORTED} management VRF is NOT_IMPLEMENTED for {platform}; intent preserved")]
    return renderer(part, management, interfaces_by_id or {}, interface)


def sonic_config_db(management: dict | None, unsupported: list) -> dict:
    """SONiC: only the platform management VRF (``mgmt``, bound to eth0 by the NOS) is expressible in config_db."""
    if not present(management):
        return {}
    names = _names(management)
    doc = {}
    if list(names.values()) == ["mgmt"] and not management.get("bindings"):
        doc["MGMT_VRF_CONFIG"] = {"vrf_global": {"mgmtVrfEnabled": "true"}}
    else:
        unsupported.append(f"// {UNSUPPORTED[2:]} SONiC supports only the built-in 'mgmt' VRF on eth0 (MGMT_VRF_CONFIG); intent preserved")
    for route in (management.get("routes") or {}).values():
        unsupported.append(f"// {UNSUPPORTED[2:]} SONiC management VRF route {route['destination']} is NOT_IMPLEMENTED; intent preserved")
    for service in (management.get("services") or {}).values():
        unsupported.append(f"// {UNSUPPORTED[2:]} SONiC management VRF service {service['service']} is NOT_IMPLEMENTED; intent preserved")
    return doc


# --- Tier-1 structural validation (pure: used by the validation engine) ----------------------------------------------------------
def problems(platform: str, management: dict | None, interfaces: list[dict]) -> list[dict]:
    """-> [{"code", "object_id", "message"}] for one device's management intent."""
    if not present(management):
        return []
    found = []
    by_id = {row.get("id"): row for row in interfaces}
    names = _names(management)
    if platform not in RENDERERS and platform != models.Platform.SONIC.value:
        found.append({"code": "MGMT_VRF_PLATFORM_UNSUPPORTED", "object_id": "", "message": f"No management VRF renderer for {platform}."})
    for collection in ("bindings", "routes", "services"):
        for obj in management.get(collection, {}).values():
            if obj.get("vrf_id") not in names:
                found.append({"code": "MGMT_VRF_REFERENCE_INVALID", "object_id": obj.get("id", ""), "message": "References a missing VRF."})
    for binding in management.get("bindings", {}).values():
        interface = by_id.get(binding.get("interface_id"))
        if interface is None:
            found.append({"code": "MGMT_INTERFACE_REFERENCE_INVALID", "object_id": binding.get("id", ""), "message": "References a missing interface."})
        elif interface.get("kind") not in L3_KINDS:
            found.append({"code": "MGMT_BINDING_INVALID", "object_id": binding["id"], "message": "Only layer-3 interfaces can join a VRF."})
        elif not interface.get("addresses"):
            found.append({"code": "MGMT_BINDING_NO_ADDRESS", "object_id": binding["id"],
                          "message": "A management VRF interface without an address cannot carry management."})
    for vrf_id, name in names.items():
        # SONiC's management VRF is bound to eth0 by the NOS itself (no binding object exists to model)
        if platform != models.Platform.SONIC.value and not any(b.get("vrf_id") == vrf_id for b in management.get("bindings", {}).values()):
            found.append({"code": "MGMT_VRF_UNBOUND", "object_id": vrf_id, "message": f"VRF {name} has no interface: it cannot carry management."})
        if platform != models.Platform.SONIC.value and not any(
                s.get("vrf_id") == vrf_id and s.get("service") in ("SSH", "EAPI", "GNMI", "NETCONF")
                for s in management.get("services", {}).values()):
            found.append({"code": "MGMT_VRF_NO_ACCESS_SERVICE", "object_id": vrf_id,
                          "message": f"VRF {name} enables no access service (SSH / API): NMAS could not manage the device through it."})
    for route in management.get("routes", {}).values():
        vrf_interfaces = [by_id.get(b["interface_id"]) for b in management.get("bindings", {}).values() if b.get("vrf_id") == route.get("vrf_id")]
        connected = False
        for interface in filter(None, vrf_interfaces):
            for address in (interface.get("addresses") or {}).values():
                try:
                    if ipaddress.ip_address(route["next_hop"]) in ipaddress.ip_interface(address.get("cidr") or "").network:
                        connected = True
                except ValueError:
                    continue
        if not connected:
            found.append({"code": "MGMT_ROUTE_NEXT_HOP_UNREACHABLE", "object_id": route.get("id", ""),
                          "message": "The next hop is not inside any subnet of the VRF's bound interfaces."})
    return found


# --- capability classification -----------------------------------------------------------------------------------------------
FEATURES = ("VRF_DEFINE", "INTERFACE_BINDING", "STATIC_ROUTE", "SSH", "EAPI", "GNMI", "SYSLOG", "NTP", "SNMP", "NETCONF")
_S, _NI, _U, _OOS = "SUPPORTED", "NOT_IMPLEMENTED", "UNSUPPORTED", "OUT_OF_SCOPE"


def _row(render: str, validate: str, import_: str, execute: str, compensate: str, live: str, basis: str) -> dict:
    return {"render": render, "validate": validate, "import": import_, "execute": execute, "compensate": compensate,
            "live_verified": live, "basis": basis}


FEATURE_OBJECT = {"VRF_DEFINE": "mgmt_vrf", "INTERFACE_BINDING": "mgmt_vrf_binding", "STATIC_ROUTE": "mgmt_vrf_route"}
# Features config_import.parser_ceos lifts into intent (only for a VRF that carries a management access service).
EOS_IMPORT = frozenset({"VRF_DEFINE", "INTERFACE_BINDING", "STATIC_ROUTE", "SSH", "EAPI", "GNMI"})


def capability_matrix(live_evidence: dict | None = None) -> dict:
    """{platform: {feature: dimensions}}.  Nothing is SUPPORTED because it renders.  ``execute`` / ``compensate`` are
    SUPPORTED only where ``execution.capability.management_gate`` holds (recorded live apply + compensation evidence);
    ``live_verified`` names the evidence file (``live_evidence`` key ``"<platform>:live:<FEATURE>"``) or says NOT_VERIFIED."""
    from ..execution import capability as execution_capability
    from . import capability_evidence

    live_evidence = capability_evidence.LIVE if live_evidence is None else live_evidence
    matrix: dict = {}
    eos_exec = {"VRF_DEFINE", "INTERFACE_BINDING", "STATIC_ROUTE", "SSH", "EAPI", "GNMI", "SYSLOG", "NTP", "SNMP"}
    for feature in FEATURES:
        live = live_evidence.get(f"arista_ceos:live:{feature}", "NOT_VERIFIED")
        if feature == "NETCONF":
            matrix.setdefault("arista_ceos", {})[feature] = _row(_U, _S, _NI, _NI, _NI, "NOT_VERIFIED",
                                                                  "NETCONF in a VRF is not modelled for EOS: rendered as the "
                                                                  "UNSUPPORTED marker, which validation blocks.")
            continue
        object_type = FEATURE_OBJECT.get(feature, "mgmt_vrf_service")
        gated = feature in eos_exec and execution_capability.management_gate(
            "arista_ceos", object_type, feature if object_type == "mgmt_vrf_service" else "")
        matrix.setdefault("arista_ceos", {})[feature] = _row(
            _S, _S, _S if feature in EOS_IMPORT else _NI, _S if gated else _NI, _S if gated else _NI, live,
            "Rendered by core.services.management.vrf and validated; the cEOS executor path (structural flattening, "
            "management_inverse / snapshot inverse, digest-verified compensation) is implemented and unit-tested, and "
            + ("live apply + compensation evidence is recorded." if gated else
               "execution stays refused until the isolated fixture records live evidence."))
    for platform, served, label in (
            (models.Platform.CISCO_C8000V_IOSXE.value, {"VRF_DEFINE", "INTERFACE_BINDING", "STATIC_ROUTE", "SYSLOG", "NTP"}, "IOS XE"),
            (models.Platform.CISCO_IOSXR.value, {"VRF_DEFINE", "INTERFACE_BINDING", "STATIC_ROUTE", "SSH", "SYSLOG", "NTP", "GNMI"}, "IOS XR"),
            (models.Platform.NOKIA_SRLINUX.value, {"VRF_DEFINE", "INTERFACE_BINDING", "STATIC_ROUTE", "SSH", "GNMI", "SYSLOG", "NTP"}, "SR Linux"),
            (models.Platform.UBUNTU_FRR.value, {"VRF_DEFINE", "INTERFACE_BINDING", "STATIC_ROUTE", "SSH", "GNMI"}, "Ubuntu / FRR")):
        for feature in FEATURES:
            matrix.setdefault(platform, {})[feature] = _row(
                _S if feature in served else _NI, _S if feature in served else _NI, _NI, _NI, _NI, "NOT_VERIFIED",
                f"{label}: rendered and validated only (syntax from vendor documentation, not live-verified); no executor "
                "path applies management VRF objects on this platform." if feature in served else
                f"{label}: not modelled.")
    for feature in FEATURES:
        matrix.setdefault(models.Platform.SONIC.value, {})[feature] = _row(
            _S if feature == "VRF_DEFINE" else _U, _S if feature == "VRF_DEFINE" else _NI, _NI, _NI, _NI, "NOT_VERIFIED",
            "SONiC: only the built-in 'mgmt' VRF on eth0 (MGMT_VRF_CONFIG) is expressible; render-only."
            if feature == "VRF_DEFINE" else "SONiC binds the management VRF to eth0 only; other objects are not expressible.")
        matrix.setdefault("juniper_junos", {})[feature] = _row(_OOS, _OOS, _OOS, _OOS, _OOS, "NOT_VERIFIED",
                                                               "Junos is not in the NMAS platform catalogue (no image, no driver).")
    return matrix
