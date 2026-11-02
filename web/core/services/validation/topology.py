"""Interface / link / VLAN / MTU cross-endpoint validation.

Only links whose ends can be correlated are judged.  The topology source is
read-only evidence; where one end is outside the Change the other end's
evidence is NetBox (distinguished as such and only ever a WARNING), and where
nothing is known nothing is guessed.

Access/trunk semantics stay conservative: an access-to-trunk link is
compatible when the access VLAN equals the trunk native VLAN (default 1);
otherwise the combination is AMBIGUOUS and reported as a WARNING, never as a
blocking error.  MTU differences are a WARNING; nothing here proves an MTU
mismatch fatal.
"""

from __future__ import annotations

import ipaddress

from .context import PHYSICAL_KINDS
from .findings import Code, Severity

DEFAULT_NATIVE = 1


def _endpoint(ctx, end: dict) -> dict:
    device = ctx.model.devices.get(end["device"])
    interface = device.interface_by_name(end["interface"]) if device else None
    return {
        "device": end["device"],
        "name": end["interface"],
        "in_change": device is not None,
        "interface": interface,
        "model": device,
    }


def get_link_pairs(ctx) -> list[dict]:
    """Topology links annotated with the candidate interface at each end."""
    if "links" in ctx.cache:
        return ctx.cache["links"]
    pairs = []
    topology = ctx.topology
    if topology is not None:
        for link in topology["links"]:
            pairs.append({"a": _endpoint(ctx, link["a"]), "z": _endpoint(ctx, link["z"])})
    ctx.cache["links"] = pairs
    return pairs


def link_label(pair) -> str:
    return f"{pair['a']['device']}:{pair['a']['name']} <-> {pair['z']['device']}:{pair['z']['name']}"


def _both_candidate(pair) -> bool:
    return bool(pair["a"]["interface"] and pair["z"]["interface"])


def _native(interface) -> int:
    value = interface.get("native_vlan")
    return value if isinstance(value, int) else DEFAULT_NATIVE


def _children(ctx, endpoint) -> list[dict]:
    model = endpoint["model"]
    iid = endpoint["interface"]["id"]
    return [i for i in model.interfaces.values() if i.get("kind") == "SUBINTERFACE" and i.get("parent_id") == iid]


def _p2p_prefix(ctx, pair, a, z) -> None:
    for family in (4, 6):
        a_addrs = [r for r in ctx.model.addresses_of(a["device"], a["interface"]["id"]) if r.family == family and not r.ip.is_link_local]
        z_addrs = [r for r in ctx.model.addresses_of(z["device"], z["interface"]["id"]) if r.family == family and not r.ip.is_link_local]
        if not a_addrs or not z_addrs:
            continue  # a single-family link is legitimate; only judge families both ends carry
        if any(ra.network == rz.network and ra.ip != rz.ip for ra in a_addrs for rz in z_addrs):
            continue
        if any(ra.ip == rz.ip for ra in a_addrs for rz in z_addrs) and any(
            ra.network == rz.network for ra in a_addrs for rz in z_addrs
        ):
            continue  # identical hosts are reported by IP_DUPLICATE, not as a subnet mismatch
        ctx.add(
            Code.LINK_PREFIX_MISMATCH,
            f"IPv{family} addresses on {link_label(pair)} do not share a subnet: "
            + ", ".join(f"{r.device}:{r.interface_name} {r.iface}" for r in [*a_addrs, *z_addrs]) + ".",
            device=a["device"], object_type="link", object_id=link_label(pair),
            related_devices=[z["device"]],
            related_objects=[f"{r.device}:{r.interface_name}:{r.address_id}" for r in [*a_addrs, *z_addrs]],
            source="TOPOLOGY+INTENT",
            evidence={"family": family, "evidence_kind": "candidate_vs_candidate",
                      "addresses": [{"device": r.device, "interface": r.interface_name, "cidr": str(r.iface)} for r in [*a_addrs, *z_addrs]]},
            remediation="Address both ends of a direct routed link from the same subnet (a valid /31 or /127 pair where used).",
        )


def _netbox_far_side_prefix(ctx, pair) -> None:
    """One end candidate-controlled, the other outside the Change: compare with NetBox (WARNING only)."""
    if ctx.netbox is None:
        return
    for near, far in ((pair["a"], pair["z"]), (pair["z"], pair["a"])):
        if not (near["interface"] and near["interface"].get("kind") == "ROUTED_PHYSICAL") or far["in_change"]:
            continue
        for family in (4, 6):
            near_addrs = [r for r in ctx.model.addresses_of(near["device"], near["interface"]["id"]) if r.family == family and not r.ip.is_link_local]
            far_rows = [r for r in ctx.netbox_addresses_of(far["device"], far["name"]) if r["family"] == family]
            if not near_addrs or not far_rows:
                continue
            far_ifaces = [ipaddress.ip_interface(r["cidr"]) for r in far_rows]
            if any(n.network == f.network for n in (r.iface for r in near_addrs) for f in far_ifaces):
                continue
            ctx.add(
                Code.LINK_PREFIX_MISMATCH,
                f"IPv{family} address on {near['device']}:{near['name']} does not share a subnet with the NetBox "
                f"address of {far['device']}:{far['name']} (a device outside this Change).",
                severity=Severity.WARNING, device=near["device"], object_type="link", object_id=link_label(pair),
                related_devices=[far["device"]], source="TOPOLOGY+NETBOX",
                evidence={"family": family, "evidence_kind": "candidate_vs_netbox",
                          "candidate": [str(r.iface) for r in near_addrs], "netbox": [str(f) for f in far_ifaces]},
                remediation="Confirm the far end is renumbered by another Change, or correct the candidate address.",
            )


def _access_access(ctx, pair, a, z) -> None:
    va, vz = a["interface"].get("access_vlan"), z["interface"].get("access_vlan")
    if va is None and vz is None:
        return
    if va is not None and vz is not None and va != vz:
        ctx.add(
            Code.LINK_ACCESS_VLAN_MISMATCH,
            f"Access ports on {link_label(pair)} carry different VLANs ({va} vs {vz}).",
            device=a["device"], object_type="link", object_id=link_label(pair), related_devices=[z["device"]],
            source="TOPOLOGY+INTENT", evidence={"a_vlan": va, "z_vlan": vz},
            remediation="Use the same access VLAN on both ends.",
        )
    elif (va is None) != (vz is None):
        ctx.add(
            Code.LINK_ACCESS_VLAN_MISMATCH,
            f"Only one access port on {link_label(pair)} sets an access VLAN ({va} vs {vz}); the other uses the default VLAN.",
            severity=Severity.WARNING, device=a["device"], object_type="link", object_id=link_label(pair),
            related_devices=[z["device"]], source="TOPOLOGY+INTENT", evidence={"a_vlan": va, "z_vlan": vz},
            remediation="Set the access VLAN explicitly on both ends.",
        )


def _trunk_trunk(ctx, pair, a, z) -> None:
    ia, iz = a["interface"], z["interface"]
    na, nz = _native(ia), _native(iz)
    if na != nz:
        ctx.add(
            Code.LINK_NATIVE_VLAN_MISMATCH,
            f"Trunk ports on {link_label(pair)} use different native VLANs ({na} vs {nz}).",
            device=a["device"], object_type="link", object_id=link_label(pair), related_devices=[z["device"]],
            source="TOPOLOGY+INTENT", evidence={"a_native": na, "z_native": nz},
            remediation="Use the same native VLAN on both trunk ends.",
        )
    allowed_a, allowed_z = set(ia.get("trunk_allowed_vlans") or []), set(iz.get("trunk_allowed_vlans") or [])
    if allowed_a and allowed_z and not (allowed_a & allowed_z):
        ctx.add(
            Code.LINK_TRUNK_VLAN_MISSING,
            f"Trunk allowed-VLAN sets on {link_label(pair)} share no VLAN.",
            device=a["device"], object_type="link", object_id=link_label(pair), related_devices=[z["device"]],
            source="TOPOLOGY+INTENT",
            evidence={"a_allowed": sorted(allowed_a), "z_allowed": sorted(allowed_z)},
            remediation="Allow at least the VLANs both switches use on this trunk.",
        )
        return
    # Concrete requirement: a VLAN both switches use locally (access port or SVI/subinterface tag)
    def local_vlans(endpoint):
        found = set()
        for interface in endpoint["model"].interfaces.values():
            for key in ("access_vlan", "vlan_id"):
                if isinstance(interface.get(key), int) and interface.get("kind") in ("ACCESS", "SVI"):
                    found.add(interface[key])
        return found
    required = (local_vlans(a) & local_vlans(z)) - {200}
    for vlan in sorted(required):
        missing = [name for name, allowed in (("A", allowed_a), ("Z", allowed_z)) if allowed and vlan not in allowed]
        if missing:
            ctx.add(
                Code.LINK_TRUNK_VLAN_MISSING,
                f"VLAN {vlan} is used by both switches of {link_label(pair)} but the trunk does not allow it on "
                f"{'both ends' if len(missing) == 2 else 'one end'}.",
                severity=Severity.WARNING, device=a["device"], object_type="link", object_id=link_label(pair),
                related_devices=[z["device"]], source="TOPOLOGY+INTENT",
                evidence={"vlan": vlan, "a_allowed": sorted(allowed_a), "z_allowed": sorted(allowed_z)},
                remediation="Add the VLAN to the trunk allowed list if it is meant to span this link.",
            )


def _access_trunk(ctx, pair, access, trunk) -> None:
    vlan = access["interface"].get("access_vlan")
    vlan = vlan if isinstance(vlan, int) else DEFAULT_NATIVE
    native = _native(trunk["interface"])
    if vlan == native:
        return  # provably compatible: untagged frames map onto the same VLAN
    ctx.add(
        Code.LINK_MODE_MISMATCH,
        f"{link_label(pair)} joins an access port (VLAN {vlan}) to a trunk with native VLAN {native}; "
        "untagged frames land in different VLANs.",
        severity=Severity.WARNING, device=access["device"], object_type="link", object_id=link_label(pair),
        related_devices=[trunk["device"]], source="TOPOLOGY+INTENT",
        evidence={"access_vlan": vlan, "trunk_native": native},
        remediation="Align the access VLAN with the trunk native VLAN, or make both ends trunks.",
    )


def _routed_l2(ctx, pair, routed, other) -> None:
    kids = _children(ctx, routed)
    tags = sorted({k["encapsulation_vlan"] for k in kids if isinstance(k.get("encapsulation_vlan"), int)})
    if other["interface"]["kind"] == "TRUNK":
        allowed = set(other["interface"].get("trunk_allowed_vlans") or [])
        if tags:
            for tag in tags:
                if allowed and tag not in allowed:
                    ctx.add(
                        Code.LINK_TRUNK_VLAN_MISSING,
                        f"Subinterface tag {tag} on {routed['device']}:{routed['name']} is not allowed on the "
                        f"trunk {other['device']}:{other['name']}.",
                        device=routed["device"], object_type="link", object_id=link_label(pair),
                        related_devices=[other["device"]], source="TOPOLOGY+INTENT",
                        evidence={"tag": tag, "allowed": sorted(allowed)},
                        remediation="Allow the subinterface VLAN on the trunk.",
                    )
        else:
            ctx.add(
                Code.LINK_MODE_MISMATCH,
                f"{link_label(pair)} joins a routed port without subinterfaces to a trunk; only native-VLAN "
                "traffic can be exchanged.",
                severity=Severity.WARNING, device=routed["device"], object_type="link", object_id=link_label(pair),
                related_devices=[other["device"]], source="TOPOLOGY+INTENT", evidence={"trunk_native": _native(other["interface"])},
                remediation="Add tagged subinterfaces, or make the far end an access port.",
            )
    elif tags:  # routed with tagged children facing an access port
        ctx.add(
            Code.LINK_MODE_MISMATCH,
            f"{routed['device']}:{routed['name']} has tagged subinterfaces but faces the access port "
            f"{other['device']}:{other['name']}, which drops tagged frames.",
            severity=Severity.WARNING, device=routed["device"], object_type="link", object_id=link_label(pair),
            related_devices=[other["device"]], source="TOPOLOGY+INTENT", evidence={"tags": tags},
            remediation="Make the far end a trunk.",
        )


def _mtu(ctx, pair, a, z) -> None:
    ma, mz = a["interface"].get("mtu"), z["interface"].get("mtu")
    if isinstance(ma, int) and isinstance(mz, int) and ma != mz:
        ospf = any(
            binding.get("interface_id") in (a["interface"]["id"], z["interface"]["id"])
            for endpoint in (a, z)
            for instance in (endpoint["model"].routing.get("ospf") or {}).values()
            for binding in (instance.get("interfaces") or {}).values()
        )
        ctx.add(
            Code.LINK_MTU_MISMATCH,
            f"MTU differs on {link_label(pair)} ({ma} vs {mz})" + ("; OSPF adjacency may stall on an MTU mismatch." if ospf else "."),
            device=a["device"], object_type="link", object_id=link_label(pair), related_devices=[z["device"]],
            source="TOPOLOGY+INTENT", evidence={"a_mtu": ma, "z_mtu": mz, "ospf_on_link": ospf},
            remediation="Use the same MTU on both ends unless the difference is intentional.",
        )


def _vlans_in_netbox(ctx) -> None:
    if ctx.netbox is None:
        return
    known = set(ctx.netbox["vlans"]) | {1}
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        seen: dict[int, list] = {}
        for interface in device.ordered(device.interfaces):
            ids = set()
            for key in ("access_vlan", "native_vlan", "vlan_id", "encapsulation_vlan"):
                if isinstance(interface.get(key), int):
                    ids.add(interface[key])
            ids.update(v for v in (interface.get("trunk_allowed_vlans") or []) if isinstance(v, int))
            for vlan in ids - known:
                seen.setdefault(vlan, []).append(interface.get("name"))
        for vlan in sorted(seen):
            ctx.add(
                Code.VLAN_NOT_IN_NETBOX,
                f"{name}: VLAN {vlan} (used by {', '.join(map(str, seen[vlan]))}) is not modeled in NetBox.",
                device=name, object_type="vlan", object_id=str(vlan), source="NETBOX",
                evidence={"vlan": vlan, "interfaces": seen[vlan]},
                remediation="Model the VLAN in NetBox if it is a project VLAN.",
            )


def validate_topology(ctx) -> None:
    topology = ctx.topology
    _vlans_in_netbox(ctx)
    if topology is None:
        return
    for name in sorted(ctx.model.devices):
        device = ctx.model.devices[name]
        if name not in topology["nodes"]:
            ctx.add(
                Code.TOPOLOGY_DEVICE_UNKNOWN,
                f"Device {name} is not present in the topology source; its links were not evaluated.",
                severity=Severity.INFO if device.target_type == "NEW_DEVICE" else Severity.WARNING,
                device=name, object_type="DeviceIntent", object_id=name, source="TOPOLOGY",
                remediation="Existing devices should appear in the Containerlab topology; new devices are expected not to.",
            )
    evaluated = 0
    for pair in get_link_pairs(ctx):
        _netbox_far_side_prefix(ctx, pair)
        if not _both_candidate(pair):
            continue
        a, z = pair["a"], pair["z"]
        ka, kz = a["interface"].get("kind"), z["interface"].get("kind")
        if ka not in PHYSICAL_KINDS or kz not in PHYSICAL_KINDS:
            continue
        evaluated += 1
        if ka == "ROUTED_PHYSICAL" and kz == "ROUTED_PHYSICAL":
            _p2p_prefix(ctx, pair, a, z)
        elif ka == "ACCESS" and kz == "ACCESS":
            _access_access(ctx, pair, a, z)
        elif ka == "TRUNK" and kz == "TRUNK":
            _trunk_trunk(ctx, pair, a, z)
        elif {ka, kz} == {"ACCESS", "TRUNK"}:
            _access_trunk(ctx, pair, *((a, z) if ka == "ACCESS" else (z, a)))
        elif "ROUTED_PHYSICAL" in (ka, kz):
            routed, other = (a, z) if ka == "ROUTED_PHYSICAL" else (z, a)
            _routed_l2(ctx, pair, routed, other)
        _mtu(ctx, pair, a, z)
    ctx.checked["links_evaluated"] = evaluated
