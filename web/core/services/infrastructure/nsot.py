"""NetBox (NSOT) reconciliation driven by lifecycle facts (``NsotProjection``).

Desired state is computed from the lifecycle only:
    status      REGISTERED / DISCOVERED -> planned; BOOTSTRAPPED / ISOLATED / READY_FOR_COMMISSIONING / COMMISSIONING -> staged;
                IN_SERVICE -> active (maintenance stays active: NetBox 4 has no maintenance device status, so it is
                recorded in ``desired.maintenance`` only); DECOMMISSION_PENDING -> decommissioning; DECOMMISSIONED / WITHDRAWN
                -> offline (the object is kept, its history preserved -- never deleted); FAILED -> failed
    interfaces  the local interfaces of APPROVED + VERIFIED attachments
    cables      only between verified attachment endpoints, and only when the peer device and interface exist in NetBox
    mgmt IP     from the admission hand-off payload or the commissioning (ProvisioningRun) data only; it must ALREADY exist
                in NetBox IPAM -- a missing address is a DISCREPANCY, never created; nothing is allocated (no DHCP, no VLAN 200)
    mgmt VRF    the VRF of the device's ACTIVE management path (routed-VRF paths); the VRF must already exist in NetBox; the
                management address NMAS assigns is placed in it.  An address already in ANOTHER VRF is a discrepancy.
    VLAN        verify only: a verified attachment's VLAN must exist in NetBox and be carried by the upstream (peer) interface
                (untagged for an access attachment, tagged or untagged for a trunk).  NMAS never creates a VLAN and never edits
                the peer's interface -- a missing or different VLAN is a discrepancy.

NMAS never invents a site, device type, IP or link: what it cannot prove becomes a discrepancy.  The writer is the injectable
``client`` (``lookup`` / ``apply``); production writes happen only when ``settings.NMAS_NSOT_RECONCILE_WRITE`` is True --
otherwise the computed operations are recorded and the projection is PLANNED (dry run).
"""

from __future__ import annotations

from django.conf import settings

from ... import models
from .. import secret_policy
from . import facts

P, S = models.NsotProjectionState, models.DeviceLifecycleState
CONSUMER = "phase8-nsot"
STATUS = {
    S.REGISTERED: "planned", S.DISCOVERED: "planned", S.BOOTSTRAPPED: "staged", S.ISOLATED: "staged",
    S.READY_FOR_COMMISSIONING: "staged", S.COMMISSIONING: "staged", S.IN_SERVICE: "active", S.DECOMMISSION_PENDING: "decommissioning",
    S.DECOMMISSIONED: "offline", S.WITHDRAWN: "offline", S.FAILED: "failed",
}
OPS = ("set_status", "create_interface", "create_cable", "assign_ip", "set_ip_vrf")
# NetBox 4.x refuses a cable on these interface types (dcim/constants.py NONCONNECTABLE_IFACE_TYPES: virtual, wireless,
# cellular, channel).  The lab model declares its interfaces "virtual", so a cable there is an operator decision about the
# interface type -- a discrepancy, never a write that can only fail and be retried forever.
NONCONNECTABLE_TYPES = frozenset({
    "virtual", "lag", "bridge", "channel",
    "ieee802.11a", "ieee802.11g", "ieee802.11n", "ieee802.11ac", "ieee802.11ad", "ieee802.11ax", "ieee802.11ay", "ieee802.11be",
    "ieee802.15.1", "ieee802.15.4", "other-wireless", "gsm", "cdma", "lte", "4g", "5g",
})


class NetboxUnavailable(Exception):
    """NetBox could not be reached / answered with an error (retryable).  Never carries the token or the raw response."""


def write_enabled() -> bool:
    return bool(getattr(settings, "NMAS_NSOT_RECONCILE_WRITE", False))


def management_facts(device) -> dict:
    """{interface, ipv4, ipv6} from the admission hand-off payload, else the device's commissioning (ProvisioningRun) data."""
    event = models.LifecycleOutboxEvent.objects.filter(device=device, topic=models.OutboxTopic.NSOT_DEVICE_ADMITTED).order_by("-pk").first()
    source = (event.payload or {}).get("management", {}) if event else {}
    if not source and device.provisioning_run_id:
        source = device.provisioning_run.management or {}
    found = {k: str(source[k]) for k in ("interface", "ipv4", "ipv6") if source.get(k)}
    state = models.DeviceManagementState.objects.filter(device=device).select_related("active_path").first()
    active = state.active_path if state is not None else None
    if active is not None and active.approval_state == models.ManagementApproval.APPROVED and active.vrf:
        found["vrf"] = active.vrf
    return found


def desired_state(device) -> dict:
    """What NetBox should show for ``device`` (identifiers only)."""
    verified = list(facts.verified_production_attachments(device))
    return {
        "name": device.name, "status": STATUS.get(device.lifecycle_state, "offline"), "maintenance": facts.under_maintenance(device.name),
        "interfaces": sorted({a.local_interface for a in verified if a.local_interface}),
        "cables": [{"a_device": device.name, "a_interface": a.local_interface, "b_device": a.upstream_device,
                    "b_interface": a.upstream_interface, "source": facts.attachment_ref(a)} for a in verified if a.local_interface],
        "management": management_facts(device) if device.lifecycle_state not in facts.TERMINAL else {},
        "vlans": [{"peer_device": a.upstream_device, "peer_interface": a.upstream_interface, "vlan": int(a.vlan),
                   "tagged_ok": a.connectivity != models.AttachmentConnectivity.ACCESS, "source": facts.attachment_ref(a)}
                  for a in verified if a.vlan],
    }


def plan(desired: dict, client) -> tuple[list, list]:
    """(operations, discrepancies) to make NetBox match ``desired``.  Reads only; raises NetboxUnavailable."""
    ops, problems, name = [], [], desired["name"]
    current = client.lookup("device", name=name)
    if current is None:
        return [], [{"code": "NETBOX_DEVICE_MISSING", "device": name}]
    if current.get("status") != desired["status"]:
        ops.append({"op": "set_status", "device": name, "from": current.get("status", ""), "status": desired["status"]})
    interfaces = set(client.lookup("interfaces", device=name) or [])
    for interface in desired["interfaces"]:
        if interface not in interfaces:
            ops.append({"op": "create_interface", "device": name, "interface": interface})
    for cable in desired["cables"]:
        existing = client.lookup("cable", device=name, interface=cable["a_interface"])
        if existing:
            if (existing.get("peer_device"), existing.get("peer_interface")) != (cable["b_device"], cable["b_interface"]):
                problems.append({"code": "CABLE_MISMATCH", "interface": cable["a_interface"], "source": cable["source"]})
            continue
        if client.lookup("device", name=cable["b_device"]) is None:
            problems.append({"code": "CABLE_PEER_NOT_IN_NETBOX", "peer": cable["b_device"], "source": cable["source"]})
            continue
        if cable["b_interface"] not in set(client.lookup("interfaces", device=cable["b_device"]) or []):
            problems.append({"code": "CABLE_PEER_INTERFACE_MISSING", "peer": cable["b_device"], "interface": cable["b_interface"],
                             "source": cable["source"]})
            continue
        ends = ((name, cable["a_interface"]), (cable["b_device"], cable["b_interface"]))
        blocked = [f"{device}:{interface}" for device, interface in ends
                   if (row := client.lookup("interface", device=device, interface=interface)) and row.get("type") in NONCONNECTABLE_TYPES]
        if blocked:
            problems.append({"code": "CABLE_ENDPOINT_NOT_CONNECTABLE", "endpoints": blocked, "source": cable["source"]})
            continue
        ops.append({"op": "create_cable", **{k: cable[k] for k in ("a_device", "a_interface", "b_device", "b_interface", "source")}})
    for want in desired.get("vlans") or []:
        if client.lookup("vlan", vid=want["vlan"]) is None:
            problems.append({"code": "VLAN_NOT_IN_NETBOX", "vlan": want["vlan"], "source": want["source"]})
            continue
        carried = client.lookup("interface_vlans", device=want["peer_device"], interface=want["peer_interface"])
        if carried is None:
            problems.append({"code": "VLAN_PEER_INTERFACE_MISSING", "peer": want["peer_device"], "interface": want["peer_interface"],
                             "source": want["source"]})
            continue
        if not (carried.get("untagged") == want["vlan"] or (want["tagged_ok"] and want["vlan"] in (carried.get("tagged") or []))):
            problems.append({"code": "VLAN_MISMATCH", "peer": want["peer_device"], "interface": want["peer_interface"], "vlan": want["vlan"],
                             "netbox": carried, "source": want["source"]})
    management = desired.get("management") or {}
    vrf = management.get("vrf", "")
    if vrf and client.lookup("vrf", name=vrf) is None:
        problems.append({"code": "VRF_NOT_IN_NETBOX", "vrf": vrf})
        vrf = ""
    for family in ("ipv4", "ipv6"):
        address = management.get(family)
        if not address:
            continue
        interface = management.get("interface", "")
        found = client.lookup("ip", address=address)
        if found is None:
            problems.append({"code": "MGMT_IP_NOT_IN_IPAM", "address": address})
        elif found.get("device") and found.get("device") != name:
            problems.append({"code": "MGMT_IP_ASSIGNED_ELSEWHERE", "address": address})
        elif not interface:
            problems.append({"code": "MGMT_INTERFACE_UNKNOWN", "address": address})
        elif vrf and found.get("vrf") and found.get("vrf") != vrf:
            problems.append({"code": "VRF_MISMATCH", "address": address, "vrf": vrf, "netbox": found.get("vrf")})
        else:
            if (found.get("device"), found.get("interface")) != (name, interface):
                if interface not in interfaces and not any(o.get("interface") == interface for o in ops if o["op"] == "create_interface"):
                    ops.append({"op": "create_interface", "device": name, "interface": interface})
                ops.append({"op": "assign_ip", "device": name, "interface": interface, "address": address})
            if vrf and not found.get("vrf"):
                ops.append({"op": "set_ip_vrf", "device": name, "address": address, "vrf": vrf})
    return ops, problems


def reconcile(device, *, client, write: bool | None = None, sequence: int = 0) -> models.NsotProjection:
    """Compute, record and (only when writes are enabled) apply the NetBox state of ``device``.  Raises NetboxUnavailable."""
    write = write_enabled() if write is None else bool(write)
    successor = facts.successor_of(device)
    if successor is not None:
        # the NetBox object (same name) now belongs to the restored successor's projection: never touch it from history
        desired, ops, problems = {"name": device.name, "superseded_by": successor.device_id}, [], []
    else:
        desired = desired_state(device)
        ops, problems = plan(desired, client)
    applied = []
    if write:
        for op in ops:
            client.apply(op)
            applied.append(op)
        state = P.DISCREPANCY if problems else P.IN_SYNC
    else:
        state = P.PLANNED if ops else (P.DISCREPANCY if problems else P.IN_SYNC)
    projection, _created = models.NsotProjection.objects.get_or_create(device=device, defaults={"name": device.name})
    projection.state = state
    projection.desired = secret_policy.redact({**desired, "planned_operations": ops, "write_enabled": write})
    projection.applied = secret_policy.redact((list(projection.applied or []) + applied)[-100:])
    projection.discrepancies = secret_policy.redact(problems)
    if sequence:
        projection.last_sequence = max(int(projection.last_sequence), int(sequence))
    projection.save()
    return projection


def apply(event, *, nsot_client=None, **_context) -> str:
    """Consumer entry point.  -> APPLIED | SUPERSEDED; NetBox unavailable -> ConsumerError(NSOT_UNAVAILABLE) (retried)."""
    device = models.ManagedDevice.objects.get(pk=event.device_id)
    projection = models.NsotProjection.objects.filter(device=device).first()
    if projection is not None and facts.superseded(event, projection.last_sequence):
        return "SUPERSEDED"
    try:
        client = nsot_client if nsot_client is not None else default_client()
        reconcile(device, client=client, sequence=event.sequence)
    except NetboxUnavailable as exc:
        raise facts.ConsumerError("NSOT_UNAVAILABLE") from exc
    return "APPLIED"


def mark_failed(event, code: str) -> None:
    """After a failed delivery (outside the rolled-back consumer transaction): NetBox unavailable -> UNAVAILABLE."""
    if code != "NSOT_UNAVAILABLE":
        return
    device = models.ManagedDevice.objects.get(pk=event.device_id)
    projection, _created = models.NsotProjection.objects.get_or_create(device=device, defaults={"name": device.name})
    projection.state = P.UNAVAILABLE
    projection.save(update_fields=["state", "updated_at"])


def summary() -> dict:
    counts = {}
    for state in models.NsotProjection.objects.values_list("state", flat=True):
        counts[state] = counts.get(state, 0) + 1
    return counts


def default_client():
    """The production NetBox client (pynetbox).  Any construction failure is NetboxUnavailable (no detail leaks)."""
    try:
        from .. import nsot_netbox

        return PynetboxClient(nsot_netbox._client())
    except Exception as exc:  # noqa: BLE001 - configuration / import failure: retry later, never echo it
        raise NetboxUnavailable("NETBOX_CLIENT_UNAVAILABLE") from exc


class PynetboxClient:
    """The ``lookup`` / ``apply`` interface over a ``pynetbox.api``.  Every error becomes NetboxUnavailable."""

    def __init__(self, api):
        self.api = api

    def lookup(self, kind: str, **query):
        try:
            if kind == "device":
                row = self.api.dcim.devices.get(name=query["name"])
                return None if row is None else {"id": row.id, "name": str(row.name), "status": getattr(row.status, "value", str(row.status))}
            if kind == "interfaces":
                return sorted(str(i.name) for i in self.api.dcim.interfaces.filter(device=query["device"]))
            if kind == "interface":
                row = self.api.dcim.interfaces.get(device=query["device"], name=query["interface"])
                return None if row is None else {"name": str(row.name), "type": str(getattr(row.type, "value", row.type) or "")}
            if kind == "ip":
                row = self.api.ipam.ip_addresses.get(address=query["address"])
                if row is None:
                    return None
                assigned = getattr(row, "assigned_object", None)
                device = getattr(getattr(assigned, "device", None), "name", "") if assigned else ""
                return {"id": row.id, "address": str(row.address), "device": str(device or ""),
                        "interface": str(getattr(assigned, "name", "") or "") if assigned else "",
                        "vrf": str(getattr(getattr(row, "vrf", None), "name", "") or "")}
            if kind == "vrf":
                row = self.api.ipam.vrfs.get(name=query["name"])
                return None if row is None else {"id": row.id, "name": str(row.name)}
            if kind == "vlan":
                rows = list(self.api.ipam.vlans.filter(vid=int(query["vid"])))
                return {"id": rows[0].id, "vid": int(rows[0].vid)} if len(rows) == 1 else None   # absent or ambiguous: never guessed
            if kind == "interface_vlans":
                row = self.api.dcim.interfaces.get(device=query["device"], name=query["interface"])
                if row is None:
                    return None
                untagged = getattr(row, "untagged_vlan", None)
                return {"mode": str(getattr(getattr(row, "mode", None), "value", "") or ""),
                        "untagged": int(untagged.vid) if untagged is not None else None,
                        "tagged": sorted(int(v.vid) for v in (getattr(row, "tagged_vlans", None) or []))}
            if kind == "cable":
                interface = self.api.dcim.interfaces.get(device=query["device"], name=query["interface"])
                peers = list(getattr(interface, "link_peers", None) or []) if interface is not None and getattr(interface, "cable", None) else []
                if not peers:
                    return None
                peer = peers[0]
                return {"peer_device": str(getattr(peer.device, "name", "")), "peer_interface": str(peer.name)}
        except Exception as exc:  # noqa: BLE001 - transport / API failure is retryable and never echoed
            raise NetboxUnavailable("NETBOX_LOOKUP_FAILED") from exc
        raise ValueError(f"unknown lookup {str(kind)[:20]}")

    def apply(self, op: dict):
        kind = op.get("op")
        if kind not in OPS:
            raise ValueError(f"unknown operation {str(kind)[:20]}")
        try:
            dcim = self.api.dcim
            if kind == "set_status":
                return dcim.devices.get(name=op["device"]).update({"status": op["status"]})
            if kind == "create_interface":
                device = dcim.devices.get(name=op["device"])
                return dcim.interfaces.create(device=device.id, name=op["interface"], type="other")
            if kind == "create_cable":
                a = dcim.interfaces.get(device=op["a_device"], name=op["a_interface"])
                b = dcim.interfaces.get(device=op["b_device"], name=op["b_interface"])
                return dcim.cables.create(a_terminations=[{"object_type": "dcim.interface", "object_id": a.id}],
                                          b_terminations=[{"object_type": "dcim.interface", "object_id": b.id}], status="connected")
            if kind == "set_ip_vrf":
                address = self.api.ipam.ip_addresses.get(address=op["address"])
                return address.update({"vrf": self.api.ipam.vrfs.get(name=op["vrf"]).id})
            interface = dcim.interfaces.get(device=op["device"], name=op["interface"])
            address = self.api.ipam.ip_addresses.get(address=op["address"])
            return address.update({"assigned_object_type": "dcim.interface", "assigned_object_id": interface.id})
        except Exception as exc:  # noqa: BLE001
            raise NetboxUnavailable("NETBOX_WRITE_FAILED") from exc
