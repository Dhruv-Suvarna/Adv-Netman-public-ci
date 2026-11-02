"""NetBox mapping for managed devices -- READ-ONLY.

NetBox is documented intent.  The lifecycle registry and ``inventory.yml`` stay authoritative: a difference is reported as a
discrepancy and never copied over either side.  ``NetboxDeviceReader`` has no write method at all; ``import_cable_attachments``
writes only the NMAS database (PENDING expected attachments with source NETBOX_CABLE that a person must still approve).
"""

from __future__ import annotations

from ... import models
from ..provisioning.ipam import IpamUnavailable
from . import attachments as attachment_service
from . import identity
from .codes import blocker

S = models.DeviceLifecycleState
# The NetBox device status that corresponds to each lifecycle state ('' = no NetBox device should represent it).
STATUS_PROJECTION = {
    S.REGISTERED: "planned", S.DISCOVERED: "planned", S.BOOTSTRAPPED: "staged", S.ISOLATED: "staged",
    S.READY_FOR_COMMISSIONING: "staged", S.COMMISSIONING: "staged", S.IN_SERVICE: "active",
    S.DECOMMISSION_PENDING: "decommissioning", S.DECOMMISSIONED: "offline", S.WITHDRAWN: "", S.FAILED: "failed",
}


def projection(device) -> dict:
    """What NetBox should show for ``device`` (a plan for a later, authorized sync -- nothing is written here)."""
    return {"name": device.name, "status": STATUS_PROJECTION[device.lifecycle_state], "serial": device.verified_serial or device.expected_serial,
            "netbox_device_id": device.netbox_device_id}


def _value(field):
    return str(getattr(field, "value", field) or "")


class NetboxDeviceReader:
    """Read-only pynetbox reader.  Every upstream failure becomes ``IpamUnavailable`` (no upstream text leaves this class)."""

    def __init__(self, client=None):
        self._client = client

    @property
    def client(self):
        if self._client is None:
            from ..nsot_netbox import _client

            self._client = _client()
        return self._client

    def _guard(self, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            raise IpamUnavailable() from exc

    def device(self, name: str) -> dict | None:
        def read():
            found = list(self.client.dcim.devices.filter(name=name))
            if not found:
                return None
            row = found[0]
            return {"id": row.id, "name": str(row.name), "status": _value(row.status), "serial": str(getattr(row, "serial", "") or "")}
        return self._guard(read)

    def cables(self, name: str) -> list[dict]:
        """The cabled interfaces of device ``name`` with their far ends (device / interface names only)."""
        def read():
            rows = []
            for interface in self.client.dcim.interfaces.filter(device=name):
                if not getattr(interface, "cable", None):
                    continue
                for peer in getattr(interface, "link_peers", None) or ():
                    peer_device = getattr(getattr(peer, "device", None), "name", "")
                    if not peer_device or not getattr(peer, "name", ""):
                        continue
                    untagged = getattr(interface, "untagged_vlan", None)
                    rows.append({"local_interface": str(interface.name), "upstream_device": str(peer_device),
                                 "upstream_interface": str(peer.name), "mgmt_only": bool(getattr(interface, "mgmt_only", False)),
                                 "mode": _value(getattr(interface, "mode", "")), "untagged_vlan": getattr(untagged, "vid", None)})
            return rows
        return self._guard(read)


def compare(device, reader) -> dict:
    """Compare ``device`` with its NetBox record -> {"available", "netbox": {...} | None, "discrepancies": [...]}.  Read-only."""
    try:
        record = reader.device(device.name)
    except IpamUnavailable:
        return {"available": False, "netbox": None, "discrepancies": [], "blockers": [blocker("IPAM_UNAVAILABLE")]}
    expected = projection(device)
    found = []
    if record is None:
        if expected["status"]:
            found.append({"code": "NETBOX_DEVICE_ABSENT", "detail": f"no NetBox device named {device.name}"})
        return {"available": True, "netbox": None, "discrepancies": found, "blockers": []}
    if expected["status"] and record["status"] != expected["status"]:
        found.append({"code": "NETBOX_STATUS_DIFFERS", "detail": f"NetBox {record['status']!r}, lifecycle projects {expected['status']!r}"})
    if not expected["status"]:
        found.append({"code": "NETBOX_DEVICE_UNEXPECTED", "detail": "the lifecycle state projects no NetBox device"})
    serial, _ = identity.normalize_serial(record["serial"])
    if serial and expected["serial"] and serial != expected["serial"]:
        found.append({"code": "NETBOX_SERIAL_DIFFERS", "detail": "NetBox documents a different serial"})
    if device.netbox_device_id and device.netbox_device_id != record["id"]:
        found.append({"code": "NETBOX_ID_DIFFERS", "detail": f"registered NetBox id {device.netbox_device_id}, found {record['id']}"})
    return {"available": True, "netbox": record, "discrepancies": found, "blockers": []}


def _attachment_shape(cable: dict) -> tuple[str, str, int | None]:
    """Purpose / connectivity / VLAN of a documented cable, from NetBox's own interface fields (never from names)."""
    purpose = models.AttachmentPurpose.MANAGEMENT if cable["mgmt_only"] else models.AttachmentPurpose.PRODUCTION
    mode = cable["mode"].lower()
    if mode == "access":
        return purpose, models.AttachmentConnectivity.ACCESS, cable["untagged_vlan"]
    if mode.startswith("tagged"):
        return purpose, models.AttachmentConnectivity.TRUNK, cable["untagged_vlan"]
    return purpose, models.AttachmentConnectivity.ROUTED, None


def import_cable_attachments(device, *, actor: str, reader) -> dict:
    """Turn NetBox cables of ``device`` into PENDING expected attachments (source NETBOX_CABLE).  Writes the NMAS database only;
    each one still needs a second person's approval, and documented cables never verify anything."""
    try:
        cables = reader.cables(device.name)
    except IpamUnavailable:
        return {"ok": False, "created": [], "skipped": [], "blockers": [blocker("IPAM_UNAVAILABLE")]}
    created, skipped = [], []
    for cable in cables:
        purpose, connectivity, vlan = _attachment_shape(cable)
        result = attachment_service.register_attachment(
            device, upstream_device=cable["upstream_device"], upstream_interface=cable["upstream_interface"],
            local_interface=cable["local_interface"], purpose=purpose, connectivity=connectivity, vlan=vlan, actor=actor,
            source=models.AttachmentSource.NETBOX_CABLE)
        entry = {"upstream": f"{cable['upstream_device']}:{cable['upstream_interface']}", "local_interface": cable["local_interface"]}
        if result.ok:
            created.append({**entry, "attachment": result.attachment.pk})
        else:
            skipped.append({**entry, "codes": result.codes})
    return {"ok": True, "created": created, "skipped": skipped, "blockers": []}
