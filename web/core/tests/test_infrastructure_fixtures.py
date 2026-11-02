"""Shared fixtures for the V2 Phase 8 infrastructure tests (NMAS database + in-memory fakes only; no NetBox, no device).

The lab shape comes from the real Phase 2 / 4 services (``helpers.management.lab``): mgmt_swt, S1, S3 and R1 adopted (legacy
in service), NMAS attached to mgmt_swt, R1's verified out-of-band attachment.  A path is made ACTIVE through the selector's own
write helpers -- the probe layer is the Phase 4 tests' concern.  ``FakeNetbox`` implements the ``lookup`` / ``apply`` client
interface in memory; it proves the contract only, never the live NetBox.
"""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from core import models
from core.services.commissioning import outbox
from core.services.management import selector
from core.tests.helpers import lifecycle as L
from core.tests.helpers import management as M

H, ST, K = models.ManagementPathHealth, models.ManagementStatus, models.ManagementTransitionKind


def lab():
    return M.lab()


def activate(device, path, *, previous=None, kind=K.ACTIVATE):
    """Make ``path`` the selector's ACTIVE healthy path (and record the switch, which emits MANAGEMENT_PATH_CHANGED)."""
    with transaction.atomic():
        if previous is not None:
            selector._path_write(previous, is_active=False, health_state=H.FAILED)
        selector._path_write(path, is_active=True, health_state=H.HEALTHY, activated_at=timezone.now())
        selector._save_state(selector.state_for(device), status=ST.ACTIVE, active_path=path)
        selector._transition(device, kind, from_path=previous, to_path=path, reason_code="PATH_VERIFIED", actor="nmas-management-selector",
                             actor_kind="AUTOMATION")
    path.refresh_from_db()
    return path


def lose_paths(device, path):
    with transaction.atomic():
        selector._path_write(path, is_active=False, health_state=H.FAILED)
        selector._save_state(selector.state_for(device), status=ST.NO_PATH, active_path=None)
        selector._transition(device, K.LOST, from_path=path, reason_code="MGMT_NO_USABLE_PATH", actor="nmas-management-selector",
                             actor_kind="AUTOMATION")


def oob_path(env):
    r1 = env["devices"]["R1"]
    return M.path(r1, env["nmas"], attachment=env["oob"], endpoint="192.168.200.1")


def vrf_path(device, env, endpoint="10.99.0.1"):
    return M.path(device, env["nmas"], path_type=models.ManagementPathType.ROUTED_VRF, endpoint=endpoint, vrf="MGMT")


def new_device_with_verified_uplink(name="NEW1", *, upstream="S1", port="Ethernet7", local="Ethernet1", verify=True, serial=L.SERIAL,
                                    mac=L.MAC):
    device = L.register(name, serial=serial, mac=mac).device
    attachment = L.attach(device, upstream=upstream, port=port, local=local).attachment
    if verify:
        M.observe_attachment(device, attachment)
    attachment.refresh_from_db()
    device.refresh_from_db()
    return device, attachment


def force_state(device, lifecycle_state, admission_state=None):
    """Test-only: set a lifecycle state the Phase 7 service would set (the model's own authorized-write flag)."""
    device = models.ManagedDevice.objects.get(pk=device.pk)
    device.lifecycle_state = lifecycle_state
    if admission_state:
        device.admission_state = admission_state
    if lifecycle_state in (models.DeviceLifecycleState.DECOMMISSIONED, models.DeviceLifecycleState.WITHDRAWN):
        device.retired_at = timezone.now()
    device._lifecycle_write = True
    device.save()
    return device


def fact(device, name, detail=None):
    with transaction.atomic():
        return outbox.record_fact(device, name, actor="system:test", detail=detail)


def successor_of(device, *, admission=models.ProductionAdmissionState.ADMITTED):
    row = models.ManagedDevice(name=device.name, platform=device.platform, role=device.role, origin=models.DeviceOrigin.RESTORED,
                               inventory_authority=device.inventory_authority, lifecycle_state=models.DeviceLifecycleState.IN_SERVICE,
                               admission_state=admission, registered_by="system:test", predecessor=device)
    row._lifecycle_write = True
    row.save()
    return row


def maintenance(name, state="ACTIVE"):
    return models.MaintenanceRecord.objects.create(device_name=name, state=state, requested_by=L.OPERATOR, reason="test window",
                                                   requested_at=timezone.now(), requested_duration_seconds=3600, snapshot={})


class FakeNetbox:
    """In-memory ``lookup`` / ``apply`` NetBox client.  ``down=True`` makes every call raise NetboxUnavailable."""

    def __init__(self, *, devices=None, interfaces=None, ips=None, cables=None, down=False, vlans=None, vrfs=None, port_vlans=None,
                 types=None):
        self.devices = {name: {"id": i + 1, "name": name, "status": status} for i, (name, status) in enumerate((devices or {}).items())}
        self.vlans, self.vrfs = set(vlans or ()), set(vrfs or ())
        self.port_vlans = dict(port_vlans or {})   # (device, interface) -> {"untagged": vid|None, "tagged": [vid, ...]}
        self.types = dict(types or {})             # (device, interface) -> NetBox interface type (default "other")
        self.interfaces = {k: set(v) for k, v in (interfaces or {}).items()}
        self.ips = dict(ips or {})                 # address -> {"device": name|"", "interface": name|""}
        self.cables = dict(cables or {})           # (device, interface) -> (peer_device, peer_interface)
        self.down, self.applied, self.created_ips = down, [], []

    def _check(self):
        if self.down:
            from core.services.infrastructure import nsot

            raise nsot.NetboxUnavailable("down")

    def lookup(self, kind, **query):
        self._check()
        if kind == "device":
            return self.devices.get(query["name"])
        if kind == "interfaces":
            return sorted(self.interfaces.get(query["device"], set()))
        if kind == "ip":
            found = self.ips.get(query["address"])
            return None if found is None else {"id": 1, "address": query["address"], **found}
        if kind == "cable":
            peer = self.cables.get((query["device"], query["interface"]))
            return None if peer is None else {"peer_device": peer[0], "peer_interface": peer[1]}
        if kind == "vlan":
            return {"id": query["vid"], "vid": query["vid"]} if query["vid"] in self.vlans else None
        if kind == "vrf":
            return {"id": 1, "name": query["name"]} if query["name"] in self.vrfs else None
        if kind == "interface":
            if query["interface"] not in self.interfaces.get(query["device"], set()):
                return None
            return {"name": query["interface"], "type": self.types.get((query["device"], query["interface"]), "other")}
        if kind == "interface_vlans":
            key = (query["device"], query["interface"])
            if query["interface"] not in self.interfaces.get(query["device"], set()):
                return None
            return {"mode": "access", "untagged": None, "tagged": [], **self.port_vlans.get(key, {})}
        raise ValueError(kind)

    def apply(self, op):
        self._check()
        self.applied.append(dict(op))
        if op["op"] == "set_status":
            self.devices[op["device"]]["status"] = op["status"]
        elif op["op"] == "create_interface":
            self.interfaces.setdefault(op["device"], set()).add(op["interface"])
        elif op["op"] == "create_cable":
            self.cables[(op["a_device"], op["a_interface"])] = (op["b_device"], op["b_interface"])
            self.cables[(op["b_device"], op["b_interface"])] = (op["a_device"], op["a_interface"])
        elif op["op"] == "assign_ip":
            self.ips[op["address"]] = {**self.ips.get(op["address"], {}), "device": op["device"], "interface": op["interface"]}
        elif op["op"] == "set_ip_vrf":
            self.ips[op["address"]] = {**self.ips[op["address"]], "vrf": op["vrf"]}
