"""The provisioned-device registry: which devices a provisioning run admitted into NMAS.

``health.inventory.managed_devices()`` overlays ``devices()`` onto the tracked ``inventory.yml``.  The tracked inventory always wins on a name, and
this module can only ADD entries -- it can never change or hide a production device.  ADMITTED entries are resolvable (so the engines can read and
write the device) but the execution gate lets only the entry's own provisioning Change use them (``admitted_for``).
"""

from __future__ import annotations

from django.utils import timezone

from ... import models

State = models.ProvisionedDeviceState
_HEALTH_PLATFORM = {"arista_ceos": "ceos", "ubuntu_frr": "linux"}


def _entry(row) -> dict:
    return {"name": row.name, "platform": _HEALTH_PLATFORM.get(row.platform, row.platform), "address": row.address,
            "address_v6": row.address_v6, "container": row.container, "provisioned": True, "provisioning_state": row.state,
            "lab": row.lab, "disposable": row.disposable}


def devices() -> dict:
    """{name: inventory-shaped entry} for every live (ADMITTED / ACTIVE) registry row."""
    return {row.name: _entry(row) for row in models.ProvisionedDevice.objects.exclude(state=State.RETIRED)}


def live_entry(name: str):
    return models.ProvisionedDevice.objects.exclude(state=State.RETIRED).filter(name=name).first()


def owner_of_container(container: str):
    """The live registry entry that already owns this container, if any (one container is one device)."""
    if not container:
        return None
    return models.ProvisionedDevice.objects.exclude(state=State.RETIRED).filter(container=container).first()


def admitted_for(name: str, change) -> bool:
    """May ``change`` execute against the NEW device ``name``?  Only the provisioning Change that admitted it."""
    row = live_entry(name)
    return bool(row and change is not None and row.run.change_id == change.pk)


def is_provisioned(name: str) -> bool:
    return live_entry(name) is not None


# A provisioning run whose device is synchronized to NetBox: NSOT_SYNCED, or PROBATION (entered only from NSOT_SYNCED; the run
# then carries its probation bundle and the soak observing it).
_SYNCED = (models.ProvisioningStatus.NSOT_SYNCED, models.ProvisioningStatus.PROBATION)


def _probation_problem(run) -> str:
    """'' unless ``run`` is in PROBATION and that probation is not an authorized, still-trustworthy one.

    A soak decides Golden promotion, not management: a governed Change during probation ends the soak as INVALIDATED /
    OVERLAPPING_EXECUTION, a health FAIL / INCOMPLETE result or an operator cancel leaves the device managed (an existing
    device's soak behaves the same).  Two endings say the device no longer provably runs what was verified -- a broken bundle
    (BUNDLE_INTEGRITY_FAILED) and configuration drift (CONFIGURATION_DRIFT) -- and those revoke the scope.
    """
    if run.status != models.ProvisioningStatus.PROBATION:
        return ""
    from ..soak import codes as soak_codes

    soak = run.soak_run
    if run.probation_bundle_id is None or soak is None or soak.bundle_id != run.probation_bundle_id:
        return "PROBATION_UNBOUND"
    if soak.state == models.SoakState.INVALIDATED and soak.terminal_reason in (soak_codes.BUNDLE_INTEGRITY_FAILED,
                                                                            soak_codes.CONFIGURATION_DRIFT):
        return "PROBATION_UNTRUSTED"
    return ""


def managed_scope_refusal(name: str) -> str:
    """Why ``name`` is NOT a natively provisioned device that NMAS admitted to production and synchronized to NetBox ('' = it is).

    Such a device may be the target of later ordinary Changes even before NetBox's ``managed`` tag lists it.  Every link of the
    chain must hold and point at the same objects:

    * the live registry row is ACTIVE, not disposable, and carries a NetBox device id;
    * its provisioning run is NSOT_SYNCED or in an authorized PROBATION (``_probation_problem``), and its recorded NetBox
      identity names this device, is ``active``, is in the managed scope and has the registry row's NetBox id;
    * the live ManagedDevice of that name was REGISTERED_NEW, is IN_SERVICE and ADMITTED, its identity is VERIFIED with a
      pinned host key, no configuration drift is recorded, and it has no other NetBox id;
    * an ADMITTED commissioning record binds that ManagedDevice to that same provisioning run.
    """
    row = models.ProvisionedDevice.objects.select_related("run", "run__soak_run").filter(name=name, state=State.ACTIVE).first()
    if row is None:
        return "NOT_ACTIVE_PROVISIONED"
    if row.disposable:
        return "DISPOSABLE"
    if row.netbox_device_id is None:
        return "NETBOX_ID_MISSING"
    run = row.run
    if run.status not in _SYNCED:
        return "NOT_SYNCHRONIZED"
    identity = (run.result or {}).get("netbox_identity") or {}
    if not identity:
        return "NOT_SYNCHRONIZED"
    if identity.get("device_id") != row.netbox_device_id or identity.get("name") != name or identity.get("status") != "active":
        return "NETBOX_IDENTITY_MISMATCH"
    if identity.get("managed_scope") is not True:
        return "MANAGED_SCOPE_MISSING"
    problem = _probation_problem(run)
    if problem:
        return problem
    device = models.ManagedDevice.objects.filter(
        name=name, origin=models.DeviceOrigin.REGISTERED_NEW, lifecycle_state=models.DeviceLifecycleState.IN_SERVICE,
        admission_state=models.ProductionAdmissionState.ADMITTED).first()
    if device is None:
        return "DEVICE_NOT_ADMITTED"
    if device.identity_state != models.IdentityVerificationState.VERIFIED or not device.verified_host_key:
        return "IDENTITY_NOT_VERIFIED"
    if device.compliance_state == models.ComplianceState.DRIFT:
        return "CONFIGURATION_DRIFT"
    if device.netbox_device_id not in (None, row.netbox_device_id):
        return "NETBOX_IDENTITY_MISMATCH"
    if not models.CommissioningRecord.objects.filter(device=device, provisioning_run=run,
                                                     state=models.CommissioningState.ADMITTED).exists():
        return "COMMISSIONING_NOT_BOUND"
    return ""


def active_managed(name: str) -> bool:
    """Is ``name`` an NMAS-admitted, NetBox-synchronized natively provisioned device (``managed_scope_refusal`` is empty)?"""
    return not managed_scope_refusal(name)


def admit(run, *, netbox_device_id=None) -> models.ProvisionedDevice:
    target = run.bootstrap_target or {}
    management = run.management or {}
    return models.ProvisionedDevice.objects.create(
        name=run.device_name, platform=run.platform, run=run, transport=run.bootstrap_transport, container=str(target.get("container") or ""),
        lab=str(target.get("lab") or ""), address=str(management.get("ipv4") or "").split("/")[0],
        address_v6=str(management.get("ipv6") or "").split("/")[0], disposable=run.disposable, netbox_device_id=netbox_device_id,
    )


def activate(row) -> models.ProvisionedDevice:
    row.state = State.ACTIVE
    row.save(update_fields=["state", "updated_at"])
    return row


def retire(row, *, now=None) -> models.ProvisionedDevice:
    if row.state != State.RETIRED:
        row.state, row.retired_at = State.RETIRED, now or timezone.now()
        row.save(update_fields=["state", "retired_at", "updated_at"])
    return row
