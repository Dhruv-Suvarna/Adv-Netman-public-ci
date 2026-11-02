"""The ONE managed-device resolution service: who NMAS manages, how, and with what authority.

Sources, in precedence order (a later source can only ADD a name, never redefine or hide an earlier one):

    INVENTORY_FILE          the tracked ``inventory.yml`` network devices -- authoritative for their addresses and credential
                            references (references only: no secret is read here)
    PROVISIONING_REGISTRY   devices a V2 Phase 5 provisioning run admitted (``ProvisionedDevice``)
    NMAS_REGISTRY           registered new devices (``ManagedDevice`` origin REGISTERED_NEW) that are not reachable yet:
                            visible with their identity and expected attachments, but NOT_MANAGED_YET -- no engine resolves them

The lifecycle registry (``ManagedDevice``) is an overlay: it adds the stable device id, lifecycle, identity verification and
expected attachments to the source that owns the name.  A conflict is reported as a ``Discrepancy``, never silently merged.

Management addresses are a LIST of candidates (management multihoming arrives in a later phase without a schema change).  A
candidate is only ever a declared address: ``auto`` and any address inside the Containerlab management network are refused,
so resolution can never fall back to the hidden lab management plane.  ``runtime_container`` is the lab runtime reference
the Linux executor already uses (``docker exec``); it is reported as what it is and never as a management path.

``engine_devices()`` is the exact dictionary the execution / health / soak engines have always consumed
(``health.inventory.managed_devices``): inventory first, then the provisioning registry.  Its content is unchanged.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from django.conf import settings
from django.db import DatabaseError

from ... import models
from ..health import inventory as health_inventory


class Authority:
    INVENTORY_FILE = "INVENTORY_FILE"
    PROVISIONING_REGISTRY = "PROVISIONING_REGISTRY"
    NMAS_REGISTRY = "NMAS_REGISTRY"


class Scope:
    WRITABLE = "WRITABLE"                          # an ordinary managed device
    WRITABLE_RESTRICTED = "WRITABLE_RESTRICTED"    # an ADMITTED provisioned device: only its own provisioning Change may write
    READ_ONLY = "READ_ONLY"                        # monitored, never written by NMAS (e.g. R5)
    NOT_MANAGED_YET = "NOT_MANAGED_YET"            # registered, not reachable: no engine resolves it


WRITABLE_SCOPES = frozenset({Scope.WRITABLE, Scope.WRITABLE_RESTRICTED})
# inventory ``monitoring.platform`` -> catalogue platform (the catalogue values map to themselves)
INVENTORY_PLATFORM = {"ceos": models.Platform.ARISTA_CEOS.value, "linux": models.Platform.UBUNTU_FRR.value,
                      **{value: value for value in models.Platform.values}}
# Containerlab's documented default management network (used when the tracked topology declares none of its own).
CONTAINERLAB_DEFAULT_MGMT = ("172.20.20.0/24", "3fff:172:20:20::/64")


@dataclass(frozen=True)
class ManagementCandidate:
    address: str
    family: int
    source: str                  # INVENTORY_DECLARED | PROVISIONING_REGISTRY
    interface: str = ""
    network: str = "OTHER"       # VLAN200 when inside the static management networks
    preference: int = 0          # declaration order; path classification and ordering belong to management multihoming

    def as_dict(self) -> dict:
        return {"address": self.address, "family": self.family, "source": self.source, "interface": self.interface,
                "network": self.network, "preference": self.preference}


@dataclass(frozen=True)
class Discrepancy:
    code: str
    name: str
    detail: str = ""

    def as_dict(self) -> dict:
        return {"code": self.code, "name": self.name, "detail": self.detail}


@dataclass(frozen=True)
class ManagedTarget:
    name: str
    platform: str                         # catalogue platform value ('' when unmapped)
    health_platform: str
    authority: str
    scope: str
    role: str = ""
    management_candidates: tuple = ()
    transports: tuple = ()
    credential_refs: dict = field(default_factory=dict)   # references only (runtime://...), never a secret
    lifecycle: dict | None = None
    attachments: tuple = ()
    engine_entry: dict | None = None      # the legacy engine dictionary, when an engine may resolve the device
    runtime_container: str = ""
    operational: str = "UNKNOWN"          # no live probe happens during resolution

    @property
    def writable(self) -> bool:
        return self.scope in WRITABLE_SCOPES

    @property
    def device_id(self) -> str:
        return (self.lifecycle or {}).get("device_id", "")

    def primary_address(self, family: int = 4) -> str:
        return next((c.address for c in self.management_candidates if c.family == family), "")

    def as_dict(self) -> dict:
        return {"name": self.name, "device_id": self.device_id, "platform": self.platform, "health_platform": self.health_platform,
                "role": self.role, "authority": self.authority, "scope": self.scope, "writable": self.writable,
                "management_candidates": [c.as_dict() for c in self.management_candidates], "transports": list(self.transports),
                "credential_refs": dict(self.credential_refs), "lifecycle": dict(self.lifecycle or {}),
                "attachments": list(self.attachments), "operational": self.operational,
                "runtime_container": self.runtime_container, "engine_resolvable": self.engine_entry is not None}


@dataclass(frozen=True)
class Resolution:
    targets: dict
    discrepancies: tuple = ()

    def get(self, name: str) -> ManagedTarget | None:
        return self.targets.get(str(name))


# --- helpers --------------------------------------------------------------------------------------------------------------------
def _tracked_topology(document: dict) -> dict:
    path = Path(settings.REPO_ROOT) / f"{document.get('lab_name', '')}.clab.yml"
    try:
        with open(path, encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError):
        return {}


def forbidden_networks(document: dict | None = None) -> tuple:
    """The Containerlab management networks: the tracked topology's own ``mgmt`` subnets, plus Containerlab's defaults."""
    document = health_inventory.load_inventory() if document is None else document
    mgmt = _tracked_topology(document).get("mgmt") or {}
    found = []
    for value in (mgmt.get("ipv4-subnet"), mgmt.get("ipv6-subnet"), *CONTAINERLAB_DEFAULT_MGMT):
        try:
            if value:
                found.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            continue
    return tuple(dict.fromkeys(found))


def _management_networks(document: dict) -> list:
    management = document.get("management") or {}
    networks = []
    for key in ("nmas_ipv4", "nmas_ipv6"):
        try:
            if management.get(key):
                networks.append(ipaddress.ip_interface(str(management[key])).network)
        except ValueError:
            continue
    return networks


def _candidates(name: str, values, *, source: str, interface: str, document: dict, forbidden, discrepancies: list) -> tuple:
    vlan200 = _management_networks(document)
    found = []
    for raw in values:
        text = str(raw or "").strip()
        if not text:
            continue
        if text == "auto":
            discrepancies.append(Discrepancy("MANAGEMENT_ADDRESS_AUTO_REFUSED", name, "an 'auto' address is the Containerlab-assigned one"))
            continue
        try:
            ip = ipaddress.ip_address(text.split("/")[0])
        except ValueError:
            discrepancies.append(Discrepancy("MANAGEMENT_ADDRESS_INVALID", name, text[:64]))
            continue
        if any(ip.version == net.version and ip in net for net in forbidden):
            discrepancies.append(Discrepancy("CONTAINERLAB_MANAGEMENT_ADDRESS_REFUSED", name, str(ip)))
            continue
        network = "VLAN200" if any(ip.version == net.version and ip in net for net in vlan200) else "OTHER"
        found.append(ManagementCandidate(str(ip), ip.version, source, interface, network, len(found)))
    return tuple(found)


def _credential_refs(entry: dict, raw_platform: str, document: dict) -> dict:
    """Dedicated account references only; shared fleet fallback is forbidden."""
    if raw_platform == "linux":
        refs = {"username": entry.get("username"), "ssh_key_ref": entry.get("ssh_key_ref")}
    else:
        refs = {"username": entry.get("username"),
                "credential_ref": entry.get("credential_ref"),
                "ssh_key_ref": entry.get("ssh_key_ref")}
    return {key: str(value) for key, value in refs.items()
            if value and (key in ("username", "profile") or str(value).startswith("runtime://"))}


def _lifecycle_summary(row) -> dict:
    return {"device_id": row.device_id, "pk": row.pk, "origin": row.origin, "lifecycle_state": row.lifecycle_state,
            "identity_state": row.identity_state, "admission_state": row.admission_state, "ztp_state": row.ztp_state,
            "compliance_state": row.compliance_state, "role": row.role}


def _attachment_rows(row) -> tuple:
    return tuple({"id": a.pk, "upstream_device": a.upstream_device, "upstream_interface": a.upstream_interface,
                  "local_interface": a.local_interface, "purpose": a.purpose, "connectivity": a.connectivity, "vlan": a.vlan,
                  "approval_state": a.approval_state, "verification_state": a.verification_state}
                 for a in row.attachments.exclude(approval_state=models.AttachmentApproval.REVOKED).order_by("id"))


def _lifecycle_rows(discrepancies: list) -> dict:
    """Live ManagedDevice rows by name.  An unreadable registry (no table yet, no database) adds nothing and is reported."""
    try:
        return {row.name: row for row in models.ManagedDevice.objects.exclude(
            lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).prefetch_related("attachments")}
    except DatabaseError:
        discrepancies.append(Discrepancy("LIFECYCLE_REGISTRY_UNAVAILABLE", "*", "the lifecycle registry could not be read"))
        return {}


# --- resolution -----------------------------------------------------------------------------------------------------------------
def resolve_all(*, document: dict | None = None, with_lifecycle: bool = True) -> Resolution:
    """Every managed / registered device with its authority, scope, management candidates and lifecycle overlay.

    ``with_lifecycle=False`` skips the lifecycle registry (no ``ManagedDevice`` query): addresses, scope and credential
    references are identical; only the overlay and the NMAS_REGISTRY-only devices are absent."""
    document = health_inventory.load_inventory() if document is None else document
    discrepancies: list = []
    forbidden = forbidden_networks(document)
    engine = engine_devices(document=document)
    rows = _lifecycle_rows(discrepancies) if with_lifecycle else {}
    targets: dict = {}

    for name, entry in sorted((document.get("network_devices") or {}).items()):
        entry = entry or {}
        monitoring = entry.get("monitoring") or {}
        raw_platform = str(monitoring.get("platform") or "")
        refs = _credential_refs(entry, raw_platform, document)
        writable = not entry.get("edge") and bool(refs.get("credential_ref") or refs.get("ssh_key_ref"))
        row = rows.get(name)
        overlay = None
        if row is not None:
            if row.origin != models.DeviceOrigin.LEGACY_ADOPTION:
                discrepancies.append(Discrepancy("REGISTRATION_SHADOWED_BY_INVENTORY", name, row.device_id))
            else:
                overlay = row
                if row.platform != INVENTORY_PLATFORM.get(raw_platform, ""):
                    discrepancies.append(Discrepancy("LIFECYCLE_PLATFORM_MISMATCH", name, f"{row.platform} vs inventory {raw_platform}"[:120]))
        candidates = _candidates(name, (monitoring.get("address"), monitoring.get("address_v6")), source="INVENTORY_DECLARED",
                                 interface=str(monitoring.get("source_interface") or ""), document=document, forbidden=forbidden,
                                 discrepancies=discrepancies)
        transports = ("SSH",) if raw_platform != "linux" else ("SSH", "DOCKER_EXEC_LAB_RUNTIME")
        targets[name] = ManagedTarget(
            name=name, platform=INVENTORY_PLATFORM.get(raw_platform, ""), health_platform=health_inventory.health_platform(raw_platform),
            authority=Authority.INVENTORY_FILE, scope=Scope.WRITABLE if writable else Scope.READ_ONLY,
            role=overlay.role if overlay else "", management_candidates=candidates, transports=transports if writable else (),
            credential_refs=refs, lifecycle=_lifecycle_summary(overlay) if overlay else None,
            attachments=_attachment_rows(overlay) if overlay else (), engine_entry=engine.get(name),
            runtime_container=str((engine.get(name) or {}).get("container") or ""),
        )

    for name, entry in sorted(health_inventory.provisioned_devices().items()):
        if name in targets:
            discrepancies.append(Discrepancy("REGISTRY_SHADOWED_BY_INVENTORY", name, "inventory.yml wins"))
            continue
        row = rows.get(name)
        overlay = row if row is not None and row.origin == models.DeviceOrigin.REGISTERED_NEW else None
        restricted = entry.get("provisioning_state") == models.ProvisionedDeviceState.ADMITTED
        targets[name] = ManagedTarget(
            name=name, platform=INVENTORY_PLATFORM.get(str(entry.get("platform") or ""), ""),
            health_platform=health_inventory.health_platform(entry.get("platform")), authority=Authority.PROVISIONING_REGISTRY,
            scope=Scope.WRITABLE_RESTRICTED if restricted else Scope.WRITABLE, role=overlay.role if overlay else "",
            management_candidates=_candidates(name, (entry.get("address"), entry.get("address_v6")), source="PROVISIONING_REGISTRY",
                                              interface="", document=document, forbidden=forbidden, discrepancies=discrepancies),
            transports=("DOCKER_EXEC_LAB_RUNTIME",), lifecycle=_lifecycle_summary(overlay) if overlay else None,
            attachments=_attachment_rows(overlay) if overlay else (), engine_entry=engine.get(name),
            runtime_container=str(entry.get("container") or ""),
        )

    for name, row in sorted(rows.items()):
        if name in targets:
            continue
        if row.origin == models.DeviceOrigin.LEGACY_ADOPTION:   # adopted, but no longer in the inventory: never resolvable
            discrepancies.append(Discrepancy("ADOPTED_DEVICE_NOT_IN_INVENTORY", name, row.device_id))
            continue
        targets[name] = ManagedTarget(
            name=name, platform=row.platform, health_platform=health_inventory.health_platform(row.platform),
            authority=Authority.NMAS_REGISTRY, scope=Scope.NOT_MANAGED_YET, role=row.role,
            lifecycle=_lifecycle_summary(row), attachments=_attachment_rows(row),
        )
    return Resolution(targets, tuple(discrepancies))


def resolve(name: str, *, document: dict | None = None, with_lifecycle: bool = True) -> ManagedTarget | None:
    return resolve_all(document=document, with_lifecycle=with_lifecycle).get(name)


def engine_devices(*, document: dict | None = None) -> dict:
    """The engines' device dictionary, unchanged: ``inventory.yml`` devices, then live provisioning-registry entries (never
    redefining an inventory name).  Registered-but-unreachable devices are deliberately absent."""
    devices = health_inventory.inventory_devices(document=document)
    for name, entry in health_inventory.provisioned_devices().items():
        devices.setdefault(name, entry)
    return devices


def is_writable(name: str) -> bool:
    target = resolve(name)
    return bool(target and target.writable)


def adoption_scope(name: str, *, document: dict | None = None) -> tuple[ManagedTarget | None, str]:
    """-> (inventory target, '' | refusal code) for an Adopt Existing Device request."""
    document = health_inventory.load_inventory() if document is None else document
    if str(name) not in (document.get("network_devices") or {}):
        return None, "NOT_IN_INVENTORY"
    target = resolve(name, document=document)
    if target is None or target.authority != Authority.INVENTORY_FILE:
        return None, "NOT_IN_INVENTORY"
    if not target.writable:
        return target, "OUT_OF_WRITABLE_SCOPE"
    if not target.platform:
        return target, "PLATFORM_UNMAPPED"
    return target, ""
