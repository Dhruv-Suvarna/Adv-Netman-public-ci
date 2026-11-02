"""NetBox / IPAM planning and reservation for a provisioning request.  NetBox stays the authority for structured addressing.

    plan()      READ-ONLY conflict detection: device name, duplicate management addresses, containing prefix, DHCP ranges, VLAN policy.
    reserve()   writes the planned objects (device ``planned``, management interface, addresses ``reserved``) and records exactly which objects
                THIS run created.  A failure part-way compensates in reverse order before it reports -- no half reservation is left behind.
    activate()  after a verified provision: device / addresses become ``active``; a managed (non-disposable) device joins the IaC
                managed scope (ownership + ``managed`` tags, ``iac_managed = true``), which is read back before it is reported.
    release()   reconciliation: deletes ONLY the objects this run created (by the ids it recorded), newest first, and reports each one.

Existing allocations are never edited: every conflict is a refusal, never an overwrite.  Provisioning objects carry their own ``nmas-provisioning``
tag and stay OUTSIDE the IaC ownership scope (``csci5840-iac`` / ``managed``) until the device is really managed, so the production NetBox
verifiers never see a half-provisioned device.

VLAN 200 is static management only: an address inside the management networks must be static IPv4 + IPv6, a DHCP / DHCPv6 assignment there is
refused whatever else is true, and a disposable device may not take a VLAN 200 address at all.

All NetBox I/O goes through a small gateway object so the rules are tested without NetBox (``NetboxGateway`` is the real one).
"""

from __future__ import annotations

import ipaddress

from ..health import inventory
from .codes import blocker

PROVISIONING_TAG = "nmas-provisioning"
DISPOSABLE_TAG = "nmas-disposable"
STATIC, DHCP, DHCPV6 = "static", "dhcp", "dhcpv6"


class IpamUnavailable(Exception):
    """NetBox could not be read or written.  Carries no upstream text."""


class ReservationFailed(Exception):
    def __init__(self, released: list, created: list):
        super().__init__("IPAM_RESERVATION_FAILED")
        self.released, self.created = released, created


# --- pure rules ----------------------------------------------------------------------------------------------------------------
def management_networks() -> list:
    """The production management (VLAN 200) networks, from the tracked inventory -- never from the browser."""
    management = inventory.load_inventory().get("management") or {}
    networks = []
    for key in ("nmas_ipv4", "nmas_ipv6"):
        if management.get(key):
            networks.append(ipaddress.ip_interface(str(management[key])).network)
    return networks


def inventory_names() -> set[str]:
    document = inventory.load_inventory()
    return {*(document.get("network_devices") or {}), *(document.get("hosts") or {}), "WebServer"}


def inventory_addresses() -> set[str]:
    found = set()
    for entry in (inventory.load_inventory().get("network_devices") or {}).values():
        monitoring = (entry or {}).get("monitoring") or {}
        for key in ("address", "address_v6"):
            value = str(monitoring.get(key) or "")
            if value and value != "auto":
                found.add(str(ipaddress.ip_address(value)))
    return found


def parse_management(management: dict) -> tuple[dict | None, list[dict]]:
    """Normalize the requested management addressing.  -> ({interface, vlan, assignment, addresses: [ip_interface]}, blockers)"""
    interface = str(management.get("interface") or "").strip()
    assignment = str(management.get("assignment") or STATIC).strip().lower()
    addresses = []
    try:
        for key in ("ipv4", "ipv6"):
            if management.get(key):
                parsed = ipaddress.ip_interface(str(management[key]))
                if parsed.version != (4 if key == "ipv4" else 6) or "/" not in str(management[key]):
                    raise ValueError(key)
                addresses.append(parsed)
        vlan = int(management["vlan"]) if management.get("vlan") not in (None, "") else None
    except (ValueError, TypeError):
        return None, [blocker("MANAGEMENT_ADDRESS_INVALID")]
    if not interface or not addresses or assignment not in (STATIC, DHCP, DHCPV6) or len(interface) > 64:
        return None, [blocker("MANAGEMENT_ADDRESS_INVALID")]
    return {"interface": interface, "vlan": vlan, "assignment": assignment, "addresses": addresses}, []


def vlan_policy_blockers(parsed: dict, *, disposable: bool) -> list[dict]:
    networks = management_networks()
    inside = [a for a in parsed["addresses"] if any(a.ip in n for n in networks if n.version == a.version)]
    on_vlan200 = parsed["vlan"] == 200 or bool(inside)
    if not on_vlan200:
        return []
    if parsed["assignment"] != STATIC:
        return [blocker("VLAN200_DHCP_FORBIDDEN", assignment=parsed["assignment"])]
    if disposable:
        return [blocker("DISPOSABLE_IN_PRODUCTION_MANAGEMENT")]
    if {a.version for a in parsed["addresses"]} != {4, 6}:
        return [blocker("VLAN200_DUAL_STACK_REQUIRED")]
    return []


# --- planning (read-only) ------------------------------------------------------------------------------------------------------
def plan(run, gateway, *, registry_names=()) -> tuple[dict, list[dict]]:
    """-> (plan document, blockers).  Reads NetBox; writes nothing."""
    parsed, blockers = parse_management(run.management or {})
    if blockers:
        return {}, blockers
    blockers = vlan_policy_blockers(parsed, disposable=run.disposable)
    name = run.device_name
    try:
        if name in inventory_names() or name in set(registry_names) or gateway.device_exists(name):
            blockers.append(blocker("NAME_CONFLICT", name=name))
        taken = inventory_addresses()
        addresses, new_prefixes = [], []
        for address in parsed["addresses"]:
            host = str(address.ip)
            holders = gateway.address_holders(host)
            if host in taken or holders:
                blockers.append(blocker("MGMT_IP_DUPLICATE", address=host, holders=holders[:5]))
            if gateway.dhcp_ranges_containing(host):
                blockers.append(blocker("DHCP_POOL_CONFLICT", address=host))
            prefix = gateway.containing_prefix(host)
            if prefix is None:
                if run.disposable:
                    new_prefixes.append(str(address.network))
                else:
                    blockers.append(blocker("PREFIX_NOT_IN_IPAM", address=host))
            elif ipaddress.ip_network(prefix).prefixlen != address.network.prefixlen:
                blockers.append(blocker("PREFIX_LENGTH_MISMATCH", address=str(address), prefix=prefix))
            addresses.append({"address": str(address), "family": address.version, "interface": parsed["interface"],
                              "prefix": prefix or str(address.network), "role": "management"})
    except IpamUnavailable:
        return {}, [blocker("IPAM_UNAVAILABLE")]
    document = {
        "device": {"name": name, "platform": run.platform, "role": run.role, "site": run.site, "status": "planned"},
        "interfaces": [{"name": parsed["interface"], "management": True, "vlan": parsed["vlan"]}],
        "addresses": addresses, "new_prefixes": sorted(set(new_prefixes)), "assignment": parsed["assignment"],
        "tags": [PROVISIONING_TAG, *([DISPOSABLE_TAG] if run.disposable else [])],
    }
    return document, blockers


# --- writes --------------------------------------------------------------------------------------------------------------------
def release(gateway, created: list) -> list[dict]:
    """Delete, newest first, exactly the objects recorded in ``created``.  Never raises: every object's fate is reported."""
    report = []
    for item in reversed(list(created or [])):
        try:
            gateway.delete(item["kind"], item["id"])
            report.append({**item, "released": True})
        except Exception:  # noqa: BLE001 - reconciliation reports; it never hides a leftover behind an exception
            report.append({**item, "released": False})
    return report


def reserve(document: dict, gateway, *, provenance: dict) -> dict:
    """Create the planned objects.  -> {"created": [{kind, id, name}], "device_id", ...}.  Compensates and raises on any failure."""
    created: list[dict] = []

    def record(kind, obj_id, name):
        created.append({"kind": kind, "id": obj_id, "name": name})
        return obj_id

    try:
        for prefix in document["new_prefixes"]:
            record("prefix", gateway.create_prefix(prefix, tags=document["tags"], provenance=provenance), prefix)
        device = document["device"]
        device_id = record("device", gateway.create_device(device, tags=document["tags"], provenance=provenance), device["name"])
        interface_ids = {}
        for interface in document["interfaces"]:
            interface_ids[interface["name"]] = record(
                "interface", gateway.create_interface(device_id, interface, tags=document["tags"]), interface["name"])
        for address in document["addresses"]:
            record("ip_address", gateway.create_address(address, interface_ids[address["interface"]], tags=document["tags"],
                                                        provenance=provenance), address["address"])
    except Exception as exc:  # noqa: BLE001 - any failure (NetBox, model, transport) rolls the reservation back
        raise ReservationFailed(release(gateway, created), created) from exc
    return {"created": created, "device_id": device_id, "device_name": device["name"], "status": "planned"}


def activate(gateway, refs: dict, *, managed: bool) -> dict:
    """The device is really provisioned: device ``active``, addresses ``active``.  ``managed`` joins the IaC managed scope.

    ``managed_scope`` reports what NetBox was proven to hold, never only what was requested: a requested scope the gateway
    did not confirm raises ``IpamUnavailable`` (the NSOT stage then refuses and can be retried)."""
    result = gateway.activate(refs["created"], managed=managed) or {}
    joined = bool(managed) and result.get("managed_scope") is True
    if managed and not joined:
        raise IpamUnavailable()
    return {**refs, "status": "active", "managed_scope": joined}


# --- the real gateway ----------------------------------------------------------------------------------------------------------
class NetboxGateway:
    """pynetbox-backed gateway.  Every upstream error becomes ``IpamUnavailable`` (no upstream text leaves this class)."""

    _ENDPOINTS = {"prefix": ("ipam", "prefixes"), "device": ("dcim", "devices"), "interface": ("dcim", "interfaces"),
                  "ip_address": ("ipam", "ip_addresses")}

    def __init__(self, client=None):
        self._client = client

    @property
    def client(self):
        if self._client is None:
            from ..nsot_netbox import _client  # the one place the web application builds its NetBox client

            self._client = _client()
        return self._client

    def _guard(self, fn):
        try:
            return fn()
        except IpamUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            raise IpamUnavailable() from exc

    def _endpoint(self, kind):
        app, name = self._ENDPOINTS[kind]
        return getattr(getattr(self.client, app), name)

    def _tag_refs(self, names):
        refs = []
        for name in names:
            tag = self.client.extras.tags.get(name=name) or self.client.extras.tags.create(
                name=name, slug=name, description="Created by NMAS new-device provisioning.")
            refs.append({"id": tag.id})
        return refs

    # reads
    def device_exists(self, name):
        return self._guard(lambda: bool(list(self.client.dcim.devices.filter(name=name))))

    def address_holders(self, host):
        def read():
            return [{"address": str(r.address), "status": str(getattr(r.status, "value", r.status)),
                     "device": str(getattr(getattr(r.assigned_object, "device", None), "name", "") or "")}
                    for r in self.client.ipam.ip_addresses.filter(address=host)]
        return self._guard(read)

    def containing_prefix(self, host):
        def read():
            found = [ipaddress.ip_network(str(p.prefix)) for p in self.client.ipam.prefixes.filter(contains=host)]
            return str(max(found, key=lambda n: n.prefixlen)) if found else None
        return self._guard(read)

    def dhcp_ranges_containing(self, host):
        def read():
            ip = ipaddress.ip_address(host)
            return [f"{r.start_address}-{r.end_address}" for r in self.client.ipam.ip_ranges.all()
                    if ipaddress.ip_interface(str(r.start_address)).ip.version == ip.version
                    and ipaddress.ip_interface(str(r.start_address)).ip <= ip <= ipaddress.ip_interface(str(r.end_address)).ip]
        return self._guard(read)

    # writes
    def create_prefix(self, prefix, *, tags, provenance):
        return self._guard(lambda: self.client.ipam.prefixes.create(
            prefix=prefix, status="reserved", tags=self._tag_refs(tags), description=_describe(provenance)).id)

    def create_device(self, device, *, tags, provenance):
        def write():
            site = self.client.dcim.sites.get(name=device["site"]) if device.get("site") else next(iter(self.client.dcim.sites.all()), None)
            role = self.client.dcim.device_roles.get(slug=_ROLE_SLUG.get(device["role"], device["role"]))
            platform_type = _device_type(self.client, device["platform"])
            if site is None or role is None or platform_type is None:
                raise IpamUnavailable()
            return self.client.dcim.devices.create(
                name=device["name"], site=site.id, role=role.id, device_type=platform_type.id, status="planned",
                tags=self._tag_refs(tags), comments=_describe(provenance)).id
        return self._guard(write)

    def create_interface(self, device_id, interface, *, tags):
        return self._guard(lambda: self.client.dcim.interfaces.create(
            device=device_id, name=interface["name"], type="virtual", mgmt_only=bool(interface.get("management")),
            tags=self._tag_refs(tags)).id)

    def create_address(self, address, interface_id, *, tags, provenance):
        return self._guard(lambda: self.client.ipam.ip_addresses.create(
            address=address["address"], status="reserved", assigned_object_type="dcim.interface", assigned_object_id=interface_id,
            tags=self._tag_refs(tags), description=_describe(provenance)).id)

    def _scope_tags(self):
        """The existing ownership / managed / unmanaged tags.  The two scope tags are NetBox's authority (``populate_netbox``):
        they are looked up, never created here, so a missing one refuses the activation instead of inventing the scope."""
        from ..nsot_netbox import nb

        tags = self.client.extras.tags
        ownership, managed = tags.get(slug=nb.OWNERSHIP_TAG_FILTER), tags.get(slug=nb.MANAGED_TAG_NAME)
        if ownership is None or managed is None:
            raise IpamUnavailable()
        return ownership.id, managed.id, getattr(tags.get(slug=nb.UNMANAGED_TAG_NAME), "id", None)

    def activate(self, created, *, managed):
        """Objects become ``active``.  With ``managed`` the device also joins the IaC managed scope exactly as
        ``netbox_ipam.get_managed_devices`` reads it: the ownership and ``managed`` tags plus ``iac_managed = true``
        (tag and field must agree).  The scope is read back; -> ``{"managed_scope": bool}`` (True only when proven)."""
        def write():
            from ..nsot_netbox import nb

            scope = self._scope_tags() if managed else None
            objects = []
            for item in created:                                # read everything and refuse conflicts BEFORE the first write
                obj = self._endpoint(item["kind"]).get(item["id"])
                if obj is None:
                    raise IpamUnavailable()
                if item["kind"] in ("device", "ip_address", "prefix"):
                    objects.append((item, obj))
            devices = [(item, obj) for item, obj in objects if item["kind"] == "device"]
            if scope is not None:
                if len(devices) != 1:
                    raise IpamUnavailable()                    # the run's one device is what carries the managed scope
                if scope[2] is not None and scope[2] in [_ref_id(tag) for tag in (getattr(devices[0][1], "tags", None) or [])]:
                    raise IpamUnavailable()                    # tagged ``unmanaged``: a NetBox integrity conflict, never overwritten
            for item, obj in objects:
                values = {"status": "active"}
                if scope is not None and item["kind"] == "device":
                    current = [_ref_id(tag) for tag in (getattr(obj, "tags", None) or [])]
                    values["tags"] = [{"id": tag} for tag in dict.fromkeys([*current, scope[0], scope[1]])]
                    values["custom_fields"] = {nb.MANAGED_CUSTOM_FIELD: True}
                obj.update(values)
            if scope is None:
                return {"managed_scope": False}
            stored = self._endpoint("device").get(devices[0][0]["id"])
            tags = {_ref_id(tag) for tag in (getattr(stored, "tags", None) or [])}
            fields = getattr(stored, "custom_fields", None) or {}
            if not ({scope[0], scope[1]} <= tags and (scope[2] is None or scope[2] not in tags)
                    and fields.get(nb.MANAGED_CUSTOM_FIELD) is True):
                raise IpamUnavailable()
            return {"managed_scope": True}
        return self._guard(write)

    def delete(self, kind, obj_id):
        def write():
            obj = self._endpoint(kind).get(obj_id)
            if obj is not None:
                obj.delete()
        return self._guard(write)


def _ref_id(tag):
    """The id of a tag as NetBox returns it (a record) or as it was written (``{"id": ...}``)."""
    return tag.get("id") if isinstance(tag, dict) else getattr(tag, "id", None)


def _describe(provenance: dict) -> str:
    return f"NMAS provisioning {provenance.get('prov_id', '')} requested by {provenance.get('requested_by', '')}"[:200]


# What NetBox already calls each platform / role (read from the existing fleet's objects; nothing is invented or created here).
_DEVICE_TYPE_HINT = {"arista_ceos": "ceos", "ubuntu_frr": "ubuntu"}
_ROLE_SLUG = {"router": "router", "switch": "switch", "edge": "router"}


def _device_type(client, platform: str):
    """The device type NetBox already uses for this platform, or None (the reservation then fails closed)."""
    hint = _DEVICE_TYPE_HINT.get(platform)
    if not hint:
        return None
    for candidate in client.dcim.device_types.all():
        if hint in str(candidate.slug).lower():
            return candidate
    return None
