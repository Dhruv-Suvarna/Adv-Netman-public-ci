"""Bootstrap networks and the provider-neutral DHCP bootstrap policy.

A bootstrap network is refused unless it is an isolated IPv4 subnet that is not VLAN 200, does not overlap the protected
management / lab / production prefixes (or any address the tracked inventory declares), has a gateway and a pool inside the
subnet, a separate service link, relays that sit on the subnet and name trusted managed upstreams, and an isolated provider
directory.  The DHCP policy contains ONLY open ZTP sessions whose Phase 2 authorization is approved (or consumed but still
inside its window): revocation or expiry removes the device at the next application.
"""

from __future__ import annotations

import ipaddress

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from ... import models
from ..devices import attachments as attachment_service
from ..devices import events, resolver
from ..devices.codes import blocker
from ..isolation import service as isolation_service
from . import adapters, dhcp
from .dhcp.base import ProviderError, safe_root

Outcome = models.DeviceLifecycleEventOutcome
# Never a bootstrap subnet: the static management network (VLAN 200), Containerlab's management bridge, Docker defaults.
PROTECTED_PREFIXES = ("192.168.200.0/24", "172.20.20.0/24", "172.17.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
MANAGEMENT_VLAN = attachment_service.MANAGEMENT_VLAN
DHCP_ELIGIBLE_AUTH = (models.BootstrapAuthorizationState.APPROVED, models.BootstrapAuthorizationState.CONSUMED)


def protected_prefixes() -> list:
    extra = getattr(settings, "NMAS_ZTP_PROTECTED_PREFIXES", ()) or ()
    return [ipaddress.ip_network(p) for p in (*PROTECTED_PREFIXES, *extra)]


def _inventory_addresses() -> list:
    found = []
    try:
        for target in resolver.resolve_all(with_lifecycle=False).targets.values():
            for candidate in target.management_candidates:
                try:
                    found.append(ipaddress.ip_address(candidate.address))
                except ValueError:
                    continue
    except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - an unreadable inventory must not make an unsafe network look safe
        return [None]
    return found


def network_problems(*, name, ipv4_prefix, gateway, pool_start, pool_end, service_prefix, service_address, vlan=None,
                     trusted_relays=(), config_root="", http_port=8080, tftp_port=69, check_upstreams=True) -> list[dict]:
    """Every reason the definition is unsafe or inconsistent ([] when it is a valid isolated bootstrap network)."""
    def bad(reason, **details):
        return blocker("BOOTSTRAP_NETWORK_INVALID", reason=reason, **details)

    problems = []
    try:
        subnet = ipaddress.IPv4Network(str(ipv4_prefix), strict=True)
        service = ipaddress.IPv4Network(str(service_prefix), strict=True)
        gw, start, end, svc = (ipaddress.IPv4Address(str(v)) for v in (gateway, pool_start, pool_end, service_address))
    except ValueError:
        return [bad("addresses must be valid IPv4 prefixes / addresses")]
    if vlan not in (None, "") and (not str(vlan).isdigit() or not 1 <= int(vlan) <= 4094):
        problems.append(bad("VLAN out of range"))
    if str(vlan) == str(MANAGEMENT_VLAN):
        problems.append(blocker("VLAN200_PURPOSE_FORBIDDEN"))
    if subnet.prefixlen < 16 or subnet.prefixlen > 29:
        problems.append(bad("the bootstrap subnet must be /16 to /29"))
    for protected in protected_prefixes():
        if protected.version == 4 and (subnet.overlaps(protected) or service.overlaps(protected)):
            problems.append(bad("overlaps a protected management / lab prefix", prefix=str(protected)))
    if subnet.overlaps(service):
        problems.append(bad("the service link must be separate from the bootstrap subnet"))
    for address in _inventory_addresses():
        if address is None:
            problems.append(bad("the tracked inventory could not be read to prove the subnet is unused"))
        elif address.version == 4 and (address in subnet or address in service):
            problems.append(bad("an inventory device address lies inside the subnet"))
    hosts = (subnet.network_address, subnet.broadcast_address)
    if gw not in subnet or gw in hosts:
        problems.append(bad("the gateway must be a host address of the subnet"))
    if start not in subnet or end not in subnet or start > end or start in hosts or end in hosts:
        problems.append(bad("the pool must be an ordered host range inside the subnet"))
    elif start <= gw <= end:
        problems.append(bad("the gateway must not be inside the pool"))
    if svc not in service or svc in (service.network_address, service.broadcast_address):
        problems.append(bad("the service address must be a host of the service link"))
    for port in (http_port, tftp_port):
        if not str(port).isdigit() or not 1 <= int(port) <= 65535:
            problems.append(bad("ports must be 1-65535"))
    if not isinstance(trusted_relays, (list, tuple)) or not trusted_relays:
        problems.append(bad("at least one trusted relay is required: DHCP alone never provides attachment evidence"))
    else:
        seen = set()
        for relay in trusted_relays:
            if not isinstance(relay, dict) or set(relay) != {"relay_address", "upstream_device"}:
                problems.append(bad("each relay names exactly relay_address and upstream_device"))
                continue
            try:
                relay_ip = ipaddress.IPv4Address(str(relay["relay_address"]))
            except ValueError:
                problems.append(bad("a relay address is invalid"))
                continue
            if relay_ip not in subnet or relay_ip in seen:
                problems.append(bad("relay addresses are distinct hosts of the bootstrap subnet"))
            seen.add(relay_ip)
            if check_upstreams:
                problems += attachment_service.upstream_problems(str(name), str(relay["upstream_device"]))
    try:
        safe_root(config_root)
    except ProviderError as exc:
        problems.append(blocker(exc.code))
    return problems


def create_network(*, actor: str, **fields) -> tuple[object | None, list[dict]]:
    """Record a bootstrap network (NMAS database only; nothing is applied to any DHCP service here)."""
    name, _ = (str(fields.get("name") or "").strip(), None)
    try:
        models.DEVICE_NAME_VALIDATOR(name)
    except ValidationError:
        return None, [blocker("NAME_INVALID")]
    if fields.get("provider", "ISC_DHCP") not in models.DhcpProviderKind.values:
        return None, [blocker("DHCP_PROVIDER_UNSUPPORTED")]
    problems = network_problems(name=name, **{k: fields.get(k) for k in (
        "ipv4_prefix", "gateway", "pool_start", "pool_end", "service_prefix", "service_address", "vlan", "trusted_relays", "config_root")},
        http_port=fields.get("http_port", 8080), tftp_port=fields.get("tftp_port", 69))
    if models.BootstrapNetwork.objects.filter(name=name).exists():
        problems.append(blocker("NAME_COLLISION", holders=["BOOTSTRAP_NETWORK"]))
    if problems:
        events.audit("BOOTSTRAP_NETWORK_CREATE", Outcome.REFUSED, actor=actor, object_id=name[:64] or "(invalid)",
                     summary=f"bootstrap network {name} refused", metadata={"codes": [p["code"] for p in problems]})
        return None, problems
    vlan = fields.get("vlan")
    row = models.BootstrapNetwork.objects.create(
        name=name, provider=fields.get("provider", "ISC_DHCP"), ipv4_prefix=str(ipaddress.IPv4Network(fields["ipv4_prefix"])),
        gateway=fields["gateway"], pool_start=fields["pool_start"], pool_end=fields["pool_end"],
        vlan=int(vlan) if str(vlan or "").isdigit() else None, service_address=fields["service_address"],
        service_prefix=str(ipaddress.IPv4Network(fields["service_prefix"])), http_port=int(fields.get("http_port", 8080)),
        tftp_port=int(fields.get("tftp_port", 69)), trusted_relays=list(fields["trusted_relays"]), config_root=fields["config_root"],
        lease_file=str(fields.get("lease_file") or ""), netbox_prefix_id=fields.get("netbox_prefix_id"), created_by=actor[:150])
    events.audit("BOOTSTRAP_NETWORK_CREATE", Outcome.RECORDED, actor=actor, object_id=row.name, summary=f"bootstrap network {row.name} recorded",
                 metadata={"prefix": row.ipv4_prefix, "provider": row.provider, "relays": len(row.trusted_relays)})
    return row, []


def stored_network_problems(network) -> list[dict]:
    if network is None or network.state != models.BootstrapNetworkState.ACTIVE:
        return [blocker("BOOTSTRAP_NETWORK_NOT_FOUND")]
    return network_problems(name=network.name, ipv4_prefix=network.ipv4_prefix, gateway=network.gateway, pool_start=network.pool_start,
                            pool_end=network.pool_end, service_prefix=network.service_prefix, service_address=network.service_address,
                            vlan=network.vlan, trusted_relays=network.trusted_relays, config_root=network.config_root,
                            http_port=network.http_port, tftp_port=network.tftp_port, check_upstreams=False)


def relay_for(network, upstream_device: str) -> str:
    """The trusted relay address the network lists for ``upstream_device`` ('' when the upstream relays nothing here)."""
    return next((str(r["relay_address"]) for r in network.trusted_relays or () if r.get("upstream_device") == upstream_device), "")


def relay_map(network) -> dict:
    return {str(r["relay_address"]): str(r["upstream_device"]) for r in network.trusted_relays or ()}


def allocate_address(network) -> str:
    """The first pool address no open session of the network holds ('' when exhausted)."""
    taken = set(models.ZtpSession.objects.filter(network=network, stage__in=tuple(models.ZTP_SESSION_OPEN))
                .values_list("reserved_address", flat=True))
    gateway = ipaddress.IPv4Address(network.gateway)
    relays = {ipaddress.IPv4Address(r) for r in relay_map(network)}
    address = ipaddress.IPv4Address(network.pool_start)
    while address <= ipaddress.IPv4Address(network.pool_end):
        if str(address) not in taken and address != gateway and address not in relays:
            return str(address)
        address += 1
    return ""


def artifact_url(network, artifact) -> str:
    path = f"/ztp/v1/{artifact.artifact_id}/{artifact.filename}"
    if artifact.transport == adapters.base.TFTP:
        return f"tftp://{network.service_address}{path}"
    port = "" if network.http_port == 80 else f":{network.http_port}"
    return f"http://{network.service_address}{port}{path}"


def eligible_sessions(network, *, now=None):
    now = now or timezone.now()
    return (models.ZtpSession.objects.select_related("device", "authorization", "authorization__attachment")
            .filter(network=network, stage__in=tuple(models.ZTP_SESSION_OPEN), authorization__state__in=DHCP_ELIGIBLE_AUTH,
                    authorization__valid_from__lte=now, authorization__valid_until__gt=now)
            .exclude(device__lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).order_by("id"))


def build_policy(network, *, now=None) -> dhcp.BootstrapPolicy:
    reservations = []
    for session in eligible_sessions(network, now=now):
        artifact = session.artifacts.filter(state=models.BootstrapArtifactState.ACTIVE).first()
        adapter = adapters.get(session.adapter)
        attachment = session.authorization.attachment
        relay = relay_for(network, attachment.upstream_device)
        if artifact is None or adapter is None or not relay or not isolation_service.enforced(attachment):
            continue                    # Phase 5: no DHCP answer for a port whose isolation is not (or no longer) in force
        params = adapter.select_discovery_parameters(artifact_url(network, artifact), session.transport, network.service_address)
        reservations.append(dhcp.Reservation(session.session_id, session.device.name, session.reserved_address, relay,
                                             attachment.upstream_interface, params.vendor_class_prefix, tuple(params.options)))
    return dhcp.BootstrapPolicy(network.name, network.ipv4_prefix, network.gateway, network.service_prefix, tuple(reservations))


def _record_application(network, provider, result, *, actor, sessions, code=""):
    with transaction.atomic():
        row = models.DhcpProviderApplication.objects.create(
            network=network, provider=network.provider, state=result.state, config_sha256=result.config_sha256,
            previous_sha256=result.previous_sha256, config_text=result.config_text, sessions=sessions,
            validation=result.validation, read_back=result.read_back, code=code or result.code, actor=actor[:150])
        events.audit("DHCP_POLICY_" + result.state, Outcome.RECORDED if result.ok else Outcome.REFUSED, actor=actor,
                     object_id=network.name, summary=f"bootstrap DHCP policy {result.state.lower()} on {network.name}",
                     metadata={"application": row.pk, "sha256": result.config_sha256, "sessions": sessions, "provider": network.provider})
        for session in models.ZtpSession.objects.filter(pk__in=[int(s[4:]) for s in sessions]).select_related("device"):
            events.record(session.device, "ZTP_DHCP_POLICY", Outcome.RECORDED if result.ok else Outcome.REFUSED, actor=actor,
                          actor_kind=events.AUTOMATION, from_state=session.device.lifecycle_state, to_state=session.device.lifecycle_state,
                          bootstrap_authorization=session.authorization, evidence={
                              "session": session.session_id, "network": network.name, "state": result.state,
                              "config_sha256": result.config_sha256, "reserved_address": session.reserved_address,
                              "dhcp_is_not_identity": True, "production_admission": False})
    return row


def validate_policy(network, *, actor: str, runner=None):
    """Render and validate with the provider's own parser; apply nothing.  -> (application row, blockers)."""
    problems = stored_network_problems(network)
    if problems:
        return None, problems
    provider = dhcp.for_network(network, runner=runner)
    policy = build_policy(network)
    try:
        text = provider.render(policy)
        validation = provider.validate(text)
    except ProviderError as exc:
        return None, [blocker(exc.code, detail=exc.detail[:200])]
    result = dhcp.ApplyResult(validation["ok"], "VALIDATED" if validation["ok"] else "FAILED", text, dhcp.base.sha256_text(text),
                              validation=validation, code="" if validation["ok"] else "DHCP_PROVIDER_ERROR")
    row = _record_application(network, provider, result, actor=actor, sessions=[r.session_id for r in policy.reservations])
    return row, [] if result.ok else [blocker("DHCP_PROVIDER_ERROR")]


def apply_policy(network, *, actor: str, runner=None):
    """Validate, atomically apply to the isolated provider, read back.  -> (application row, blockers)."""
    problems = stored_network_problems(network)
    if problems:
        return None, problems
    provider = dhcp.for_network(network, runner=runner)
    if not provider.operational:
        return None, [blocker("DHCP_PROVIDER_UNSUPPORTED", provider=network.provider)]
    policy = build_policy(network)
    try:
        result = provider.apply(policy)
    except ProviderError as exc:
        return None, [blocker(exc.code, detail=exc.detail[:200])]
    row = _record_application(network, provider, result, actor=actor, sessions=[r.session_id for r in policy.reservations])
    return row, [] if result.ok else [blocker(result.code or "DHCP_PROVIDER_ERROR")]


def rollback_policy(network, *, actor: str, runner=None):
    provider = dhcp.for_network(network, runner=runner)
    try:
        result = provider.rollback()
    except ProviderError as exc:
        return None, [blocker(exc.code, detail=exc.detail[:200])]
    row = _record_application(network, provider, result, actor=actor, sessions=[])
    return row, [] if result.ok else [blocker(result.code or "DHCP_PROVIDER_ERROR")]


def policy_current(network) -> bool:
    """Whether the last APPLIED policy carries exactly the sessions that are eligible now (False = re-apply needed)."""
    last = network.applications.filter(state__in=("APPLIED", "ROLLED_BACK")).order_by("-id").first()
    wanted = sorted(s.session_id for s in eligible_sessions(network) if s.artifacts.filter(state="ACTIVE").exists())
    return last is not None and last.state == "APPLIED" and sorted(last.sessions) == wanted
