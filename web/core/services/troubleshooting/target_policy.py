"""Central, fail-closed authorization for Troubleshooter network operations.

This module deliberately separates *identity* from *reachability*.  A route,
RFC1918 membership, DNS answer, ARP/LLDP discovery, or a Docker address never
creates authority.  The caller must present an authoritative snapshot for one
named device and an exact endpoint.  The policy then issues a short-lived,
content-bound grant which must be revalidated immediately before connection and
before each authorization-sensitive operation.

The pure policy is intentionally independent of Django so the same decision can
be enforced by a web worker, gateway adapter, or isolated device worker.  Site
adapters are responsible for constructing :class:`TargetSnapshot` only from
NMAS inventory, lifecycle/identity state, and approved management paths.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Iterable


class Capability(str, Enum):
    READ_DIAGNOSTIC = "READ_DIAGNOSTIC"
    OBSERVE_IDENTITY = "OBSERVE_IDENTITY"
    PROPOSE_CHANGE = "PROPOSE_CHANGE"
    APPLY_CHANGE = "APPLY_CHANGE"


class PrincipalKind(str, Enum):
    USER = "user"
    TROUBLESHOOTER_AGENT = "troubleshooter_agent"
    CHANGE_ENGINE = "change_engine"
    SYSTEM = "system"


_OPERATION = re.compile(r"^[a-z][a-z0-9_.:-]{1,95}$")
_AUTH_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:#/-]{7,191}$")


@dataclass(frozen=True)
class Principal:
    name: str
    kind: PrincipalKind
    permissions: frozenset[Capability] = field(default_factory=frozenset)
    tenant: str = "default"


@dataclass(frozen=True)
class TargetSnapshot:
    """One authoritative, point-in-time target description.

    ``endpoints`` contains exact IP literals from authoritative inventory.
    ``approved_path_endpoints`` is the exact endpoint set from currently
    approved management paths.  A diagnostic endpoint must occur in both.
    Identity observation is a narrower bootstrap capability and may use an
    explicitly authorized legacy endpoint, but it still needs a pin and a
    digest-bound observation authorization.
    """

    topology_id: str
    tenant: str
    device: str
    platform: str
    scope: str
    identity_state: str
    lifecycle_state: str
    admission_state: str
    endpoints: frozenset[str]
    approved_path_endpoints: frozenset[str] = field(default_factory=frozenset)
    excluded: bool = False
    revoked: bool = False
    identity_pin: str = ""
    revision: str = ""


@dataclass(frozen=True)
class TargetRequest:
    principal: Principal
    capability: Capability
    topology_id: str
    device: str = ""
    endpoint: str = ""
    port: int = 0
    transport: str = ""
    operation_id: str = ""
    authorization_ref: str = ""
    authorization_expires_at: datetime | None = None
    allow_legacy_identity_endpoint: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class TargetGrant:
    grant_id: str
    digest: str
    principal: str
    principal_kind: str
    principal_tenant: str
    capability: str
    topology_id: str
    device: str
    endpoint: str
    port: int
    transport: str
    operation_id: str
    authorization_ref: str
    target_revision: str
    issued_at: datetime
    expires_at: datetime


class AuthorizationRefused(RuntimeError):
    def __init__(self, code: str, reasons: Iterable[str] = ()):
        self.code = code
        self.reasons = tuple(reasons)
        super().__init__(f"{code}: {'; '.join(self.reasons)}" if self.reasons else code)


DEFAULT_DIAGNOSTIC_OPERATIONS = frozenset({
    # Command-catalog identifiers, never raw command text.
    "cli:version", "cli:interfaces", "cli:interface", "cli:ospf_neighbors",
    "cli:ospf3_neighbors", "cli:ospf6_neighbors", "cli:bgp_summary",
    "cli:bgp6_summary", "cli:ip_route", "cli:ipv6_route", "cli:route4",
    "cli:route6", "cli:arp", "cli:neigh", "cli:ipv6_neighbors",
    "cli:mac_table", "cli:switchport", "cli:acl_rules", "cli:acl_attach",
    "cli:spanning_tree", "cli:interface_transceiver", "cli:link_stats",
    "cli:addr", "snmp:get", "snmp:walk", "gnmi:get", "syslog:read",
    "dns:query", "probe:tcp_connect", "probe:trace", "source:read",
})


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("authorization times must be timezone-aware")
    return value.astimezone(timezone.utc)


def _canonical_ip(value: str) -> str:
    ip = ipaddress.ip_address(str(value))
    if ip.version == 6 and ip.ipv4_mapped is not None:
        # Canonicalize mapped IPv4 so it cannot bypass an IPv4 protected set.
        return str(ip.ipv4_mapped)
    return str(ip)


def _body(grant: TargetGrant | dict) -> dict:
    if isinstance(grant, TargetGrant):
        raw = dict(grant.__dict__)
    else:
        raw = dict(grant)
    raw.pop("digest", None)
    for key in ("issued_at", "expires_at"):
        value = raw.get(key)
        if isinstance(value, datetime):
            raw[key] = _utc(value).isoformat()
    return raw


def _digest(body: dict) -> str:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class TargetPolicy:
    """Authorize exact targets and mint expiring, tamper-evident grants."""

    def __init__(self, *, topology_id: str, snapshot: Callable[[str], TargetSnapshot | None],
                 protected_addresses: Iterable[str] = (), excluded_devices: Iterable[str] = ("R5",),
                 diagnostic_operations: Iterable[str] = DEFAULT_DIAGNOSTIC_OPERATIONS,
                 max_grant_seconds: int = 60, now: Callable[[], datetime] | None = None,
                 authorization_validator: Callable[[TargetRequest, TargetSnapshot, datetime], bool] | None = None,
                 audit: Callable[[dict], None] | None = None):
        if not topology_id or len(topology_id) > 128:
            raise ValueError("an exact topology_id is required")
        if not 1 <= int(max_grant_seconds) <= 300:
            raise ValueError("max_grant_seconds must be 1..300")
        self.topology_id = topology_id
        self._snapshot = snapshot
        self.protected = frozenset(_canonical_ip(v) for v in protected_addresses)
        self.excluded = frozenset(str(v) for v in excluded_devices)
        self.operations = frozenset(str(v) for v in diagnostic_operations)
        if not self.operations or any(not _OPERATION.fullmatch(v) for v in self.operations):
            raise ValueError("diagnostic operations must be fixed identifiers")
        self.max_grant_seconds = int(max_grant_seconds)
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._authorization_validator = authorization_validator
        self._audit = audit or (lambda _event: None)

    def _emit(self, request: TargetRequest, decision: Decision) -> None:
        # Deliberately excludes credentials, raw commands and authorization
        # contents.  The reference is hashed for correlation without disclosure.
        ref = hashlib.sha256(request.authorization_ref.encode()).hexdigest()[:16] if request.authorization_ref else ""
        self._audit({"event": "target_authorization", "principal": request.principal.name,
                     "principal_kind": request.principal.kind.value, "capability": request.capability.value,
                     "topology": request.topology_id, "device": request.device, "endpoint": request.endpoint,
                     "transport": request.transport, "operation_id": request.operation_id,
                     "authorization_ref_hash": ref, "allowed": decision.allowed, "code": decision.code})

    def decide(self, request: TargetRequest, *, at: datetime | None = None) -> tuple[Decision, TargetSnapshot | None]:  # pylint: disable=too-many-branches  # one flat fail-closed check per target-policy condition; each branch returns a distinct refusal
        now = _utc(at or self._now())
        reasons: list[str] = []
        if request.topology_id != self.topology_id:
            reasons.append("cross-topology request")
        if request.capability not in request.principal.permissions:
            reasons.append("principal lacks capability")
        if request.capability == Capability.APPLY_CHANGE and request.principal.kind != PrincipalKind.CHANGE_ENGINE:
            reasons.append("only the governed Change Engine may apply changes")
        if request.capability == Capability.PROPOSE_CHANGE:
            if request.endpoint or request.transport or request.port:
                reasons.append("change proposals do not open network connections")
            decision = Decision(not reasons, "ALLOWED" if not reasons else "CAPABILITY_REFUSED", tuple(reasons))
            self._emit(request, decision)
            return decision, None
        if request.capability == Capability.APPLY_CHANGE:
            # This policy is a boundary check, not a second change executor.
            reasons.append("execution must remain inside Change Engine eligibility, lock and rollback workflow")
            decision = Decision(False, "CHANGE_ENGINE_HANDOFF_REQUIRED", tuple(reasons))
            self._emit(request, decision)
            return decision, None
        if not request.device:
            reasons.append("device is required")
        target = self._snapshot(request.device) if request.device else None
        if target is None:
            reasons.append("device absent from authoritative inventory")
        if target is not None:
            if target.topology_id != self.topology_id or target.device != request.device:
                reasons.append("authoritative target identity/topology mismatch")
            if target.tenant != request.principal.tenant:
                reasons.append("cross-tenant request")
            if target.excluded or target.device in self.excluded or target.scope not in {"WRITABLE", "WRITABLE_RESTRICTED"}:
                reasons.append("device is excluded from managed scope")
            if target.revoked:
                reasons.append("target authorization is revoked")
            if request.capability == Capability.READ_DIAGNOSTIC:
                if target.identity_state != "VERIFIED":
                    reasons.append("device identity is not verified")
                if target.lifecycle_state != "IN_SERVICE":
                    reasons.append("device lifecycle is not in service")
                if target.admission_state not in {"ADMITTED", "LEGACY_PREEXISTING"}:
                    reasons.append("device is not admitted")
            elif request.capability == Capability.OBSERVE_IDENTITY:
                if target.lifecycle_state in {"DECOMMISSIONED", "WITHDRAWN", "RETIRED"}:
                    reasons.append("terminal device cannot be observed")
                if not target.identity_pin:
                    reasons.append("identity observation requires an enrolled pin")
        try:
            endpoint = _canonical_ip(request.endpoint)
        except ValueError:
            endpoint = ""
            reasons.append("endpoint must be an IP literal")
        if endpoint and endpoint in self.protected:
            reasons.append("VM host/management endpoint is protected")
        if target is not None and endpoint:
            exact = {_canonical_ip(v) for v in target.endpoints}
            approved = {_canonical_ip(v) for v in target.approved_path_endpoints}
            if endpoint not in exact:
                reasons.append("address substitution: endpoint is not authoritative for device")
            if request.capability == Capability.READ_DIAGNOSTIC and endpoint not in approved:
                reasons.append("endpoint has no current approved management path")
            if request.capability == Capability.OBSERVE_IDENTITY and endpoint not in approved:
                if not request.allow_legacy_identity_endpoint:
                    reasons.append("identity endpoint has no approved path")
        if not 1 <= int(request.port or 0) <= 65535:
            reasons.append("valid destination port is required")
        if request.transport.upper() not in {"SSH", "SNMP", "GNMI", "HTTPS", "DNS", "PROBE", "SOURCE"}:
            reasons.append("transport is not registered")
        if not _OPERATION.fullmatch(request.operation_id or "") or request.operation_id not in self.operations:
            reasons.append("operation is not in the fixed diagnostic registry")
        if not _AUTH_REF.fullmatch(request.authorization_ref or ""):
            reasons.append("digest-bound authorization reference is required")
        try:
            expires = _utc(request.authorization_expires_at) if request.authorization_expires_at else None
        except ValueError:
            expires = None
        if expires is None or expires <= now:
            reasons.append("authorization is absent or expired")
        if target is not None:
            if self._authorization_validator is None:
                reasons.append("authorization validator is unavailable")
            else:
                try:
                    if not self._authorization_validator(request, target, now):
                        reasons.append("authorization reference is not active for this principal and target")
                except Exception:  # pylint: disable=broad-exception-caught  # fail closed without exposing provider/DB detail
                    reasons.append("authorization validation failed")
        decision = Decision(not reasons, "ALLOWED" if not reasons else "TARGET_REFUSED", tuple(reasons))
        self._emit(request, decision)
        return decision, target

    def authorize(self, request: TargetRequest, *, at: datetime | None = None) -> TargetGrant:
        now = _utc(at or self._now())
        decision, target = self.decide(request, at=now)
        if not decision.allowed or target is None:
            raise AuthorizationRefused(decision.code, decision.reasons)
        auth_expiry = _utc(request.authorization_expires_at)  # decide() proved it exists
        expiry = min(auth_expiry, now + timedelta(seconds=self.max_grant_seconds))
        raw = {
            "grant_id": "tg-" + secrets.token_hex(12), "principal": request.principal.name,
            "principal_kind": request.principal.kind.value, "capability": request.capability.value,
            "principal_tenant": request.principal.tenant,
            "topology_id": request.topology_id, "device": request.device,
            "endpoint": _canonical_ip(request.endpoint), "port": int(request.port),
            "transport": request.transport.upper(), "operation_id": request.operation_id,
            "authorization_ref": request.authorization_ref, "target_revision": target.revision,
            "issued_at": now, "expires_at": expiry,
        }
        return TargetGrant(digest=_digest(_body(raw)), **raw)

    def revalidate(self, grant: TargetGrant, *, operation_id: str | None = None,
                   endpoint: str | None = None, at: datetime | None = None) -> TargetGrant:
        now = _utc(at or self._now())
        if not secrets.compare_digest(grant.digest, _digest(_body(grant))):
            raise AuthorizationRefused("GRANT_TAMPERED")
        if grant.expires_at <= now:
            raise AuthorizationRefused("GRANT_EXPIRED")
        if operation_id is not None and operation_id != grant.operation_id:
            raise AuthorizationRefused("OPERATION_SUBSTITUTION")
        if endpoint is not None and _canonical_ip(endpoint) != grant.endpoint:
            raise AuthorizationRefused("ADDRESS_SUBSTITUTION")
        current = self._snapshot(grant.device)
        if current is None or current.revision != grant.target_revision or current.revoked:
            raise AuthorizationRefused("TARGET_AUTHORIZATION_CHANGED")
        if current.topology_id != grant.topology_id or grant.endpoint not in {_canonical_ip(v) for v in current.endpoints}:
            raise AuthorizationRefused("TARGET_AUTHORIZATION_CHANGED")
        if self._authorization_validator is None:
            raise AuthorizationRefused("AUTHORIZATION_VALIDATOR_UNAVAILABLE")
        principal = Principal(grant.principal, PrincipalKind(grant.principal_kind),
                              frozenset({Capability(grant.capability)}), tenant=grant.principal_tenant)
        request = TargetRequest(principal=principal, capability=Capability(grant.capability), topology_id=grant.topology_id,
                                device=grant.device, endpoint=grant.endpoint, port=grant.port, transport=grant.transport,
                                operation_id=grant.operation_id, authorization_ref=grant.authorization_ref,
                                authorization_expires_at=grant.expires_at)
        try:
            active = self._authorization_validator(request, current, now)
        except Exception as exc:
            raise AuthorizationRefused("AUTHORIZATION_VALIDATION_FAILED") from exc
        if not active:
            raise AuthorizationRefused("AUTHORIZATION_REVOKED")
        if grant.capability == Capability.READ_DIAGNOSTIC.value and grant.endpoint not in {
                _canonical_ip(v) for v in current.approved_path_endpoints}:
            raise AuthorizationRefused("MANAGEMENT_PATH_CHANGED")
        return grant

