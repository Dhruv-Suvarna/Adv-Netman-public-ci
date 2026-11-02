"""Plan-derived affected-device scope (deterministic; never from hostname patterns).

A precheck must not demand a perfect fleet: an unrelated telemetry problem on S4 must not block a change to R1.  The
scope is built ONLY from persisted Phase-13/14 facts:

* TARGET  every device that owns a plan Configlet (blocking policy applies).  Cross-device Configlet dependency edges
          only ever join TARGET devices; they are recorded as ``reasons`` so an operator sees why order matters.
* PEER    a device that is NOT a target but was linked to one by the pinned validation: a resolved BGP peer
          (``BGP_PEER_RESOLVED.peer_device``), an FHRP domain member (``FHRP_DOMAIN.devices``), or a finding's
          ``related_devices``.  Peers supply postcheck evidence; their health never blocks (WARN at most).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ... import models
from . import inventory
from .codes import Role


@dataclass
class ScopeDevice:
    name: str
    role: str
    reasons: list = field(default_factory=list)
    managed: bool = True


@dataclass
class AffectedScope:
    devices: dict = field(default_factory=dict)

    @property
    def roles(self) -> dict:
        return {name: device.role for name, device in self.devices.items()}

    def names(self, role: str | None = None) -> list[str]:
        return sorted(n for n, d in self.devices.items() if role is None or d.role == role)

    def to_dict(self) -> dict:
        return {"devices": [{"device": d.name, "role": d.role, "managed": d.managed, "reasons": sorted(d.reasons)}
                            for _, d in sorted(self.devices.items())]}


def _add(scope: AffectedScope, name: str, role: str, reason: str, managed: set) -> None:
    device = scope.devices.get(name)
    if device is None:
        device = scope.devices[name] = ScopeDevice(name=name, role=role, managed=name in managed)
    if reason not in device.reasons:
        device.reasons.append(reason)


def build_affected_scope(plan) -> AffectedScope:
    """The deterministic affected-device scope of a plan (see the module docstring)."""
    managed = set(inventory.managed_devices())
    scope = AffectedScope()
    configlets = list(plan.configlets.order_by("sequence"))
    targets = {c.target_device for c in configlets}
    for name in sorted(targets):
        _add(scope, name, Role.TARGET, "DEPLOY_TARGET", managed)

    by_id = {c.pk: c for c in configlets}
    for edge in models.ConfigletDependency.objects.filter(configlet__plan=plan):
        dependent, dependency = by_id.get(edge.configlet_id), by_id.get(edge.depends_on_id)
        if dependent and dependency and dependent.target_device != dependency.target_device:
            _add(scope, dependent.target_device, Role.TARGET, f"DEPENDS_ON:{dependency.target_device}", managed)
            _add(scope, dependency.target_device, Role.TARGET, f"DEPENDED_ON_BY:{dependent.target_device}", managed)

    run = plan.validation_run
    for fact in run.derived_facts or []:
        kind = fact.get("type")
        if kind == "BGP_PEER_RESOLVED" and fact.get("device") in targets and fact.get("peer_device"):
            if fact["peer_device"] not in targets:
                _add(scope, fact["peer_device"], Role.PEER, f"BGP_PEER_OF:{fact['device']}", managed)
        elif kind == "FHRP_DOMAIN":
            members = set(fact.get("devices") or [])
            if members & targets:
                for name in sorted(members - targets):
                    _add(scope, name, Role.PEER, "FHRP_DOMAIN_MEMBER", managed)
    for finding in (run.report or {}).get("findings", []):
        if finding.get("device") in targets:
            for name in finding.get("related_devices") or []:
                if name not in targets:
                    _add(scope, name, Role.PEER, f"VALIDATION_RELATED:{finding.get('code')}", managed)
    return scope
