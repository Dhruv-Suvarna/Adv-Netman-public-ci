"""A shielded route transition as validated data.  An invalid transition builds nothing.

The shield is a TEMPORARY static cover around one route replacement.  cEOS-lab replaces a route by deleting it and then
installing the new one; a packet forwarded in between has no route.  Two shapes are proven (docs/V2_LOSSLESS_ROUTE_SHIELD.md):

* ``MORE_SPECIFIC_PAIR``   the two halves of the protected prefix.  They carry the traffic for as long as they exist.
* ``LESS_SPECIFIC_COVER``  one shorter prefix containing the protected prefix.  It forwards only during the replacement gap,
                           so installing or removing it never touches a route that is carrying traffic.

A cover longer than /64 is refused: deleting an in-use /65 dropped packets on every attempt.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..execution.executors.base import ConfigletSpec
from ..health.requirements import Requirement, expand

MORE_SPECIFIC, LESS_SPECIFIC = "MORE_SPECIFIC_PAIR", "LESS_SPECIFIC_COVER"
STATIC, ISIS = "static", "isis"
PLATFORM = "arista_ceos"
SHIELD_OBJECT = "route_shield"          # an executor CONFIG_BLOCK type: undone by the inverse proven against the running config


class ShieldError(ValueError):
    """The transition is not a shape that was proven.  Nothing is planned from it."""


@dataclass(frozen=True)
class Owner:
    source: str                      # STATIC or ISIS
    interface: str
    next_hop: str = ""               # static only


@dataclass(frozen=True)
class Step:
    """One configuration step of the protected change, with its exact inverse."""

    label: str
    lines: tuple[str, ...]
    remove_paths: tuple[str, ...] = ()       # set => an intentional removal, verified by these paths being absent
    restore: tuple[str, ...] = ()            # the lines that put a removal back
    object_type: str = SHIELD_OBJECT         # additive steps only
    wait_new_owner: bool = False             # the next step is only safe once the new owner forwards the protected prefixes


@dataclass(frozen=True)
class Transition:
    key: str
    kind: str                        # a readiness key
    device: str
    protected: tuple[str, ...]       # the prefixes whose forwarding entry is replaced
    old: Owner
    new: Owner
    shield_kind: str
    shield_prefixes: tuple[str, ...]
    shield_next_hop: str
    shield_interface: str
    steps: tuple[Step, ...]
    settle_seconds: float = 60.0
    upstream: tuple[str, ...] = ()   # routers that forward toward ``device``: each must hold a cover of every protected prefix
    via_peer: str = ""               # the shield hands the traffic to this device, which must forward it onward and not back
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self):
        if self.shield_kind not in (MORE_SPECIFIC, LESS_SPECIFIC) or not self.protected or not self.shield_prefixes or not self.steps:
            raise ShieldError(f"{self.key}: incomplete transition.")
        for owner in (self.old, self.new):
            if owner.source not in (STATIC, ISIS) or not owner.interface:
                raise ShieldError(f"{self.key}: an owner needs a known source and an interface.")
        if any(name.lower().startswith(("management", "ma")) for name in (self.shield_interface, self.old.interface, self.new.interface)):
            raise ShieldError(f"{self.key}: the management interface can never carry production traffic.")
        try:
            hop = ipaddress.ip_address(self.shield_next_hop)
            protected = [ipaddress.ip_network(p) for p in self.protected]
            shield = [ipaddress.ip_network(p) for p in self.shield_prefixes]
        except ValueError as exc:
            raise ShieldError(f"{self.key}: {exc}") from None
        if hop.version != 6 or hop.is_link_local or any(n.version != 6 for n in (*protected, *shield)):
            raise ShieldError(f"{self.key}: the shield is an IPv6 static route to a global next hop.")
        if any(n.prefixlen > 64 for n in shield):
            raise ShieldError(f"{self.key}: a cover longer than /64 is not loss-free and is refused.")
        if self.shield_kind == MORE_SPECIFIC:
            for prefix in protected:
                if sorted(n for n in shield if n.subnet_of(prefix)) != sorted(prefix.subnets(prefixlen_diff=1)):
                    raise ShieldError(f"{self.key}: {prefix} needs exactly its two halves as the shield.")
            if any(not any(n.subnet_of(p) for p in protected) for n in shield):
                raise ShieldError(f"{self.key}: a shield route covers nothing that is protected.")
        else:
            for prefix in protected:
                if sum(1 for n in shield if prefix.subnet_of(n) and n.prefixlen < prefix.prefixlen) != 1:
                    raise ShieldError(f"{self.key}: {prefix} needs exactly one shorter cover.")
            if any(sum(1 for p in protected if p.subnet_of(n)) < 1 for n in shield):
                raise ShieldError(f"{self.key}: a cover contains nothing that is protected.")

    # -- what the executor is asked to do ---------------------------------------------------------------------------
    def shield_lines(self) -> tuple[str, ...]:
        return tuple(f"ipv6 route {prefix} {self.shield_next_hop}" for prefix in self.shield_prefixes)

    def _spec(self, index: int, tag: str, lines, *, object_type=SHIELD_OBJECT, removal=None) -> ConfigletSpec:
        if removal is None:
            return ConfigletSpec(f"RS-{self.key}-{index}-{tag}", index, self.device, PLATFORM, object_type, "CREATE_DEFINE", tuple(lines))
        return ConfigletSpec(f"RS-{self.key}-{index}-{tag}", index, self.device, PLATFORM, "config_removal_delete", "REMOVE_DELETE", tuple(lines),
                             {"absent_paths": list(removal["absent_paths"])}, origin="REMOVAL", removal=removal)

    def install_spec(self) -> ConfigletSpec:
        return self._spec(1, "shield-install", self.shield_lines())

    def step_specs(self) -> list[ConfigletSpec]:
        specs = []
        for index, step in enumerate(self.steps, 10):
            removal = None
            if step.remove_paths:
                removal = {"item": step.label, "absent_paths": list(step.remove_paths), "restorable": bool(step.restore), "restore_lines": list(step.restore)}
            specs.append(self._spec(index, step.label, step.lines, object_type=step.object_type, removal=removal))
        return specs

    def remove_spec(self) -> ConfigletSpec:
        lines = self.shield_lines()
        return self._spec(90, "shield-remove", [f"no {line}" for line in lines],
                          removal={"item": "temporary route shield", "absent_paths": list(lines), "restorable": True, "restore_lines": list(lines)})

    # -- what must be observed --------------------------------------------------------------------------------------
    def _need(self, stage: str, kind: str, label: str, **expected) -> Requirement:
        return Requirement(cfg_id=f"RS-{self.key}-{stage}", device=self.device, kind=kind, label=f"{self.device} {label}",
                           expected=expected, check_types=expand(kind, expected))

    def _owned(self, stage: str, owner: Owner) -> list[Requirement]:
        if owner.source == ISIS:
            return [self._need(stage, "ISIS_ROUTE_INTENDED", f"{p} by IS-IS via {owner.interface}", prefix=p, interfaces=[owner.interface]) for p in self.protected]
        return [self._need(stage, "ROUTE_INTENDED", f"{p} static via {owner.interface}", prefix=p, next_hop=owner.next_hop,
                           exit_interface=owner.interface) for p in self.protected] + \
               [self._need(stage, "ISIS_ROUTE_INTENDED", f"{p} not owned by IS-IS", prefix=p, present=False) for p in self.protected]

    def shield_requirements(self) -> list[Requirement]:
        return [self._need("shield", "ROUTE_INTENDED", f"shield {p}", prefix=p, next_hop=self.shield_next_hop, exit_interface=self.shield_interface)
                for p in self.shield_prefixes]

    def old_requirements(self) -> list[Requirement]:
        return self._owned("original", self.old)

    def new_requirements(self) -> list[Requirement]:
        return self._owned("transition", self.new)
