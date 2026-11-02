"""What this lab's access design offers for each device: its role and the existing drain mechanisms.

Nothing is invented here.  A boundary router (R1, R2) drains in two directional components: northbound by the existing
IS-IS access-side steering, southbound by the existing OSPFv3 core-side steering.  IPv4 runs on RIP and has no proven
drain.  An access switch (S1, S2) has single-homed hosts attached: that is allowed topology, and it has no mechanism
that moves an attached host's traffic elsewhere.
"""

from __future__ import annotations

from core.services.route_shield import readiness as shield_readiness

from . import model

BOUNDARY_ROUTER, ACCESS_SWITCH = "BOUNDARY_ROUTER", "ACCESS_SWITCH"
ROLES = {"R1": BOUNDARY_ROUTER, "R2": BOUNDARY_ROUTER, "S1": ACCESS_SWITCH, "S2": ACCESS_SWITCH}

ISIS_NORTHBOUND = "ISIS_ACCESS_METRIC_STEER"
OSPFV3_SOUTHBOUND = "OSPFV3_CORE_STEER"
RIP_IPV4 = "RIP_IPV4_DRAIN"


# FALLBACK ONLY (tests, and a caller with no live observation): the collector derives the role, the access relations and
# the intersecting devices from the cabling and from what the devices report (``topology.py``), and hands them in.
INTERSECTS = {"R1": ("R2", "S1"), "R2": ("R1", "S2"), "S1": ("R1", "S2"), "S2": ("R2", "S1")}


def intersecting(device: str) -> tuple[str, ...]:
    role_of(device)
    return INTERSECTS[device]


def role_of(device: str) -> str:
    try:
        return ROLES[device]
    except KeyError:
        raise model.MaintenanceError("DEVICE_NOT_SUPPORTED", f"{device} has no maintenance policy") from None


def required_cells(device: str) -> tuple[tuple[str, str], ...]:
    """Every (family, direction) whose traffic must be classified before a verdict exists for ``device``."""
    role_of(device)
    return tuple((family, direction) for family in model.FAMILIES for direction in model.DIRECTIONS)


def mechanisms(device: str, shield_states: dict | None = None) -> dict:
    """(family, direction) -> Mechanism, for the cells that have one.  A cell without an entry has no way to move."""
    return mechanisms_for(role_of(device), shield_readiness.READINESS if shield_states is None else shield_states)


def mechanisms_for(role: str, states: dict) -> dict:
    """The existing drain mechanisms of a device of ``role``.  Only a boundary router has any."""
    if role != BOUNDARY_ROUTER:
        return {}
    north = states.get(shield_readiness.ISIS_METRIC_STEER, model.NOT_READY)
    south = states.get(shield_readiness.OSPFV3_EXTERNAL_METRIC_STEER, model.NOT_READY)
    return {
        (model.IPV6, model.NORTHBOUND): model.Mechanism(ISIS_NORTHBOUND, model.IPV6, model.NORTHBOUND,
                                                        "existing IS-IS access-side metric steering", north),
        (model.IPV6, model.SOUTHBOUND): model.Mechanism(OSPFV3_SOUTHBOUND, model.IPV6, model.SOUTHBOUND,
                                                        "existing OSPFv3 core-side steering", south),
        # IPv4 runs on RIP: no drain of it is proven, so the cell blocks only when it carries active production traffic.
        **{(model.IPV4, direction): model.Mechanism(RIP_IPV4, model.IPV4, direction, "IPv4 RIP drain (no proven mechanism)", model.NOT_READY)
           for direction in model.DIRECTIONS},
    }
