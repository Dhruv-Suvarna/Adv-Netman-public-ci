"""What a maintenance operation may never touch.  Pure: operations and the scope in, violations out.

Two boundaries, checked when the plan is built and again by the executor immediately before every write:

* the writable managed scope: every device an operation writes to must be in it (``config_workbench.scope``: NetBox
  marks it IaC-managed AND the inventory gives it a supported platform).  R5 and the web server are outside it.
* the management plane: VLAN 200 and every management interface.  No operation may name them, and a kernel cover may
  never leave through a management interface.  A plan that does is refused; it is never "fixed up".

* the maintenance primitives: an operation may carry only the statements of the existing drain mechanisms -- the IS-IS
  metric of an interface, the metric of an existing route map, and the switch's temporary /33 shield halves of the
  access aggregate (``route_shield.lab.steer``).  Anything else -- a static route to any other prefix, a core kernel
  cover, an interface shutdown, a new route map or redistribution -- would build a path the topology does not have, and
  is refused.

A violation is a refusal, never a warning: there is no argument that allows one.
"""

from __future__ import annotations

import ipaddress
import re

from ..route_shield import lab

MANAGEMENT_VLAN = 200
PROTECTED_SCOPE = "PROTECTED_SCOPE_VIOLATION"
OUTSIDE_SCOPE = "TARGET_OUTSIDE_WRITABLE_SCOPE"
NOT_A_PRIMITIVE = "NOT_A_MAINTENANCE_PRIMITIVE"
SHIELD_PREFIXES = frozenset(lab._halves(lab.AGGREGATE))      # the only static routes a maintenance may name (temporarily)

_PRIMITIVES = (
    re.compile(r"^interface (Ethernet|Port-Channel)\d+(/\d+)*$"),       # the header of the uplink whose IS-IS metric changes
    re.compile(r"^isis metric \d{1,8}$"),
    re.compile(r"^route-map [A-Za-z0-9_-]{1,63} permit \d{1,5}$"),        # the header of an existing route map
    re.compile(r"^set metric \d{1,8}$"),
    re.compile(r"^no set metric$"),
)
_STATIC = re.compile(r"^(no )?ipv6 route (\S+) (\S+)( \d{1,3})?$")

_VLAN = re.compile(rf"\bvlan\s*{MANAGEMENT_VLAN}\b", re.IGNORECASE)                    # "interface Vlan200", "vlan 200", "access vlan 200"
_VLAN_LIST = re.compile(r"\ballowed\s+vlan\b(.*)$", re.IGNORECASE)                       # "switchport trunk allowed vlan 10,20,200"
_MANAGEMENT = re.compile(r"\b(management\s*\d+(/\d+)*|ma\d+(/\d+)*|mgmt\d*)\b", re.IGNORECASE)
_DEV = re.compile(r"\bdev\s+(\S+)")


def _in_vlan_list(text: str) -> bool:
    for part in text.replace(" ", "").replace("add", "").replace("remove", "").split(","):
        bounds = part.split("-")
        try:
            low, high = int(bounds[0]), int(bounds[-1])
        except ValueError:
            continue
        if low <= MANAGEMENT_VLAN <= high:
            return True
    return False


def line_violation(line: str, management_interfaces=()) -> str:
    """Why ``line`` touches the management plane, or ''."""
    text = str(line).strip()
    if _VLAN.search(text):
        return f"names VLAN {MANAGEMENT_VLAN}"
    listed = _VLAN_LIST.search(text)
    if listed and _in_vlan_list(listed.group(1)):
        return f"changes a VLAN list that contains VLAN {MANAGEMENT_VLAN}"
    if _MANAGEMENT.search(text):
        return "names a management interface"
    lowered = text.lower()
    for name in management_interfaces:
        if name and re.search(rf"(^|\s){re.escape(str(name).lower())}(\s|$)", lowered):
            return f"names the management interface {name}"
    for dev in _DEV.findall(text):
        if dev.lower() in {str(n).lower() for n in management_interfaces} or dev.lower() == "eth0":
            return f"leaves through the management interface {dev}"
    return ""


def statement_violation(line: str) -> str:
    """Why ``line`` is not a statement of an existing drain mechanism, or ''."""
    text = str(line).strip()
    if any(pattern.fullmatch(text) for pattern in _PRIMITIVES):
        return ""
    static = _STATIC.fullmatch(text)
    if static:
        try:
            ipaddress.ip_address(static.group(3))
        except ValueError:
            return "a static route that does not name a next-hop address"
        return "" if static.group(2) in SHIELD_PREFIXES else f"a static route to {static.group(2)}, which is not a shield half of {lab.AGGREGATE}"
    return "not a statement of an existing drain mechanism"


WRITABLE_PLATFORMS = frozenset({"ceos"})                     # the platform whose executor and statement shapes were proven


def violations(ops, *, writable, management_interfaces: dict | None = None, platforms: dict | None = None) -> list[str]:
    """Every reason the operations ``ops`` may not run.  ``writable``: the device names of the writable managed scope.
    ``management_interfaces``: device -> its management interface names (from the inventory).  ``platforms``: device ->
    its inventory platform; a device whose platform is known and is not one the maintenance statements were proven on
    is refused (an FRR core router is never written)."""
    management_interfaces, platforms = management_interfaces or {}, platforms or {}
    allowed, found = set(writable), []
    for op in ops:
        if op.device not in allowed:
            found.append(f"{OUTSIDE_SCOPE}: {op.key} writes to {op.device}, which is not in the writable managed scope")
        platform = platforms.get(op.device)
        if platform and platform not in WRITABLE_PLATFORMS:
            found.append(f"{NOT_A_PRIMITIVE}: {op.key} writes to {op.device} ({platform}); maintenance statements exist for {', '.join(sorted(WRITABLE_PLATFORMS))} only")
        if getattr(op, "cover", None) is not None:
            found.append(f"{NOT_A_PRIMITIVE}: {op.key} on {op.device} is a core kernel cover, a migration guard that creates a route the topology does not have")
        for line in (*op.lines, *op.inverse):
            why = line_violation(line, management_interfaces.get(op.device, ()))
            if why:
                found.append(f"{PROTECTED_SCOPE}: {op.key} on {op.device} {why}: {str(line).strip()[:120]}")
                continue
            why = statement_violation(line)
            if why:
                found.append(f"{NOT_A_PRIMITIVE}: {op.key} on {op.device}: {why}: {str(line).strip()[:120]}")
    return found
