"""The cEOS operations of a decommissioning and of its restoration, derived from the device's own sanitized running configuration.

Every operation is one ``isolation.transaction`` operation with its exact inverse, so the governed transaction can prove each
step and undo it newest first:

    transition   ADD   ``max-metric router-lsa`` under each OSPFv2 / OSPFv3 process: OSPF's own stub-router function moves
                       transit traffic onto the alternate paths the routing domain already has (no new drain mechanism)
    removal      ADD   ``shutdown`` on every production interface that is up (never the management interface)
                 REMOVE each routing process block (OSPFv2, OSPFv3, RIP, BGP); its restore path is the block as it stood
    restore      the inverse: re-add the routing blocks from the snapshot, then ``no shutdown`` the interfaces the
                 decommissioning shut (REMOVE of the ``shutdown`` statement)

Nothing is inferred from names: interfaces and processes come from the configuration text.  Management interfaces are given by
the caller (from the device's management address) and are never touched.  Unknown or unsupported constructs are reported as
findings and refuse the plan rather than being skipped silently.
"""

from __future__ import annotations

import re

PLATFORM = "arista_ceos"
ROUTING = (re.compile(r"router ospf \d+( vrf \S+)?"), re.compile(r"ipv6 router ospf \d+( vrf \S+)?"), re.compile(r"router ospfv3( vrf \S+)?"),
           re.compile(r"router rip"), re.compile(r"router bgp \d+(\.\d+)?"), re.compile(r"router isis \S+"))
OSPF = (re.compile(r"router ospf \d+"), re.compile(r"ipv6 router ospf \d+"))
PRODUCTION_INTERFACE = re.compile(r"interface (Ethernet\d+(/\d+)*|Port-Channel\d+|Vlan\d+)")
COST_OUT = "max-metric router-lsa"


class PlanError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, str(detail)[:300]


def blocks(text: str) -> dict[str, list[str]]:
    """{top-level header: [header, child lines ...]} in configuration order (comments and ``end`` dropped)."""
    found, header = {}, None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("!") or line.strip() == "end":
            continue
        if not line.startswith(" "):
            header = line.strip()
            found.setdefault(header, [header])
        elif header is not None:
            found[header].append(line)
    return found


def paths(lines: list[str]) -> list[str]:
    """The structural paths (``header > child``) of one block, as ``config_workbench.structure.config_paths`` names them."""
    out, header = [], ""
    for line in lines:
        if not line.startswith(" "):
            header = line.strip()
            out.append(header)
        else:
            out.append(f"{header} > {line.strip()}")
    return out


def op(key: str, kind: str, lines: list[str], inverse: list[str], present: list[str], description: str) -> dict:
    return {"key": key, "kind": kind, "lines": list(lines), "inverse": list(inverse), "paths": list(present), "description": description}


def routing_processes(text: str) -> list[str]:
    return [header for header in blocks(text) if any(p.fullmatch(header) for p in ROUTING)]


def ospf_processes(text: str) -> dict[str, str]:
    """{family: header} of the OSPF processes (IPV4: OSPFv2, IPV6: OSPFv3) the transition can cost out."""
    found = {}
    for header in blocks(text):
        if OSPF[0].fullmatch(header):
            found.setdefault("IPV4", header)
        elif OSPF[1].fullmatch(header):
            found.setdefault("IPV6", header)
    return found


def interface_address(lines: list[str]) -> list[str]:
    return [line.split()[2].split("/")[0] for line in lines if re.match(r"\s+ipv?6? address \S+", line) and len(line.split()) >= 3]


def management_interfaces(text: str, addresses) -> list[str]:
    """The interfaces that hold one of the device's management ``addresses`` (or sit in a management VRF): never decommissioned."""
    wanted = {str(a).split("/")[0] for a in addresses or () if a}
    found = []
    for header, lines in blocks(text).items():
        if not header.startswith("interface "):
            continue
        name = header.split(" ", 1)[1]
        if name.startswith("Management") or any(line.strip().startswith("vrf MGMT") for line in lines) \
                or wanted.intersection(interface_address(lines)):
            found.append(name)
    return found


def production_interfaces(text: str, management: list[str]) -> list[str]:
    """Routed / switched production interfaces that are currently administratively up (not ``shutdown``)."""
    out = []
    for header, lines in blocks(text).items():
        if not PRODUCTION_INTERFACE.fullmatch(header):
            continue
        name = header.split(" ", 1)[1]
        if name in management or any(line.strip() == "shutdown" for line in lines[1:]):
            continue
        out.append(name)
    return out


def render_decommission(text: str, *, management_addresses, transition: bool) -> dict:
    """{"transition": [ops], "removal": [ops], "facts": {...}} for one device.  Raises PlanError when nothing safe can be planned."""
    sections = blocks(text)
    management = management_interfaces(text, management_addresses)
    if not management:
        raise PlanError("MANAGEMENT_INTERFACE_UNKNOWN", "the device's management address is on no interface; NMAS would cut itself off")
    ospf = ospf_processes(text)
    transition_ops = []
    if transition:
        if not ospf:
            raise PlanError("TRANSITION_MECHANISM_UNAVAILABLE", "no OSPF process to cost out")
        for family, header in sorted(ospf.items()):
            if any(line.strip() == COST_OUT for line in sections[header][1:]):
                raise PlanError("TRANSITION_ALREADY_PRESENT", f"{header} already holds {COST_OUT}")
            transition_ops.append(op(f"cost-out-{family.lower()}", "ADD", [header, f"   {COST_OUT}"], [header, f"   no {COST_OUT}"],
                                     [f"{header} > {COST_OUT}"], f"{family}: OSPF stub-router cost-out ({header})"))
    removal = []
    for name in production_interfaces(text, management):
        header = f"interface {name}"
        removal.append(op(f"shutdown-{name}", "ADD", [header, "   shutdown"], [header, "   no shutdown"], [f"{header} > shutdown"],
                          f"{name}: administratively down"))
    for header in routing_processes(text):
        lines = list(sections[header])
        if transition and header in ospf.values():
            lines.append(f"   {COST_OUT}")          # the block as it stands after the transition step (compensation restores exactly it)
        removal.append(op(f"remove-{header.replace(' ', '-')}", "REMOVE", [f"no {header}"], lines, [header], f"remove {header}"))
    if not removal:
        raise PlanError("NOTHING_TO_DECOMMISSION", "no production interface is up and no routing process is configured")
    return {"transition": transition_ops, "removal": removal,
            "facts": {"management_interfaces": management, "ospf": ospf, "routing": routing_processes(text),
                      "interfaces": [o["key"][len("shutdown-"):] for o in removal if o["key"].startswith("shutdown-")]}}


def render_restore(snapshot_text: str, current_text: str, *, management_addresses) -> dict:
    """The operations that bring the decommissioned configuration back from ``snapshot_text`` onto a device now holding
    ``current_text``: the routing blocks the snapshot had and the device lacks, then ``no shutdown`` of each production interface
    the snapshot had up and the device has shut.  Conflicts (a block present but different) refuse the plan."""
    snap, now = blocks(snapshot_text), blocks(current_text)
    management = management_interfaces(current_text, management_addresses)
    ops, conflicts = [], []
    for header in routing_processes(snapshot_text):
        if header in now:
            if now[header] != snap[header]:
                conflicts.append(f"{header} exists and differs from the snapshot")
            continue
        lines = [line for line in snap[header] if line.strip() != COST_OUT]
        ops.append(op(f"restore-{header.replace(' ', '-')}", "ADD", lines, [f"no {header}"], paths(lines), f"restore {header}"))
    for name in production_interfaces(snapshot_text, management):
        header = f"interface {name}"
        current = now.get(header)
        if current is None:
            conflicts.append(f"{name} no longer exists")
            continue
        if [line for line in current[1:] if line.strip() != "shutdown"] != [line for line in snap[header][1:] if line.strip() != "shutdown"]:
            conflicts.append(f"{name} differs from the snapshot")
            continue
        if any(line.strip() == "shutdown" for line in current[1:]):
            ops.append(op(f"no-shutdown-{name}", "REMOVE", [header, "   no shutdown"], [header, "   shutdown"], [f"{header} > shutdown"],
                          f"{name}: administratively up"))
    if conflicts:
        raise PlanError("RESTORE_CONFLICT", "; ".join(conflicts)[:300])
    if not ops:
        raise PlanError("NOTHING_TO_RESTORE", "the device already holds the snapshot's routing and interface state")
    return {"operations": ops, "facts": {"management_interfaces": management}}


def render_recovery(plan_ops: list[dict], present_paths) -> dict:
    """Bring a device that a decommission run left part-way (a lost session, a crash) back to its baseline, from the run's OWN frozen
    operations and the paths the device holds NOW.  Newest operation first, each only where its effect is on the device:

        ADD     (cost-out, shutdown) all its paths present  -> REMOVE its lines again (``no ...``), restore lines = the ADD lines
        REMOVE  (routing process)    all its paths absent   -> ADD the captured block back, inverse = the removal

    A partly present effect is a conflict: something other than this run changed the device, and nothing is planned.  Every
    recovery operation is the exact inverse the original plan already carried; the governed postcheck then requires the baseline
    configuration digest itself."""
    present = set(present_paths)
    ops, conflicts = [], []
    for original in reversed(list(plan_ops)):
        wanted = list(original["paths"])
        found = [path for path in wanted if path in present]
        if original["kind"] == "ADD":
            if not found:
                continue
            if len(found) != len(wanted):
                conflicts.append(f"{original['key']}: partly present")
                continue
            ops.append(op(f"undo-{original['key']}", "REMOVE", list(original["inverse"]), list(original["lines"]), wanted,
                          f"undo: {original['description']}"))
            present -= set(wanted)
        else:
            if len(found) == len(wanted):
                continue
            if found:
                conflicts.append(f"{original['key']}: partly present")
                continue
            restored = list(original["inverse"])
            ops.append(op(f"undo-{original['key']}", "ADD", restored, list(original["lines"]), paths(restored),
                          f"undo: {original['description']}"))
            present |= set(paths(restored))
    if conflicts:
        raise PlanError("RECOVERY_CONFLICT", "; ".join(conflicts)[:300])
    return {"operations": ops}
