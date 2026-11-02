"""Traffic-aware readiness.  SAFE DRAIN = production traffic moved away AND the alternate healthy where one is needed
AND zero observed production loss AND no critical dependency stranded.

The verdict is formed per address family and direction, from the flows observed there.  There is no device-level
"redundant" flag: a cell with no active production traffic is clear whether or not another path exists, and a cell
with active production traffic is blocked unless an existing mechanism for exactly that cell is READY.
"""

from __future__ import annotations

from . import model, policy

ALL_CELLS = tuple((family, direction) for family in model.FAMILIES for direction in model.DIRECTIONS)
CLEAR, DRAINABLE, BLOCKED = "CLEAR", "DRAINABLE", "BLOCKED"

TRAFFIC_UNKNOWN = "PRODUCTION_TRAFFIC_UNKNOWN"
NO_LOSSLESS_DRAIN = "ACTIVE_TRAFFIC_NO_LOSSLESS_DRAIN"
MECHANISM_NOT_READY = "DRAIN_MECHANISM_NOT_READY"
ALTERNATE_UNHEALTHY = "ALTERNATE_PATH_UNHEALTHY"
DEPENDENCY_STRANDED = "CRITICAL_DEPENDENCY_STRANDED"


def _workloads(flows) -> tuple[str, ...]:
    return tuple(sorted({flow.workload for flow in flows}))


def evaluate(request: model.Request, flows, dependencies=(), *, alternates: dict | None = None, mechanisms: dict | None = None) -> model.Report:
    """``alternates`` maps (family, direction) to True / False / None (health of the path the traffic would move to).
    ``mechanisms`` defaults to the device's policy; a collector hands in the ones it derived.  Flows of other traffic
    classes never block; they are noted.  A flow whose derived path avoids the device (``on_device`` False) is classified
    and irrelevant.  A cell that has a READY mechanism and a healthy alternate is drained even while its traffic is
    quiet (``preventive``): the traffic must not find the device again while it is in maintenance."""
    device = request.device
    available = policy.mechanisms(device) if mechanisms is None else mechanisms
    alternates = alternates or {}
    report = model.Report(device)
    for family, direction in policy.required_cells(device) if mechanisms is None else ALL_CELLS:
        classified = [f for f in flows if f.cell == (family, direction) and f.traffic_class == model.PRODUCTION]
        production = [f for f in classified if f.on_device is not False]
        unknown = [f for f in production if f.activity == model.UNKNOWN]
        active = [f for f in production if f.activity == model.ACTIVE]
        cell = {"verdict": CLEAR, "mechanism": None, "active": _workloads(active), "reasons": []}

        def block(code, blocking, detail=""):
            cell["verdict"] = BLOCKED
            cell["reasons"].append(code)
            report.blockers.append(model.Finding(code, family, direction, model.PRODUCTION, _workloads(blocking), detail))

        if not classified:
            block(TRAFFIC_UNKNOWN, (), "no production flow of this family and direction was classified")
        elif unknown:
            block(TRAFFIC_UNKNOWN, unknown, "activity not established")
        if active:
            mechanism = available.get((family, direction))
            if mechanism is None:
                block(NO_LOSSLESS_DRAIN, active, "no existing mechanism moves this traffic; quiesce the workload to proceed")
            else:
                cell["mechanism"] = mechanism.key
                if mechanism.state != model.READY:
                    block(MECHANISM_NOT_READY, active, f"{mechanism.key} is {mechanism.state}")
                if mechanism.needs_alternate and alternates.get((family, direction)) is not True:
                    block(ALTERNATE_UNHEALTHY, active, "the path the traffic would move to is not verified healthy")
                if cell["verdict"] != BLOCKED:
                    cell["verdict"] = DRAINABLE
        elif cell["verdict"] == CLEAR and any(f.on_device is True for f in production):
            mechanism = available.get((family, direction))
            if mechanism is not None and mechanism.state == model.READY and alternates.get((family, direction)) is True:
                cell.update(verdict=DRAINABLE, mechanism=mechanism.key, preventive=True)
        report.cells[(family, direction)] = cell
    for flow in flows:
        if flow.traffic_class != model.PRODUCTION and flow.activity != model.QUIESCED:
            report.notes.append(model.Finding("NON_PRODUCTION_TRAFFIC_PRESENT", flow.family, flow.direction, flow.traffic_class, (flow.workload,)))
    for dependency in dependencies:
        if dependency.critical and dependency.stranded is not False:
            report.blockers.append(model.Finding(DEPENDENCY_STRANDED, workloads=(dependency.name,),
                                                 detail=dependency.detail or ("not established" if dependency.stranded is None else dependency.kind)))
    return report


IRRELEVANT = "NOT_THROUGH_DEVICE"


def flow_rows(report: model.Report, observation: dict) -> list[dict]:
    """One row per observed flow: why that flow allows or blocks the entry.  ``observation`` is the stored observation
    summary.  Pure: every value is read from the report and the observation; nothing is inferred from a device name."""
    paths, alternates = observation.get("paths") or {}, observation.get("alternates") or {}
    mechanisms, single = observation.get("mechanisms") or {}, set(observation.get("single_homed") or ())
    rows = []
    for flow in observation.get("flows") or []:
        key = f"{flow['family']}/{flow['direction']}"
        cell = (report.cells or {}).get((flow["family"], flow["direction"])) or {}
        source, _sep, destination = str(flow["workload"]).partition(" to ")
        host = source if flow["direction"] == model.NORTHBOUND else destination
        mechanism = mechanisms.get(key)
        alternate = alternates.get(key)
        if flow.get("on_device") is False:
            redundancy, verdict = "not needed: the flow does not pass the device", IRRELEVANT
        elif host in single:
            redundancy, verdict = "none: the host is single-homed to this device", cell.get("verdict", "")
        elif alternate is True:
            redundancy, verdict = "alternate path verified healthy", cell.get("verdict", "")
        elif alternate is False:
            redundancy, verdict = "alternate path NOT healthy", cell.get("verdict", "")
        else:
            redundancy, verdict = "not established", cell.get("verdict", "")
        reasons = [f.text() for f in report.blockers if (f.family, f.direction) == (flow["family"], flow["direction"])
                   and (not f.workloads or flow["workload"] in f.workloads)] if verdict != IRRELEVANT else []
        rows.append({
            "label": flow["label"], "family": flow["family"], "direction": flow["direction"], "source": source, "destination": destination,
            "path": (paths.get(flow["label"]) or {}).get("path", ""), "path_complete": (paths.get(flow["label"]) or {}).get("complete"),
            "on_device": flow.get("on_device"), "activity": flow["activity"], "evidence": flow.get("evidence", ""),
            "redundancy": redundancy, "mechanism": (mechanism or {}).get("key", "none"), "mechanism_state": (mechanism or {}).get("state", "NO_MECHANISM"),
            "proven_drain": bool(mechanism and mechanism.get("state") == model.READY and alternate is True),
            "verdict": verdict, "blocking": reasons,
        })
    return rows
