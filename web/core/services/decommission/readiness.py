"""Decommission traffic readiness: the maintenance readiness engine (``maintenance_mode.readiness.evaluate``) over one observation.

The verdict is one of

    QUIESCENT              no monitored production flow passes the device (or the operator stopped it) and every family and
                           direction was observed -- no transition is needed, redundancy or not
    REDUNDANT_TRANSITION   production traffic passes the device, and for every such cell an EXISTING mechanism (OSPF's stub-router
                           function on a process the device already runs) is READY and the alternate path, derived from the
                           live adjacencies with the device removed, is healthy
    BLOCKED                anything else: traffic not established (blind spot), active traffic with no lossless alternative (the
                           operator must stop or relocate it outside NMAS), a stranded dependency, an unhealthy alternate

A topology without redundancy is not a defect: it only means active traffic has to be stopped by its owner before removal.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from ..maintenance_mode import model
from ..maintenance_mode import readiness as engine

QUIESCENT, REDUNDANT_TRANSITION, BLOCKED = "QUIESCENT", "REDUNDANT_TRANSITION", "BLOCKED"
MECHANISM = "OSPF_STUB_ROUTER"
INSTRUCTIONS = {
    engine.NO_LOSSLESS_DRAIN: "Active production traffic has no lossless alternative through an existing mechanism: stop or relocate "
                              "it outside NMAS (the workload's owner), then evaluate again.",
    engine.TRAFFIC_UNKNOWN: "Production traffic of this family and direction could not be established: fix the monitoring blind spot "
                            "before decommissioning; NMAS never reads 'not observed' as quiet.",
    engine.MECHANISM_NOT_READY: "The device's OSPF process is not in a state that can move the traffic (adjacencies not FULL).",
    engine.ALTERNATE_UNHEALTHY: "No healthy alternate path avoids the device for this traffic (it may be the traffic's only gateway): "
                                "stop or relocate the traffic outside NMAS, then evaluate again.",
    engine.DEPENDENCY_STRANDED: "A dependency would be stranded: resolve it (decommission or re-home the dependent first).",
}


@dataclass
class Observation:
    """What one read-only observation established.  ``alternates`` maps (family, direction) -> True / False / None."""

    device: str
    flows: list = field(default_factory=list)                    # maintenance_mode.model.Flow
    paths: dict = field(default_factory=dict)                    # flow label -> [router, ...] (derived from the live RIBs)
    alternates: dict = field(default_factory=dict)
    adjacencies: dict = field(default_factory=dict)              # family -> {"device": [peer, ...] FULL, "graph": [[a, b], ...]}
    ospf: dict = field(default_factory=dict)                     # family -> process header on the device ("" = none)
    counters: dict = field(default_factory=dict)                 # host -> {family: {before, after}} (bounded, numeric)
    window: dict = field(default_factory=dict)                   # {started, finished, seconds}
    blind_spots: list = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "device": self.device,
            "flows": [{"label": f.label, "workload": f.workload, "family": f.family, "direction": f.direction, "activity": f.activity,
                       "on_device": f.on_device, "evidence": f.evidence} for f in self.flows],
            "paths": self.paths, "alternates": {f"{k[0]}/{k[1]}": v for k, v in self.alternates.items()},
            "adjacencies": self.adjacencies, "ospf": self.ospf, "counters": self.counters, "window": self.window,
            "blind_spots": list(self.blind_spots),
        }


def mechanisms(observation: Observation) -> dict:
    """The existing mechanism per cell: the device's own OSPF process of that family, READY when it has FULL adjacencies."""
    found = {}
    for family in model.FAMILIES:
        header = (observation.ospf or {}).get(family)
        if not header:
            continue
        full = ((observation.adjacencies or {}).get(family) or {}).get("device") or []
        state = model.READY if full else model.NOT_READY
        for direction in model.DIRECTIONS:
            found[(family, direction)] = model.Mechanism(MECHANISM, family, direction, f"{header}: max-metric router-lsa", state=state)
    return found


def evaluate(observation: Observation, dependencies=(), *, operator: str, reason: str, now) -> dict:
    """-> {"verdict", "cells", "blockers" [{code, family, direction, workloads, detail, instruction}], "notes", "digest"}."""
    from datetime import timedelta

    request = model.Request(observation.device, operator or "-", reason or "-", timedelta(hours=1), now)
    deps = [model.Dependency(d["name"], d["kind"], critical=bool(d.get("critical", True)), stranded=d.get("stranded"), detail=d.get("detail", ""))
            for d in dependencies]
    report = engine.evaluate(request, observation.flows, deps, alternates=observation.alternates, mechanisms=mechanisms(observation))
    blockers = [{"code": f.code, "family": f.family, "direction": f.direction, "workloads": list(f.workloads), "detail": f.detail,
                 "instruction": INSTRUCTIONS.get(f.code, "")} for f in report.blockers]
    for spot in observation.blind_spots:
        blockers.append({"code": engine.TRAFFIC_UNKNOWN, "family": "", "direction": "", "workloads": [], "detail": str(spot)[:200],
                         "instruction": INSTRUCTIONS[engine.TRAFFIC_UNKNOWN]})
    cells = {f"{family}/{direction}": {**cell, "active": list(cell.get("active") or ())} for (family, direction), cell in report.cells.items()}
    if blockers:
        verdict = BLOCKED
    elif any(cell["verdict"] == engine.DRAINABLE and cell["active"] for cell in cells.values()):
        verdict = REDUNDANT_TRANSITION
    else:
        verdict = QUIESCENT
    body = {"verdict": verdict, "cells": cells, "blockers": blockers, "notes": [f.text() for f in report.notes],
            "observation": observation.summary()}
    body["digest"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    return body


def traffic_moved(observation: Observation) -> list[str]:
    """After the transition step: the labels of production flows that STILL pass the device (empty = every flow moved)."""
    return sorted(f.label for f in observation.flows if f.traffic_class == model.PRODUCTION and f.activity != model.QUIESCED
                  and f.on_device is not False)


def loss_findings(measurement: dict) -> list[dict]:
    """Postcheck of a continuous measurement {flow: {sent, received}}: every measured flow delivered every packet, and something
    was measured at all (no measurement is not zero loss)."""
    if not measurement:
        return [{"check": "traffic", "detail": "no continuous measurement was recorded"}]
    failed = []
    flows = {flow: counts for flow, counts in measurement.items() if not str(flow).startswith("_")}   # "_seconds" etc. are metadata
    if not flows:
        return [{"check": "traffic", "detail": "no continuous measurement was recorded"}]
    for flow, counts in sorted(flows.items()):
        if not isinstance(counts, dict):
            failed.append({"check": "traffic", "detail": f"{flow}: malformed measurement"})
            continue
        sent, received = counts.get("sent"), counts.get("received")
        if not isinstance(sent, int) or not isinstance(received, int) or sent <= 0:
            failed.append({"check": "traffic", "detail": f"{flow}: no packets measured"})
        elif received < sent:
            failed.append({"check": "traffic", "detail": f"{flow}: {sent - received} of {sent} packets lost"})
    return failed
