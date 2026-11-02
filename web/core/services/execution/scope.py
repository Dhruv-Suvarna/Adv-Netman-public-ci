"""Execution scope: which plan Configlets a run may execute, in the plan's own order.

The Phase-14 plan is the execution authority: nothing is re-planned or re-ordered here.

* Complete        the ENTIRE plan.
* Partial (UAT)   an ordered PREFIX of the plan, up to an explicit ``through`` Configlet.  The repository defines no
                  arbitrary-subset semantics for Partial (its acknowledgements speak of "dependent stages may stop" and
                  "partial success may remain applied", i.e. an ordered run that halts), so the conservative reading is
                  the one used: a prefix of a topological order is dependency-closed by construction.  Dependency safety
                  is nevertheless verified explicitly, never assumed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ... import models
from .codes import Mode, blocker


@dataclass
class ExecutionScope:
    mode: str
    ordered: list                    # every plan Configlet in plan order
    selected: list                   # the Configlets this run will execute, in order
    through_cfg_id: str = ""
    dependencies: dict = field(default_factory=dict)   # cfg_id -> [cfg_id it depends on]

    @property
    def requested_cfg_ids(self) -> list[str]:
        return [c.cfg_id for c in self.selected]

    @property
    def unselected(self) -> list:
        chosen = {c.cfg_id for c in self.selected}
        return [c for c in self.ordered if c.cfg_id not in chosen]

    @property
    def devices(self) -> list[str]:
        return sorted({c.target_device for c in self.selected})

    def to_dict(self) -> dict:
        return {
            "mode": self.mode, "through_cfg_id": self.through_cfg_id, "requested": self.requested_cfg_ids,
            "plan_order": [c.cfg_id for c in self.ordered], "unselected": [c.cfg_id for c in self.unselected], "devices": self.devices,
        }


def _dependency_map(plan) -> dict:
    by_pk = {c.pk: c.cfg_id for c in plan.configlets.all()}
    found: dict[str, list[str]] = {}
    for edge in models.ConfigletDependency.objects.filter(configlet__plan=plan):
        found.setdefault(by_pk[edge.configlet_id], []).append(by_pk[edge.depends_on_id])
    return {key: sorted(value) for key, value in found.items()}


def resolve_scope(plan, mode: str, through_cfg_id: str = "") -> tuple[ExecutionScope | None, list[dict]]:
    """-> (scope, blockers).  ``scope`` is None only when the plan has no Configlets."""
    ordered = list(plan.configlets.order_by("sequence"))
    if not ordered:
        return None, [blocker("PLAN_EMPTY")]
    dependencies = _dependency_map(plan)
    blockers: list[dict] = []
    position = {c.cfg_id: index for index, c in enumerate(ordered)}
    for cfg_id, needs in dependencies.items():
        if any(position[need] >= position[cfg_id] for need in needs):
            blockers.append(blocker("PLAN_ORDER_INVALID", cfg_id=cfg_id))
    if mode == Mode.COMPLETE:
        selected, through = list(ordered), ""
    else:
        through = str(through_cfg_id or "").strip()
        if not through:
            blockers.append(blocker("UAT_SCOPE_REQUIRED"))
            selected = []
        elif through not in position:
            blockers.append(blocker("UAT_SCOPE_INVALID"))
            selected = []
        else:
            selected = ordered[: position[through] + 1]
    scope = ExecutionScope(mode=mode, ordered=ordered, selected=selected, through_cfg_id=through, dependencies=dependencies)
    # explicit dependency safety: every prerequisite of a selected Configlet is itself selected (and earlier)
    chosen = {c.cfg_id for c in selected}
    for cfg_id in sorted(chosen):
        missing = [need for need in dependencies.get(cfg_id, []) if need not in chosen]
        if missing:
            blockers.append(blocker("UAT_SCOPE_INVALID", cfg_id=cfg_id, missing=missing))
    return scope, blockers
