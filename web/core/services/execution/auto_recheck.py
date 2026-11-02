"""Recheck of race-sensitive AUTO-derived addresses IMMEDIATELY before the first device mutation.

Phase 13 derives an AUTO address as a read-only PROPOSAL (lowest free host of a NetBox prefix; "not reserved, must be
rechecked immediately before deployment").  The plan carries that proposal into a Configlet.  Deploying it merely
because the old plan says so would be wrong, so this module re-derives it from CURRENT NetBox / inventory evidence with
the SAME Phase-13 addressing code and compares.

Option B of the design ("refuse if the address can no longer safely be guaranteed") is implemented, not option A:
the project has no static-address reservation write path (its "reservation" concept is DHCP assignment-mode custom fields
on NetBox interfaces), and Python must not invent a NetBox write to make deployment work.  Therefore:

* the recheck is READ-ONLY: it writes nothing to NetBox, accepted intent, the plan or the run;
* any difference, an unavailable NetBox, a blocking AUTO finding, or changed accepted intent REFUSES execution;
* nothing is reserved, so there is nothing to release when a Complete run fails;
* the recheck narrows the race window (current evidence, taken right before mutation) but cannot close it: NetBox is
  passive and offers no lock.  This is stated in the run report and the documentation, not hidden.
"""

from __future__ import annotations

from .. import change_validation_service as cvs
from ..validation import addressing, snapshot as snapshot_module
from ..validation.context import ProjectModel, ValidationContext
from .codes import blocker


def auto_configlets(configlets) -> list:
    return [c for c in configlets if ((c.metadata or {}).get("derived") or {}).get("kind") == "AUTO_ADDRESS"]


def recheck_auto_addresses(plan, configlets, *, sources=None) -> tuple[list[dict], list[dict]]:
    """-> (blockers, checked).  ``checked`` lists every AUTO Configlet with its planned and current proposal."""
    autos = auto_configlets(configlets)
    if not autos:
        return [], []
    change = plan.change

    def refuse(reason: str, **details):
        return [blocker("AUTO_ADDRESS_RECHECK_FAILED", reason=reason, **details)], []

    bundle = sources if sources is not None else cvs.build_source_snapshot(change)
    if not bundle.netbox.available:
        return refuse("NETBOX_UNAVAILABLE")
    snapshot = snapshot_module.build_change_snapshot(change)
    if snapshot_module.hash_snapshot(snapshot) != plan.validation_input_hash:
        return refuse("ACCEPTED_INTENT_CHANGED")
    ctx = ValidationContext(snapshot=snapshot, model=ProjectModel(snapshot), sources=bundle)
    try:
        addressing.validate_addressing(ctx)
    except Exception:  # noqa: BLE001 - a derivation bug must refuse execution, never permit it
        return refuse("DERIVATION_ERROR")
    current = {(fact["device"], fact["object_id"]): fact for fact in ctx.derived if fact.get("type") == "AUTO_ADDRESS"}
    checked, mismatches = [], []
    for configlet in autos:
        source = (configlet.desired_state_ref or {}).get("source") or {}
        planned = ((configlet.metadata or {}).get("derived") or {}).get("proposed_address")
        fact = current.get((configlet.target_device, source.get("object_id")))
        now_proposed = (fact or {}).get("proposed_address")
        checked.append({"cfg_id": configlet.cfg_id, "device": configlet.target_device, "planned": planned, "current": now_proposed})
        if now_proposed != planned:
            mismatches.append({"cfg_id": configlet.cfg_id, "planned": planned, "current": now_proposed})
    if mismatches:
        return [blocker("AUTO_ADDRESS_RECHECK_FAILED", reason="ADDRESS_CHANGED", configlets=mismatches)], checked
    return [], checked
