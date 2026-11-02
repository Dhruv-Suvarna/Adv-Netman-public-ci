"""Dependency-aware commissioning: a generic directed graph "device depends on upstream", never special-cased by name.

Edges come from two places:

* ``CommissioningDependency`` rows (ACTIVE): declared by an operator, or derived from an approved attachment whose upstream is
  itself a natively onboarded device (``derive``; e.g. R7's attachment on R6's port gives R7 -> R6, R6's on R4 gives nothing
  because R4 is a legacy in-service device);
* nothing else -- the graph is exactly what was recorded, so a re-evaluation after an upstream changes state is idempotent.

An upstream is SATISFIED when it is IN_SERVICE and either ADMITTED by NMAS or a legacy pre-existing production device.  A
downstream device is never commissioned because its upstream became ready: it still needs its own readiness and approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from ..devices import events, identity
from ..devices.codes import blocker, codes

Kind, State = models.DependencyKind, models.DependencyState
Outcome = models.DeviceLifecycleEventOutcome
S, A = models.DeviceLifecycleState, models.ProductionAdmissionState


@dataclass
class DependencyResult:
    ok: bool
    action: str
    dependency: object | None = None
    blockers: list = field(default_factory=list)

    @property
    def codes(self) -> list[str]:
        return codes(self.blockers)


def edges() -> dict[int, set[int]]:
    """{device pk: {upstream pk}} of every ACTIVE dependency."""
    graph: dict[int, set[int]] = {}
    for device_id, upstream_id in models.CommissioningDependency.objects.filter(state=State.ACTIVE).values_list("device_id", "upstream_id"):
        graph.setdefault(device_id, set()).add(upstream_id)
    return graph


def reaches(graph: dict, start: int, goal: int) -> bool:
    """Is ``goal`` reachable from ``start`` following "depends on" edges?"""
    seen, stack = set(), [start]
    while stack:
        node = stack.pop()
        if node == goal:
            return True
        if node in seen:
            continue
        seen.add(node)
        stack.extend(graph.get(node, ()))
    return False


def cycles(graph: dict | None = None) -> list[list[int]]:
    """Every elementary cycle found by a depth-first search (each reported once, as the list of pks on it)."""
    graph = edges() if graph is None else graph
    found, colour, path = [], {}, []

    def visit(node):
        colour[node] = 1
        path.append(node)
        for nxt in sorted(graph.get(node, ())):
            if colour.get(nxt, 0) == 0:
                visit(nxt)
            elif colour.get(nxt) == 1:
                found.append(path[path.index(nxt):] + [nxt])
        path.pop()
        colour[node] = 2

    for node in sorted(graph):
        if colour.get(node, 0) == 0:
            visit(node)
    return found


def order(device_ids, graph: dict | None = None) -> list[int]:
    """A commissioning order of ``device_ids`` (upstreams first).  Raises ValueError on a cycle among them."""
    graph = edges() if graph is None else graph
    wanted = set(device_ids)
    pending = {d: {u for u in graph.get(d, ()) if u in wanted} for d in wanted}
    result = []
    while pending:
        ready = sorted(d for d, ups in pending.items() if not ups)
        if not ready:
            raise ValueError("COMMISSIONING_DEPENDENCY_CYCLE")
        for node in ready:
            result.append(node)
            del pending[node]
        for ups in pending.values():
            ups.difference_update(ready)
    return result


def _live(device) -> bool:
    return device is not None and not device.is_terminal


def satisfied(upstream) -> tuple[bool, str]:
    """Is this upstream genuinely available for a dependent device?  -> (ok, reason)."""
    if not _live(upstream):
        return False, "the upstream is not a live managed device"
    if upstream.lifecycle_state != S.IN_SERVICE:
        return False, f"the upstream is {upstream.lifecycle_state}"
    if upstream.admission_state == A.ADMITTED:
        admission = models.ProductionAdmission.objects.filter(device=upstream, state=models.AdmissionState.ADMITTED).order_by("-id").first()
        if admission is None:
            return False, "the upstream claims admission without an ADMITTED production admission record"
        return True, f"admitted by {admission.admission_id}"
    if upstream.admission_state == A.LEGACY_PREEXISTING and upstream.origin == models.DeviceOrigin.LEGACY_ADOPTION:
        return True, "legacy in-service production device"
    return False, f"the upstream admission state is {upstream.admission_state}"


def unmet(device) -> list[dict]:
    """Blockers for every ACTIVE dependency of ``device`` that is not satisfied, plus any cycle through it."""
    found = []
    graph = edges()
    for cycle in cycles(graph):
        if device.pk in cycle:
            names = dict(models.ManagedDevice.objects.filter(pk__in=cycle).values_list("pk", "name"))
            found.append(blocker("COMMISSIONING_DEPENDENCY_CYCLE", cycle=[names.get(pk, str(pk)) for pk in cycle]))
            break
    for dependency in models.CommissioningDependency.objects.select_related("upstream").filter(device=device, state=State.ACTIVE):
        ok, reason = satisfied(dependency.upstream)
        if not ok:
            found.append(blocker("COMMISSIONING_DEPENDENCY_UNMET", upstream=dependency.upstream.name, kind=dependency.kind, reason=reason))
    return found


def _event(device, action, outcome, *, actor, blockers=(), evidence=None):
    fresh = models.ManagedDevice.objects.select_for_update().get(pk=device.pk)
    return events.record(fresh, action, outcome, actor=actor, actor_kind=events.AUTOMATION if actor.startswith("system:") else events.HUMAN,
                         from_state=fresh.lifecycle_state, to_state=fresh.lifecycle_state, blockers=list(blockers), evidence=evidence or {})


def add(device, upstream, *, kind: str, actor: str, reason: str = "") -> DependencyResult:
    """Record ``device`` depends on ``upstream``.  Idempotent; refuses self-dependencies, terminal devices and cycles."""
    action = "COM_DEPENDENCY_ADD"
    text, problems = identity.clean_text(reason, max_length=200)
    if kind not in Kind.values or problems:
        problems = problems or [blocker("COMMISSIONING_DEPENDENCY_INVALID", detail="unknown dependency kind")]
    elif upstream is None or not _live(device) or not _live(upstream) or upstream.pk == device.pk:
        problems = [blocker("COMMISSIONING_DEPENDENCY_INVALID", detail="both ends must be distinct live managed devices")]
    elif reaches(edges(), upstream.pk, device.pk):
        problems = [blocker("COMMISSIONING_DEPENDENCY_CYCLE", device=device.name, upstream=upstream.name)]
    if problems:
        with transaction.atomic():
            _event(device, action, Outcome.REFUSED, actor=actor, blockers=problems)
        return DependencyResult(False, action, None, problems)
    existing = models.CommissioningDependency.objects.filter(device=device, upstream=upstream, state=State.ACTIVE).first()
    if existing is not None:
        return DependencyResult(True, action, existing)
    try:
        with transaction.atomic():
            row = models.CommissioningDependency.objects.create(device=device, upstream=upstream, kind=kind, reason=text, created_by=actor[:150])
            _event(device, action, Outcome.RECORDED, actor=actor, evidence={"upstream": upstream.device_id, "kind": kind, "dependency": row.pk})
    except IntegrityError:
        row = models.CommissioningDependency.objects.filter(device=device, upstream=upstream, state=State.ACTIVE).first()
    return DependencyResult(True, action, row)


def remove(dependency, *, actor: str, reason: str) -> DependencyResult:
    action = "COM_DEPENDENCY_REMOVE"
    text, problems = identity.clean_text(reason, max_length=200)
    if dependency.state != State.ACTIVE or problems or not text:
        problems = problems or [blocker("COMMISSIONING_DEPENDENCY_INVALID", detail="an active dependency and a reason are required")]
        with transaction.atomic():
            _event(dependency.device, action, Outcome.REFUSED, actor=actor, blockers=problems)
        return DependencyResult(False, action, dependency, problems)
    if dependency.kind == Kind.ATTACHMENT_UPSTREAM and models.DeviceAttachment.objects.filter(
            device=dependency.device, upstream_device=dependency.upstream.name).exclude(approval_state=models.AttachmentApproval.REVOKED).exists():
        problems = [blocker("COMMISSIONING_DEPENDENCY_INVALID", detail="the attachment that implies it is still live; revoke it first")]
        with transaction.atomic():
            _event(dependency.device, action, Outcome.REFUSED, actor=actor, blockers=problems)
        return DependencyResult(False, action, dependency, problems)
    with transaction.atomic():
        dependency.state, dependency.removed_by, dependency.removed_at = State.REMOVED, actor[:150], timezone.now()
        dependency.reason = (dependency.reason + " | removed: " + text)[:200]
        dependency.save(update_fields=["state", "removed_by", "removed_at", "reason"])
        _event(dependency.device, action, Outcome.RECORDED, actor=actor, evidence={"upstream": dependency.upstream.device_id, "reason": text})
    return DependencyResult(True, action, dependency)


def derive(device, *, actor: str) -> list[DependencyResult]:
    """Create the ATTACHMENT_UPSTREAM dependencies implied by the device's live attachments whose upstream is a natively onboarded
    device (idempotent).  A legacy inventory upstream implies no row: its availability is its own IN_SERVICE state."""
    results = []
    for attachment in models.DeviceAttachment.objects.filter(device=device).exclude(approval_state=models.AttachmentApproval.REVOKED):
        upstream = models.ManagedDevice.objects.filter(identity.LIVE, name=attachment.upstream_device,
                                                       origin=models.DeviceOrigin.REGISTERED_NEW).first()
        if upstream is not None:
            results.append(add(device, upstream, kind=Kind.ATTACHMENT_UPSTREAM, actor=actor,
                               reason=f"attachment {attachment.pk} rides on {upstream.name}:{attachment.upstream_interface}"))
    return results


def graph_view(devices=None) -> dict:
    """{nodes: [...], edges: [...], cycles: [...]} for the UI and the topology contract (pks resolved to names)."""
    rows = models.CommissioningDependency.objects.select_related("device", "upstream").filter(state=State.ACTIVE)
    if devices is not None:
        rows = rows.filter(device__in=devices) | rows.filter(upstream__in=devices)
    nodes, links = {}, []
    for row in rows:
        for end in (row.device, row.upstream):
            nodes[end.name] = {"name": end.name, "device_id": end.device_id, "lifecycle_state": end.lifecycle_state,
                               "admission_state": end.admission_state}
        ok, reason = satisfied(row.upstream)
        links.append({"device": row.device.name, "upstream": row.upstream.name, "kind": row.kind, "satisfied": ok, "reason": reason})
    names = dict(models.ManagedDevice.objects.values_list("pk", "name"))
    return {"nodes": sorted(nodes.values(), key=lambda n: n["name"]), "edges": links,
            "cycles": [[names.get(pk, str(pk)) for pk in cycle] for cycle in cycles()]}
