"""The persisted operational topology (``TopologyNode`` / ``TopologyEdge``) and its NetworkX view.

Provenance rules -- a link is never inferred:
    * PRODUCTION edge  = an APPROVED attachment whose verification is VERIFIED (a trusted observation); an unverified,
                         mismatched or revoked attachment, or two adjacent IP addresses, never create an edge
    * MANAGEMENT edge  = an APPROVED ``ManagementPath`` (peer = the adjacent switch, or ``nmas:<attachment>`` for a routed path)
    * an edge is ACTIVE while its provenance holds, its device is live and its peer is not a decommissioned managed device;
      edges that lose provenance are deactivated (kept as history), never deleted

Everything is rebuilt from the NMAS database, so a restart (or a replayed fact) converges to the same rows.
"""

from __future__ import annotations

import networkx as nx

from ... import models
from . import facts

N, S, A = models.TopologyNodeState, models.DeviceLifecycleState, models.ProductionAdmissionState
Kind = models.TopologyEdgeKind
CONSUMER = "phase8-topology"
UNMANAGED = "UNMANAGED"
_LIFECYCLE_NODE = {
    S.REGISTERED: N.PLANNED, S.DISCOVERED: N.DISCOVERED, S.BOOTSTRAPPED: N.AUTHENTICATED, S.ISOLATED: N.ISOLATED,
    S.READY_FOR_COMMISSIONING: N.ISOLATED, S.COMMISSIONING: N.COMMISSIONED, S.DECOMMISSION_PENDING: N.IN_SERVICE,
    S.DECOMMISSIONED: N.DECOMMISSIONED, S.WITHDRAWN: N.DECOMMISSIONED, S.FAILED: N.UNCERTAIN,
}


def node_state(device) -> str:
    """The topology state of ``device`` from its lifecycle, admission and the maintenance engine."""
    if device.lifecycle_state == S.IN_SERVICE:
        if device.admission_state not in facts.ADMITTED_STATES:
            return N.COMMISSIONED
        return N.MAINTENANCE if facts.under_maintenance(device.name) else N.IN_SERVICE
    return _LIFECYCLE_NODE.get(device.lifecycle_state, N.UNCERTAIN)


def _peer_live(peer: str) -> bool:
    """False only when ``peer`` names a managed device that is decommissioned / withdrawn with no live successor."""
    if facts.live_device(peer) is not None:
        return True
    return not models.ManagedDevice.objects.filter(name=peer).exists()


def desired_edges(device) -> dict:
    """{(local_interface, peer, peer_interface, kind): {source, facts}} -- the edges ``device``'s records prove right now."""
    wanted = {}
    attachments, inherited = facts.provenance_attachments(device)
    for att in attachments:
        detail = {"connectivity": att.connectivity, "vlan": att.vlan, **({"inherited_from": inherited} if inherited else {})}
        wanted.setdefault((att.local_interface, att.upstream_device, att.upstream_interface, Kind.PRODUCTION),
                          {"source": facts.attachment_ref(att), "facts": detail})
    approved = models.ManagementPath.objects.filter(device=device, approval_state=models.ManagementApproval.APPROVED).select_related(
        "nmas_attachment").order_by("preference_class", "id")
    for path in approved:
        peer = path.via_device or f"nmas:{path.nmas_attachment.name}"[:64]
        wanted.setdefault((path.local_interface, peer, path.remote_interface, Kind.MANAGEMENT),
                          {"source": path.path_id, "facts": {"path_type": path.path_type, "is_active": path.is_active,
                                                             "health": path.health_state, "vrf": path.vrf}})
    return wanted


def _ensure_peer_node(peer: str) -> None:
    """A peer that is a live managed device gets its node the moment an edge points at it, even if it has emitted no fact since
    Phase 8 (an adopted legacy switch): otherwise the incremental graph shows it UNMANAGED while ``rebuild()`` shows it
    IN_SERVICE.  Bounded: the node exists before its own edges are reconciled, so each device is created once."""
    device = facts.live_device(peer)
    if device is not None and not models.TopologyNode.objects.filter(device=device).exists():
        reconcile_device(device, fact="PEER_REFERENCED")


def reconcile_edges(device) -> dict:
    """Create / (re)activate / deactivate ``device``'s edges to match its provenance.  -> counts."""
    wanted = desired_edges(device)
    alive = device.lifecycle_state not in facts.TERMINAL
    counts = {"created": 0, "activated": 0, "deactivated": 0}
    for (local, peer, peer_interface, kind), spec in wanted.items():
        _ensure_peer_node(peer)
        active = alive and (kind == Kind.MANAGEMENT or _peer_live(peer))
        edge, created = models.TopologyEdge.objects.get_or_create(
            device=device, local_interface=local, peer=peer, peer_interface=peer_interface, kind=kind,
            defaults={"source": spec["source"], "active": active, "facts": spec["facts"]})
        if created:
            counts["created"] += 1
        elif edge.active != active or edge.facts != spec["facts"]:
            if active and not edge.active:
                counts["activated"] += 1
            elif edge.active and not active:
                counts["deactivated"] += 1
            edge.active, edge.facts = active, spec["facts"]
            edge.save(update_fields=["active", "facts", "updated_at"])
    for edge in models.TopologyEdge.objects.filter(device=device, active=True):
        if (edge.local_interface, edge.peer, edge.peer_interface, edge.kind) not in wanted:
            edge.active = False
            edge.save(update_fields=["active", "updated_at"])
            counts["deactivated"] += 1
    return counts


def reconcile_device(device, *, sequence: int = 0, fact: str = "") -> models.TopologyNode:
    """Upsert ``device``'s node, reconcile its edges and refresh every edge that points at it (decommission / restore)."""
    node, _created = models.TopologyNode.objects.get_or_create(device=device, defaults={"name": device.name, "platform": device.platform,
                                                                                        "role": device.role or ""})
    node.state, node.role = node_state(device), device.role or ""
    node.facts = {"lifecycle_state": device.lifecycle_state, "admission_state": device.admission_state,
                  "maintenance": facts.under_maintenance(device.name), "last_fact": fact[:40]}
    if sequence:
        node.last_sequence = max(int(node.last_sequence), int(sequence))
    node.save()
    reconcile_edges(device)
    for other in models.ManagedDevice.objects.filter(topology_edges__peer=device.name).exclude(pk=device.pk).distinct():
        reconcile_edges(other)
    return node


def apply(event, **_context) -> str:
    """Consumer entry point.  -> APPLIED | SUPERSEDED (an older fact never regresses the node)."""
    device = models.ManagedDevice.objects.get(pk=event.device_id)
    node = models.TopologyNode.objects.filter(device=device).first()
    if node is not None and facts.superseded(event, node.last_sequence):
        return "SUPERSEDED"
    reconcile_device(device, sequence=event.sequence, fact=facts.fact_of(event))
    return "APPLIED"


def rebuild() -> int:
    """Reconcile every managed device from the database (restart / drift repair).  -> nodes reconciled."""
    count = 0
    for device in models.ManagedDevice.objects.order_by("pk"):
        reconcile_device(device, fact="REBUILD")
        count += 1
    return count


# --- NetworkX view --------------------------------------------------------------------------------------------------------------
def _node_id_by_name() -> dict:
    """name -> node id, preferring the live device's node over a decommissioned predecessor."""
    mapping = {}
    for node in models.TopologyNode.objects.select_related("device").order_by("device__pk"):
        if node.name not in mapping or node.device.lifecycle_state not in facts.TERMINAL:
            mapping[node.name] = node.device.device_id
    return mapping


def graph(*, active_only: bool = True) -> nx.MultiGraph:
    """A ``networkx.MultiGraph`` from the persisted rows.  Node ids are stable device ids (``DEV-000001``); an inventory peer that
    is not a managed device appears as ``unmanaged:<name>`` with state UNMANAGED.  With ``active_only`` a decommissioned
    registration that a restored successor replaced is omitted (one node per name; the old row stays as history)."""
    g = nx.MultiGraph()
    replaced = set(models.ManagedDevice.objects.filter(successors__isnull=False).values_list("pk", flat=True))
    for node in models.TopologyNode.objects.select_related("device").order_by("device__pk"):
        if active_only and node.device_id in replaced:
            continue
        g.add_node(node.device.device_id, name=node.name, platform=node.platform, role=node.role, state=node.state,
                   last_sequence=node.last_sequence)
    by_name = _node_id_by_name()
    edges = models.TopologyEdge.objects.select_related("device").order_by("pk")
    if active_only:
        edges = edges.filter(active=True)
    for edge in edges:
        peer_id = by_name.get(edge.peer)
        if peer_id is None:
            peer_id = f"unmanaged:{edge.peer}"
            if peer_id not in g:
                g.add_node(peer_id, name=edge.peer, platform="", role="", state=UNMANAGED, last_sequence=0)
        g.add_edge(edge.device.device_id, peer_id, key=f"{edge.kind}:{edge.local_interface}:{edge.peer_interface}", kind=edge.kind,
                   local_interface=edge.local_interface, peer_interface=edge.peer_interface, source=edge.source, active=edge.active)
    return g


def summary() -> dict:
    """Node counts by state and edge counts by kind / activity (for the operator page and ``status``)."""
    nodes = {}
    for state in models.TopologyNode.objects.values_list("state", flat=True):
        nodes[state] = nodes.get(state, 0) + 1
    edges = {}
    for kind, active in models.TopologyEdge.objects.values_list("kind", "active"):
        key = f"{kind}:{'active' if active else 'inactive'}"
        edges[key] = edges.get(key, 0) + 1
    return {"nodes": nodes, "edges": edges}


def upstream_of(device_name: str) -> list[dict]:
    """The devices ``device_name`` depends on: peers of its ACTIVE PRODUCTION edges and its ACTIVE commissioning dependencies."""
    device = facts.live_device(device_name)
    if device is None:
        return []
    rows = {}
    for edge in models.TopologyEdge.objects.filter(device=device, kind=Kind.PRODUCTION, active=True):
        rows.setdefault(edge.peer, {"name": edge.peer, "via": f"PRODUCTION_EDGE:{edge.source}"})
    for dep in models.CommissioningDependency.objects.select_related("upstream").filter(device=device, state=models.DependencyState.ACTIVE):
        rows.setdefault(dep.upstream.name, {"name": dep.upstream.name, "via": "COMMISSIONING_DEPENDENCY"})
    return [rows[name] for name in sorted(rows)]


def _direct_dependents(name: str) -> list[tuple]:
    found = []
    edges = models.TopologyEdge.objects.select_related("device").filter(peer=name, kind=Kind.PRODUCTION, active=True)
    found += [(e.device, f"PRODUCTION_EDGE:{e.source}") for e in edges]
    # the attachment itself (so an analysis never misses a dependent because the dispatcher has not run yet)
    attachments = models.DeviceAttachment.objects.select_related("device").filter(
        upstream_device=name, purpose=models.AttachmentPurpose.PRODUCTION, approval_state=models.AttachmentApproval.APPROVED,
        verification_state=models.AttachmentVerification.VERIFIED)
    found += [(a.device, f"PRODUCTION_ATTACHMENT:{facts.attachment_ref(a)}") for a in attachments]
    deps = models.CommissioningDependency.objects.select_related("device", "upstream").filter(upstream__name=name,
                                                                                               state=models.DependencyState.ACTIVE)
    found += [(d.device, "COMMISSIONING_DEPENDENCY") for d in deps]
    return [(device, via) for device, via in found if device.lifecycle_state not in facts.TERMINAL and device.name != name]


def downstream_dependents(device_name: str) -> list[dict]:
    """Every live managed device that depends on ``device_name``, recursively: an ACTIVE PRODUCTION edge or a VERIFIED approved
    production attachment pointing at it, or an ACTIVE ``CommissioningDependency`` on it.  Each row: name, device_id,
    lifecycle_state, admission_state, via (the proving record), parent (the device it depends on).  Sorted by name."""
    seen, rows, queue = {str(device_name)}, {}, [str(device_name)]
    while queue:
        parent = queue.pop(0)
        for device, via in _direct_dependents(parent):
            if device.name in seen:
                continue
            seen.add(device.name)
            rows[device.name] = {"name": device.name, "device_id": device.device_id, "lifecycle_state": device.lifecycle_state,
                                 "admission_state": device.admission_state, "via": via, "parent": parent}
            queue.append(device.name)
    return [rows[name] for name in sorted(rows)]
