"""Map Phase-13 semantic dependencies onto Configlet dependencies.

Phase 14 does NOT rediscover dependency semantics.  Every RESOLVED edge of the
pinned validation's graph ("A depends on B", typed REQUIRES / DEFINE_BEFORE_ATTACH /
PARENT_BEFORE_CHILD / ADDRESS_BEFORE_ROUTING / INTERFACE_BEFORE_SERVICE /
REFERENCES) becomes "the Configlet of A depends on the Configlet of B".  Edges may
cross devices (nothing restricts a ConfigletDependency to one device; it must stay
inside the one plan).  Two Configlets of one object (a BGP neighbor definition and
its address-family activation) get an explicit internal edge.

Defensive integrity checks only -- this module never validates network semantics.
"""

from __future__ import annotations

from .errors import PlanGenerationError


def map_dependencies(graph: dict, specs: list, node_to_key: dict, *, skipped_nodes=frozenset()) -> dict:
    """-> {(dependent_key, dependency_key): {"edge_types": [...], "reasons": [...]}} (deterministic)."""
    node_ids = {node["id"] for node in graph.get("nodes", [])}
    edges: dict[tuple, dict] = {}

    def add(dependent: str, dependency: str, edge_type: str, reason: str) -> None:
        if dependent == dependency:
            return  # internal to one Configlet (e.g. a PBR sequence inside its policy)
        entry = edges.setdefault((dependent, dependency), {"edge_types": set(), "reasons": set()})
        entry["edge_types"].add(edge_type)
        if reason:
            entry["reasons"].add(reason)

    for edge in sorted(graph.get("edges", []), key=lambda e: (e["from"], e["to"], e["type"])):
        if edge.get("status") != "RESOLVED":
            raise PlanGenerationError("DEPENDENCY_MISSING", edge_from=edge["from"], edge_to=edge["to"], edge_type=edge["type"])
        source, target = edge["from"], edge["to"]
        if source not in node_ids or target not in node_ids:
            raise PlanGenerationError("DEPENDENCY_MISSING", edge_from=source, edge_to=target, edge_type=edge["type"])
        dependent, dependency = node_to_key.get(source), node_to_key.get(target)
        if dependent is None or dependency is None:
            if source in skipped_nodes or target in skipped_nodes:
                continue  # an object with no deployable configuration has no Configlet to order
            raise PlanGenerationError("DEPENDENCY_MISSING", edge_from=source, edge_to=target, edge_type=edge["type"])
        add(dependent, dependency, edge["type"], edge.get("reason", ""))

    for spec in specs:
        if spec.parent_key:
            add(spec.key, spec.parent_key, "REQUIRES", "address-family activation requires the neighbor definition")

    return {
        pair: {"edge_types": sorted(entry["edge_types"]), "reasons": sorted(entry["reasons"])}
        for pair, entry in sorted(edges.items())
    }
