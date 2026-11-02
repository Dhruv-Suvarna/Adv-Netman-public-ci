"""Deterministic, cycle-safe topological ordering of Configlets.

Priority is a coarse class; DEPENDENCIES OVERRIDE IT.  Among the Configlets whose
dependencies are all satisfied, the next one emitted is the smallest by

    (priority, device name, operation class, source object identity)

(the Configlet's ``sort_key``: DEFINE before ACTIVATE_ATTACH within a class; the
source identity is the stable ``<device>/<type>/<object id>`` -- never a database
primary key).  The same input therefore always yields the same order.  Devices are
NOT completed one at a time: a dependency on another device's Configlet interleaves
naturally.  NetworkX order is not relied upon.

A cycle leaves Configlets that can never become ready; that is reported (with one
deterministic cycle) instead of guessing an order.
"""

from __future__ import annotations

import heapq

from .errors import PlanGenerationError


def topological_order(sort_keys: dict[str, tuple], dependencies) -> list[str]:
    """``dependencies`` is an iterable of ``(dependent_key, dependency_key)``.  Returns keys in execution order."""
    remaining = {key: 0 for key in sort_keys}
    dependents: dict[str, list[str]] = {key: [] for key in sort_keys}
    needs: dict[str, list[str]] = {key: [] for key in sort_keys}
    for dependent, dependency in dependencies:
        if dependent == dependency:
            raise PlanGenerationError("CONFIGLET_CYCLE", cycle=[dependent, dependent])
        if dependent not in remaining or dependency not in remaining:
            raise PlanGenerationError("DEPENDENCY_MISSING", dependent=dependent, dependency=dependency)
        remaining[dependent] += 1
        dependents[dependency].append(dependent)
        needs[dependent].append(dependency)

    ready = [(sort_keys[key], key) for key, count in remaining.items() if count == 0]
    heapq.heapify(ready)
    order: list[str] = []
    while ready:
        _, key = heapq.heappop(ready)
        order.append(key)
        for follower in sorted(dependents[key]):
            remaining[follower] -= 1
            if remaining[follower] == 0:
                heapq.heappush(ready, (sort_keys[follower], follower))

    if len(order) != len(sort_keys):
        stuck = sorted(key for key, count in remaining.items() if count > 0)
        raise PlanGenerationError("CONFIGLET_CYCLE", cycle=_find_cycle(stuck, needs), stuck=stuck[:20])
    return order


def _find_cycle(stuck: list[str], needs: dict[str, list[str]]) -> list[str]:
    """One deterministic cycle among the never-ready Configlets (follow "depends on" from the smallest)."""
    stuck_set = set(stuck)
    node = stuck[0]
    seen: dict[str, int] = {}
    path: list[str] = []
    while node not in seen:
        seen[node] = len(path)
        path.append(node)
        node = sorted(dep for dep in needs[node] if dep in stuck_set)[0]
    return path[seen[node]:] + [node]
