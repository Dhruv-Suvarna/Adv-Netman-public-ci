"""Deterministic path classification and cross-subsystem impact expansion (pure, no I/O)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from . import rules
from .rules import UNCLASSIFIED


def classify_path(path: str) -> tuple[str, ...]:
    """Every subsystem a path belongs to, in stable (declaration) order; ``(UNCLASSIFIED,)`` if none."""
    hits = [rule.subsystem for rule in rules.PATH_RULES if any(rules.glob_match(p, path) for p in rule.patterns)]
    seen: list[str] = []
    for sub in hits:
        if sub not in seen:
            seen.append(sub)
    return tuple(seen) if seen else (UNCLASSIFIED,)


@dataclass(frozen=True)
class Impact:
    subsystem: str
    via: tuple[str, ...]  # chain from a directly changed subsystem to this one (inclusive)
    reason: str           # why the LAST hop matters
    wide: bool = False    # "django-wide" from a foundational change: only its Django test surface is implied, and it does not propagate


def expand_impact(direct: set[str] | frozenset[str]) -> dict[str, Impact]:
    """Transitive consumers of the directly changed subsystems (shortest chain, deterministic).

    Subsystems already changed directly are not repeated as "impacted".
    """
    order = [s.id for s in rules.SUBSYSTEM_LIST]
    impacted: dict[str, Impact] = {}
    queue: deque[tuple[str, tuple[str, ...]]] = deque((sub, (sub,)) for sub in sorted(direct, key=order.index))
    known = set(direct)

    def add(consumer: str, chain: tuple[str, ...], reason: str, *, wide: bool = False) -> None:
        if consumer in known:
            return
        known.add(consumer)
        impacted[consumer] = Impact(consumer, (*chain, consumer), reason, wide)
        if not wide:
            queue.append((consumer, (*chain, consumer)))

    while queue:
        current, chain = queue.popleft()
        if current in rules.BROADENING:
            for consumer in rules.DJANGO_WIDE_CONSUMERS:
                add(consumer, chain, f"{rules.SUBSYSTEMS[current].title} is foundational: every Django subsystem consumes it", wide=True)
        for edge in rules.IMPACT_EDGES:
            if edge.source == current:
                add(edge.consumer, chain, edge.reason)
    return {sub: impacted[sub] for sub in sorted(impacted, key=order.index)}


def subsystem_order() -> list[str]:
    return [s.id for s in rules.SUBSYSTEM_LIST]
