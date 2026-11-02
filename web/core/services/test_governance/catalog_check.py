"""Static catalog validation -- runs on EVERY Tier-3 run (targeted pull requests included), without executing tests.

Checks: the policy loads; every deployed artifact is classified; every Python artifact parses; every ``@case``
declaration on a Django test is well-formed, unique, and points at a real artifact / symbol / platform / feature /
generated requirement; every Lab 7 example target exists; every case and artifact the baseline locks still exists.
It also lists NEW required symbols (absent from the bundled evidence) so a pull request shows the debt it would add
before the full evidence run on main measures it.
"""

from __future__ import annotations

import json

from . import cells as cells_module, inventory, symbols
from .cases import Case, shape_errors
from .constants import BUNDLED_EVIDENCE, ArtifactType, Scope
from .gate import load_baseline
from .policy import PolicyError, default_policy

GENERATED_PREFIXES = ("TPL:", "CFG:", "EXE:", "CELL:", "SYM:")


def collect_declared(labels=("core",)) -> list[tuple[str, Case]]:
    """(test id, case) for every declaration on a test method of the Django suite (imports the tests; runs nothing)."""
    from django.test.runner import DiscoverRunner

    suite = DiscoverRunner(verbosity=0).build_suite(list(labels))
    out = []

    def walk(item):
        if hasattr(item, "__iter__") and not hasattr(item, "_testMethodName"):
            for child in item:
                walk(child)
            return
        method = getattr(item, getattr(item, "_testMethodName", ""), None)
        for candidate in (method, getattr(method, "__func__", None), getattr(method, "__wrapped__", None)):
            for declared in getattr(candidate, "_tg_cases", ()) or ():
                out.append((item.id(), declared))

    walk(suite)
    unique, seen = [], set()
    for test_id, declared in out:
        if (test_id, declared.case_id) not in seen:
            seen.add((test_id, declared.case_id))
            unique.append((test_id, declared))
    return unique


def generated_requirements(inv, cell_rows, policy=None) -> set[str]:
    policy = policy or default_policy()
    out = set()
    for artifact in inv.artifacts:
        if artifact.scope != Scope.CURRENT:
            continue
        if artifact.type == ArtifactType.JINJA:
            out.add(f"TPL:{artifact.path}:RENDER:POSITIVE")
            if artifact.variables:
                out.add(f"TPL:{artifact.path}:STRICT_UNDEFINED:NEGATIVE")
        elif artifact.type in (ArtifactType.YAML, ArtifactType.JSON):
            out.add(f"CFG:{artifact.path}:LOAD:POSITIVE")
            if not policy.external_consumer(artifact.path):
                out.add(f"CFG:{artifact.path}:MALFORMED:NEGATIVE")
        elif artifact.type in (ArtifactType.SHELL, ArtifactType.SYSTEMD, ArtifactType.CONFIG):
            out.add(f"EXE:{artifact.path}:STATIC:POSITIVE")
    for cell in cell_rows:
        if cell.supported:
            for stage in cell.stages:
                for polarity in ("POSITIVE", "NEGATIVE"):
                    out.add(cells_module.cell_case_id(cell.platform, cell.feature, stage, polarity))
    return out


def validate_catalog(*, declared: list[tuple[str, Case]] | None = None, baseline: dict | None = None, bundled=None) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        policy = default_policy()
    except PolicyError as exc:
        return {"errors": [f"POLICY_INVALID {exc}"], "warnings": [], "artifacts": 0, "symbols": 0, "declared": 0}
    try:
        cell_rows = cells_module.default_cells()
    except cells_module.LedgerError as exc:
        return {"errors": [f"LEDGER_INVALID {exc}"], "warnings": [], "artifacts": 0, "symbols": 0, "declared": 0}
    inv = inventory.build_inventory(policy=policy, cells=cell_rows)
    errors.extend(inv.errors)
    by_path = inv.by_path()
    modules = symbols.inventory_symbols([a.path for a in inv.artifacts if a.type == ArtifactType.PYTHON], policy=policy)
    symbol_ids = {s.id for m in modules.values() for s in m.symbols}
    for module in modules.values():
        if module.error:
            errors.append(f"UNPARSABLE PY:{module.path}: {module.error}")
    for target in policy.symbol_exemptions:
        if target not in symbol_ids:
            errors.append(f"STALE_EXEMPTION {target}: the exempted symbol does not exist")
    for example in policy.assignment_examples:
        for target in example["targets"]:
            if target not in symbol_ids:
                errors.append(f"EXAMPLE_TARGET_MISSING {example['requirement']}: {target}")

    declared = collect_declared() if declared is None else declared
    required = generated_requirements(inv, cell_rows, policy)
    platforms = {c.platform for c in cell_rows}
    features = {c.feature for c in cell_rows}
    first: dict[str, Case] = {}
    for test_id, item in declared:
        for problem in shape_errors(item):
            errors.append(f"MALFORMED_CASE {test_id}: {problem}")
        previous = first.setdefault(item.case_id, item)
        if previous != item:
            errors.append(f"DUPLICATE_CASE_ID {item.case_id}: declared with different metadata ({test_id})")
        if item.artifact_path not in by_path:
            errors.append(f"BROKEN_TARGET {item.case_id}: {item.artifact_path} is not a deployed artifact")
        elif item.symbol and item.symbol not in symbol_ids:
            errors.append(f"BROKEN_TARGET {item.case_id}: symbol {item.symbol} does not exist")
        if item.platform and (item.platform not in platforms or item.feature not in features):
            errors.append(f"UNKNOWN_CELL {item.case_id}: {item.platform} x {item.feature} is not a capability cell")
        if item.case_id.startswith(GENERATED_PREFIXES[:-1]) and item.case_id not in required:
            errors.append(f"UNKNOWN_GENERATED_CASE {item.case_id}: no such current requirement")

    baseline = load_baseline() if baseline is None else baseline
    for case_id in sorted(set(baseline.get("declared_cases") or ()) - set(first)):
        errors.append(f"BROKEN_REFERENCE {case_id}: locked by the baseline but no test declares it any more")
    present = {a.id for a in inv.artifacts}
    for artifact_id in sorted(set(baseline.get("artifacts") or ()) - present):
        errors.append(f"ARTIFACT_DISAPPEARED {artifact_id}: recorded in the baseline but no longer deployed")
    new_artifacts = sorted(present - set(baseline.get("artifacts") or ())) if baseline.get("artifacts") else []
    for artifact_id in new_artifacts:
        warnings.append(f"NEW_ARTIFACT {artifact_id}: not yet in the baseline; the full evidence run measures its cases")

    known = _bundled_symbols(BUNDLED_EVIDENCE if bundled is None else bundled)
    if known:
        for module in modules.values():
            artifact = by_path.get(module.path)
            if artifact is None or artifact.scope != Scope.CURRENT:
                continue
            for symbol in module.symbols:
                if symbol.positive_required and symbol.id not in known:
                    warnings.append(f"NEW_SYMBOL {symbol.id}: needs {'positive + negative' if symbol.negative_required else 'a positive'} "
                                    "case; unmeasured until the full evidence run")
    return {"errors": errors, "warnings": warnings, "artifacts": len(inv.artifacts), "symbols": len(symbol_ids), "declared": len(first)}


def _bundled_symbols(path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {s["id"] for a in data.get("artifacts") or () for s in a.get("symbols") or ()}
