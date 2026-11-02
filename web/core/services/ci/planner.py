"""Change-effect analysis -> a structured, deterministic, explainable validation plan (pure, no execution).

    ChangeSet -> classify each path -> direct subsystems -> transitive impact -> required / optional checks,
    every one with the reason it was selected.

The planner owns NO project intelligence of its own: the mapping lives in ``rules``; the fixed commands
live in ``catalog``.  It never builds a deployment order, a Configlet plan or a Change validation -- those
stay with their own subsystems.  Unknown significant paths broaden validation; they never shrink it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Callable

from . import classify, rules
from .catalog import CHECKS, CHECK_ORDER
from .changes import STRATEGY_ALL_TRACKED, ChangeSet
from .constants import ENGINE_VERSION, MAX_CHANGED_FILES, MAX_LIST, FileStatus, Mode
from .rules import UNCLASSIFIED

_MIGRATION_RE = re.compile(r"^web/core/migrations/0\d+_[^/]+\.py$")
_TEST_MODULE_RE = re.compile(r"^web/core/tests/test_([a-z0-9_]+)\.py$")
_TEST_PATH_RE = re.compile(r"^(web/core/tests|monitoring/tests|challenge_console/tests|docs)/")


@dataclass
class PlannedCheck:
    id: str
    gate: str
    title: str
    required: bool
    reasons: list[str] = field(default_factory=list)
    params: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {"id": self.id, "gate": self.gate, "title": self.title, "required": self.required, "reasons": sorted(set(self.reasons))}
        if self.params:
            out["params"] = self.params
        return out


@dataclass
class PlanWarning:
    code: str
    message: str
    paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "paths": self.paths[:MAX_LIST]}


@dataclass
class ValidationPlan:
    mode_requested: str
    mode_effective: str
    mode_reasons: list[str]
    files: list[dict]
    files_total: int
    direct: list[str]
    impacted: list[dict]
    unclassified: list[str]
    required: list[PlannedCheck]
    optional: list[PlannedCheck]
    test_selection: dict[str, list[str]]
    warnings: list[PlanWarning]
    scope_paths: list[str]  # files the syntax check covers (not serialized: it can be the whole repository)
    empty_change: bool = False

    def to_dict(self) -> dict:
        return {
            "mode_requested": self.mode_requested,
            "mode_effective": self.mode_effective,
            "mode_reasons": self.mode_reasons,
            "empty_change": self.empty_change,
            "changed_files_total": self.files_total,
            "changed_files_truncated": self.files_total > len(self.files),
            "changed_files": self.files,
            "affected_subsystems": {"direct": self.direct, "impacted": self.impacted},
            "unclassified_paths": self.unclassified[:MAX_LIST],
            "required_checks": [c.to_dict() for c in self.required],
            "optional_checks": [c.to_dict() for c in self.optional],
            "test_selection": {k: sorted(set(v)) for k, v in sorted(self.test_selection.items())},
            "warnings": [w.to_dict() for w in self.warnings],
            "plan_hash": self.plan_hash(),
        }

    def plan_hash(self) -> str:
        """SHA-256 of WHAT will be validated for WHICH change effect (SHAs are provenance, not identity)."""
        core = {
            "engine": ENGINE_VERSION,
            "mode": self.mode_effective,
            "files": [(f["path"], f["status"], f.get("old_path")) for f in self.files],
            "required": [(c.id, c.params) for c in self.required],
            "optional": [c.id for c in self.optional],
        }
        return hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_plan(
    changes: ChangeSet, *, mode: str = Mode.TARGETED, include_lab: bool = False,
    all_tracked: Callable[[], list[str]] | None = None,
) -> ValidationPlan:
    if mode not in Mode.ALL:
        raise ValueError(f"unknown mode {mode!r}")

    per_file: list[dict] = []
    by_subsystem: dict[str, list[str]] = {}
    unclassified: list[str] = []
    ordered = sorted(set(changes.files), key=lambda f: (f.path, f.status, f.old_path or ""))  # order/duplicate independent
    for changed in ordered:
        subs: list[str] = []
        for path in changed.paths():
            for sub in classify.classify_path(path):
                if sub not in subs:
                    subs.append(sub)
                by_subsystem.setdefault(sub, []).append(path)
        if subs == [UNCLASSIFIED]:
            unclassified.append(changed.path)
        entry = {"path": changed.path, "status": changed.status, "subsystems": [s for s in subs if s != UNCLASSIFIED] or [UNCLASSIFIED]}
        if changed.old_path:
            entry["old_path"] = changed.old_path
        per_file.append(entry)

    direct = [s for s in classify.subsystem_order() if s in by_subsystem]
    impacted_map = classify.expand_impact(set(direct))

    mode_reasons: list[str] = []
    effective = Mode.TARGETED
    if mode == Mode.FULL:
        effective = Mode.FULL
        mode_reasons.append("full regression was requested")
    if changes.strategy == STRATEGY_ALL_TRACKED:
        effective = Mode.FULL
        mode_reasons.append("no comparison base: every tracked file is treated as changed, so the whole regression surface is required")
    if unclassified:
        effective = Mode.FULL
        mode_reasons.append(f"{len(unclassified)} path(s) match no classification rule (conservative full validation): {', '.join(sorted(unclassified)[:3])}")
    if not mode_reasons:
        mode_reasons.append("targeted validation from the change-effect analysis")

    reasons_by_check: dict[str, list[str]] = {}
    test_selection: dict[str, list[str]] = {}
    lab_reasons: dict[str, list[str]] = {}
    flags = {"full_django": False, "monitoring": False, "grafana": False}

    def note(check_id: str, reason: str) -> None:
        reasons_by_check.setdefault(check_id, []).append(reason)

    def select(subsystem: str, why: str, *, django_only: bool = False) -> None:
        selection = rules.SELECTIONS.get(subsystem)
        if selection is None:
            return
        if selection.full_django:
            flags["full_django"] = True
            test_selection.setdefault("core", []).append(why)
        for name in selection.django:
            test_selection.setdefault(f"core.tests.test_{name}", []).append(why)
        if django_only:  # a foundational Django change implies the Django surface, not monitoring / lab verifiers
            return
        if selection.monitoring_unit:
            flags["monitoring"] = True
            note("monitoring.unit", why)
        if selection.grafana_drift:
            flags["grafana"] = True
            note("grafana.drift", why)
        for lab in selection.lab:
            lab_reasons.setdefault(f"lab.{lab}", []).append(why)

    for sub in direct:
        paths = sorted(set(by_subsystem[sub]))
        extra = f" +{len(paths) - 1} more" if len(paths) > 1 else ""
        title = rules.SUBSYSTEMS[sub].title
        selection = rules.SELECTIONS.get(sub)
        why = f"{selection.reason if selection else title + ' changed'} [{paths[0]}{extra}]"
        select(sub, why)
    for sub, impact in impacted_map.items():
        chain = " -> ".join(impact.via)
        select(sub, f"{rules.SUBSYSTEMS[sub].title} is affected via {chain}: {impact.reason}", django_only=impact.wide)

    # a changed Django test module is itself the most direct regression for that change
    for changed in ordered:
        match = _TEST_MODULE_RE.match(changed.path)
        if match and changed.status != FileStatus.DELETED:
            test_selection.setdefault(f"core.tests.test_{match.group(1)}", []).append(f"test module itself changed [{changed.path}]")
    for changed in ordered:
        for pattern, name, why in rules.PATH_SELECTIONS:
            if any(rules.glob_match(pattern, p) for p in changed.paths()):
                test_selection.setdefault(f"core.tests.test_{name}", []).append(f"{why} [{changed.path}]")

    required: list[PlannedCheck] = []

    def add(check_id: str, reasons: list[str], params: dict | None = None, *, required_flag: bool = True, into=None) -> PlannedCheck:
        definition = CHECKS[check_id]
        planned = PlannedCheck(check_id, definition.gate, definition.title, required_flag, list(reasons), params or {})
        (into if into is not None else required).append(planned)
        return planned

    baseline = "baseline gate: runs for every change"
    add("static.hygiene", [baseline])
    add("static.syntax", [baseline])
    add("django.check", [baseline])
    add("django.migrations", [baseline])
    add("governance.catalog", [baseline + " (Lab 7 test catalog)"])

    full_reasons = list(mode_reasons)
    if effective == Mode.FULL:
        add("quality.pylint", full_reasons + ["full: every deployed Python artifact"])
        governance = "full regression: the suites run traced under coverage.py to produce the Lab 7 test-governance evidence"
        add("django.tests", full_reasons + [governance], {"labels": ["core"], "governance": True})
        add("monitoring.unit", full_reasons + [governance], {"governance": True})
        add("grafana.drift", full_reasons)
        add("governance.report", [governance])
    else:
        labels: list[str] = []
        reasons: list[str] = []
        if flags["full_django"]:
            labels = ["core"]
            reasons = test_selection.get("core", [])
        elif test_selection:
            labels = sorted(test_selection)
            for label in labels:
                reasons.extend(test_selection[label])
        if labels:
            add("django.tests", reasons, {"labels": labels})
        if flags["monitoring"]:
            add("monitoring.unit", reasons_by_check.get("monitoring.unit", []))
        if flags["grafana"]:
            add("grafana.drift", reasons_by_check.get("grafana.drift", []))
        changed_python = sorted({f.path for f in ordered if f.status != FileStatus.DELETED and f.path.endswith(".py")
                                 and not _TEST_PATH_RE.match(f.path)})
        if changed_python:
            add("quality.pylint", [f"changed Python file(s): {', '.join(changed_python[:3])}{' ...' if len(changed_python) > 3 else ''}"],
                {"paths": changed_python[:MAX_LIST]})

    if effective == Mode.FULL:
        lab_ids = [f"lab.{key}" for key in rules.LAB_VERIFIERS]
        for lab_id in lab_ids:
            lab_reasons.setdefault(lab_id, []).append("full regression: lab-backed verifier in the final gate")
    optional: list[PlannedCheck] = []
    for lab_id in sorted(lab_reasons, key=CHECK_ORDER.__getitem__):
        add(lab_id, lab_reasons[lab_id], required_flag=include_lab, into=required if include_lab else optional)

    required.sort(key=lambda c: CHECK_ORDER[c.id])

    # syntax scope
    scope_set = {f.path for f in ordered if f.status != FileStatus.DELETED}
    if effective == Mode.FULL and all_tracked is not None:
        scope_set |= set(all_tracked())  # the whole repository, plus any new uncommitted files in the change
    scope = sorted(scope_set)

    warnings = _path_warnings(changes, unclassified)

    return ValidationPlan(
        mode_requested=mode, mode_effective=effective, mode_reasons=mode_reasons,
        files=per_file[:MAX_CHANGED_FILES], files_total=len(per_file),
        direct=direct,
        impacted=[{"id": s, "via": list(i.via), "reason": i.reason} for s, i in impacted_map.items()],
        unclassified=sorted(unclassified), required=required, optional=optional,
        test_selection=test_selection, warnings=warnings, scope_paths=scope, empty_change=changes.empty,
    )


def _path_warnings(changes: ChangeSet, unclassified: list[str]) -> list[PlanWarning]:
    warnings: list[PlanWarning] = []
    if unclassified:
        warnings.append(PlanWarning(
            rules.WARN_UNCLASSIFIED, "path(s) match no Tier-3 classification rule; full validation was used. Add a rule in ci/rules.py.", sorted(unclassified)))
    if changes.strategy == STRATEGY_ALL_TRACKED:  # synthetic "added" statuses: per-path warnings would be noise
        return warnings
    frozen, runtime, migrations = [], [], []
    for changed in changes.files:
        for path in changed.paths():
            subs = classify.classify_path(path)
            if any(rules.SUBSYSTEMS[s].frozen for s in subs if s in rules.SUBSYSTEMS):
                frozen.append(path)
            if "runtime_artifacts" in subs:
                runtime.append(path)
        touched = [changed.old_path] if changed.old_path else []
        if changed.status in (FileStatus.MODIFIED, FileStatus.DELETED):
            touched.append(changed.path)
        migrations.extend(p for p in touched if _MIGRATION_RE.match(p))
    if frozen:
        warnings.append(PlanWarning(rules.WARN_FROZEN, "frozen Lab-1 baseline file changed; this needs explicit authorization", sorted(set(frozen))))
    if runtime:
        warnings.append(PlanWarning(rules.WARN_RUNTIME, "runtime log / cache / local-state file changed; it should stay out of source commits", sorted(set(runtime))))
    if migrations:
        warnings.append(PlanWarning(rules.WARN_MIGRATION, "an existing migration was modified, deleted or renamed; migrations are append-only history", sorted(set(migrations))))
    return warnings
