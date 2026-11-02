"""Declared test cases: explicit, machine-readable metadata ON the test that proves the case (one place, no copy).

    from core.services.test_governance.cases import case, NEGATIVE

    @case("CONFIG_IMPORT_UNKNOWN_ROUTING_FAMILY", target="web/core/services/config_import/service.py::import_config",
          polarity=NEGATIVE, condition="unsupported routing family in the parsed configuration",
          expected="import fails closed; no intent is written")
    def test_unknown_family_fails_closed(self): ...

The decorator only attaches metadata (it never changes how the test runs).  The tracer reads it when the test starts,
so the evidence run records exactly which declared cases ran and how they ended.  ``catalog.validate_declared``
checks every declaration (unique id, real target artifact / symbol, valid polarity / platform / feature) and the
tracked baseline locks every declared id: deleting the test that proves a case makes the case BROKEN_REFERENCE.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .constants import CELL_STAGES, Polarity

POSITIVE, NEGATIVE = Polarity.POSITIVE, Polarity.NEGATIVE
CASE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?::[A-Za-z0-9_.\-/|]+)*$")
STAGES = tuple(stage for stage, _title in CELL_STAGES)


@dataclass(frozen=True)
class Case:
    case_id: str
    target: str            # "<repo path>" (an artifact) or "<repo path>::<qualified name>" (a symbol)
    polarity: str
    condition: str
    expected: str
    requirement: str = ""  # requirement / risk the case covers
    platform: str = ""
    feature: str = ""
    stage: str = ""

    @property
    def artifact_path(self) -> str:
        return self.target.split("::", 1)[0]

    @property
    def symbol(self) -> str:
        return self.target if "::" in self.target else ""

    def to_dict(self) -> dict:
        return {"case_id": self.case_id, "target": self.target, "polarity": self.polarity, "condition": self.condition,
                "expected": self.expected, "requirement": self.requirement, "platform": self.platform, "feature": self.feature,
                "stage": self.stage}

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        return cls(**{k: str(data.get(k) or "") for k in ("case_id", "target", "polarity", "condition", "expected", "requirement",
                                                         "platform", "feature", "stage")})


def shape_errors(item: Case) -> list[str]:
    """Problems detectable without the repository (the catalog validator adds the repository checks)."""
    errors = []
    if not CASE_ID_RE.match(item.case_id):
        errors.append(f"{item.case_id!r}: case id must be UPPER_SNAKE (optionally ':'-qualified)")
    if item.polarity not in Polarity.ALL:
        errors.append(f"{item.case_id}: polarity must be POSITIVE or NEGATIVE, not {item.polarity!r}")
    if not item.target or item.target.startswith("/") or ".." in item.target.split("::", 1)[0].split("/"):
        errors.append(f"{item.case_id}: target must be a repository-relative artifact path (optionally ::symbol)")
    if not item.condition.strip() or not item.expected.strip():
        errors.append(f"{item.case_id}: condition and expected result are required")
    if item.stage and item.stage not in STAGES:
        errors.append(f"{item.case_id}: unknown lifecycle stage {item.stage!r}")
    if bool(item.platform) != bool(item.feature):
        errors.append(f"{item.case_id}: platform and feature are declared together")
    return errors


def case(case_id: str, *, target: str, polarity: str, condition: str, expected: str, requirement: str = "",
         platform: str = "", feature: str = "", stage: str = ""):
    """Attach one declared case to a test method (stackable: one test may prove several cases)."""
    item = Case(case_id, target, polarity, condition, expected, requirement, platform, feature, stage)
    problems = shape_errors(item)
    if problems:
        raise ValueError("; ".join(problems))  # a malformed declaration breaks test import loudly, never silently

    def decorate(func):
        existing = list(getattr(func, "_tg_cases", ()))
        existing.append(item)
        func._tg_cases = tuple(existing)
        return func

    return decorate


def declared_on(func) -> tuple[Case, ...]:
    return tuple(getattr(func, "_tg_cases", ()) or ())
