"""Load and validate ``policy.yml`` (the repository-owned scope / exemption / mapping policy).

A malformed policy is a catalog error (Tier-3 fails closed); it is never silently replaced by defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from ..ci.rules import glob_match
from .constants import POLICY_FILE


class PolicyError(ValueError):
    """The policy file is missing, malformed or internally inconsistent."""


@dataclass(frozen=True)
class Rule:
    pattern: str
    reason: str


@dataclass(frozen=True)
class Group:
    id: str
    title: str
    paths: tuple[str, ...] = ()
    subsystems: tuple[str, ...] = ()


@dataclass(frozen=True)
class Policy:
    exclude: tuple[Rule, ...]
    artifact_exemptions: tuple[Rule, ...]
    symbol_exemptions: dict[str, str]
    platform_dirs: dict[str, str]
    platform_artifacts: dict[str, str]
    template_features: dict[str, tuple[str, ...]]
    generic_groups: tuple[Group, ...]
    negative_intent_words: frozenset[str] = field(default_factory=frozenset)
    pylint_false_positives: dict[tuple[str, str], str] = field(default_factory=dict)
    assignment_examples: tuple[dict, ...] = ()
    external_consumers: tuple[Rule, ...] = ()

    def external_consumer(self, path: str) -> Rule | None:
        return next((r for r in self.external_consumers if glob_match(r.pattern, path)), None)

    def pylint_false_positive(self, path: str, symbol: str) -> str:
        return self.pylint_false_positives.get((path, symbol), "")

    def excluded(self, path: str) -> Rule | None:
        return next((r for r in self.exclude if glob_match(r.pattern, path)), None)

    def exemption(self, path: str) -> Rule | None:
        return next((r for r in self.artifact_exemptions if glob_match(r.pattern, path)), None)

    def group_for(self, path: str, subsystems: tuple[str, ...]) -> Group:
        for group in self.generic_groups:
            if any(glob_match(p, path) for p in group.paths):
                return group
        for group in self.generic_groups:
            if any(s in group.subsystems for s in subsystems):
                return group
        return Group("unclassified", "Unclassified")


def _rules(raw, name: str) -> tuple[Rule, ...]:
    if not isinstance(raw, list):
        raise PolicyError(f"{name} must be a list")
    out = []
    for item in raw:
        if not isinstance(item, dict) or not str(item.get("pattern") or "").strip() or not str(item.get("reason") or "").strip():
            raise PolicyError(f"every {name} entry needs a non-empty pattern AND reason: {item!r}")
        out.append(Rule(str(item["pattern"]), str(item["reason"])))
    return tuple(out)


def parse_policy(data) -> Policy:
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise PolicyError("policy schema_version must be 1")
    sym = data.get("symbol_exemptions") or []
    if not isinstance(sym, list):
        raise PolicyError("symbol_exemptions must be a list")
    symbol_exemptions: dict[str, str] = {}
    for item in sym:
        target, reason = str((item or {}).get("symbol") or ""), str((item or {}).get("reason") or "").strip()
        if "::" not in target or not reason:
            raise PolicyError(f"a symbol exemption needs 'path::qualname' and a reason: {item!r}")
        if target in symbol_exemptions:
            raise PolicyError(f"duplicate symbol exemption {target}")
        symbol_exemptions[target] = reason
    for key in ("platform_dirs", "platform_artifacts", "template_features"):
        if not isinstance(data.get(key), dict):
            raise PolicyError(f"{key} must be a mapping")
    groups, seen = [], set()
    for item in data.get("generic_groups") or []:
        gid = str((item or {}).get("id") or "")
        if not gid or gid in seen or not str(item.get("title") or ""):
            raise PolicyError(f"generic group needs a unique id and a title: {item!r}")
        if not (item.get("paths") or item.get("subsystems")):
            raise PolicyError(f"generic group {gid} matches nothing (no paths, no subsystems)")
        seen.add(gid)
        groups.append(Group(gid, str(item["title"]), tuple(item.get("paths") or ()), tuple(item.get("subsystems") or ())))
    if not groups:
        raise PolicyError("generic_groups is empty")
    words = data.get("negative_intent_words") or []
    if not isinstance(words, list) or not all(isinstance(w, str) and w.isidentifier() for w in words):
        raise PolicyError("negative_intent_words must be a list of lower-case words")
    false_positives: dict[tuple[str, str], str] = {}
    for item in data.get("pylint_false_positives") or []:
        key = (str((item or {}).get("path") or ""), str((item or {}).get("symbol") or ""))
        if not all(key) or not str(item.get("reason") or "").strip():
            raise PolicyError(f"a Pylint false positive needs path, symbol and reason: {item!r}")
        false_positives[key] = str(item["reason"])
    examples = []
    for item in data.get("assignment_examples") or []:
        targets = (item or {}).get("targets") or []
        if not str(item.get("requirement") or "") or not targets or not all(isinstance(t, str) and "::" in t for t in targets):
            raise PolicyError(f"an assignment example needs a requirement and 'path::qualname' targets: {item!r}")
        examples.append({"requirement": str(item["requirement"]), "description": str(item.get("description") or ""),
                         "targets": tuple(targets)})
    return Policy(
        external_consumers=_rules(data.get("external_consumers") or [], "external_consumers"),
        assignment_examples=tuple(examples),
        pylint_false_positives=false_positives,
        exclude=_rules(data.get("exclude") or [], "exclude"),
        artifact_exemptions=_rules(data.get("artifact_exemptions") or [], "artifact_exemptions"),
        symbol_exemptions=symbol_exemptions,
        platform_dirs={str(k): str(v) for k, v in data["platform_dirs"].items()},
        platform_artifacts={str(k): str(v) for k, v in data["platform_artifacts"].items()},
        template_features={str(k): tuple(str(f) for f in v) for k, v in data["template_features"].items()},
        generic_groups=tuple(groups),
        negative_intent_words=frozenset(w.lower() for w in words),
    )


def load_policy(path: Path | None = None) -> Policy:
    target = Path(path or POLICY_FILE)
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"cannot read {target.name}: {type(exc).__name__}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"{target.name} is not valid YAML") from exc
    return parse_policy(data)


@lru_cache(maxsize=1)
def default_policy() -> Policy:
    return load_policy()
