"""Discover and classify every DEPLOYED automation artifact of the repository (deterministic, read-only).

Discovery is from Git (tracked + untracked-not-ignored files), so a new file is seen the moment it exists -- nobody has
to remember to list it.  Classification reuses the ONE Tier-3 path table (``ci/rules.py`` via ``ci/classify.py``) for
the subsystem, ``policy.yml`` for exclusions / exemptions / platform mapping, and the capability ledger for the
current-scope decision of platform-specific artifacts.  An artifact that no rule classifies is a catalog error.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from ..ci import classify, gitio
from ..ci.rules import SUBSYSTEMS, UNCLASSIFIED
from . import cells as cells_module
from .constants import REPO_ROOT, ArtifactType, Scope
from .policy import Policy, default_policy

TEST_ROOTS = ("web/core/tests/", "monitoring/tests/", "challenge_console/tests/")
_TEST_KINDS = ("test", "doc", "runtime", "meta")

# (path glob, deploy/runtime role) -- first match wins; presentation only.
ROLE_RULES = (
    ("web/core/management/commands/*.py", "Django management command"),
    ("web/core/services/**", "backend service"),
    ("web/core/*views*.py", "website view"),
    ("web/core/urls.py", "website routes"),
    ("web/core/models.py", "data model"),
    ("web/core/middleware.py", "website access boundary"),
    ("web/core/**", "Django application"),
    ("web/config/**", "Django project configuration"),
    ("web/manage.py", "Django entry point"),
    ("modules/**", "network automation module"),
    ("master.py", "network automation orchestrator"),
    ("hostserv.py", "network automation host services"),
    ("address_report.py", "network automation report"),
    ("monitoring/scripts/*.sh", "monitoring installer / launcher"),
    ("monitoring/scripts/**", "monitoring script"),
    ("monitoring/config/**", "monitoring policy / configuration"),
    ("monitoring/**", "monitoring stack"),
    ("netbox/scripts/**", "NetBox integration script"),
    ("netbox/**", "NetBox stack configuration"),
    ("templates/features/**", "feature configuration template"),
    ("templates/monitoring/**", "monitoring configuration template"),
    ("templates/baselines/**", "intent template baseline"),
    ("templates/*.cfg.j2", "Lab-1 device configuration template"),
    ("dhcp/**", "DHCP server template"),
    ("deploy/systemd/**", "systemd unit"),
    ("deploy/scripts/**", "deployment installer"),
    ("deploy/**", "deployment configuration"),
    (".github/**", "CI workflow"),
    ("tier3.py", "CI launcher"),
    ("scripts/ci/**", "CI launcher"),
    ("scripts/**", "operator launcher"),
    ("tools/**", "developer tooling"),
    ("challenge_console/**", "operations console"),
    ("inventory.yml", "lab inventory"),
    ("*.clab.yml", "lab topology definition"),
)


@dataclass(frozen=True)
class Artifact:
    id: str
    path: str
    type: str
    subsystems: tuple[str, ...]
    group: str
    group_title: str
    role: str
    platform: str = ""
    features: tuple[str, ...] = ()
    scope: str = Scope.CURRENT
    scope_reason: str = ""
    sha256: str = ""
    classified: bool = True
    variables: tuple[str, ...] = ()   # Jinja templates: the top-level variables the template references

    @property
    def subsystem(self) -> str:
        return self.subsystems[0] if self.subsystems else UNCLASSIFIED

    def to_dict(self) -> dict:
        return {
            "id": self.id, "path": self.path, "type": self.type, "subsystems": list(self.subsystems), "group": self.group,
            "group_title": self.group_title, "role": self.role, "platform": self.platform, "features": list(self.features),
            "scope": self.scope, "scope_reason": self.scope_reason, "sha256": self.sha256, "classified": self.classified,
            "variables": list(self.variables),
        }


@dataclass
class Inventory:
    artifacts: list[Artifact]
    test_files: list[str]
    errors: list[str] = field(default_factory=list)

    def by_id(self) -> dict[str, Artifact]:
        return {a.id: a for a in self.artifacts}

    def by_path(self) -> dict[str, Artifact]:
        return {a.path: a for a in self.artifacts}


def artifact_type(path: str) -> str | None:
    name = PurePosixPath(path).name
    if name == "Dockerfile" or name.endswith(".Dockerfile"):
        return ArtifactType.DOCKERFILE
    suffix = PurePosixPath(path).suffix.lower()
    return {
        ".py": ArtifactType.PYTHON, ".j2": ArtifactType.JINJA, ".yml": ArtifactType.YAML, ".yaml": ArtifactType.YAML,
        ".json": ArtifactType.JSON, ".sh": ArtifactType.SHELL, ".service": ArtifactType.SYSTEMD, ".timer": ArtifactType.SYSTEMD,
        ".socket": ArtifactType.SYSTEMD, ".conf": ArtifactType.CONFIG,
    }.get(suffix)


def artifact_id(kind: str, path: str) -> str:
    return f"{kind}:{path}"


def role_for(path: str) -> str:
    from ..ci.rules import glob_match

    return next((role for pattern, role in ROLE_RULES if glob_match(pattern, path)), "repository file")


def is_test_file(path: str) -> bool:
    return path.endswith(".py") and any(path.startswith(root) for root in TEST_ROOTS)


def list_repository_files(repo: Path = REPO_ROOT) -> list[str]:
    """Tracked + untracked-not-ignored files (so a brand-new uncommitted module is visible), existing on disk."""
    try:
        out = gitio.run_git(repo, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        paths = sorted({p for p in out.split("\0") if p})
    except gitio.GitError:
        # Not a git checkout (e.g. an exported tree): walk the filesystem.  .git-like dirs are never artifacts.
        paths = sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_file() and ".git" not in p.parts)
    return [p for p in paths if (repo / p).is_file()]


def _sha256(repo: Path, path: str) -> str:
    return hashlib.sha256((repo / path).read_bytes()).hexdigest()


def classify_artifact(path: str, kind: str, *, policy: Policy, supported: frozenset, supported_platforms: frozenset,
                      sha256: str = "") -> Artifact:
    subsystems = tuple(s for s in classify.classify_path(path) if s == UNCLASSIFIED or SUBSYSTEMS[s].kind not in _TEST_KINDS)
    if not subsystems:
        subsystems = classify.classify_path(path)
    classified = UNCLASSIFIED not in subsystems
    group = policy.group_for(path, subsystems)
    platform, features, scope, reason = "", (), Scope.CURRENT, ""

    parts = PurePosixPath(path).parts
    if kind == ArtifactType.JINJA and len(parts) == 4 and parts[0] == "templates" and parts[1] == "features":
        platform = policy.platform_dirs.get(parts[2], "")
        stem = PurePosixPath(path).stem
        features = policy.template_features.get(stem, ())
        if not platform or not features:
            classified = False
            reason = "feature template has no platform / feature mapping in policy.yml"
    elif path in policy.platform_artifacts:
        platform = policy.platform_artifacts[path]

    exemption = policy.exemption(path)
    if exemption:
        scope, reason = Scope.EXEMPT, exemption.reason
    elif features:
        live = sorted(f for f in features if (platform, f) in supported)
        if not live:
            scope = Scope.NOT_CURRENT_SCOPE
            reason = f"no SUPPORTED capability cell for {platform} x {', '.join(features)} (capability matrix)"
        else:
            reason = f"renders SUPPORTED cell(s): {', '.join(live)}"
    elif platform and platform not in supported_platforms:
        scope = Scope.NOT_CURRENT_SCOPE
        reason = f"{platform} has no SUPPORTED capability cell (capability matrix)"
    return Artifact(artifact_id(kind, path), path, kind, subsystems, group.id, group.title, role_for(path), platform, features,
                    scope, reason, sha256, classified)


def build_inventory(repo: Path = REPO_ROOT, *, files: list[str] | None = None, policy: Policy | None = None,
                    cells: tuple | None = None) -> Inventory:
    policy = policy or default_policy()
    cell_rows = cells if cells is not None else cells_module.default_cells()
    supported = cells_module.supported_cells(cell_rows)
    platforms = cells_module.supported_platforms(cell_rows)
    files = list_repository_files(repo) if files is None else sorted(set(files))
    artifacts: list[Artifact] = []
    tests: list[str] = []
    errors: list[str] = []
    for path in files:
        if is_test_file(path):
            tests.append(path)
            continue
        kind = artifact_type(path)
        if kind is None or policy.excluded(path):
            continue
        digest = _sha256(repo, path) if (repo / path).is_file() else ""
        artifact = classify_artifact(path, kind, policy=policy, supported=supported, supported_platforms=platforms, sha256=digest)
        if not artifact.classified:
            errors.append(f"UNCLASSIFIED_ARTIFACT {artifact.id}: {artifact.scope_reason or 'no Tier-3 subsystem rule matches (ci/rules.py)'}")
        artifacts.append(artifact)
    artifacts = _template_facts(repo, artifacts)
    return Inventory(artifacts, tests, errors)


def template_variables(source: str) -> tuple[str, ...]:
    from jinja2 import Environment, TemplateSyntaxError, meta

    try:
        return tuple(sorted(meta.find_undeclared_variables(Environment().parse(source))))
    except TemplateSyntaxError:
        return ()


def _template_facts(repo: Path, artifacts: list[Artifact]) -> list[Artifact]:
    """Record each template's variables, and mark a non-feature template that NO deployed artifact references as unused.

    Feature templates are reached through the capability mapping (policy.yml); every other template must be named by
    its producer (inventory.yml, a renderer, an include).  An unreferenced template is not deployed behavior, so it is
    NOT_CURRENT_SCOPE rather than missing current-scope coverage."""
    from dataclasses import replace

    texts = {}
    for artifact in artifacts:
        if artifact.type in (ArtifactType.PYTHON, ArtifactType.YAML, ArtifactType.SHELL, ArtifactType.JINJA):
            try:
                texts[artifact.path] = (repo / artifact.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                texts[artifact.path] = ""
    out = []
    for artifact in artifacts:
        if artifact.type != ArtifactType.JINJA:
            out.append(artifact)
            continue
        artifact = replace(artifact, variables=template_variables(texts.get(artifact.path, "")))
        if artifact.scope == Scope.CURRENT and not artifact.path.startswith("templates/features/"):
            name = PurePosixPath(artifact.path).name
            if not any(name in text for path, text in texts.items() if path != artifact.path):
                artifact = replace(artifact, scope=Scope.NOT_CURRENT_SCOPE,
                                   scope_reason="no deployed producer references this template (unused; not deployed behavior)")
        out.append(artifact)
    return out


def fingerprint(inventory: Inventory, repo: Path = REPO_ROOT, *, extra: tuple[Path, ...] = ()) -> str:
    """SHA-256 over every deployed artifact, every test file and the governance policy -- the evidence inputs.

    Two checkouts with the same fingerprint produce the same evidence (documentation-only commits do not change it)."""
    digest = hashlib.sha256()
    rows = [(a.path, a.sha256) for a in inventory.artifacts]
    rows += [(t, _sha256(repo, t)) for t in inventory.test_files if (repo / t).is_file()]
    for path in extra:
        if path.is_file():
            rows.append((path.relative_to(repo).as_posix() if path.is_relative_to(repo) else path.name,
                         hashlib.sha256(path.read_bytes()).hexdigest()))
    for path, sha in sorted(set(rows)):
        digest.update(f"{path}\0{sha}\n".encode())
    return digest.hexdigest()


def head_sha(repo: Path = REPO_ROOT) -> str:
    try:
        out = gitio.run_git(repo, ["rev-parse", "HEAD"]).strip()
    except gitio.GitError:
        return ""
    return out if len(out) == 40 else ""
