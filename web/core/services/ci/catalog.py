"""The fixed Tier-3 check catalogue.

Every command Tier 3 can ever run is defined HERE, by id, with a fixed argument vector.  There is
no path from a browser, a Change, a Configlet, a pull-request title or a CLI string to an argv --
the only variable inputs are the Django test module labels the planner selects from its own table
(and those are validated against ``core.tests.<name>``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import rules
from .constants import DEFAULT_CHECK_TIMEOUT_SECONDS, Gate

STATIC_TIMEOUT = 300
LAB_TIMEOUT = 600
# The security-remediation full trace remained CPU-active when the old 3,600s
# bound expired. Keep a finite per-suite bound, but allow the expanded suite up
# to 90 minutes inside the workflow's separate two-hour job ceiling.
SUITE_TIMEOUT = 5400
GOVERNANCE_TIMEOUT = 1200
_MODULE_RE = re.compile(r"^[a-z][a-z0-9_]{0,80}$")
_LINT_PATH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}\.py$")
# Lab 7 test-governance output directory (repository-relative; ignored by Git; uploaded as the test-governance artifact)
GOVERNANCE_DIR = "tier3-governance"
# Non-secret GitHub provenance the governance report records (run id, repository, ref, event, commit) -- never a token
PROVENANCE_ENV = ("GITHUB_RUN_ID", "GITHUB_REPOSITORY", "GITHUB_REF_NAME", "GITHUB_EVENT_NAME", "GITHUB_SHA", "GITHUB_SERVER_URL")


@dataclass(frozen=True)
class CheckDef:
    id: str
    gate: str
    title: str
    kind: str  # "inprocess" | "command"
    timeout: int = DEFAULT_CHECK_TIMEOUT_SECONDS


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    cwd: str = "."                       # relative to the repository root
    env_extra: dict = field(default_factory=dict)
    inherit_env: bool = False            # True only for the explicit, operator-opted lab gate
    forward_env: tuple[str, ...] = ()    # named NON-SECRET variables copied from the caller when present (provenance only)


CHECK_LIST = (
    CheckDef("static.hygiene", Gate.STATIC, "Credential formats, conflict markers, credential-store files (added content)", "inprocess", STATIC_TIMEOUT),
    CheckDef("static.syntax", Gate.STATIC, "Python / JSON / YAML / Jinja / shell syntax", "inprocess", STATIC_TIMEOUT),
    CheckDef("django.check", Gate.STATIC, "Django system check", "command", STATIC_TIMEOUT),
    CheckDef("django.migrations", Gate.STATIC, "Django migration drift (makemigrations --check --dry-run)", "command", STATIC_TIMEOUT),
    CheckDef("governance.catalog", Gate.STATIC, "Lab 7 test catalog: inventory classification, declared cases, references, baseline locks", "command",
             STATIC_TIMEOUT),
    CheckDef("quality.pylint", Gate.STATIC, "Pylint quality gate (critical messages + tracked baseline)", "command", GOVERNANCE_TIMEOUT),
    CheckDef("django.tests", Gate.REPOSITORY, "Django regression tests", "command", SUITE_TIMEOUT),
    CheckDef("monitoring.unit", Gate.REPOSITORY, "Monitoring / NetBox / topology unit tests", "command", SUITE_TIMEOUT),
    CheckDef("grafana.drift", Gate.REPOSITORY, "Generated Grafana dashboard JSON drift", "command", STATIC_TIMEOUT),
    CheckDef("governance.report", Gate.REPOSITORY, "Lab 7 coverage evidence: statements / branches / functions / cases, schema, closure gate",
             "command", GOVERNANCE_TIMEOUT),
    *(CheckDef(f"lab.{key}", Gate.LAB, f"LAB: {meta[0]}", "command", LAB_TIMEOUT) for key, meta in rules.LAB_VERIFIERS.items()),
)
CHECKS: dict[str, CheckDef] = {c.id: c for c in CHECK_LIST}
CHECK_ORDER: dict[str, int] = {c.id: i for i, c in enumerate(CHECK_LIST)}

# Django needs a settings SECRET_KEY: Tier 3 always runs the offline gates in DEBUG mode with the
# settings' own fake development key, and never forwards the caller's secret-shaped environment.
DJANGO_ENV = {"DJANGO_DEBUG": "true"}


def valid_test_module(name: str) -> bool:
    return bool(_MODULE_RE.match(name))


def command_for(check_id: str, *, python: str, params: dict | None = None) -> Command:
    params = params or {}
    if check_id == "django.check":
        return Command((python, "manage.py", "check"), cwd="web", env_extra=DJANGO_ENV)
    if check_id == "django.migrations":
        return Command((python, "manage.py", "makemigrations", "--check", "--dry-run"), cwd="web", env_extra=DJANGO_ENV)
    if check_id == "django.tests":
        labels = list(params.get("labels") or ["core"])
        for label in labels:
            if label != "core" and not (label.startswith("core.tests.") and valid_test_module(label[len("core.tests."):])):
                raise ValueError(f"refusing unexpected Django test label {label!r}")
        if params.get("governance"):  # FULL mode: the same suite, traced and under coverage.py (one run, two results)
            return Command((python, "-m", "coverage", "run", "--rcfile=../.coveragerc", f"--data-file=../{GOVERNANCE_DIR}/.coverage.django",
                            "manage.py", "test", "--verbosity", "2", *labels), cwd="web",
                           env_extra={**DJANGO_ENV, "NMAS_TG_REPO": "..", "NMAS_TG_TRACE_OUT": f"../{GOVERNANCE_DIR}/django-trace.json"})
        return Command((python, "manage.py", "test", *labels), cwd="web", env_extra=DJANGO_ENV)
    if check_id == "monitoring.unit":
        if params.get("governance"):
            return Command((python, "-m", "coverage", "run", "--rcfile=.coveragerc", f"--data-file={GOVERNANCE_DIR}/.coverage.monitoring",
                            "web/core/services/test_governance/traced_unittest.py", "discover", "-s", "monitoring/tests", "-p", "test_*.py"),
                           env_extra={"NMAS_TG_REPO": ".", "NMAS_TG_TRACE_OUT": f"{GOVERNANCE_DIR}/monitoring-trace.json"})
        return Command((python, "-m", "unittest", "discover", "-s", "monitoring/tests", "-p", "test_*.py"))
    if check_id == "governance.catalog":
        return Command((python, "manage.py", "nmas_test_governance", "validate-catalog", "--ci"), cwd="web", env_extra=DJANGO_ENV)
    if check_id == "quality.pylint":
        paths = list(params.get("paths") or [])
        for path in paths:
            if not _LINT_PATH_RE.match(path) or ".." in path.split("/"):
                raise ValueError(f"refusing unexpected Pylint path {path!r}")
        return Command((python, "manage.py", "nmas_test_governance", "pylint", "--ci", "--out", f"../{GOVERNANCE_DIR}",
                        *(("--paths", *paths) if paths else ())), cwd="web", env_extra=DJANGO_ENV)
    if check_id == "governance.report":
        return Command((python, "manage.py", "nmas_test_governance", "report", "--ci", "--dir", f"../{GOVERNANCE_DIR}", "--mode", "full"),
                       cwd="web", env_extra=DJANGO_ENV, forward_env=PROVENANCE_ENV)
    if check_id == "grafana.drift":
        return Command((python, "monitoring/scripts/build_grafana_dashboards.py", "--check"))
    if check_id.startswith("lab."):
        _title, script, extra, interpreter = rules.LAB_VERIFIERS[check_id[4:]]
        exe = python if interpreter == "python" else "bash"
        return Command((exe, script, *extra), inherit_env=True)
    raise KeyError(check_id)
