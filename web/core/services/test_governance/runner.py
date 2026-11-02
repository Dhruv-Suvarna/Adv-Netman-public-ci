"""Run one complete evidence collection: traced tests under coverage.py, Pylint, then the report and the gate.

    nmas_nmas_test_governance run --out DIR        (management command)  =  this module's :func:`run_evidence`

Every command is a fixed argument vector (no shell, no user-supplied argv); child processes get a minimal environment
(no token, webhook, credential or lab address).  Device-facing code is exercised only through the suites' own fakes:
nothing here contacts a device, NetBox, GitHub or the lab.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .constants import REPO_ROOT, REPORT_FILENAME, ArtifactType, Scope

# DISPLAY / XAUTHORITY: an X display name and cookie-file path (no secret value) so the Tk console tests run under xvfb-run, exactly as
# in Tier-3.  Run the evidence collection as ``xvfb-run -a ... nmas_test_governance run``; without a display those cases stay MISSING.
SAFE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "VIRTUAL_ENV", "DISPLAY", "XAUTHORITY")
GITHUB_PROVENANCE_KEYS = ("GITHUB_RUN_ID", "GITHUB_REPOSITORY", "GITHUB_REF_NAME", "GITHUB_EVENT_NAME", "GITHUB_SHA", "GITHUB_SERVER_URL")
SUITE_TIMEOUT = 3600
PYLINT_TIMEOUT = 900


@dataclass
class StepResult:
    name: str
    returncode: int | None
    tail: str = ""


@dataclass
class EvidenceRun:
    out: Path
    steps: list[StepResult] = field(default_factory=list)

    @property
    def traces(self) -> list[Path]:
        return [p for p in (self.out / "django-trace.json", self.out / "monitoring-trace.json") if p.is_file()]


def child_env(extra: dict | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "DJANGO_DEBUG": "true"})
    env.update(extra or {})
    return env


def _run(name: str, argv: list[str], *, cwd: Path, env: dict, timeout: int, stdout_path: Path | None = None) -> StepResult:
    try:
        proc = subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout, shell=False,  # noqa: S603
                              errors="replace")
    except subprocess.TimeoutExpired:
        return StepResult(name, None, f"timed out after {timeout}s")
    except OSError as exc:
        return StepResult(name, None, f"could not start: {type(exc).__name__}")
    if stdout_path is not None:
        stdout_path.write_text(proc.stdout or "", encoding="utf-8")
        text = proc.stderr or ""
    else:
        text = (proc.stdout or "") + (proc.stderr or "")
    return StepResult(name, proc.returncode, text[-3000:])


def suite_commands(out: Path, *, python: str, labels: tuple[str, ...] = ("core",), repo: Path = REPO_ROOT) -> list[tuple[str, list[str], Path, dict]]:
    rc = str(repo / ".coveragerc")
    return [
        ("django.tests", [python, "-m", "coverage", "run", f"--rcfile={rc}", f"--data-file={out / '.coverage.django'}", "manage.py", "test", *labels],
         repo / "web", {"NMAS_TG_REPO": str(repo), "NMAS_TG_TRACE_OUT": str(out / "django-trace.json")}),
        ("monitoring.unit", [python, "-m", "coverage", "run", f"--rcfile={rc}", f"--data-file={out / '.coverage.monitoring'}",
                             "web/core/services/test_governance/traced_unittest.py", "discover", "-s", "monitoring/tests", "-p", "test_*.py"],
         repo, {"NMAS_TG_REPO": str(repo), "NMAS_TG_TRACE_OUT": str(out / "monitoring-trace.json")}),
    ]


def lint_paths(repo: Path = REPO_ROOT) -> list[str]:
    from . import inventory

    inv = inventory.build_inventory(repo)
    return [a.path for a in inv.artifacts if a.type == ArtifactType.PYTHON and a.scope != Scope.EXEMPT]


def run_pylint(out: Path, *, python: str, paths: list[str] | None = None, repo: Path = REPO_ROOT) -> StepResult:
    paths = lint_paths(repo) if paths is None else paths
    argv = [python, "-m", "pylint", f"--rcfile={repo / '.pylintrc'}", "--output-format=json2", "--exit-zero", *paths]
    result = _run("pylint", argv, cwd=repo, env=child_env({"NMAS_PYLINTRC": str(repo / ".pylintrc")}), timeout=PYLINT_TIMEOUT,
                  stdout_path=out / "pylint.json")
    (out / "pylint-paths.json").write_text(json.dumps(paths), encoding="utf-8")
    return result


def combine_coverage(out: Path, *, python: str, repo: Path = REPO_ROOT) -> list[StepResult]:
    rc = f"--rcfile={repo / '.coveragerc'}"
    data = f"--data-file={out / '.coverage'}"
    parts = [str(p) for p in (out / ".coverage.django", out / ".coverage.monitoring") if p.is_file()]
    env = child_env({"NMAS_TG_REPO": str(repo)})
    if parts:
        steps = [_run("coverage.combine", [python, "-m", "coverage", "combine", rc, data, "--keep", *parts], cwd=repo, env=env, timeout=600)]
    elif (out / ".coverage").is_file():
        # already combined (a second ``report`` over the same directory): the combined data file is the input
        steps = [StepResult("coverage.combine", 0, "already combined; reusing .coverage")]
    else:
        steps = [StepResult("coverage.combine", 1, "no coverage data in the output directory")]
    steps.append(_run("coverage.json", [python, "-m", "coverage", "json", rc, data, "-o", str(out / "coverage.json"), "--ignore-errors"],
                      cwd=repo, env=env, timeout=600))
    steps.append(_run("coverage.xml", [python, "-m", "coverage", "xml", rc, data, "-o", str(out / "coverage.xml"), "--ignore-errors"],
                      cwd=repo, env=env, timeout=600))
    return steps


def provenance_from_env(env=None) -> dict:
    env = os.environ if env is None else env
    out = {key.lower().replace("github_", ""): env[key][:200] for key in GITHUB_PROVENANCE_KEYS if env.get(key)}
    out["python"] = sys.version.split()[0]
    return out


def build_and_gate(out: Path, *, baseline: dict, repo: Path = REPO_ROOT, mode: str = "full", env=None) -> dict:
    from . import gate, report as report_module, schema

    pylint_json = out / "pylint.json" if (out / "pylint.json").is_file() else None
    linted = json.loads((out / "pylint-paths.json").read_text()) if (out / "pylint-paths.json").is_file() else None
    coverage_json = out / "coverage.json" if (out / "coverage.json").is_file() else None
    traces = [p for p in (out / "django-trace.json", out / "monitoring-trace.json") if p.is_file()]
    provenance = {**provenance_from_env(env), "mode": mode}
    data = report_module.assemble(trace_paths=traces, coverage_json=coverage_json, pylint_json=pylint_json, baseline=baseline,
                                  provenance=provenance, repo=repo, linted=linted)
    data["gate"] = gate.evaluate(data, baseline)
    data["payload_sha256"] = report_module.payload_hash(data)
    problems = schema.validate(data)
    if problems:
        raise ValueError("generated report violates its schema: " + "; ".join(problems[:5]))
    report_module.write_report(data, out / REPORT_FILENAME)
    return data


def run_evidence(out: Path, *, python: str | None = None, labels: tuple[str, ...] = ("core",), repo: Path = REPO_ROOT,
                 skip_pylint: bool = False, progress=None) -> EvidenceRun:
    python = python or sys.executable
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    run = EvidenceRun(out)
    emit = progress or (lambda _msg: None)
    for name, argv, cwd, extra in suite_commands(out, python=python, labels=labels, repo=repo):
        emit(f"running {name} (traced, under coverage) ...")
        run.steps.append(_run(name, argv, cwd=cwd, env=child_env(extra), timeout=SUITE_TIMEOUT))
    emit("combining coverage ...")
    run.steps.extend(combine_coverage(out, python=python, repo=repo))
    if not skip_pylint:
        emit("running Pylint ...")
        run.steps.append(run_pylint(out, python=python, repo=repo))
    return run
