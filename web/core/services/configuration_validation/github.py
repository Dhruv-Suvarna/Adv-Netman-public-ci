"""The GitHub REST API, as far as Configuration Validation needs it: one dispatch, one run lookup, one job list.

The ONLY module that talks to GitHub.  The token is read from the protected runtime environment at call time
(``settings.NMAS_GITHUB_TOKEN_ENV``); it is never stored on a model, logged, placed in a template context or included
in an error.  Standard library only, bounded, one attempt: a failure is a result (``GitHubError`` with a fixed code),
never a retry loop inside a web request.
"""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.conf import settings

TIMEOUT_SECONDS = 8
NOT_CONFIGURED, REFUSED, UNREACHABLE, UNREADABLE = "GITHUB_NOT_CONFIGURED", "GITHUB_REFUSED", "GITHUB_UNREACHABLE", "GITHUB_RESPONSE_UNREADABLE"


class GitHubError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


def is_configured() -> bool:
    return bool(os.environ.get(settings.NMAS_GITHUB_TOKEN_ENV, "").strip()) and "/" in settings.NMAS_GITHUB_REPOSITORY


def repository() -> str:
    return settings.NMAS_GITHUB_REPOSITORY


def _call(method: str, path: str, body: dict | None = None):
    token = os.environ.get(settings.NMAS_GITHUB_TOKEN_ENV, "").strip()
    if not token or "/" not in settings.NMAS_GITHUB_REPOSITORY:
        raise GitHubError(NOT_CONFIGURED, "no GitHub token is provisioned for this NMAS instance")
    request = Request(f"{settings.NMAS_GITHUB_API_URL}/repos/{settings.NMAS_GITHUB_REPOSITORY}{path}", method=method,
                      data=json.dumps(body).encode() if body is not None else None,
                      headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28",
                               "Content-Type": "application/json", "User-Agent": "nmas-configuration-validation"})
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed https API origin from settings
            raw = response.read(2_000_000)
    except HTTPError as exc:
        raise GitHubError(REFUSED, f"HTTP {exc.code}") from None            # never the response body: it can echo the request
    except (URLError, TimeoutError, OSError):
        raise GitHubError(UNREACHABLE) from None
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        raise GitHubError(UNREADABLE) from None


def dispatch(event_type: str, client_payload: dict) -> None:
    """``repository_dispatch``: GitHub answers 204 and names no run; the run is found by its correlation id."""
    _call("POST", "/dispatches", {"event_type": event_type, "client_payload": client_payload})


WORKFLOW_PATH = ".github/workflows/configuration-validation.yml"
DISPATCH_EVENT = "repository_dispatch"


def is_validation_run(run: dict) -> bool:
    """A run of THE workflow "Configuration Validation" of the configured repository, started by a dispatch.  A run of
    any other workflow, or one started another way, is never a Configuration Validation result, whatever it is called."""
    name = str(((run.get("repository") or {}).get("full_name")) or "")
    return (str(run.get("path") or "").split("@")[0] == WORKFLOW_PATH and run.get("event") == DISPATCH_EVENT
            and (not name or name.lower() == settings.NMAS_GITHUB_REPOSITORY.lower()))


def dispatch_runs() -> list[dict]:
    """The most recent runs of the Configuration Validation workflow (newest first, one bounded request)."""
    data = _call("GET", f"/actions/runs?event={DISPATCH_EVENT}&per_page=100")
    return [run for run in data.get("workflow_runs") or [] if isinstance(run, dict) and is_validation_run(run)]


def find_runs(correlation_id: str, runs: list[dict] | None = None) -> list[dict]:
    """Every Configuration Validation run whose name (the workflow's ``run-name``) carries ``correlation_id``."""
    found = dispatch_runs() if runs is None else runs
    return [run for run in found if str(correlation_id) in str(run.get("display_title") or "")]


def get_run(run_id: int) -> dict:
    return _call("GET", f"/actions/runs/{int(run_id)}")


def failed_steps(run_id: int) -> list[str]:
    data = _call("GET", f"/actions/runs/{int(run_id)}/jobs?per_page=20")
    return [f"{job.get('name')}: {step.get('name')}" for job in data.get("jobs") or [] for step in job.get("steps") or [] if step.get("conclusion") == "failure"]
