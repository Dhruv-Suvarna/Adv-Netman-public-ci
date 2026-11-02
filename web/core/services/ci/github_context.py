"""Derive a Tier-3 comparison from GitHub Actions event data (pure: env mapping + one JSON file).

The workflow YAML does no derivation and interpolates no event data into a shell: it only runs the
Tier-3 launcher, which calls :func:`resolve_from_environment` (reading ``GITHUB_EVENT_NAME``,
``GITHUB_EVENT_PATH`` and ``GITHUB_SHA``).  Everything is validated before use.

    pull_request        base = PR base SHA, head = PR head SHA, merge-base diff, targeted
    push                base = ``before``, head = ``after``, direct diff; FULL on the default branch, targeted elsewhere;
                        an all-zero ``before`` (new branch) has no base -> full
    workflow_dispatch   ``inputs.base`` given -> targeted vs that base; none -> FULL (deterministic, no ``HEAD^`` guess);
                        ``inputs.mode`` may force ``full``
    anything else       FULL, no base
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from . import gitio
from .constants import Mode

MAX_EVENT_BYTES = 5_000_000
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9._/@:+-]{1,100}$")


class GitHubContextError(ValueError):
    """The event data is missing or malformed (a usage error, not a validation failure)."""


@dataclass(frozen=True)
class GitHubRange:
    base: str | None
    head: str
    merge_base: bool
    mode: str
    event: str
    notes: tuple[str, ...] = ()
    context: dict = field(default_factory=dict)  # bounded, non-secret scalars for report provenance


def _label(value: object) -> str | None:
    text = str(value) if value is not None else ""
    return text if _SAFE_LABEL.match(text) else None


def _revision(value: object, what: str) -> str:
    text = str(value or "")
    if not gitio.valid_revision(text):
        raise GitHubContextError(f"event {what} is missing or not a valid revision")
    return text


def load_event(env: Mapping[str, str]) -> dict:
    path = env.get("GITHUB_EVENT_PATH", "")
    if not path:
        raise GitHubContextError("GITHUB_EVENT_PATH is not set; --from-github must run inside GitHub Actions")
    file = Path(path)
    try:
        if file.stat().st_size > MAX_EVENT_BYTES:
            raise GitHubContextError("event payload is unreasonably large")
        return json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubContextError(f"cannot read the event payload: {type(exc).__name__}") from exc


def resolve_from_environment(env: Mapping[str, str], payload: dict | None = None) -> GitHubRange:
    event = env.get("GITHUB_EVENT_NAME", "")
    if not event:
        raise GitHubContextError("GITHUB_EVENT_NAME is not set")
    payload = load_event(env) if payload is None else payload
    checkout = env.get("GITHUB_SHA", "")
    context = {
        "event": _label(event) or "unknown", "ref_name": _label(env.get("GITHUB_REF_NAME")),
        "repository": _label(env.get("GITHUB_REPOSITORY")), "run_id": _label(env.get("GITHUB_RUN_ID")),
        "checkout_sha": checkout if re.fullmatch(r"[0-9a-f]{40}", checkout) else None,
    }
    if event == "pull_request":  # NOT pull_request_target: untrusted PR code must never run with that event's privileges
        pr = payload.get("pull_request") or {}
        context["base_ref"] = _label((pr.get("base") or {}).get("ref"))
        context["head_ref"] = _label((pr.get("head") or {}).get("ref"))
        return GitHubRange(_revision((pr.get("base") or {}).get("sha"), "pull_request.base.sha"),
                           _revision((pr.get("head") or {}).get("sha"), "pull_request.head.sha"),
                           True, Mode.TARGETED, event, ("pull request: merge-base diff against the PR base",), context)
    if event == "push":
        after = payload.get("after") or checkout
        head = _revision(after if not re.fullmatch(r"0{40}", str(after)) else checkout, "push.after")
        before = str(payload.get("before") or "")
        default_branch = (payload.get("repository") or {}).get("default_branch")
        on_default = bool(default_branch) and payload.get("ref") == f"refs/heads/{default_branch}"
        mode = Mode.FULL if on_default else Mode.TARGETED
        notes = ["push to the default branch: full regression" if on_default else "push: exact before..after diff"]
        if not before or re.fullmatch(r"0{40}", before):
            notes.append("new branch (no previous commit): no comparison base, so full validation")
            return GitHubRange(None, head, False, Mode.FULL, event, tuple(notes), context)
        return GitHubRange(_revision(before, "push.before"), head, False, mode, event, tuple(notes), context)
    head = _revision(checkout, "GITHUB_SHA")
    if event == "workflow_dispatch":
        inputs = payload.get("inputs") or {}
        base = str(inputs.get("base") or "").strip()
        requested = str(inputs.get("mode") or "").strip().lower()
        if requested and requested not in Mode.ALL:
            raise GitHubContextError(f"workflow_dispatch input mode must be one of {', '.join(Mode.ALL)}")
        if base:
            mode = requested or Mode.TARGETED
            return GitHubRange(_revision(base, "inputs.base"), head, True, mode, event, ("manual run: merge-base diff against inputs.base",), context)
        return GitHubRange(None, head, False, Mode.FULL, event, ("manual run without a base: full regression",), context)
    return GitHubRange(None, head, False, Mode.FULL, event, (f"event {_label(event) or 'unknown'!r} has no defined comparison: full regression",), context)
