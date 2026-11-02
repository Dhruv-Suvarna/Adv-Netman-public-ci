"""In-process static checks: syntax and repository hygiene.

They READ and PARSE repository files (``ast.parse`` / ``json`` / ``yaml.safe_load`` / Jinja
``parse``); nothing is imported, executed or rendered.  Findings carry a path, a line and a stable
code -- never file content.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import redact
from .changes import ScanLine
from .constants import MAX_LIST, CheckStatus, FileStatus

SYNTAX_EXTENSIONS = {".py": "python", ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".j2": "jinja", ".sh": "shell"}
MAX_PARSE_BYTES = 2_000_000

# Files that must never be added: credential stores by NAME (content is not needed to know that).
SECRET_FILE_RE = re.compile(r"(?:^|/)(?:\.env|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]*\.(?:pem|key|p12|pfx|jks)|secrets?\.[a-z]+)$")
SECRET_FILE_ALLOW = re.compile(r"(?:^|/)\.env\.example$")
SECRET_DIR_PREFIX = "monitoring/runtime/"
SECRET_DIR_ALLOW = {"monitoring/runtime/.gitkeep"}


@dataclass
class StaticOutcome:
    status: str
    summary: str
    findings: list[dict] = field(default_factory=list)
    counts: dict = field(default_factory=dict)


def _finding(code: str, path: str, line: int | None, message: str) -> dict:
    return {"code": code, "path": path, "line": line, "message": redact.bound_string(message, 200)}


def check_syntax(repo: Path, paths: list[str], *, shell_runner=None) -> StaticOutcome:
    """Parse every existing file of a known type.  ``shell_runner(path) -> (ok, message)`` checks ``.sh`` via ``bash -n``."""
    findings: list[dict] = []
    checked: dict[str, int] = {}
    for rel in paths:
        suffix = Path(rel).suffix
        kind = SYNTAX_EXTENSIONS.get(suffix)
        target = repo / rel
        if kind is None or not target.is_file() or target.is_symlink():
            continue
        try:
            if target.stat().st_size > MAX_PARSE_BYTES:
                continue
            source = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(_finding("SYNTAX_UNREADABLE", rel, None, f"cannot read file: {type(exc).__name__}"))
            continue
        checked[kind] = checked.get(kind, 0) + 1
        try:
            if kind == "python":
                ast.parse(source, filename=rel)
            elif kind == "json":
                json.loads(source)
            elif kind == "yaml":
                _parse_yaml(source)
            elif kind == "jinja":
                _parse_jinja(source)
            elif kind == "shell" and shell_runner is not None:
                ok, message = shell_runner(rel)
                if not ok:
                    findings.append(_finding("SYNTAX_SHELL", rel, None, message))
        except SyntaxError as exc:
            findings.append(_finding("SYNTAX_PYTHON", rel, exc.lineno, exc.msg))
        except json.JSONDecodeError as exc:
            findings.append(_finding("SYNTAX_JSON", rel, exc.lineno, exc.msg))
        except _TemplateError as exc:
            findings.append(_finding("SYNTAX_JINJA", rel, exc.line, exc.message))
        except _YamlError as exc:
            findings.append(_finding("SYNTAX_YAML", rel, exc.line, exc.message))
    total = sum(checked.values())
    counts = {"files_checked": total, **{f"{k}_files": v for k, v in sorted(checked.items())}}
    if findings:
        return StaticOutcome(CheckStatus.FAIL, f"{len(findings)} syntax error(s) in {total} file(s)", findings[:MAX_LIST], counts)
    return StaticOutcome(CheckStatus.PASS, f"{total} file(s) parsed cleanly" if total else "no parseable files in scope", [], counts)


class _TemplateError(Exception):
    def __init__(self, message, line):
        self.message, self.line = message, line


class _YamlError(Exception):
    def __init__(self, message, line):
        self.message, self.line = message, line


def _parse_yaml(source: str) -> None:
    import yaml

    try:
        list(yaml.safe_load_all(source))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        raise _YamlError(getattr(exc, "problem", "invalid YAML"), (mark.line + 1) if mark else None) from exc


def _parse_jinja(source: str) -> None:
    import jinja2

    try:
        jinja2.Environment().parse(source)  # parse only: never compiled, never rendered
    except jinja2.TemplateSyntaxError as exc:
        raise _TemplateError(exc.message, exc.lineno) from exc


def check_hygiene(lines: list[ScanLine], truncated: bool, changed_files: list[tuple[str, str]]) -> StaticOutcome:
    """Credential formats, conflict markers, and credential-store file names in what the change adds."""
    findings: list[dict] = []
    for path, status in changed_files:
        if status == FileStatus.DELETED:
            continue
        if (SECRET_FILE_RE.search(path) and not SECRET_FILE_ALLOW.search(path)) or (
            path.startswith(SECRET_DIR_PREFIX) and path not in SECRET_DIR_ALLOW
        ):
            findings.append(_finding("HYGIENE_CREDENTIAL_FILE", path, None, "a credential-store file name must not be committed"))
    for item in lines:
        for name in redact.scan_line(item.text):
            findings.append(_finding("HYGIENE_CREDENTIAL_PATTERN", item.path, item.line, f"credential format {name} detected (value not shown)"))
        if redact.CONFLICT_MARKER_RE.match(item.text):
            findings.append(_finding("HYGIENE_CONFLICT_MARKER", item.path, item.line, "merge-conflict marker in added content"))
    counts = {"lines_scanned": len(lines), "files_considered": len(changed_files), "scan_truncated": truncated}
    if findings:
        return StaticOutcome(CheckStatus.FAIL, f"{len(findings)} hygiene finding(s)", findings[:MAX_LIST], counts)
    if truncated:
        return StaticOutcome(CheckStatus.WARN, "hygiene scan truncated at the line bound; the remainder was not scanned", [], counts)
    return StaticOutcome(CheckStatus.PASS, f"{len(lines)} added line(s) scanned; no credential format or conflict marker", [], counts)
