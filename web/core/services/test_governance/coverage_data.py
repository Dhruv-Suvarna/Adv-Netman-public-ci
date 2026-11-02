"""coverage.py JSON (``coverage json``) -> statement / branch figures per artifact and per symbol.

NMAS consumes this structured data (never the HTML report).  Files coverage.py never saw (a module no test imported)
are still measured: their statements are counted with coverage.py's own parser and reported as 0 % covered, so an
untested file can never look better than a tested one.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .constants import REPO_ROOT

MAX_RANGES = 60


class CoverageDataError(ValueError):
    pass


@dataclass
class FileCoverage:
    path: str
    executed: frozenset[int] = frozenset()
    missing: frozenset[int] = frozenset()
    executed_branches: tuple[tuple[int, int], ...] = ()
    missing_branches: tuple[tuple[int, int], ...] = ()
    measured: bool = True          # False: never imported by any test (statements counted, nothing covered)
    error: str = ""

    @property
    def statements(self) -> int:
        return len(self.executed) + len(self.missing)

    @property
    def branches(self) -> int:
        return len(self.executed_branches) + len(self.missing_branches)

    def figures(self, first: int = 0, last: int = 10 ** 9) -> dict:
        executed = sum(1 for n in self.executed if first <= n <= last)
        missing = sorted(n for n in self.missing if first <= n <= last)
        b_exec = sum(1 for a, _b in self.executed_branches if first <= a <= last)
        b_miss = sorted((a, b) for a, b in self.missing_branches if first <= a <= last)
        statements, branches = executed + len(missing), b_exec + len(b_miss)
        return {
            "statements": statements, "covered": executed, "line_pct": pct(executed, statements),
            "branches": branches, "covered_branches": b_exec, "branch_pct": pct(b_exec, branches),
            "missing_lines": compress(missing), "missing_branches": [f"{a}->{b}" for a, b in b_miss[:MAX_RANGES]],
        }


def pct(covered: int, total: int) -> float | None:
    return round(100.0 * covered / total, 2) if total else None


def compress(lines: list[int]) -> list[str]:
    """[1,2,3,7,9,10] -> ["1-3", "7", "9-10"] (bounded)."""
    out: list[str] = []
    start = prev = None
    for n in sorted(lines):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = n
    if start is not None:
        out.append(f"{start}-{prev}" if start != prev else str(start))
    return out[:MAX_RANGES] + ([f"... {len(out) - MAX_RANGES} more range(s)"] if len(out) > MAX_RANGES else [])


def _relative(path: str, repo: Path) -> str | None:
    try:
        return Path(path).resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return None


def parse_coverage_json(data, *, repo: Path = REPO_ROOT) -> dict[str, FileCoverage]:
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise CoverageDataError("coverage JSON has no 'files' mapping")
    out = {}
    for raw_path, row in data["files"].items():
        rel = _relative(raw_path, repo) if Path(raw_path).is_absolute() else Path(raw_path).as_posix()
        if rel is None or not isinstance(row, dict):
            continue
        out[rel] = FileCoverage(
            rel, frozenset(int(n) for n in row.get("executed_lines") or ()), frozenset(int(n) for n in row.get("missing_lines") or ()),
            tuple((int(a), int(b)) for a, b in row.get("executed_branches") or ()),
            tuple((int(a), int(b)) for a, b in row.get("missing_branches") or ()))
    return out


def unmeasured(path: str, repo: Path = REPO_ROOT) -> FileCoverage:
    """A file no test imported: count its statements / branches with coverage.py's parser, all missing."""
    try:
        from coverage.python import PythonParser
    except ImportError:  # the web server has no coverage.py; the report is always built in Tier-3 where it exists
        return FileCoverage(path, measured=False, error="coverage.py unavailable")
    try:
        parser = PythonParser(filename=str(repo / path))
        parser.parse_source()
        exits = parser.exit_counts()
        arcs = [(a, b) for a, b in parser.arcs() if a > 0 and exits.get(a, 0) > 1]
        return FileCoverage(path, frozenset(), frozenset(parser.statements), (), tuple(sorted(arcs)), measured=False)
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - an unparsable file is reported, never fatal
        return FileCoverage(path, measured=False, error=f"{type(exc).__name__}")
