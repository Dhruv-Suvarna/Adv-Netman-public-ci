"""Tier-3 vocabulary, versions and output bounds.

Tier 3 is repository-level change-effect / integration / regression validation.  It is
deliberately NOT Tier 1 (field syntax during a Device Builder commit) and NOT Tier 2
(Phase-13 whole-Change semantic validation against NetBox/topology).  Nothing in this
package deploys, writes NetBox/Git, contacts a device, or touches a Change.
"""

from __future__ import annotations

ENGINE_VERSION = "16.1.0"  # 16.1: Lab 7 governance checks (catalog, Pylint, traced coverage evidence)
REPORT_SCHEMA_VERSION = 1


class Mode:
    """How much of the repository regression surface is required."""

    TARGETED = "targeted"
    FULL = "full"
    ALL = (TARGETED, FULL)


class Gate:
    """Where a check may run.  STATIC/REPOSITORY are offline; LAB needs the real lab."""

    STATIC = "static"          # syntax, hygiene, Django system check, migration drift
    REPOSITORY = "repository"  # unit / contract / view-boundary regression suites (all faked, no lab)
    LAB = "lab"                # existing real external verifiers; explicit operator opt-in only
    ALL = (STATIC, REPOSITORY, LAB)


class CheckStatus:
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    ERROR = "ERROR"      # the check could not be executed reliably (crash, timeout, tool missing)
    NOT_RUN = "NOT_RUN"  # deliberately not executed (policy); NEVER counted as a pass
    ALL = (PASS, WARN, FAIL, ERROR, NOT_RUN)


class Result:
    """Overall Tier-3 result (project vocabulary; INCOMPLETE mirrors Phase 13/15)."""

    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"
    ALL = (PASS, PASS_WITH_WARNINGS, FAIL, INCOMPLETE)


class ExitCode:
    OK = 0          # PASS or PASS_WITH_WARNINGS
    FAIL = 1        # a required check failed
    USAGE = 2       # bad arguments / unresolvable revision / not a git repository
    INCOMPLETE = 3  # a required check could not be executed (never reported as a pass)


class FileStatus:
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


# Output bounds (reports are safe to publish as CI artifacts).
MAX_CHANGED_FILES = 500
MAX_LIST = 200
MAX_STRING = 300
MAX_OUTPUT_LINES = 40
MAX_OUTPUT_CHARS = 4000
MAX_REPORT_BYTES = 512 * 1024
DEFAULT_CHECK_TIMEOUT_SECONDS = 900
