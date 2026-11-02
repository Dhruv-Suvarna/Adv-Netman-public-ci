"""Test-governance vocabulary, versions and fixed paths (pure: no Django, no I/O)."""

from __future__ import annotations

from pathlib import Path

GENERATOR_VERSION = "1.0.0"
REPORT_SCHEMA_VERSION = 1
REPORT_FILENAME = "test-governance-report.json"

# web/core/services/test_governance/constants.py -> repository root
REPO_ROOT = Path(__file__).resolve().parents[4]
PACKAGE_DIR = Path(__file__).resolve().parent
POLICY_FILE = PACKAGE_DIR / "policy.yml"
BASELINE_FILE = PACKAGE_DIR / "baseline.json"
SCHEMA_FILE = PACKAGE_DIR / "report.schema.json"
BUNDLED_EVIDENCE = REPO_ROOT / "docs" / "evidence" / "lab7" / REPORT_FILENAME
CAPABILITY_LEDGER = REPO_ROOT / "docs" / "evidence" / "v2-phase4-exhaustive" / "progress-ledger.json"


class ArtifactType:
    PYTHON = "PY"
    JINJA = "JINJA"
    YAML = "YAML"
    JSON = "JSON"
    SHELL = "SH"
    SYSTEMD = "SYSTEMD"
    CONFIG = "CONF"       # apache / rsyslog / snmptrapd / dhcpd-style operational configuration
    DOCKERFILE = "DOCKER"
    ALL = (PYTHON, JINJA, YAML, JSON, SHELL, SYSTEMD, CONFIG, DOCKERFILE)
    LABELS = {
        PYTHON: "Python", JINJA: "Jinja template", YAML: "YAML", JSON: "JSON", SHELL: "Shell script",
        SYSTEMD: "systemd unit", CONFIG: "Service configuration", DOCKERFILE: "Dockerfile",
    }


class Scope:
    """Whether an artifact / symbol / case counts toward CURRENT closure."""

    CURRENT = "CURRENT"                       # deployed, currently implemented: counts toward closure
    NOT_CURRENT_SCOPE = "NOT_CURRENT_SCOPE"   # deployed code for a platform / feature that is not currently supported
    EXEMPT = "EXEMPT"                         # deliberately not unit-tested, with a documented reason
    ALL = (CURRENT, NOT_CURRENT_SCOPE, EXEMPT)


class Disposition:
    """What a Python symbol requires (decided by documented AST rules; see symbols.py)."""

    POS_NEG = "POSITIVE_AND_NEGATIVE"  # exposed boundary with inputs: both a positive and a negative case
    POS = "POSITIVE"                   # exposed behavior without a meaningful input boundary: a positive case
    INTERNAL = "INTERNAL"              # private helper: proven through its public boundary + line / branch coverage
    EXEMPT = "EXEMPT"                  # no independent behavior worth a case (reason recorded)
    ALL = (POS_NEG, POS, INTERNAL, EXEMPT)


class Polarity:
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    ALL = (POSITIVE, NEGATIVE)


class CaseState:
    """State of ONE required case in an evidence run.  PASS needs: the test exists, ran in the evidence run, passed."""

    PASS = "PASS"
    FAIL = "FAIL"                    # a test claiming the case ran and failed / errored
    MISSING = "MISSING"              # no test proves the case
    BROKEN_REFERENCE = "BROKEN_REFERENCE"  # a declared / locked case whose test no longer exists or did not run
    EXEMPT = "EXEMPT"
    NOT_CURRENT_SCOPE = "NOT_CURRENT_SCOPE"
    ALL = (PASS, FAIL, MISSING, BROKEN_REFERENCE, EXEMPT, NOT_CURRENT_SCOPE)


class Basis:
    """How a test was linked to a case.  Shown next to every test so the operator can judge the strength."""

    DECLARED = "DECLARED"                  # explicit ``@case`` metadata on the test (condition + expected result)
    DIRECT_RAISE = "DIRECT_RAISE"          # test body invoked the symbol directly; the call raised; the test passed
    DIRECT_RETURN = "DIRECT_RETURN"        # test body invoked the symbol directly; the call returned; the test passed
    DIRECT_REFUSAL = "DIRECT_REFUSAL"      # as DIRECT_RETURN, from a test whose stated intent is a refusal / invalid input
    STATIC = "STATIC"                      # non-Python artifact verified by a static check (syntax / structure)
    ALL = (DECLARED, DIRECT_RAISE, DIRECT_RETURN, DIRECT_REFUSAL, STATIC)


class ArtifactStatus:
    CLOSED = "CLOSED_CURRENT_SCOPE"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    FAILING = "FAILING"
    EXEMPT = "EXEMPT"
    NOT_CURRENT_SCOPE = "NOT_CURRENT_SCOPE"
    ALL = (CLOSED, PARTIAL, MISSING, FAILING, EXEMPT, NOT_CURRENT_SCOPE)


class CellStatus:
    CLOSED = "CLOSED_CURRENT_SCOPE"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    FAILING = "FAILING"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    UNSUPPORTED = "UNSUPPORTED"


class Freshness:
    CURRENT = "CURRENT"     # evidence was produced for exactly the deployed source
    STALE = "STALE"         # the deployed source differs from the tested source
    UNKNOWN = "UNKNOWN"     # the deployed source could not be fingerprinted
    NONE = "NO_EVIDENCE"


class PylintStatus:
    PASS = "PASS"      # no message at all
    WARN = "WARN"      # only non-critical messages, all within the tracked baseline
    FAIL = "FAIL"      # a critical message, or non-critical messages above the tracked baseline
    NOT_RUN = "NOT_RUN"
    NOT_APPLICABLE = "N/A"


# Lifecycle stages of a platform x feature cell (each with a positive and a negative case where applicable).
CELL_STAGES = (
    ("MODEL", "Intent model / Tier-1 field validation"),
    ("RENDER", "Platform configuration rendering"),
    ("IMPORT", "Running-configuration parser / import"),
    ("VALIDATE", "Network-configuration validation"),
    ("EXECUTE", "Executor preflight (fake device, no write)"),
    ("COMPENSATION", "Exact inverse / compensation"),
)
