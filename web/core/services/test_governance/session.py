"""One traced test session: build the symbol targets, install the tracer, dump the observations (opt-in only).

The Django runner (``core.tests.runner.NmasTestRunner``) and the monitoring launcher (``traced_unittest.py``) both call
:func:`traced_session` when ``NMAS_TG_TRACE_OUT`` names an output file; without it nothing is installed and the suites
run exactly as before.
"""

from __future__ import annotations

import os
import platform
import time
from contextlib import contextmanager
from pathlib import Path

from .constants import REPO_ROOT, ArtifactType
from .tracer import DirectCallTracer, build_targets

TRACE_ENV = "NMAS_TG_TRACE_OUT"
TEST_ROOTS = ("web/core/tests", "monitoring/tests", "challenge_console/tests")
# frameworks plumbing that sits between a test and the boundary it drives (request middleware, the test runner)
TRANSPARENT_FILES = ("web/core/middleware.py", "web/core/tests/runner.py")


def trace_output() -> str:
    return os.environ.get(TRACE_ENV, "").strip()


POSITIVE_WORDS = frozenset({"accept", "accepts", "accepted", "valid", "succeeds", "success", "successful", "renders", "render", "ok",
                            "pass", "passes", "passed", "allows", "allowed", "builds", "creates", "returns", "preserves", "imports",
                            "parses", "roundtrip", "round", "happy", "positive", "supported", "matches", "equal", "exact"})


def all_symbol_ids(repo: Path = REPO_ROOT) -> list[str]:
    from . import inventory, symbols

    inv = inventory.build_inventory(repo)
    paths = [a.path for a in inv.artifacts if a.type == ArtifactType.PYTHON]
    return [s.id for module in symbols.inventory_symbols(paths, repo).values() for s in module.symbols]


@contextmanager
def traced_session(output: str, *, suite: str, repo: Path = REPO_ROOT):
    started = time.time()
    from .policy import default_policy

    tracer = DirectCallTracer(repo, build_targets(repo, all_symbol_ids(repo)), test_roots=TEST_ROOTS,
                              transparent_files=TRANSPARENT_FILES, suite=suite,
                              negative_words=default_policy().negative_intent_words, positive_words=POSITIVE_WORDS)
    tracer.install()
    try:
        yield tracer
    finally:
        tracer.uninstall()
        from .inventory import head_sha

        tracer.dump(Path(output), meta={"started": started, "finished": time.time(), "python": platform.python_version(),
                                        "head_sha": head_sha(repo), "tests": len(tracer.tests)})
