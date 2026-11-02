"""Run a plain ``unittest`` suite (the monitoring / NetBox suite) with the direct-invocation tracer.

    NMAS_TG_TRACE_OUT=out/monitoring-trace.json python web/core/services/test_governance/traced_unittest.py \\
        discover -s monitoring/tests -p 'test_*.py'

Same arguments as ``python -m unittest``; exit status 0 only when every test passed and at least one ran.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

WEB = Path(__file__).resolve().parents[3]
# Behave like ``python -m unittest``: the working directory first (the suites import ``modules`` from the repository root),
# never this package's own directory (its module names -- inventory, schema, policy ... -- must not shadow anything).
sys.path[0] = os.getcwd()
if str(WEB) not in sys.path:
    sys.path.append(str(WEB))

from core.services.test_governance.session import trace_output, traced_session  # noqa: E402
from core.services.test_governance.tracer import make_result_class  # noqa: E402


def main(argv: list[str]) -> int:
    output = trace_output()
    if not output:
        program = unittest.main(module=None, argv=["unittest", *argv], exit=False)
        return 0 if program.result.wasSuccessful() and program.result.testsRun else 1
    with traced_session(output, suite="monitoring") as tracer:
        runner = unittest.TextTestRunner(resultclass=make_result_class(unittest.TextTestResult, tracer), verbosity=1)
        program = unittest.main(module=None, argv=["unittest", *argv], testRunner=runner, exit=False)
    return 0 if program.result.wasSuccessful() and program.result.testsRun else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
