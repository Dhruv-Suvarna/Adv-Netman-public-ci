"""Direct-invocation tracer: WHICH deployed functions did each test call DIRECTLY, and did the call return or raise?

"A line executed" is not "the behavior was tested".  This tracer records a (test, symbol) link only when the symbol was
invoked from the test method's OWN dynamic extent with no other deployed code in between:

    test method body (or a test helper it calls)  ->  [library frames only: Django test client, mock, unittest]  ->  symbol

A function that merely ran because some other deployed function called it is NOT linked (its statements still count
toward coverage.py's line / branch figures, which are reported separately).  Calls made from ``setUp`` /
``setUpTestData`` are not linked either: fixture construction is not a test of the fixture.

Per link the tracer counts direct starts and direct exception unwinds, so the report can say whether the test drove
the symbol to a normal return (positive path) and / or to a raised refusal (negative path).

Implementation: Python 3.12 ``sys.monitoring`` (PEP 669) with its own tool id, so it coexists with coverage.py.
Events for code objects that are not inventoried symbols are disabled after their first sighting, which keeps the
overhead to the deployed functions themselves.  Pure standard library; never imports Django.
"""

from __future__ import annotations

# astroid has no model of Python 3.12 sys.monitoring; every member used here exists (PEP 669).
# pylint: disable=no-member

import inspect
import json
import os
import re
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path

TOOL_ID = 4           # sys.monitoring: 0 debugger, 1 coverage, 2 profiler, 5 optimizer -- 3 / 4 are free
TOOL_NAME = "nmas-test-governance"
MAX_WALK = 80

TEST, PROJECT, LIBRARY, TRANSPARENT = "test", "project", "library", "transparent"
NEGATIVE_INTENT, POSITIVE_INTENT, MIXED = "negative", "positive", "mixed"
_WORD_RE = re.compile(r"[a-z0-9]+")
OUTCOMES = ("PASS", "FAIL", "ERROR", "SKIP", "EXPECTED_FAILURE", "UNEXPECTED_SUCCESS")


class DirectCallTracer:
    def __init__(self, repo_root: Path, targets: dict[str, dict[str, str]], *, test_roots: tuple[str, ...],
                 transparent_files: tuple[str, ...] = (), suite: str = "django", negative_words: frozenset = frozenset(),
                 positive_words: frozenset = frozenset(), tool_id: int = TOOL_ID):
        """``targets``: absolute filename -> {qualified name -> symbol id}."""
        self.tool_id = tool_id
        self.negative_words = frozenset(negative_words)
        self.positive_words = frozenset(positive_words)
        self._subtests: list[str] = []
        self._test_intent = MIXED
        self.repo = str(Path(repo_root).resolve()) + os.sep
        self.targets = targets
        self.test_roots = tuple(str(Path(repo_root, r).resolve()) + os.sep for r in test_roots)
        self.transparent_files = frozenset(str(Path(repo_root, p).resolve()) for p in transparent_files)
        self.suite = suite
        self._file_kind: dict[str, str] = {}
        # Monitoring calls these lookups on every Python start/unwind.  Identity
        # keys avoid repeated code-object hashing.  Retaining the object prevents
        # id reuse, and keeps equal code objects from separate files distinct.
        self._code_kind: dict[int, tuple[object, str]] = {}
        self._code_symbol: dict[int, tuple[object, str | None]] = {}
        self.tests: dict[str, dict] = {}
        self._current: dict | None = None
        self._method_code = None
        self._installed = False
        self.events = 0

    # -- classification ------------------------------------------------------------------------
    def _kind_of_file(self, filename: str) -> str:
        kind = self._file_kind.get(filename)
        if kind is None:
            path = os.path.realpath(filename) if filename and not filename.startswith("<") else ""
            if not path.startswith(self.repo) or os.sep + "site-packages" + os.sep in path or os.sep + ".venv" in path:
                kind = LIBRARY
            elif path.startswith(self.test_roots):
                kind = TEST
            elif path in self.transparent_files:
                kind = TRANSPARENT
            else:
                kind = PROJECT
            self._file_kind[filename] = kind
        return kind

    def _kind_of_code(self, code) -> str:
        key = id(code)
        cached = self._code_kind.get(key)
        if cached is None:
            kind = self._kind_of_file(code.co_filename)
            if kind == PROJECT and ("<locals>" in code.co_qualname or code.co_name.startswith("<")):
                kind = TRANSPARENT  # closures / decorator wrappers / comprehensions belong to their enclosing function
            self._code_kind[key] = (code, kind)
            return kind
        return cached[1]

    def _symbol_of(self, code) -> str | None:
        key = id(code)
        try:
            return self._code_symbol[key][1]
        except KeyError:
            pass
        table = self.targets.get(os.path.realpath(code.co_filename)) if not code.co_filename.startswith("<") else None
        symbol = table.get(code.co_qualname) if table else None
        self._code_symbol[key] = (code, symbol)
        return symbol

    def _is_direct(self, frame) -> bool:
        """The nearest non-library, non-transparent caller is test code inside the running test method."""
        caller, steps = frame.f_back, 0
        while caller is not None and steps < MAX_WALK:
            kind = self._kind_of_code(caller.f_code)
            if kind == PROJECT:
                return False
            if kind == TEST:
                break
            caller, steps = caller.f_back, steps + 1
        else:
            return False
        if caller is None or self._method_code is None:
            return False
        while caller is not None and steps < MAX_WALK:   # inside the test method's own extent (not setUp / tearDown)
            if caller.f_code is self._method_code:
                return True
            caller, steps = caller.f_back, steps + 1
        return False

    # -- sys.monitoring callbacks --------------------------------------------------------------
    def _on_start(self, code, _offset):
        symbol = self._symbol_of(code)
        if symbol is None:
            return sys.monitoring.DISABLE
        current = self._current
        if current is None:
            return None
        self.events += 1
        if self._is_direct(sys._getframe(1)):
            counts = current["links"].setdefault(symbol, [0, 0, 0, 0])
            counts[2 if self._negative_context() else 0] += 1
        return None

    def _on_unwind(self, code, _offset, _exc):
        # PY_UNWIND is not a local event: returning DISABLE here would raise inside the unwinding frame and change the
        # exception the code under test sees.  Never return anything from this callback.
        symbol = self._symbol_of(code)
        if symbol is None:
            return None
        current = self._current
        if current is not None and self._is_direct(sys._getframe(1)):
            counts = current["links"].setdefault(symbol, [0, 0, 0, 0])
            counts[3 if self._negative_context() else 1] += 1
        return None

    # -- intent: what the test (or the active sub-test) says it proves ---------------------------
    def intent_of(self, text: str) -> str:
        words = set(_WORD_RE.findall(text.lower().replace("_", " ")))
        negative, positive = bool(words & self.negative_words), bool(words & self.positive_words)
        if negative and not positive:
            return NEGATIVE_INTENT
        if positive and not negative:
            return POSITIVE_INTENT
        return MIXED

    def _negative_context(self) -> bool:
        if self._subtests:
            return self.intent_of(" ".join(self._subtests)) == NEGATIVE_INTENT
        return self._test_intent == NEGATIVE_INTENT

    def push_subtest(self, text: str) -> None:
        self._subtests.append(text)

    def pop_subtest(self) -> None:
        if self._subtests:
            self._subtests.pop()

    def install(self) -> None:
        mon = sys.monitoring
        mon.use_tool_id(self.tool_id, TOOL_NAME)
        mon.register_callback(self.tool_id, mon.events.PY_START, self._on_start)
        mon.register_callback(self.tool_id, mon.events.PY_UNWIND, self._on_unwind)
        # Keep one stable monitoring mask.  Re-instrumenting the interpreter
        # around every unittest method adds cost and interacts with nested
        # runners.  _is_direct still excludes fixture/setup/teardown calls.
        mon.set_events(self.tool_id, mon.events.PY_START | mon.events.PY_UNWIND)
        self._original_subtest = unittest.TestCase.subTest
        tracer, original = self, unittest.TestCase.subTest
        sentinel = getattr(unittest.case, "_subtest_msg_sentinel", None)

        @contextmanager
        def traced_subtest(case_self, msg=sentinel, **params):
            label = " ".join([str(msg) if msg is not sentinel and msg is not None else "",
                              *(f"{k} {v}" for k, v in params.items())])
            tracer.push_subtest(label[:300])
            try:
                with original(case_self, msg, **params):
                    yield
            finally:
                tracer.pop_subtest()

        unittest.TestCase.subTest = traced_subtest
        self._installed = True

    def uninstall(self) -> None:
        if not self._installed:
            return
        mon = sys.monitoring
        mon.set_events(self.tool_id, 0)
        mon.register_callback(self.tool_id, mon.events.PY_START, None)
        mon.register_callback(self.tool_id, mon.events.PY_UNWIND, None)
        mon.free_tool_id(self.tool_id)
        unittest.TestCase.subTest = self._original_subtest
        self._installed = False

    # -- test lifecycle (called by the unittest result hooks) ----------------------------------
    def test_id(self, test) -> str:
        raw = test.id()
        # a test module that puts the repository root on sys.path makes later modules discoverable as ``web.core.tests...``
        # as well; one test has one id
        if raw.startswith("web.core.tests."):
            raw = raw[len("web."):]
        return f"{self.suite}:{raw}"

    def start_test(self, test) -> None:
        method = getattr(test, getattr(test, "_testMethodName", ""), None)
        unwrapped = inspect.unwrap(method) if method is not None else None
        code = getattr(getattr(unwrapped, "__func__", unwrapped), "__code__", None)
        cases = []
        for candidate in (method, unwrapped, getattr(method, "__func__", None)):
            for item in getattr(candidate, "_tg_cases", ()) or ():
                if item not in cases:
                    cases.append(item)
        doc = (getattr(unwrapped, "__doc__", None) or "").strip().split("\n")[0][:200]
        name = getattr(test, "_testMethodName", "")
        self._test_intent = self.intent_of(f"{name[5:] if name.startswith('test_') else name} {doc}")
        self._subtests = []
        record = {"outcome": None, "links": {}, "declared": [c.to_dict() for c in cases], "doc": doc, "intent": self._test_intent,
                  "file": os.path.relpath(code.co_filename, self.repo) if code is not None and code.co_filename.startswith(self.repo) else "",
                  "line": code.co_firstlineno if code is not None else 0}
        self.tests[self.test_id(test)] = record
        self._current = record
        self._method_code = code

    def stop_test(self, test) -> None:
        self._current = None
        self._method_code = None
        self._subtests = []

    def outcome(self, test, outcome: str) -> None:
        record = self.tests.setdefault(self.test_id(test), {"outcome": None, "links": {}, "declared": [], "doc": "", "intent": MIXED,
                                                            "file": "", "line": 0})
        previous = record["outcome"]
        # a failing sub-test fails the whole test; PASS never overwrites a failure
        if previous in ("FAIL", "ERROR") and outcome == "PASS":
            return
        record["outcome"] = outcome

    def dump(self, path: Path, *, meta: dict | None = None) -> None:
        payload = {"suite": self.suite, "meta": meta or {}, "events": self.events, "tests": self.tests}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(str(path) + ".tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, path)


def make_result_class(base, tracer: DirectCallTracer):
    """A unittest result class that reports every test's lifecycle and outcome to ``tracer``."""

    class TracedResult(base):
        def startTest(self, test):  # noqa: N802 - unittest API
            tracer.start_test(test)
            super().startTest(test)

        def stopTest(self, test):  # noqa: N802
            super().stopTest(test)
            tracer.stop_test(test)

        def addSuccess(self, test):  # noqa: N802
            tracer.outcome(test, "PASS")
            super().addSuccess(test)

        def addFailure(self, test, err):  # noqa: N802
            tracer.outcome(test, "FAIL")
            super().addFailure(test, err)

        def addError(self, test, err):  # noqa: N802
            tracer.outcome(test, "ERROR")  # also a setUpClass / module-fixture error holder: recorded under its own id
            super().addError(test, err)

        def addSkip(self, test, reason):  # noqa: N802
            tracer.outcome(test, "SKIP")
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, err):  # noqa: N802
            tracer.outcome(test, "EXPECTED_FAILURE")
            super().addExpectedFailure(test, err)

        def addUnexpectedSuccess(self, test):  # noqa: N802
            tracer.outcome(test, "UNEXPECTED_SUCCESS")
            super().addUnexpectedSuccess(test)

        def addSubTest(self, test, subtest, err):  # noqa: N802
            if err is not None:
                tracer.outcome(test, "FAIL")
            super().addSubTest(test, subtest, err)

    return TracedResult


def build_targets(repo_root: Path, symbol_ids: list[str]) -> dict[str, dict[str, str]]:
    targets: dict[str, dict[str, str]] = {}
    for sid in symbol_ids:
        path, qualname = sid.split("::", 1)
        targets.setdefault(os.path.realpath(str(Path(repo_root, path))), {})[qualname] = sid
    return targets
