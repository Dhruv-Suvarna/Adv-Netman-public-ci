"""Direct tests for the Troubleshooter deployment binding (troubleshooting/deployment.py).

Every injected transport is wrapped so that ONLY its read operations are reachable (no ``set`` / ``configure`` / ``send``
survives the wrapper), a wrapped object without the read interface is refused at construction, and every failing provider
degrades to UNAVAILABLE / an empty context with the failure recorded -- never to guessed data or another source.
"""

from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase

from core.services.troubleshooting import deployment as dep


class Cli:
    def __init__(self):
        self.closed = False

    def execute(self, rendered):
        return f"out:{rendered}"

    def provenance(self):
        return {"gateway": "g1"}

    def configure(self, text):          # must not be reachable through the wrapper
        raise AssertionError("write reached")

    def close(self):
        self.closed = True


class Snmp:
    def walk(self, oid):
        return {oid + ".1": 1}

    def get(self, oid):
        return {oid: 2}

    def set(self, oid, value):
        raise AssertionError("write reached")


class Probe:
    def capabilities(self):
        return ["tcp_connect"]

    def execute(self, request):
        return {"ok": request}


class ReadOnlyWrapperTests(SimpleTestCase):
    def test_wrappers_expose_only_the_read_interface(self):
        inner = Cli()
        cli = dep.ReadOnlyCli(inner)
        self.assertEqual((cli.execute("show version"), cli.provenance()), ("out:show version", {"gateway": "g1"}))
        self.assertFalse(hasattr(cli, "configure"))
        cli.close()
        self.assertTrue(inner.closed)
        snmp = dep.ReadOnlySnmp(Snmp())
        self.assertEqual((snmp.walk("1.3"), snmp.get("1.3")), ({"1.3.1": 1}, {"1.3": 2}))
        self.assertFalse(hasattr(snmp, "set"))
        probe = dep.ReadOnlyProbe(Probe())
        self.assertEqual((probe.capabilities(), probe.execute("r")), (("tcp_connect",), {"ok": "r"}))

    def test_wrappers_refuse_objects_without_the_read_interface(self):
        for label, wrapper, inner in (("a cli without execute", dep.ReadOnlyCli, object()),
                                      ("an snmp session without get", dep.ReadOnlySnmp, SimpleNamespace(walk=lambda oid: {})),
                                      ("a probe runner without capabilities", dep.ReadOnlyProbe, SimpleNamespace(execute=lambda r: r))):
            with self.subTest(f"{label} is refused"):
                with self.assertRaises(TypeError):
                    wrapper(inner)

    def test_wrapped_failures_propagate_unchanged(self):
        def boom(_x):
            raise TimeoutError("device timed out")
        with self.subTest("a failing cli read is not swallowed"):
            with self.assertRaises(TimeoutError):
                dep.ReadOnlyCli(SimpleNamespace(execute=boom)).execute("show version")
        with self.subTest("a failing snmp walk is not swallowed"):
            with self.assertRaises(TimeoutError):
                dep.ReadOnlySnmp(SimpleNamespace(walk=boom, get=boom)).walk("1.3")
        with self.subTest("a failing snmp get is not swallowed"):
            with self.assertRaises(TimeoutError):
                dep.ReadOnlySnmp(SimpleNamespace(walk=boom, get=boom)).get("1.3")
        with self.subTest("a failing probe is not swallowed"):
            with self.assertRaises(TimeoutError):
                dep.ReadOnlyProbe(SimpleNamespace(execute=boom, capabilities=lambda: [])).execute("r")


class Context:
    def __init__(self, value="default"):
        self.value = value


class Baseline:
    def __init__(self, result=None):
        self.result = result or {"status": "available", "data": 1}

    def __getattr__(self, name):
        if name in dep.LazyBaselineSources.METHODS:
            return lambda *a: self.result
        raise AttributeError(name)


class LazyBindingTests(SimpleTestCase):
    def test_lazy_context_resolves_on_first_use(self):
        problems, calls = [], []
        ctx = dep.LazyContext(lambda: calls.append(1) or Context("bound"), Context, problems, "fctx")
        self.assertEqual(calls, [])                                   # nothing resolved during construction
        self.assertEqual((ctx.value, ctx.value, calls, problems), ("bound", "bound", [1], []))

    def test_lazy_context_with_a_broken_or_wrong_provider_is_empty_and_reported(self):
        def broken():
            raise RuntimeError("db unavailable")
        with self.subTest("a failing provider is reported and degrades to an empty context"):
            problems = []
            self.assertEqual(dep.LazyContext(broken, Context, problems, "fctx").value, "default")
            self.assertEqual(problems, ["fctx: RuntimeError"])
        with self.subTest("a wrong context type is refused"):
            problems = []
            self.assertEqual(dep.LazyContext(lambda: object(), Context, problems, "fctx").value, "default")
            self.assertEqual(problems, ["fctx: TypeError"])

    def test_lazy_baseline_sources_return_the_bound_source(self):
        problems = []
        src = dep.LazyBaselineSources(lambda: Baseline(), problems)
        for name in ("intent", "history", "slo", "changes", "configs"):
            self.assertEqual(getattr(src, name)("r1"), {"status": "available", "data": 1})
        self.assertEqual(problems, [])

    def test_lazy_baseline_sources_refuse_unbound_invalid_or_failing_sources(self):
        cases = (("no provider", lambda: None, None), ("an incomplete source", lambda: SimpleNamespace(intent=lambda: {}), "TypeError"),
                 ("an invalid result", lambda: Baseline({"status": "maybe"}), "TypeError"))
        for label, provider, problem in cases:
            for name in ("history", "slo", "changes", "configs"):
                with self.subTest(f"{label} is unavailable for {name}"):
                    problems = []
                    src = dep.LazyBaselineSources(provider if label != "no provider" else None, problems)
                    self.assertEqual(getattr(src, name)()["status"], "unavailable")
                    if problem:
                        self.assertEqual(problems, [f"baseline.{name}: {problem}"])


class ConsistencyTests(SimpleTestCase):
    def test_consistency_problems_flag_disagreeing_or_unset_consumers(self):
        names = dep.CONSUMER_SETTINGS
        with self.subTest("unset consumers are reported"):
            self.assertTrue(all("unset" in p for p in dep.consistency_problems(SimpleNamespace())))
        with self.subTest("disagreeing consumers are reported"):
            mixed = SimpleNamespace(**{names[0]: dep.FACTORY_PATH, **{n: "other.module.factory" for n in names[1:]}})
            problems = dep.consistency_problems(mixed)
            self.assertTrue(any("disagree" in p for p in problems) if len(names) > 1 else problems)

    def test_consistency_of_equivalent_bindings_has_no_problem(self):
        bound = SimpleNamespace(**{n: dep.FACTORY_PATH.replace(".", ":", 0) for n in dep.CONSUMER_SETTINGS})
        self.assertEqual(dep.consistency_problems(bound), [])
