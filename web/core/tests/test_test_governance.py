"""Lab 7 test governance: the testing system's own tests (discovery, dispositions, catalog, tracer, parsers, report, gate).

Every scenario the governance must get right is proven here with small, temporary fixtures -- never by trusting the
real repository's numbers:

* a NEW uncovered source file / function appears as MISSING and fails the gate (it cannot become silent debt);
* a missing negative case lowers X of "X / Y" while Y stays fixed by the code;
* a failing test is never counted PASS;
* evidence for another source is STALE;
* NOT_IMPLEMENTED capability cells never count against current closure, and a cell that becomes SUPPORTED creates
  required cases at once.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from core.services.test_governance import (
    catalog, cells as cells_module, coverage_data, evidence as evidence_module, gate, inventory, policy as policy_module,
    pylint_data, report as report_module, schema, symbols,
)
from core.services.test_governance.cases import NEGATIVE, POSITIVE, Case, case, declared_on, shape_errors
from core.services.test_governance.constants import (
    REPO_ROOT, ArtifactStatus, ArtifactType, Basis, CaseState, CellStatus, Disposition, Freshness, PylintStatus, Scope,
)
from core.services.test_governance.tracer import DirectCallTracer, build_targets, make_result_class

POLICY = policy_module.default_policy()
INV = "web/core/services/test_governance/inventory.py"
CAT = "web/core/services/test_governance/catalog.py"
GATE = "web/core/services/test_governance/gate.py"


def ledger(*rows) -> tuple:
    """rows: (platform, feature, final_status)."""
    probes = {p: "PASS" for p in ("semantic", "field_validation", "renderer", "parser", "validator", "executor", "compensation")}
    return cells_module.parse_ledger({"cells": [{"platform": p, "feature": f, "final_status": s, **probes} for p, f, s in rows]})


def make_inventory(files: dict[str, str], *, cell_rows=(), root: Path | None = None):
    root = root or Path(tempfile.mkdtemp())
    for path, text in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    inv = inventory.build_inventory(root, files=list(files), policy=POLICY, cells=tuple(cell_rows))
    modules = symbols.inventory_symbols([a.path for a in inv.artifacts if a.type == ArtifactType.PYTHON], root, policy=POLICY)
    return root, inv, modules


def trace(**tests) -> catalog.Evidence:
    """tests: id -> (outcome, {symbol: [pos_starts, pos_unwinds, neg_starts, neg_unwinds]}, declared cases)."""
    return catalog.Evidence({tid: {"outcome": o, "links": links, "declared": [c.to_dict() for c in declared]}
                             for tid, (o, links, declared) in tests.items()})


SERVICE = "web/core/services/field_validators.py"   # classified by the real Tier-3 table (device_builder)
SOURCE = '''
def validate_port(value):
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ValueError("port")
    return value


def describe():
    return "ports"


def _helper(x):
    return x


class Thing:
    def __init__(self, a):
        self.a = a

    def __str__(self):
        return "thing"

    @property
    def name(self):
        return self.a

    def run(self, n):
        return n * 2
'''


class DispositionRuleTests(SimpleTestCase):
    @case("GOVERNANCE_DISPOSITION_RULES", target="web/core/services/test_governance/symbols.py::parse_symbols", polarity=POSITIVE,
          condition="a module with a boundary, a no-input function, a private helper, a trivial __init__, __str__ and an accessor",
          expected="each symbol receives exactly the documented rule (R8, R9, R2, R5, R3, R6, R8)")
    def test_each_rule_is_applied_from_the_code_not_from_the_tests(self):
        module = symbols.parse_symbols(SERVICE, SOURCE, policy=POLICY)
        got = {s.qualname: (s.disposition, s.rule) for s in module.symbols}
        self.assertEqual(got, {
            "validate_port": (Disposition.POS_NEG, "R8"), "describe": (Disposition.POS, "R9"), "_helper": (Disposition.INTERNAL, "R2"),
            "Thing.__init__": (Disposition.EXEMPT, "R5"), "Thing.__str__": (Disposition.EXEMPT, "R3"), "Thing.name": (Disposition.EXEMPT, "R6"),
            "Thing.run": (Disposition.POS_NEG, "R8"),
        })
        run = next(s for s in module.symbols if s.qualname == "Thing.run")
        self.assertEqual((run.params, run.kind, run.line_start), (("n",), "method", 27))

    def test_abstract_framework_hook_and_declared_exemption(self):
        source = "class Base:\n    def apply(self, x):\n        raise NotImplementedError\n\n    def add_arguments(self, parser):\n        parser.add_argument('--x')\n\ndef keep(y):\n    return y\n"
        exempt = policy_module.parse_policy({**_policy_data(), "symbol_exemptions": [{"symbol": f"{SERVICE}::keep", "reason": "demo reason"}]})
        got = {s.qualname: (s.disposition, s.rule, s.reason) for s in symbols.parse_symbols(SERVICE, source, policy=exempt).symbols}
        self.assertEqual(got["Base.apply"][:2], (Disposition.EXEMPT, "R4"))
        self.assertEqual(got["Base.add_arguments"][:2], (Disposition.POS, "R7"))
        self.assertEqual(got["keep"], (Disposition.EXEMPT, "R1", "demo reason"))

    def test_input_independent_callables_require_a_positive_case_only(self):
        """R10: a callable whose body never reads its parameters has no negative input case; one that reads any keeps R8."""
        source = ("class Admin:\n    def has_change_permission(self, request, obj=None):\n        return False\n\n"
                  "    def delete(self, *args, **kwargs):\n        raise ValueError('immutable')\n\n"
                  "    def forward(self, *args, **kwargs):\n        return super().save(*args, **kwargs)\n\n"
                  "def uses_nested(a):\n    def inner():\n        return a\n    return inner()\n")
        got = {s.qualname: (s.disposition, s.rule) for s in symbols.parse_symbols(SERVICE, source, policy=POLICY).symbols}
        self.assertEqual(got, {"Admin.has_change_permission": (Disposition.POS, "R10"), "Admin.delete": (Disposition.POS, "R10"),
                               "Admin.forward": (Disposition.POS_NEG, "R8"), "uses_nested": (Disposition.POS_NEG, "R8")})

    def test_a_syntax_error_is_reported_not_hidden(self):
        module = symbols.parse_symbols(SERVICE, "def broken(:\n", policy=POLICY)
        self.assertEqual((module.symbols, module.error), ([], "SyntaxError line 1"))

    def test_nested_functions_are_part_of_their_enclosing_function(self):
        module = symbols.parse_symbols(SERVICE, "def outer(a):\n    def inner(b):\n        return b\n    return inner(a)\n", policy=POLICY)
        self.assertEqual([s.qualname for s in module.symbols], ["outer"])


def _policy_data() -> dict:
    import yaml

    return yaml.safe_load(policy_module.POLICY_FILE.read_text())


class PolicyTests(SimpleTestCase):
    def test_the_tracked_policy_loads(self):
        self.assertTrue(POLICY.generic_groups)
        self.assertIn("negative", POLICY.negative_intent_words)
        self.assertEqual(len(POLICY.assignment_examples), 7)

    def test_malformed_policies_are_refused(self):
        base = _policy_data()
        for name, change in (
            ("schema", {"schema_version": 2}),
            ("exemption without reason", {"artifact_exemptions": [{"pattern": "x/**", "reason": ""}]}),
            ("symbol exemption without ::", {"symbol_exemptions": [{"symbol": "x.py", "reason": "r"}]}),
            ("group without match", {"generic_groups": [{"id": "g", "title": "G"}]}),
            ("duplicate group", {"generic_groups": [{"id": "g", "title": "G", "paths": ["a"]}, {"id": "g", "title": "H", "paths": ["b"]}]}),
            ("words", {"negative_intent_words": ["Not a word"]}),
            ("example", {"assignment_examples": [{"requirement": "IP", "targets": ["no-separator"]}]}),
            ("false positive", {"pylint_false_positives": [{"path": "a.py", "symbol": "", "reason": "r"}]}),
            ("mapping", {"platform_dirs": ["ceos"]}),
        ):
            with self.subTest(case=f"invalid {name}"):
                with self.assertRaises(policy_module.PolicyError):
                    policy_module.parse_policy({**base, **change})
        with self.assertRaises(policy_module.PolicyError):
            policy_module.parse_policy(["not", "a", "mapping"])

    def test_load_policy_refuses_unreadable_and_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(policy_module.PolicyError):
                policy_module.load_policy(Path(tmp) / "missing.yml")
            bad = Path(tmp) / "bad.yml"
            bad.write_text("a: [unclosed\n")
            with self.assertRaises(policy_module.PolicyError):
                policy_module.load_policy(bad)


class InventoryTests(SimpleTestCase):
    def test_artifact_types_ids_and_exclusions(self):
        _root, inv, _modules = make_inventory({
            SERVICE: "def f(x):\n    return x\n", "templates/features/ceos/interface_loopback.j2": "interface {{ name }}\n",
            "monitoring/config/cpu_threshold_policy.yml": "a: 1\n", "deploy/scripts/install_web_stack.sh": "set -eu\n",
            "web/core/tests/test_x.py": "", "docs/notes.py": "", "web/core/migrations/0001_initial.py": "x = 1\n",
        }, cell_rows=ledger(("arista_ceos", "interface.LOOPBACK", "SUPPORTED")))
        by_path = inv.by_path()
        self.assertEqual(sorted(by_path), sorted([SERVICE, "templates/features/ceos/interface_loopback.j2", "monitoring/config/cpu_threshold_policy.yml",
                                                  "deploy/scripts/install_web_stack.sh", "web/core/migrations/0001_initial.py"]))
        self.assertEqual(inv.test_files, ["web/core/tests/test_x.py"])
        self.assertEqual(by_path[SERVICE].id, f"PY:{SERVICE}")
        self.assertEqual(by_path[SERVICE].subsystem, "device_builder")
        template = by_path["templates/features/ceos/interface_loopback.j2"]
        self.assertEqual((template.id.split(":")[0], template.platform, template.features, template.scope),
                         ("JINJA", "arista_ceos", ("interface.LOOPBACK",), Scope.CURRENT))
        self.assertEqual(by_path["web/core/migrations/0001_initial.py"].scope, Scope.EXEMPT)
        self.assertEqual(inv.errors, [])

    @case("GOVERNANCE_NEW_UNCLASSIFIED_ARTIFACT", target=INV + "::build_inventory", polarity=NEGATIVE,
          condition="a new deployed file that no Tier-3 path rule classifies",
          expected="UNCLASSIFIED_ARTIFACT catalog error (the gate fails until it is classified)")
    def test_a_new_unclassified_file_is_a_catalog_error(self):
        _root, inv, _m = make_inventory({"brand_new_dir/automation.py": "def go(x):\n    return x\n"})
        self.assertEqual([a.classified for a in inv.artifacts], [False])
        self.assertEqual(inv.errors, ["UNCLASSIFIED_ARTIFACT PY:brand_new_dir/automation.py: no Tier-3 subsystem rule matches (ci/rules.py)"])

    def test_an_unmapped_feature_template_is_unclassified(self):
        _root, inv, _m = make_inventory({"templates/features/ceos/routing_new_protocol.j2": "x\n"})
        self.assertTrue(inv.errors and inv.errors[0].startswith("UNCLASSIFIED_ARTIFACT JINJA:templates/features/ceos/routing_new_protocol.j2"))

    @case("GOVERNANCE_NOT_IMPLEMENTED_TEMPLATE_NOT_CURRENT", target=INV + "::classify_artifact", polarity=NEGATIVE,
          condition="a feature template whose platform x feature cell is UNSUPPORTED in the capability matrix",
          expected="NOT_CURRENT_SCOPE with the capability reason (never counted as missing current-scope tests)")
    def test_not_implemented_cells_make_templates_not_current_scope(self):
        rows = ledger(("arista_ceos", "routing.ISIS", "UNSUPPORTED"))
        _root, inv, _m = make_inventory({"templates/features/ceos/routing_isis.j2": "router isis\n",
                                         "web/core/services/config_import/parser_sonic.py": "def parse(t):\n    return t\n"}, cell_rows=rows)
        scopes = {a.path: (a.scope, a.scope_reason) for a in inv.artifacts}
        self.assertEqual(scopes["templates/features/ceos/routing_isis.j2"],
                         (Scope.NOT_CURRENT_SCOPE, "no SUPPORTED capability cell for arista_ceos x routing.ISIS (capability matrix)"))
        self.assertEqual(scopes["web/core/services/config_import/parser_sonic.py"][0], Scope.NOT_CURRENT_SCOPE)

    def test_fingerprint_changes_with_code_and_tests_but_not_order(self):
        root, inv, _m = make_inventory({SERVICE: "def f(x):\n    return x\n", "web/core/tests/test_a.py": "pass\n"})
        first = inventory.fingerprint(inv, root)
        self.assertEqual(first, inventory.fingerprint(inventory.Inventory(list(reversed(inv.artifacts)), inv.test_files), root))
        (root / "web/core/tests/test_a.py").write_text("pass  # changed\n")
        self.assertNotEqual(first, inventory.fingerprint(inv, root))

    def test_the_real_repository_inventory_is_fully_classified(self):
        inv = inventory.build_inventory()
        self.assertEqual(inv.errors, [])
        ids = [a.id for a in inv.artifacts]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("PY:web/core/services/health/live.py", ids)
        self.assertIn("JINJA:templates/features/ceos/routing_ospfv2.j2", ids)
        self.assertNotIn("PY:web/core/tests/runner.py", ids)


class CellTests(SimpleTestCase):
    def test_ledger_parsing_and_stage_applicability(self):
        raw = {"cells": [{"platform": "ubuntu_frr", "feature": "routing.OSPFV2", "final_status": "SUPPORTED", "semantic": "PASS",
                          "field_validation": "PASS", "renderer": "PASS", "parser": "PASS", "validator": "FAIL", "executor": "PASS",
                          "compensation": "NOT_RUN"}]}
        (cell,) = cells_module.parse_ledger(raw)
        self.assertEqual((cell.supported, cell.stages), (True, ("MODEL", "RENDER", "IMPORT", "EXECUTE")))

    def test_malformed_ledgers_are_refused(self):
        for bad in ({}, {"cells": [{"platform": "x"}]},
                    {"cells": [{"platform": "x", "feature": "f", "final_status": "S"}, {"platform": "x", "feature": "f", "final_status": "S"}]}):
            with self.subTest(case=f"invalid {bad}"):
                with self.assertRaises(cells_module.LedgerError):
                    cells_module.parse_ledger(bad)

    def test_the_tracked_ledger_has_47_supported_cells(self):
        self.assertEqual(len(cells_module.supported_cells()), 47)


def _report(files: dict, ev: catalog.Evidence, *, cell_rows=(), baseline=None, coverage_files=None, lint=None):
    root, inv, modules = make_inventory(files, cell_rows=cell_rows)
    data = report_module.build_report(inventory=inv, modules=modules, cells=tuple(cell_rows), evidence=ev,
                                      coverage_files={} if coverage_files is None else coverage_files, lint=lint or {}, baseline=baseline,
                                      policy=POLICY, provenance={"repository_sha": "a" * 40, "source_fingerprint": "b" * 64}, repo=root)
    data["gate"] = gate.evaluate(data, baseline or {})
    data["payload_sha256"] = report_module.payload_hash(data)
    return data


SYM = f"{SERVICE}::validate_port"


class CatalogEvaluationTests(SimpleTestCase):
    def test_direct_return_proves_positive_and_raise_proves_negative(self):
        data = _report({SERVICE: SOURCE}, trace(
            **{"django:t.test_accepts_valid_port": ("PASS", {SYM: [1, 0, 0, 0]}, ()),
               "django:t.test_rejects_port_zero": ("PASS", {SYM: [0, 0, 1, 1]}, ())}))
        states = {c["id"]: (c["state"], [b for _t, b in c["evidence"]]) for c in data["cases"] if c["symbol"] == SYM}
        self.assertEqual(states, {f"SYM:{SYM}:POSITIVE": (CaseState.PASS, [Basis.DIRECT_RETURN]),
                                  f"SYM:{SYM}:NEGATIVE": (CaseState.PASS, [Basis.DIRECT_RAISE])})

    def test_refusal_by_return_value_counts_as_negative_only_in_a_negative_context(self):
        data = _report({SERVICE: SOURCE}, trace(**{"django:t.test_x": ("PASS", {SYM: [0, 0, 2, 0]}, ())}))
        neg = next(c for c in data["cases"] if c["id"] == f"SYM:{SYM}:NEGATIVE")
        pos = next(c for c in data["cases"] if c["id"] == f"SYM:{SYM}:POSITIVE")
        self.assertEqual((neg["state"], neg["evidence"][0][1], pos["state"]), (CaseState.PASS, Basis.DIRECT_REFUSAL, CaseState.MISSING))

    @case("GOVERNANCE_FAILING_TEST_NOT_PASS", target=CAT + "::state_of", polarity=NEGATIVE,
          condition="the only test proving a case failed in the evidence run", expected="the case is FAIL, never PASS; the gate fails")
    def test_a_failing_test_is_never_counted_as_pass(self):
        data = _report({SERVICE: SOURCE}, trace(**{"django:t.test_accepts": ("FAIL", {SYM: [1, 0, 0, 0]}, ())}))
        pos = next(c for c in data["cases"] if c["id"] == f"SYM:{SYM}:POSITIVE")
        self.assertEqual(pos["state"], CaseState.FAIL)
        self.assertIn("CASE_FAILED", [f["code"] for f in data["gate"]["findings"]])
        self.assertEqual(data["gate"]["result"], gate.FAIL)
        self.assertEqual(catalog.state_of(["SKIP"]), CaseState.MISSING)
        self.assertEqual(catalog.state_of(["ERROR", "PASS"]), CaseState.PASS)

    @case("GOVERNANCE_DENOMINATOR_FROM_CODE", target=CAT + "::build_catalog", polarity=NEGATIVE,
          condition="only the positive case of a boundary function has a test",
          expected="negative x / y = 0 / 2 (Y comes from the code: validate_port and Thing.run), not 0 / 0")
    def test_a_missing_negative_case_lowers_x_while_y_stays_fixed(self):
        data = _report({SERVICE: SOURCE}, trace(**{"django:t.test_accepts": ("PASS", {SYM: [1, 0, 0, 0]}, ())}))
        art = data["artifacts"][0]
        self.assertEqual((art["positive"]["pass"], art["positive"]["required"]), (1, 3))   # validate_port, describe, Thing.run
        self.assertEqual((art["negative"]["pass"], art["negative"]["required"]), (0, 2))
        self.assertEqual(art["status"], ArtifactStatus.PARTIAL)
        self.assertEqual(art["functions"], {"required": 3, "tested": 1, "internal": 1, "exempt": 3, "internal_direct": 0})

    def test_an_input_independent_symbol_is_proven_by_a_direct_test_of_either_intent(self):
        source = "def refuse_delete(*args, **kwargs):\n    raise ValueError('immutable')\n"
        sym = f"{SERVICE}::refuse_delete"
        data = _report({SERVICE: source}, trace(**{"django:t.test_delete_is_refused": ("PASS", {sym: [0, 0, 1, 1]}, ())}))
        states = {c["id"]: c["state"] for c in data["cases"] if c["symbol"] == sym}
        self.assertEqual(states, {f"SYM:{sym}:POSITIVE": CaseState.PASS})

    @case("GOVERNANCE_NEW_FUNCTION_IS_MISSING", target=GATE + "::evaluate", polarity=NEGATIVE,
          condition="a new public function appears that no test invokes and the baseline does not record as debt",
          expected="its cases are MISSING (not debt) and the gate fails with CASE_MISSING_NEW")
    def test_a_new_uncovered_function_or_file_fails_the_gate(self):
        before = _report({SERVICE: "def old(x):\n    return x\n"}, trace(**{"django:t.test_old": ("PASS", {f"{SERVICE}::old": [1, 0, 1, 1]}, ())}))
        baseline = gate.baseline_from_report(before)
        self.assertEqual(before["gate"]["result"], gate.PASS)
        after = _report({SERVICE: "def old(x):\n    return x\n\n\ndef added(y):\n    return y\n",
                         "web/core/services/health_service.py": "def fresh(z):\n    return z\n"},
                        trace(**{"django:t.test_old": ("PASS", {f"{SERVICE}::old": [1, 0, 1, 1]}, ())}), baseline=baseline)
        new = next(f for f in after["gate"]["findings"] if f["code"] == "CASE_MISSING_NEW")
        self.assertEqual(new["ids"], sorted([f"SYM:{SERVICE}::added:NEGATIVE", f"SYM:{SERVICE}::added:POSITIVE",
                                            "SYM:web/core/services/health_service.py::fresh:NEGATIVE",
                                            "SYM:web/core/services/health_service.py::fresh:POSITIVE"]))
        self.assertEqual(after["gate"]["result"], gate.FAIL)
        fresh = next(a for a in after["artifacts"] if a["path"] == "web/core/services/health_service.py")
        self.assertEqual(fresh["status"], ArtifactStatus.MISSING)

    def test_known_debt_is_visible_and_passes_with_debt_and_paid_debt_is_reported(self):
        unrelated = {"django:t.test_unrelated": ("PASS", {}, ())}   # a run that executed tests, none proving f()
        first = _report({SERVICE: "def f(x):\n    return x\n"}, trace(**unrelated))
        baseline = gate.baseline_from_report(first)
        again = _report({SERVICE: "def f(x):\n    return x\n"}, trace(**unrelated), baseline=baseline)
        self.assertEqual(again["gate"]["result"], gate.PASS_WITH_DEBT)
        self.assertTrue(all(c["debt"] for c in again["cases"] if c["state"] == CaseState.MISSING))
        paid = _report({SERVICE: "def f(x):\n    return x\n"}, trace(**{"django:t.test_f": ("PASS", {f"{SERVICE}::f": [1, 0, 1, 1]}, ())}),
                       baseline=baseline)
        self.assertIn("DEBT_RESOLVED", [f["code"] for f in paid["gate"]["findings"]])

    def test_closed_artifacts_cannot_regress_and_disappearing_artifacts_fail(self):
        closed = _report({SERVICE: "def f(x):\n    return x\n"}, trace(**{"django:t.test_f": ("PASS", {f"{SERVICE}::f": [1, 0, 1, 1]}, ())}))
        baseline = gate.baseline_from_report(closed)
        self.assertEqual(baseline["closed_artifacts"], [f"PY:{SERVICE}"])
        regressed = _report({SERVICE: "def f(x):\n    return x\n"}, trace(), baseline={**baseline, "case_debt": [c["id"] for c in closed["cases"]]})
        codes = {f["code"] for f in regressed["gate"]["findings"]}
        self.assertIn("CLOSED_REGRESSION", codes)
        gone = _report({"web/core/services/health_service.py": "X = 1\n"}, trace(), baseline=baseline)
        self.assertIn("ARTIFACT_DISAPPEARED", {f["code"] for f in gone["gate"]["findings"]})

    def test_declared_cases_satisfy_their_symbol_and_are_locked(self):
        declared = Case("PORT_ZERO_REFUSED", target=SYM, polarity=NEGATIVE, condition="port 0", expected="ValueError")
        data = _report({SERVICE: SOURCE}, trace(**{"django:t.test_zero": ("PASS", {}, (declared,))}))
        neg = next(c for c in data["cases"] if c["id"] == f"SYM:{SYM}:NEGATIVE")
        own = next(c for c in data["cases"] if c["id"] == "PORT_ZERO_REFUSED")
        self.assertEqual((neg["state"], neg["evidence"][0][1], own["state"], own["kind"]), (CaseState.PASS, Basis.DECLARED, CaseState.PASS, "DECLARED"))
        baseline = gate.baseline_from_report(data)
        self.assertEqual(baseline["declared_cases"], {"PORT_ZERO_REFUSED": SYM})
        later = _report({SERVICE: SOURCE}, trace(), baseline=baseline)
        broken = next(c for c in later["cases"] if c["id"] == "PORT_ZERO_REFUSED")
        self.assertEqual(broken["state"], CaseState.BROKEN_REFERENCE)
        self.assertIn("BROKEN_REFERENCE", {f["code"] for f in later["gate"]["findings"]})

    def test_declared_case_with_a_broken_target_is_a_catalog_error(self):
        declared = Case("GHOST", target=f"{SERVICE}::does_not_exist", polarity=POSITIVE, condition="c", expected="e")
        data = _report({SERVICE: SOURCE}, trace(**{"django:t.test": ("PASS", {}, (declared,))}))
        self.assertIn(f"BROKEN_TARGET GHOST: symbol {SERVICE}::does_not_exist does not exist", data["catalog_errors"])
        self.assertEqual(data["gate"]["result"], gate.FAIL)

    @case("GOVERNANCE_SUPPORTED_CELL_CREATES_DEBT", target=CAT + "::build_catalog", polarity=POSITIVE,
          condition="a capability cell moves from UNSUPPORTED to SUPPORTED in the ledger",
          expected="its stage cases become required current scope at once (MISSING until tests prove them)")
    def test_cells_only_count_when_supported(self):
        unsupported = _report({SERVICE: "X = 1\n"}, trace(), cell_rows=ledger(("ubuntu_frr", "routing.ISIS", "UNSUPPORTED")))
        self.assertEqual([c for c in unsupported["cases"] if c["kind"] == "CELL"], [])
        self.assertEqual(unsupported["cells"][0]["status"], CellStatus.NOT_IMPLEMENTED)
        self.assertEqual(unsupported["summary"]["cells"]["supported"], 0)
        supported = _report({SERVICE: "X = 1\n"}, trace(), cell_rows=ledger(("ubuntu_frr", "routing.ISIS", "SUPPORTED")))
        cell_cases = [c for c in supported["cases"] if c["kind"] == "CELL"]
        self.assertEqual(len(cell_cases), 12)   # 6 stages x positive / negative
        self.assertEqual({c["state"] for c in cell_cases}, {CaseState.MISSING})
        self.assertEqual(supported["cells"][0]["status"], CellStatus.MISSING)
        self.assertIn("CASE_MISSING_NEW", {f["code"] for f in supported["gate"]["findings"]})

    def test_template_structured_and_executable_requirements(self):
        files = {"templates/R1.cfg.j2": "hostname {{ h }}\n", "monitoring/config/snmp_oids.yml": "a: 1\n",
                 "deploy/scripts/install_web_stack.sh": "set -eu\n", "templates/R9_unused.cfg.j2": "x\n",
                 "monitoring/docker-compose.yml": "services: {}\n", "inventory.yml": "network_devices: {R1: {template: R1.cfg.j2}}\n"}
        tpl_pos = Case("TPL:templates/R1.cfg.j2:RENDER:POSITIVE", target="templates/R1.cfg.j2", polarity=POSITIVE, condition="c", expected="e")
        data = _report(files, trace(**{"django:t.test_render": ("PASS", {}, (tpl_pos,))}))
        ids = {c["id"]: c["state"] for c in data["cases"]}
        self.maxDiff = None
        self.assertEqual(ids, {
            "TPL:templates/R1.cfg.j2:RENDER:POSITIVE": CaseState.PASS, "TPL:templates/R1.cfg.j2:STRICT_UNDEFINED:NEGATIVE": CaseState.MISSING,
            "CFG:monitoring/config/snmp_oids.yml:LOAD:POSITIVE": CaseState.MISSING, "CFG:monitoring/config/snmp_oids.yml:MALFORMED:NEGATIVE": CaseState.MISSING,
            "EXE:deploy/scripts/install_web_stack.sh:STATIC:POSITIVE": CaseState.MISSING,
            "CFG:inventory.yml:LOAD:POSITIVE": CaseState.MISSING, "CFG:inventory.yml:MALFORMED:NEGATIVE": CaseState.MISSING,
            # an unreferenced template is not deployed behavior; an external tool's file has no NMAS loader to refuse it
            "TPL:templates/R9_unused.cfg.j2:RENDER:POSITIVE": CaseState.NOT_CURRENT_SCOPE,
            "TPL:templates/R9_unused.cfg.j2:STRICT_UNDEFINED:NEGATIVE": CaseState.NOT_CURRENT_SCOPE,
            "CFG:monitoring/docker-compose.yml:LOAD:POSITIVE": CaseState.MISSING, "CFG:monitoring/docker-compose.yml:MALFORMED:NEGATIVE": CaseState.EXEMPT})

    def test_exempt_and_not_current_cases_stay_out_of_the_denominator(self):
        rows = ledger(("sonic", "interface.LOOPBACK", "UNSUPPORTED"))
        data = _report({"web/core/services/config_import/parser_sonic.py": "def parse(t):\n    return t\n",
                        "web/core/migrations/0001_initial.py": "def f(x):\n    return x\n", SERVICE: SOURCE}, trace(), cell_rows=rows)
        statuses = {a["path"]: a["status"] for a in data["artifacts"]}
        self.assertEqual(statuses["web/core/services/config_import/parser_sonic.py"], ArtifactStatus.NOT_CURRENT_SCOPE)
        self.assertEqual(statuses["web/core/migrations/0001_initial.py"], ArtifactStatus.EXEMPT)
        self.assertEqual(data["summary"]["positive"]["required"], 3)
        self.assertEqual(data["summary"]["positive"]["exempt"], 3)
        self.assertEqual(data["summary"]["positive"]["not_current"], 1)


class TracerTests(unittest.TestCase):
    """The tracer on a real module: direct vs indirect, return vs raise, setUp exclusion, sub-test intent, outcomes."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        (root / "pkg").mkdir()
        (root / "pkg" / "target.py").write_text(
            "def boundary(x):\n    if x < 0:\n        raise ValueError(x)\n    return inner(x)\n\n\ndef inner(x):\n    return x + 1\n")
        (root / "tests").mkdir()
        cls.root = root
        sys.path.insert(0, str(root))
        import importlib

        cls.target = importlib.import_module("pkg.target")

    @classmethod
    def tearDownClass(cls):
        sys.path.remove(str(cls.root))
        sys.modules.pop("pkg.target", None)
        sys.modules.pop("pkg", None)
        cls.tmp.cleanup()

    def _run(self, test_case_class):
        tracer = DirectCallTracer(self.root, build_targets(self.root, ["pkg/target.py::boundary", "pkg/target.py::inner"]),
                                  test_roots=("tests",), suite="fixture", negative_words=frozenset({"rejects", "invalid"}),
                                  positive_words=frozenset({"valid"}), tool_id=3)  # 4 may be the outer evidence run's tracer
        # the fixture test methods must live under the tracer's test root: compile them from a file there
        result_class = make_result_class(unittest.TestResult, tracer)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_case_class)
        tracer.install()
        try:
            suite.run(result_class())
        finally:
            tracer.uninstall()
        return tracer.tests

    def _fixture_class(self):
        code = (
            "import unittest\n"
            "from pkg import target\n"
            "class Fixture(unittest.TestCase):\n"
            "    def setUp(self):\n        target.boundary(5)\n"
            "    def test_accepts(self):\n        self.assertEqual(target.boundary(1), 2)\n"
            "    def test_rejects_negative(self):\n        with self.assertRaises(ValueError):\n            target.boundary(-1)\n"
            "    def test_matrix(self):\n"
            "        for label, value in (('valid one', 1), ('invalid zero', 0)):\n"
            "            with self.subTest(case=label):\n                target.boundary(value)\n"
            "    def test_fails(self):\n        self.assertEqual(target.boundary(1), 99)\n"
        )
        path = self.root / "tests" / "fixture_tests.py"
        path.write_text(code)
        namespace: dict = {"__name__": "fixture_tests"}
        exec(compile(code, str(path), "exec"), namespace)  # noqa: S102 - a fixture test module compiled from its own file
        return namespace["Fixture"]

    def test_links_only_direct_test_body_calls_with_their_polarity(self):
        tests = self._run(self._fixture_class())
        by_name = {tid.rsplit(".", 1)[-1]: rec for tid, rec in tests.items()}
        self.assertEqual(by_name["test_accepts"]["links"], {"pkg/target.py::boundary": [1, 0, 0, 0]})   # setUp's call and inner() excluded
        self.assertEqual(by_name["test_accepts"]["outcome"], "PASS")
        self.assertEqual(by_name["test_rejects_negative"]["links"], {"pkg/target.py::boundary": [0, 0, 1, 1]})
        self.assertEqual(by_name["test_rejects_negative"]["intent"], "negative")
        self.assertEqual(by_name["test_matrix"]["links"], {"pkg/target.py::boundary": [1, 0, 1, 0]})    # sub-test intent per call
        self.assertEqual(by_name["test_fails"]["outcome"], "FAIL")
        self.assertNotIn("pkg/target.py::inner", json.dumps(tests))

    def test_the_tracer_restores_subtest_and_releases_its_tool_id(self):
        original = unittest.TestCase.subTest
        self._run(self._fixture_class())
        self.assertIs(unittest.TestCase.subTest, original)
        self.assertIsNone(sys.monitoring.get_tool(3))

    def test_nested_unittest_runner_preserves_remaining_direct_return_and_raise_evidence(self):
        code = (
            "import unittest\nfrom pkg import target\n"
            "class Fixture(unittest.TestCase):\n"
            "    def test_valid_after_nested_runner(self):\n"
            "        unittest.FunctionTestCase(lambda: None).run(unittest.TestResult())\n"
            "        self.assertEqual(target.boundary(1), 2)\n"
            "        with self.assertRaises(ValueError):\n"
            "            target.boundary(-1)\n"
        )
        path = self.root / "tests" / "nested_fixture.py"
        namespace = {"__name__": "nested_fixture"}
        exec(compile(code, str(path), "exec"), namespace)  # noqa: S102 - isolated fixture module
        tests = self._run(namespace["Fixture"])
        record = next(iter(tests.values()))
        self.assertEqual(record["outcome"], "PASS")
        self.assertEqual(record["links"], {"pkg/target.py::boundary": [2, 1, 0, 0]})

    def test_the_tracer_does_not_change_the_exception_the_code_sees(self):
        tests = self._run(self._fixture_class())
        self.assertTrue(any(rec["outcome"] == "PASS" for tid, rec in tests.items() if tid.endswith("test_rejects_negative")))

    def test_identical_functions_in_different_files_are_credited_to_their_own_file(self):
        # F5 regression: CPython code objects compare equal across files when body and first line match, so a cache keyed by the bare
        # code object credited pkg/twin_b.py::run's call to pkg/twin_a.py::run (seen first).
        import importlib

        for name in ("twin_a", "twin_b"):
            (self.root / "pkg" / f"{name}.py").write_text("\n\ndef run(x):\n    return x\n")
            self.addCleanup(sys.modules.pop, f"pkg.{name}", None)
        twin_a, twin_b = importlib.import_module("pkg.twin_a"), importlib.import_module("pkg.twin_b")
        self.assertEqual(twin_a.run.__code__, twin_b.run.__code__)            # the CPython behaviour the cache must not rely on
        code = ("import unittest\nfrom pkg import twin_a, twin_b\nclass Twins(unittest.TestCase):\n"
                "    def test_a(self):\n        twin_a.run(1)\n    def test_b(self):\n        twin_b.run(2)\n")
        path = self.root / "tests" / "twin_tests.py"
        path.write_text(code)
        namespace: dict = {"__name__": "twin_tests"}
        exec(compile(code, str(path), "exec"), namespace)  # noqa: S102 - a fixture test module compiled from its own file
        tracer = DirectCallTracer(self.root, build_targets(self.root, ["pkg/twin_a.py::run", "pkg/twin_b.py::run"]), test_roots=("tests",),
                                  suite="fixture", negative_words=frozenset(), positive_words=frozenset(), tool_id=3)
        result_class = make_result_class(unittest.TestResult, tracer)
        tracer.install()
        try:
            unittest.defaultTestLoader.loadTestsFromTestCase(namespace["Twins"]).run(result_class())
        finally:
            tracer.uninstall()
        by_name = {tid.rsplit(".", 1)[-1]: rec["links"] for tid, rec in tracer.tests.items()}
        self.assertEqual(by_name, {"test_a": {"pkg/twin_a.py::run": [1, 0, 0, 0]}, "test_b": {"pkg/twin_b.py::run": [1, 0, 0, 0]}})


class ParserTests(SimpleTestCase):
    def test_coverage_json_figures_per_file_and_symbol(self):
        raw = {"files": {str(REPO_ROOT / SERVICE): {"executed_lines": [1, 2, 3, 6], "missing_lines": [4, 5, 9],
                                                    "executed_branches": [[2, 3]], "missing_branches": [[2, 4], [9, 10]]}}}
        files = coverage_data.parse_coverage_json(raw, repo=REPO_ROOT)
        fc = files[SERVICE]
        self.assertEqual(fc.figures()["line_pct"], 57.14)
        self.assertEqual(fc.figures()["missing_lines"], ["4-5", "9"])
        self.assertEqual(fc.figures(1, 6)["branches"], 2)
        self.assertEqual(fc.figures(1, 6)["missing_branches"], ["2->4"])
        self.assertEqual(coverage_data.compress([1, 2, 3, 7, 9, 10]), ["1-3", "7", "9-10"])
        self.assertIsNone(coverage_data.pct(0, 0))
        with self.assertRaises(coverage_data.CoverageDataError):
            coverage_data.parse_coverage_json({"no": "files"})

    def test_a_file_no_test_imported_counts_as_zero_not_as_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "m.py").write_text("def f(x):\n    if x:\n        return 1\n    return 2\n")
            fc = coverage_data.unmeasured("m.py", Path(tmp))
        figs = fc.figures()
        self.assertEqual((fc.measured, figs["covered"], figs["statements"], figs["line_pct"]), (False, 0, 4, 0.0))

    def test_pylint_critical_baseline_and_false_positive_handling(self):
        data = {"messages": [
            {"type": "error", "symbol": "undefined-variable", "message": "x", "path": SERVICE, "line": 3},
            {"type": "warning", "symbol": "unused-import", "message": "y", "path": SERVICE, "line": 1},
            {"type": "warning", "symbol": "dangerous-default-value", "message": "z", "path": "modules/nmas.py", "line": 9},
            {"type": "error", "symbol": "undefined-variable", "message": "fp", "path": "monitoring/scripts/ceos_syslog_forward.py", "line": 38},
        ]}
        lint = pylint_data.parse_pylint(data, policy=POLICY, linted=["modules/snmp.py"])
        self.assertEqual((lint[SERVICE].critical, lint[SERVICE].counts), (1, {"unused-import": 1}))
        self.assertEqual(lint["modules/nmas.py"].critical, 1)            # a critical correctness warning
        self.assertEqual(lint["monitoring/scripts/ceos_syslog_forward.py"].false_positives, 1)
        self.assertEqual(lint["modules/snmp.py"].status(None), PylintStatus.PASS)
        self.assertEqual(lint[SERVICE].status({"unused-import": 1}), PylintStatus.FAIL)    # critical
        warn = pylint_data.ArtifactLint("a.py", counts={"unused-import": 2})
        self.assertEqual((warn.status({"unused-import": 2}), warn.status({"unused-import": 1})), (PylintStatus.WARN, PylintStatus.FAIL))
        self.assertEqual(warn.over_baseline({"unused-import": 1}), {"unused-import": 1})
        with self.assertRaises(pylint_data.PylintDataError):
            pylint_data.parse_pylint([], policy=POLICY)


class ReportSchemaAndDeterminismTests(SimpleTestCase):
    def setUp(self):
        self.data = _report({SERVICE: SOURCE, "templates/R1.cfg.j2": "x\n"},
                            trace(**{"django:t.test_ok": ("PASS", {SYM: [1, 0, 0, 0]}, ())}),
                            cell_rows=ledger(("arista_ceos", "routing.OSPFV2", "SUPPORTED"), ("sonic", "routing.OSPFV2", "UNSUPPORTED")))

    def test_the_report_validates_against_its_versioned_schema(self):
        self.assertEqual(schema.validate(self.data), [])

    def test_schema_violations_are_reported(self):
        broken = json.loads(json.dumps(self.data))
        broken["cases"][0]["state"] = "GREEN"
        del broken["summary"]
        problems = schema.validate(broken)
        self.assertIn("$: missing required key 'summary'", problems)
        self.assertTrue(any("GREEN" in p for p in problems))
        with self.assertRaises(ValueError):
            schema.validate({}, {"type": "object", "additionalProperties": False})

    def test_same_inputs_give_the_same_payload_hash_and_timestamps_do_not_count(self):
        again = _report({SERVICE: SOURCE, "templates/R1.cfg.j2": "x\n"}, trace(**{"django:t.test_ok": ("PASS", {SYM: [1, 0, 0, 0]}, ())}),
                        cell_rows=ledger(("arista_ceos", "routing.OSPFV2", "SUPPORTED"), ("sonic", "routing.OSPFV2", "UNSUPPORTED")))
        again["generated_at"] = "2000-01-01T00:00:00Z"
        self.assertEqual(report_module.payload_hash(again), self.data["payload_sha256"])
        changed = json.loads(json.dumps(self.data))
        changed["summary"]["positive"]["pass"] += 1
        self.assertNotEqual(report_module.payload_hash(changed), self.data["payload_sha256"])

    def test_generic_groups_and_cells_are_aggregated_separately(self):
        groups = {g["id"]: g for g in self.data["groups"]}
        self.assertIn("configuration", groups)
        self.assertEqual(groups["configuration"]["positive"]["required"], 3)
        cells = {(c["platform"], c["status"]) for c in self.data["cells"]}
        self.assertEqual(cells, {("arista_ceos", CellStatus.MISSING), ("sonic", CellStatus.NOT_IMPLEMENTED)})


class SummaryMarkdownTests(SimpleTestCase):
    """RESULTS.md / BASELINE.md are rendered from verified reports; every figure must trace back to the report."""

    def setUp(self):
        self.data = _report({SERVICE: SOURCE, "templates/R1.cfg.j2": "x\n"},
                            trace(**{"django:t.test_ok": ("PASS", {SYM: [1, 0, 0, 0]}, ()), "django:t.test_bad": ("FAIL", {}, ())}),
                            cell_rows=ledger(("arista_ceos", "routing.OSPFV2", "SUPPORTED")))

    def test_results_markdown_shows_baseline_and_final_columns_from_the_reports(self):
        from core.services.test_governance import summary

        text = summary.results_markdown(self.data, self.data)
        pos = summary.figures(self.data)["positive"]
        self.assertIn(f"| Positive cases PASS / required | {pos['pass']} / {pos['required']}", text)
        self.assertIn(self.data["payload_sha256"], text)
        self.assertIn("| arista_ceos | routing.OSPFV2 | MISSING |", text)

    def test_gap_markdown_excludes_the_named_group_and_lists_tests_that_did_not_pass(self):
        from core.services.test_governance import summary

        text = summary.gap_markdown(self.data, exclude_groups=("configuration",))
        self.assertNotIn("Configuration / Device Builder |", text)
        self.assertIn("* `django:t.test_bad`", text)
        self.assertNotIn("* `django:t.test_ok`", text)
        self.assertEqual(summary.figures(self.data, exclude_groups=("configuration",))["functions"], (0, 0))

    def test_a_compressed_report_is_verified_like_any_other_and_tampering_is_refused(self):
        import gzip

        from core.management.commands.nmas_test_governance import _read_evidence

        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "r.json.gz"
            good.write_bytes(gzip.compress(json.dumps(self.data).encode()))
            self.assertEqual(evidence_module.verify_report(_read_evidence(str(good)))["payload_sha256"], self.data["payload_sha256"])
            tampered = json.loads(json.dumps(self.data))
            tampered["summary"]["positive"]["pass"] += 1
            bad = Path(tmp) / "bad.json.gz"
            bad.write_bytes(gzip.compress(json.dumps(tampered).encode()))
            with self.assertRaises(evidence_module.EvidenceError):
                evidence_module.verify_report(_read_evidence(str(bad)))


class EvidenceStoreTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.data = _report({SERVICE: SOURCE}, trace(**{"django:t.test_ok": ("PASS", {SYM: [1, 0, 0, 0]}, ())}))
        self.raw = json.dumps(self.data).encode()

    def tearDown(self):
        self.tmp.cleanup()

    def test_accept_is_write_once_and_select_prefers_the_deployed_sha(self):
        meta = evidence_module.accept(self.raw, source="unit test", directory=self.dir)
        self.assertEqual(meta["payload_sha256"], self.data["payload_sha256"])
        evidence_module.accept(self.raw, source="unit test again", directory=self.dir)
        self.assertEqual(len(list((self.dir / "accepted").glob("*.meta.json"))), 1)
        with mock.patch.object(evidence_module, "deployed_state", return_value={"sha": "a" * 40, "fingerprint": "z" * 64}):
            chosen = evidence_module.select(self.dir, bundled=self.dir / "none.json")
        self.assertEqual((chosen["freshness"], chosen["report"]["payload_sha256"]), (Freshness.CURRENT, self.data["payload_sha256"]))

    @case("GOVERNANCE_STALE_EVIDENCE", target="web/core/services/test_governance/evidence.py::freshness", polarity=NEGATIVE,
          condition="evidence for another commit whose source fingerprint differs from the deployed checkout",
          expected="STALE with the reason; never presented as current")
    def test_evidence_for_other_source_is_stale_and_identical_source_is_current(self):
        self.assertEqual(evidence_module.freshness(self.data, {"sha": "c" * 40, "fingerprint": "d" * 64})[0], Freshness.STALE)
        self.assertEqual(evidence_module.freshness(self.data, {"sha": "c" * 40, "fingerprint": "b" * 64})[0], Freshness.CURRENT)
        self.assertEqual(evidence_module.freshness(self.data, {"sha": "", "fingerprint": ""})[0], Freshness.UNKNOWN)
        self.assertEqual(evidence_module.freshness(self.data, {"sha": "c" * 40, "fingerprint": ""})[0], Freshness.UNKNOWN)

    def test_tampered_malformed_and_oversized_reports_are_refused(self):
        tampered = json.loads(self.raw)
        tampered["summary"]["positive"]["pass"] = 999
        for raw, code in ((json.dumps(tampered).encode(), "EVIDENCE_HASH_MISMATCH"), (b"not json", "EVIDENCE_NOT_JSON"),
                          (json.dumps({"schema_version": 9}).encode(), "EVIDENCE_SCHEMA_VERSION"),
                          (json.dumps({**tampered, "cases": "x"}).encode(), "EVIDENCE_SCHEMA_INVALID")):
            with self.subTest(case=f"refused {code}"):
                with self.assertRaises(evidence_module.EvidenceError) as ctx:
                    evidence_module.accept(raw, source="x", directory=self.dir)
                self.assertEqual(ctx.exception.code, code)
        with mock.patch.object(evidence_module, "MAX_REPORT_BYTES", 10):
            with self.assertRaises(evidence_module.EvidenceError):
                evidence_module.verify_report(self.raw)
        self.assertFalse((self.dir / "accepted").exists())

    def test_no_evidence_and_a_corrupt_cached_file(self):
        with mock.patch.object(evidence_module, "deployed_state", return_value={"sha": "a" * 40, "fingerprint": "b" * 64}):
            self.assertEqual(evidence_module.select(self.dir, bundled=self.dir / "none.json")["freshness"], Freshness.NONE)
            evidence_module.accept(self.raw, source="x", directory=self.dir)
            (self.dir / "accepted" / f"{self.data['payload_sha256']}.json").write_text("{}")
            chosen = evidence_module.select(self.dir, bundled=self.dir / "none.json")
        self.assertEqual(chosen["freshness"], Freshness.NONE)
        self.assertEqual(chosen["refused"][0]["code"], "EVIDENCE_SCHEMA_VERSION")


class GitHubEvidenceTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = _report({SERVICE: SOURCE}, trace())
        self.data["provenance"]["run_id"] = "77"
        self.data["payload_sha256"] = report_module.payload_hash(self.data)

    def tearDown(self):
        self.tmp.cleanup()

    def _zip(self, payload: bytes) -> bytes:
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("test-governance-report.json", payload)
        return buf.getvalue()

    def test_refresh_accepts_only_the_runs_own_report(self):
        from core.services.test_governance import github_evidence

        runs = {"workflow_runs": [{"id": 77, "head_sha": "a" * 40, "created_at": "2026", "conclusion": "success"}]}
        artifacts = {"artifacts": [{"name": "test-governance", "archive_download_url": "https://api.github.com/x", "expired": False}]}
        calls = []

        def fake_call(method, path, body=None):
            calls.append((method, path))
            return runs if "/runs?" in path else artifacts

        with mock.patch.object(github_evidence.github, "_call", side_effect=fake_call):
            meta = github_evidence.refresh("a" * 40, directory=Path(self.tmp.name), fetch=lambda _u: self._zip(json.dumps(self.data).encode()))
            self.assertEqual((meta["run_id"], meta["payload_sha256"]), (77, self.data["payload_sha256"]))
            self.assertTrue(all(method == "GET" for method, _p in calls))
            other = {**self.data, "repository_sha": "c" * 40}
            other["payload_sha256"] = report_module.payload_hash(other)
            with self.assertRaises(evidence_module.EvidenceError) as ctx:
                github_evidence.refresh("a" * 40, directory=Path(self.tmp.name), fetch=lambda _u: self._zip(json.dumps(other).encode()))
            self.assertEqual(ctx.exception.code, github_evidence.MISMATCH)
            with self.assertRaises(evidence_module.EvidenceError):
                github_evidence.refresh("a" * 40, directory=Path(self.tmp.name), fetch=lambda _u: b"not a zip")
        with mock.patch.object(github_evidence.github, "_call", return_value={"workflow_runs": []}):
            with self.assertRaises(evidence_module.EvidenceError) as ctx:
                github_evidence.refresh("a" * 40, directory=Path(self.tmp.name))
            self.assertEqual(ctx.exception.code, github_evidence.NO_RUN)
        with self.assertRaises(evidence_module.EvidenceError):
            github_evidence.refresh("short")


class CaseDecoratorTests(SimpleTestCase):
    def test_metadata_is_attached_and_stackable_without_changing_the_test(self):
        @case("A_CASE", target=SERVICE, polarity=POSITIVE, condition="c", expected="e")
        @case("B_CASE", target=SYM, polarity=NEGATIVE, condition="c", expected="e", platform="arista_ceos", feature="routing.OSPFV2",
              stage="RENDER")
        def probe():
            return 42

        self.assertEqual(probe(), 42)
        self.assertEqual([c.case_id for c in declared_on(probe)], ["B_CASE", "A_CASE"])
        self.assertEqual(declared_on(probe)[0].symbol, SYM)

    def test_malformed_declarations_fail_loudly(self):
        for kwargs in ({"case_id": "lower"}, {"polarity": "MAYBE"}, {"target": "/abs/path.py"}, {"target": "../x.py"},
                       {"condition": " "}, {"stage": "DEPLOY"}, {"platform": "arista_ceos"}):
            args = {"case_id": "OK_ID", "target": SERVICE, "polarity": POSITIVE, "condition": "c", "expected": "e", **kwargs}
            with self.subTest(case=f"invalid {kwargs}"):
                with self.assertRaises(ValueError):
                    case(args.pop("case_id"), **args)
        self.assertEqual(shape_errors(Case("OK", SERVICE, POSITIVE, "c", "e")), [])


class StaticCatalogValidationTests(SimpleTestCase):
    def test_declarations_are_checked_against_the_repository(self):
        from core.services.test_governance import catalog_check

        bad = [("t.a", Case("X_ONE", "nope/missing.py", POSITIVE, "c", "e")),
               ("t.b", Case("X_TWO", f"{SERVICE}::nope", POSITIVE, "c", "e")),
               ("t.c", Case("X_THREE", SERVICE, POSITIVE, "c", "e", platform="arista_ceos", feature="routing.NOPE")),
               ("t.d", Case("TPL:templates/none.j2:RENDER:POSITIVE", SERVICE, POSITIVE, "c", "e")),
               ("t.e", Case("X_ONE", SERVICE, NEGATIVE, "c", "e"))]
        result = catalog_check.validate_catalog(declared=bad, baseline={"declared_cases": {"LOCKED_GONE": SERVICE},
                                                                        "artifacts": ["PY:gone.py"]})
        text = "\n".join(result["errors"])
        for expected in ("BROKEN_TARGET X_ONE", "BROKEN_TARGET X_TWO", "UNKNOWN_CELL X_THREE", "UNKNOWN_GENERATED_CASE TPL:templates/none.j2",
                         "DUPLICATE_CASE_ID X_ONE", "BROKEN_REFERENCE LOCKED_GONE", "ARTIFACT_DISAPPEARED PY:gone.py"):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)

    def test_the_real_catalog_is_valid(self):
        from core.services.test_governance import catalog_check

        result = catalog_check.validate_catalog()
        self.assertEqual(result["errors"], [])
        self.assertGreater(result["declared"], 0)
