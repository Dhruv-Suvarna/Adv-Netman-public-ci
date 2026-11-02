"""The REQUIRED test-case catalog and its evaluation against one evidence run.

The "Y" of every "X / Y" is derived from the deployed code and the capability matrix -- never from the tests that
happen to exist -- so five written tests can never display as "5 / 5" when ten cases are required:

    SYM:<path>::<qualname>:POSITIVE|NEGATIVE   every symbol whose disposition requires it (symbols.py rules R1-R9)
    TPL:<path>:RENDER:POSITIVE                  every CURRENT network Jinja template renders through its real producer
    TPL:<path>:STRICT_UNDEFINED:NEGATIVE        ... and a missing variable fails closed (StrictUndefined)
    CFG:<path>:LOAD:POSITIVE / :MALFORMED:NEGATIVE  every CURRENT YAML / JSON artifact through its loader
    EXE:<path>:STATIC:POSITIVE                  every CURRENT shell script / systemd unit / service configuration
    CELL:<platform>:<feature>:<stage>:POSITIVE|NEGATIVE  every implemented stage of every SUPPORTED capability cell
    <DECLARED_ID>                               every ``@case`` declaration (locked by the baseline once declared)

X counts a case only when a test that proves it RAN in the evidence run and PASSED.  A symbol case is proven by a
declared case on that symbol, or by a passing test that invoked the symbol DIRECTLY from its own body (tracer.py):

    POSITIVE  the direct call returned normally in a positive / neutral test context      (basis DIRECT_RETURN)
    NEGATIVE  the direct call raised in a passing test                                    (basis DIRECT_RAISE)
              the direct call returned inside a test / sub-test whose stated intent is a
              refusal or invalid input                                                    (basis DIRECT_REFUSAL)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .cases import Case, shape_errors
from .cells import Cell, cell_case_id
from .constants import ArtifactType, Basis, CaseState, Disposition, Polarity, Scope
from .inventory import Artifact, Inventory
from .symbols import ModuleSymbols

PASSING = frozenset({"PASS"})
FAILING = frozenset({"FAIL", "ERROR", "UNEXPECTED_SUCCESS"})

TEMPLATE_CASES = (("RENDER", Polarity.POSITIVE, "renders through its real producer with valid intent (deterministic output)",
                   "rendering succeeds and the output is identical on a second render"),
                  ("STRICT_UNDEFINED", Polarity.NEGATIVE, "a variable the template requires is missing",
                   "rendering fails closed with UndefinedError (no silently empty configuration)"))
STRUCTURED_CASES = (("LOAD", Polarity.POSITIVE, "the tracked file is loaded by its loader / parser",
                     "it parses; required keys are present; referenced names resolve"),
                    ("MALFORMED", Polarity.NEGATIVE, "a malformed / incomplete copy of the file",
                     "the loader or validator refuses it (no partial configuration)"))
EXECUTABLE_CASES = (("STATIC", Polarity.POSITIVE, "static verification of the deployed file (no host is modified)",
                     "shell: bash -n parse, strict mode; systemd: required sections / absolute ExecStart; config: structure"),)
STRUCTURED_TYPES = (ArtifactType.YAML, ArtifactType.JSON)
EXECUTABLE_TYPES = (ArtifactType.SHELL, ArtifactType.SYSTEMD, ArtifactType.CONFIG)


SYMBOL_TEXT = {
    Polarity.POSITIVE: ("intended input", "expected result / state"),
    Polarity.NEGATIVE: ("invalid, boundary or unexpected input", "refusal: exception, finding or blocker; no unintended effect"),
}


@dataclass
class Evidence:
    """All traced test sessions of one run (Django + monitoring), merged."""

    tests: dict[str, dict]
    sessions: list[dict] = field(default_factory=list)

    @classmethod
    def from_traces(cls, traces: list[dict]) -> "Evidence":
        tests: dict[str, dict] = {}
        sessions = []
        for trace in traces:
            sessions.append({"suite": trace.get("suite"), "meta": trace.get("meta") or {}, "tests": len(trace.get("tests") or {})})
            for test_id, record in (trace.get("tests") or {}).items():
                tests[test_id] = record
        return cls(tests, sessions)


@dataclass
class CatalogResult:
    tests: list[dict]
    cases: list[dict]
    errors: list[str]
    declared: dict[str, Case]


def _symbol_case_id(symbol_id: str, polarity: str) -> str:
    return f"SYM:{symbol_id}:{polarity}"


def _link_evidence(counts) -> tuple[bool, bool, str]:
    """(positive, negative, negative basis) from the tracer's [pos_starts, pos_unwinds, neg_starts, neg_unwinds]."""
    if len(counts) == 2:  # older two-counter format: [starts, unwinds]
        counts = [counts[0], counts[1], 0, 0]
    pos_starts, pos_unwinds, neg_starts, neg_unwinds = (int(c) for c in counts[:4])
    positive = pos_starts > pos_unwinds
    raised = pos_unwinds + neg_unwinds > 0
    refusal = neg_starts > neg_unwinds
    basis = Basis.DIRECT_RAISE if raised else Basis.DIRECT_REFUSAL
    return positive, raised or refusal, basis


def state_of(outcomes: list[str]) -> str:
    if any(o in PASSING for o in outcomes):
        return CaseState.PASS
    if any(o in FAILING for o in outcomes):
        return CaseState.FAIL
    return CaseState.MISSING


def _declared_cases(evidence: Evidence, test_ids: list, index: dict, by_path: dict, symbol_index: dict,
                    errors: list[str]) -> tuple[dict[str, Case], dict[str, list[int]]]:
    """Declared ``@case`` metadata from the evidence run, with shape / target / duplicate errors appended to ``errors``."""
    declared: dict[str, Case] = {}
    declared_tests: dict[str, list[int]] = defaultdict(list)
    for tid in test_ids:
        for raw in evidence.tests[tid].get("declared") or ():
            item = Case.from_dict(raw)
            previous = declared.get(item.case_id)
            if previous is not None and previous != item:
                errors.append(f"DUPLICATE_CASE_ID {item.case_id}: declared with different metadata by more than one test")
            declared.setdefault(item.case_id, item)
            declared_tests[item.case_id].append(index[tid])
    for item in declared.values():
        for problem in shape_errors(item):
            errors.append(f"MALFORMED_CASE {problem}")
        if item.artifact_path not in by_path:
            errors.append(f"BROKEN_TARGET {item.case_id}: artifact {item.artifact_path} is not a deployed artifact")
        elif item.symbol and item.symbol not in symbol_index:
            errors.append(f"BROKEN_TARGET {item.case_id}: symbol {item.symbol} does not exist")
    return declared, declared_tests


def _symbol_evidence(evidence: Evidence, test_ids: list, index: dict, declared: dict, declared_tests: dict) -> dict:
    """(symbol id, polarity) -> [(test index, basis)] from direct-invocation links plus declared cases."""
    sym_evidence: dict[tuple[str, str], list[tuple[int, str]]] = defaultdict(list)
    for tid in test_ids:
        for symbol, counts in (evidence.tests[tid].get("links") or {}).items():
            positive, negative, neg_basis = _link_evidence(counts)
            if positive:
                sym_evidence[(symbol, Polarity.POSITIVE)].append((index[tid], Basis.DIRECT_RETURN))
            if negative:
                sym_evidence[(symbol, Polarity.NEGATIVE)].append((index[tid], neg_basis))
    for case_id, item in declared.items():
        if item.symbol:
            for t in declared_tests[case_id]:
                sym_evidence[(item.symbol, item.polarity)].append((t, Basis.DECLARED))
    return sym_evidence


def build_catalog(inventory: Inventory, modules: dict[str, ModuleSymbols], cells: tuple[Cell, ...], evidence: Evidence, *,
                  baseline: dict | None = None, policy=None) -> CatalogResult:
    from .policy import default_policy

    policy = policy or default_policy()
    baseline = baseline or {}
    debt = set(baseline.get("case_debt") or ())
    locked = dict(baseline.get("declared_cases") or {})
    errors: list[str] = list(inventory.errors)
    by_path = inventory.by_path()

    test_ids = sorted(evidence.tests)
    index = {tid: i for i, tid in enumerate(test_ids)}
    tests = []
    for tid in test_ids:
        record = evidence.tests[tid]
        tests.append({"id": tid, "outcome": record.get("outcome") or "NOT_RUN", "file": record.get("file", ""), "line": record.get("line", 0),
                      "doc": record.get("doc", ""), "intent": record.get("intent", ""),
                      "declared": sorted({d.get("case_id", "") for d in record.get("declared") or ()})})

    symbol_index = {s.id: s for m in modules.values() for s in m.symbols}

    declared, declared_tests = _declared_cases(evidence, test_ids, index, by_path, symbol_index, errors)
    sym_evidence = _symbol_evidence(evidence, test_ids, index, declared, declared_tests)

    cases: list[dict] = []
    consumed: set[str] = set()

    def outcome_list(entries) -> list[str]:
        return [tests[t]["outcome"] for t, _b in entries]

    def add(case_id: str, *, kind: str, artifact: Artifact | None, polarity: str, title: str, condition: str, expected: str,
            scope: str, entries: list[tuple[int, str]], symbol: str = "", reason: str = "", platform: str = "", feature: str = "",
            stage: str = "", state: str | None = None) -> None:
        entries = sorted(set(entries))
        if state is None:
            if scope == Scope.NOT_CURRENT_SCOPE:
                state = CaseState.NOT_CURRENT_SCOPE
            elif scope == Scope.EXEMPT:
                state = CaseState.EXEMPT
            else:
                outcomes = outcome_list(entries)
                state = state_of(outcomes)
                if state == CaseState.MISSING and "EXPECTED_FAILURE" in outcomes:
                    reason = reason or "KNOWN DEFECT: the test reproduces a documented defect (expected failure); never counted as PASS"
                elif state == CaseState.MISSING and entries:
                    reason = reason or "the proving test(s) were skipped in the evidence run"
        cases.append({
            "id": case_id, "kind": kind, "artifact": artifact.id if artifact else "", "symbol": symbol, "polarity": polarity,
            "title": title, "condition": condition, "expected": expected, "scope": scope, "state": state,
            "evidence": [[t, b] for t, b in entries[:25]], "evidence_total": len(entries),
            "debt": state == CaseState.MISSING and case_id in debt, "reason": reason,
            "platform": platform, "feature": feature, "stage": stage,
        })

    def declared_entries(case_id: str) -> list[tuple[int, str]]:
        if case_id in declared:
            consumed.add(case_id)
        return [(t, Basis.DECLARED) for t in declared_tests.get(case_id, ())]

    # -- symbol cases -----------------------------------------------------------------------
    for artifact in inventory.artifacts:
        if artifact.type != ArtifactType.PYTHON or artifact.scope == Scope.EXEMPT:
            continue
        module = modules.get(artifact.path)
        if module is None:
            continue
        if module.error:
            errors.append(f"UNPARSABLE {artifact.id}: {module.error}")
        for symbol in module.symbols:
            if symbol.disposition == Disposition.EXEMPT:
                add(f"SYM:{symbol.id}:EXEMPT", kind="SYMBOL", artifact=artifact, polarity=Polarity.POSITIVE, symbol=symbol.id,
                    title="", condition="", expected="", scope=Scope.EXEMPT, entries=[], reason=symbol.reason)
                continue
            if symbol.disposition == Disposition.INTERNAL:
                continue
            wanted = [Polarity.POSITIVE] + ([Polarity.NEGATIVE] if symbol.negative_required else [])
            for polarity in wanted:
                # generic wording is derived by the page from kind + polarity (SYMBOL_TEXT); only declared cases carry their own
                entries = list(sym_evidence.get((symbol.id, polarity), []))
                if symbol.rule == "R10":   # input-independent: a direct test of either intent proves the single case
                    entries += sym_evidence.get((symbol.id, Polarity.NEGATIVE), [])
                add(_symbol_case_id(symbol.id, polarity), kind="SYMBOL", artifact=artifact, polarity=polarity, symbol=symbol.id,
                    title="", condition="", expected="", scope=artifact.scope, entries=entries)

    # -- template / structured / executable artifact cases ------------------------------------
    for artifact in inventory.artifacts:
        if artifact.scope == Scope.EXEMPT:
            continue
        if artifact.type == ArtifactType.JINJA:
            spec, prefix, kind = TEMPLATE_CASES, "TPL", "TEMPLATE"
        elif artifact.type in STRUCTURED_TYPES:
            spec, prefix, kind = STRUCTURED_CASES, "CFG", "STRUCTURED"
        elif artifact.type in EXECUTABLE_TYPES:
            spec, prefix, kind = EXECUTABLE_CASES, "EXE", "EXECUTABLE"
        else:
            continue
        for stage, polarity, condition, expected in spec:
            case_id = f"{prefix}:{artifact.path}:{stage}:{polarity}"
            reason = ""
            if kind == "TEMPLATE" and stage == "STRICT_UNDEFINED" and not artifact.variables:
                reason = "static template: it references no variable, so nothing can be undefined"
            elif kind == "STRUCTURED" and stage == "MALFORMED" and policy.external_consumer(artifact.path):
                reason = "external consumer: " + policy.external_consumer(artifact.path).reason
            add(case_id, kind=kind, artifact=artifact, polarity=polarity, title=f"{stage.replace('_', ' ').lower()} -- {condition}",
                condition=condition, expected=expected, scope=Scope.EXEMPT if reason and artifact.scope == Scope.CURRENT else artifact.scope,
                entries=declared_entries(case_id), platform=artifact.platform, reason=reason)

    # -- platform x feature cells ---------------------------------------------------------------
    from .constants import CELL_STAGES

    stage_titles = dict(CELL_STAGES)
    for cell in cells:
        if not cell.supported:
            continue
        for stage in cell.stages:
            for polarity in Polarity.ALL:
                case_id = cell_case_id(cell.platform, cell.feature, stage, polarity)
                add(case_id, kind="CELL", artifact=None, polarity=polarity,
                    title=f"{stage_titles[stage]} -- {'valid intent' if polarity == Polarity.POSITIVE else 'invalid / unsupported input'}",
                    condition=declared[case_id].condition if case_id in declared else "",
                    expected=declared[case_id].expected if case_id in declared else "",
                    scope=Scope.CURRENT, entries=declared_entries(case_id), platform=cell.platform, feature=cell.feature, stage=stage)

    # -- remaining declared cases (their own requirement) ---------------------------------------
    for case_id in sorted(declared):
        if case_id in consumed or case_id.startswith(("SYM:", "TPL:", "CFG:", "EXE:", "CELL:")):
            if case_id not in consumed and case_id.startswith(("TPL:", "CFG:", "EXE:", "CELL:")):
                errors.append(f"UNKNOWN_GENERATED_CASE {case_id}: no such generated requirement (wrong id or not current scope)")
            continue
        item = declared[case_id]
        artifact = by_path.get(item.artifact_path)
        add(case_id, kind="DECLARED", artifact=artifact, polarity=item.polarity, symbol=item.symbol,
            title=item.condition, condition=item.condition, expected=item.expected,
            scope=artifact.scope if artifact else Scope.CURRENT, entries=declared_entries(case_id), platform=item.platform,
            feature=item.feature, stage=item.stage, reason=item.requirement)
    # a locked (previously declared) case that no test declares any more
    for case_id in sorted(set(locked) - set(declared)):
        artifact = by_path.get(str(locked[case_id]).split("::", 1)[0])
        add(case_id, kind="DECLARED", artifact=artifact, polarity=Polarity.POSITIVE, title=f"declared case {case_id}",
            condition="", expected="", scope=Scope.CURRENT, entries=[], state=CaseState.BROKEN_REFERENCE,
            reason="the baseline locks this declared case, but no test in the evidence run declares it")
    return CatalogResult(tests, cases, errors, declared)
