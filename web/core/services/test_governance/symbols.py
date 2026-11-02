"""AST inventory of every meaningful function / method of a deployed Python artifact, each with a DISPOSITION.

The disposition is decided by fixed, documented rules (never by whether a test happens to exist), so the required
number of cases -- the "Y" of every "X / Y" -- comes from the code, not from the tests:

    R1  declared exemption in policy.yml                          -> EXEMPT (its reason)
    R2  private helper (``_name``)                                -> INTERNAL: proven through its public boundary,
                                                                     with its own line / branch coverage shown
    R3  presentation / protocol dunder (``__str__``, ``__eq__`` ...) -> EXEMPT
    R4  abstract / interface declaration (pass, ..., NotImplementedError, @abstractmethod) -> EXEMPT
    R5  trivial initializer (only stores its arguments)            -> EXEMPT
    R6  pure accessor (no arguments, a single ``return`` of a name / attribute / constant) -> EXEMPT
    R7  framework declaration hook (``add_arguments``, ``ready``)    -> POSITIVE only
    R10 input-independent callable (takes inputs but its body never reads any of them, e.g. a read-only admin
        ``has_change_permission`` returning False, an immutable model's ``delete`` that always raises)
                                                                   -> POSITIVE only: no input can change its behavior, so
                                                                      no negative input case exists; one direct test of
                                                                      either intent proves it
    R8  public callable WITH inputs (an exposed boundary)          -> POSITIVE_AND_NEGATIVE
    R9  public callable without inputs                             -> POSITIVE

Nested functions (closures) are part of their enclosing function and are not separate symbols.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from .constants import REPO_ROOT, Disposition
from .policy import Policy, default_policy

PROTOCOL_DUNDERS_WITH_BEHAVIOR = frozenset({"__init__", "__call__", "__post_init__", "__enter__", "__exit__", "__aenter__", "__aexit__"})
FRAMEWORK_HOOKS = frozenset({"add_arguments", "ready"})
PROPERTY_DECORATORS = frozenset({"property", "cached_property", "functools.cached_property"})

REASONS = {
    "R2": "private helper: proven through its public boundary; its own line / branch coverage is reported",
    "R3": "presentation / protocol dunder with no operational behavior",
    "R4": "abstract / interface declaration: no behavior of its own",
    "R5": "trivial initializer: only stores its arguments",
    "R6": "pure accessor: returns a stored value without logic",
    "R7": "framework declaration hook: a positive case proves it; it has no input boundary of its own",
    "R10": "input-independent: no parameter is ever read, so no input can change its behavior; one direct test proves it",
}


@dataclass(frozen=True)
class Symbol:
    id: str                 # "<repo path>::<qualified name>"
    artifact_path: str
    qualname: str
    name: str
    kind: str               # function | method | property | staticmethod | classmethod
    line_start: int
    line_end: int
    public: bool
    params: tuple[str, ...]
    disposition: str
    rule: str
    reason: str = ""
    is_async: bool = False

    @property
    def positive_required(self) -> bool:
        return self.disposition in (Disposition.POS, Disposition.POS_NEG)

    @property
    def negative_required(self) -> bool:
        return self.disposition == Disposition.POS_NEG

    def to_dict(self) -> dict:
        return {
            "id": self.id, "qualname": self.qualname, "kind": self.kind, "lines": [self.line_start, self.line_end],
            "public": self.public, "params": list(self.params), "disposition": self.disposition, "rule": self.rule,
            "reason": self.reason,
        }


@dataclass
class ModuleSymbols:
    path: str
    symbols: list[Symbol] = field(default_factory=list)
    error: str = ""


def symbol_id(path: str, qualname: str) -> str:
    return f"{path}::{qualname}"


def _decorator_names(node) -> list[str]:
    names = []
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        parts = []
        while isinstance(target, ast.Attribute):
            parts.append(target.attr)
            target = target.value
        if isinstance(target, ast.Name):
            parts.append(target.id)
        names.append(".".join(reversed(parts)))
    return names


def _body_without_docstring(node) -> list[ast.stmt]:
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return body


def _is_abstract(node, decorators: list[str]) -> bool:
    if any(d.split(".")[-1] in ("abstractmethod", "abstractproperty") for d in decorators):
        return True
    body = _body_without_docstring(node)
    if not body:
        return True
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, ast.Pass) or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis):
        return True
    if isinstance(stmt, ast.Raise) and stmt.exc is not None:
        target = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
        return isinstance(target, ast.Name) and target.id == "NotImplementedError"
    return False


def _is_trivial_init(node, params: tuple[str, ...]) -> bool:
    for stmt in _body_without_docstring(node):
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value = stmt.value
            plain_value = value is None or isinstance(value, (ast.Name, ast.Constant)) or (
                isinstance(value, (ast.Dict, ast.List, ast.Set, ast.Tuple)) and not any(True for _ in ast.iter_child_nodes(value)))
            if all(isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self" for t in targets) and plain_value:
                continue
            return False
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            func = stmt.value.func
            if isinstance(func, ast.Attribute) and func.attr == "__init__" and isinstance(func.value, ast.Call) \
                    and isinstance(func.value.func, ast.Name) and func.value.func.id == "super":
                continue
        return False
    return True


def _is_pure_accessor(node, params: tuple[str, ...]) -> bool:
    if params:
        return False
    body = _body_without_docstring(node)
    if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
        return False
    value = body[0].value
    while isinstance(value, ast.Attribute):
        value = value.value
    return isinstance(value, (ast.Name, ast.Constant))


def _ignores_inputs(node, params: tuple[str, ...]) -> bool:
    """True when the body (nested functions included) never reads any of ``params`` (``*args`` / ``**kw`` by bare name)."""
    if not params:
        return False
    names = {p.lstrip("*") for p in params}
    for stmt in node.body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name) and sub.id in names:
                return False
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in ("locals", "vars"):
                return False
    return True


def _params(node, *, method: bool, decorators: list[str]) -> tuple[str, ...]:
    args = node.args
    names = [a.arg for a in (*args.posonlyargs, *args.args)]
    if method and "staticmethod" not in decorators and names:
        names = names[1:]  # self / cls
    names += [a.arg for a in args.kwonlyargs]
    if args.vararg:
        names.append("*" + args.vararg.arg)
    if args.kwarg:
        names.append("**" + args.kwarg.arg)
    return tuple(names)


def disposition_for(name: str, node, *, qualname: str, path: str, method: bool, decorators: list[str], params: tuple[str, ...],
                    policy: Policy) -> tuple[str, str, str]:
    """(disposition, rule id, reason) for one function / method."""
    declared = policy.symbol_exemptions.get(symbol_id(path, qualname))
    if declared:
        return Disposition.EXEMPT, "R1", declared
    dunder = name.startswith("__") and name.endswith("__")
    if name.startswith("_") and not dunder:
        return Disposition.INTERNAL, "R2", REASONS["R2"]
    if dunder and name not in PROTOCOL_DUNDERS_WITH_BEHAVIOR:
        return Disposition.EXEMPT, "R3", REASONS["R3"]
    if _is_abstract(node, decorators):
        return Disposition.EXEMPT, "R4", REASONS["R4"]
    if name == "__init__" and _is_trivial_init(node, params):
        return Disposition.EXEMPT, "R5", REASONS["R5"]
    if method and _is_pure_accessor(node, params):
        return Disposition.EXEMPT, "R6", REASONS["R6"]
    if name in FRAMEWORK_HOOKS and method:
        return Disposition.POS, "R7", REASONS["R7"]
    if name in ("__enter__", "__exit__", "__aenter__", "__aexit__"):
        return Disposition.POS, "R9", ""
    if _ignores_inputs(node, params):
        return Disposition.POS, "R10", REASONS["R10"]
    if params:
        return Disposition.POS_NEG, "R8", ""
    return Disposition.POS, "R9", ""


def parse_symbols(path: str, source: str, *, policy: Policy | None = None) -> ModuleSymbols:
    policy = policy or default_policy()
    result = ModuleSymbols(path)
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        result.error = f"SyntaxError line {exc.lineno}"
        return result

    def visit(body, prefix: str, in_class: bool) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, f"{prefix}{node.name}.", True)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorators = _decorator_names(node)
                qualname = f"{prefix}{node.name}"
                params = _params(node, method=in_class, decorators=decorators)
                if in_class and any(d in PROPERTY_DECORATORS or d.endswith((".setter", ".getter", ".deleter")) for d in decorators):
                    kind = "property"
                elif "staticmethod" in decorators:
                    kind = "staticmethod"
                elif "classmethod" in decorators:
                    kind = "classmethod"
                else:
                    kind = "method" if in_class else "function"
                disposition, rule, reason = disposition_for(node.name, node, qualname=qualname, path=path, method=in_class,
                                                            decorators=decorators, params=params, policy=policy)
                result.symbols.append(Symbol(
                    symbol_id(path, qualname), path, qualname, node.name, kind, node.lineno, node.end_lineno or node.lineno,
                    not node.name.startswith("_") or node.name in PROTOCOL_DUNDERS_WITH_BEHAVIOR, params, disposition, rule, reason,
                    isinstance(node, ast.AsyncFunctionDef)))
            elif isinstance(node, (ast.If, ast.Try)) and not in_class:
                # module-level ``if TYPE_CHECKING`` / ``try: import`` blocks may define functions
                for block in (node.body, getattr(node, "orelse", []), getattr(node, "finalbody", [])):
                    visit(block, prefix, in_class)
                for handler in getattr(node, "handlers", []):
                    visit(handler.body, prefix, in_class)

    visit(tree.body, "", False)
    # a property setter shares its getter's qualified name: keep the first definition only (one symbol, one id)
    seen: set[str] = set()
    unique = []
    for symbol in result.symbols:
        if symbol.id not in seen:
            seen.add(symbol.id)
            unique.append(symbol)
    result.symbols = unique
    return result


def inventory_symbols(paths: list[str], repo: Path = REPO_ROOT, *, policy: Policy | None = None) -> dict[str, ModuleSymbols]:
    policy = policy or default_policy()
    out = {}
    for path in paths:
        try:
            source = (repo / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            out[path] = ModuleSymbols(path, error=f"unreadable: {type(exc).__name__}")
            continue
        out[path] = parse_symbols(path, source, policy=policy)
    return out
