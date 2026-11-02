"""Shared SR Linux data-model primitives: ``set`` paths <-> the YANG JSON tree.

SR Linux is model-driven.  The renderer emits flat ``set <path> <value>`` statements, the device stores a keyed tree and
gNMI returns that tree as JSON_IETF (module-qualified names).  Every NMAS layer that touches SR Linux needs the same three
conversions, so they live here once and carry no I/O:

* ``operations`` / ``tree_from_set_lines``  rendered statements -> structured leaf operations -> the JSON tree shape
                                             ``parser_srlinux`` imports (so a candidate and a live read parse alike);
* ``normalize``                              a gNMI JSON_IETF value -> the same plain tree (module prefixes removed);
* ``inverse``                                the exact undo of a set of operations RELATIVE TO A CAPTURED TREE: an object
                                             NMAS created is deleted at the topmost node that did not exist, a replaced
                                             leaf gets its captured value back, and anything already equal is left alone.

List keys are the only schema knowledge required.  ``LIST_KEYS`` names them for the modelled part of the tree; a statement
that walks outside ``MODELLED`` is refused by ``operations(strict=True)`` rather than guessed at, because a list mistaken
for a container would produce a wrong (and therefore unsafe) inverse.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass

# schema path (list/container names, keys removed) -> the key leaf of that list, or the ordered key leaves of a list with
# several keys (``acl-filter NAME type ipv4`` in the CLI, ``acl-filter[name=NAME][type=ipv4]`` in gNMI).  Every entry was
# verified against SR Linux 24.10.7 (a committed tree read back with ``info | as json`` and gNMI Get).
LIST_KEYS = {
    "interface": "name",
    "interface/subinterface": "index",
    "interface/subinterface/ipv4/address": "ip-prefix",
    "interface/subinterface/ipv6/address": "ip-prefix",
    "network-instance": "name",
    "network-instance/interface": "name",
    "network-instance/static-routes/route": "prefix",
    "network-instance/next-hop-groups/group": "name",
    "network-instance/next-hop-groups/group/nexthop": "index",
    "network-instance/protocols/ospf/instance": "name",
    "network-instance/protocols/ospf/instance/area": "area-id",
    "network-instance/protocols/ospf/instance/area/interface": "interface-name",
    "network-instance/protocols/bgp/afi-safi": "afi-safi-name",
    "network-instance/protocols/bgp/group": "group-name",
    "network-instance/protocols/bgp/group/afi-safi": "afi-safi-name",
    "network-instance/protocols/bgp/neighbor": "peer-address",
    "network-instance/protocols/bgp/neighbor/afi-safi": "afi-safi-name",
    "routing-policy/prefix-set": "name",
    "routing-policy/prefix-set/prefix": ("ip-prefix", "mask-length-range"),
    "routing-policy/policy": "name",
    "routing-policy/policy/statement": "name",
    "acl/acl-filter": ("name", "type"),
    "acl/acl-filter/entry": "sequence-id",
    "acl/interface": "interface-id",
    "acl/interface/input/acl-filter": ("name", "type"),
    "acl/interface/output/acl-filter": ("name", "type"),
}
# Leaf-lists.  SR Linux takes them only in bracket form (``server [ a b ]``) and a ``set`` REPLACES the whole list (verified on
# 24.10.7: a second ``set ... server [ b ]`` leaves only ``b``, also across commits).
LEAF_LISTS = frozenset({
    "interface/subinterface/ipv4/dhcp-relay/server", "interface/subinterface/ipv6/dhcp-relay/server",
    "network-instance/protocols/bgp/export-policy", "network-instance/protocols/bgp/import-policy",
    "network-instance/protocols/bgp/group/export-policy", "network-instance/protocols/bgp/group/import-policy",
    "network-instance/protocols/bgp/neighbor/export-policy", "network-instance/protocols/bgp/neighbor/import-policy",
})
# YANG choices: creating one case removes its sibling cases, so an inverse that only deletes the new case would not restore a
# captured sibling.  Such an operation is not invertible here (the caller fails closed).
CHOICES = {"acl/acl-filter/entry/action": frozenset({"accept", "drop"})}
# Presence containers that end a statement (``... action accept``): a container, not a leaf ``action`` with value ``accept``.
PRESENCE = frozenset({"acl/acl-filter/entry/action/accept", "acl/acl-filter/entry/action/drop"})
INTEGER_LEAVES = frozenset({"index", "mtu", "ip-mtu", "preference", "metric", "vlan-id", "sequence-id", "autonomous-system",
                            "peer-as", "maximum-hops", "value", "start", "end"})
# Subtrees whose list keys above are complete and live-verified: the only ones an executor may invert.
MODELLED = ("interface", "network-instance/interface", "network-instance/static-routes", "network-instance/next-hop-groups",
            "network-instance/protocols/ospf", "network-instance/protocols/bgp", "routing-policy/prefix-set",
            "routing-policy/policy", "acl/acl-filter", "acl/interface")
MISSING = object()


class ModelError(ValueError):
    """A statement that is not an SR Linux ``set`` path this model can place in the tree."""


@dataclass(frozen=True)
class Step:
    name: str
    key: object = ""      # key leaf name, a tuple of key leaf names for a multi-key list, or "" for a container
    value: object = None  # key value (a tuple of values, in key order, for a multi-key list)

    @property
    def keys(self) -> tuple:
        return () if not self.key else (self.key if isinstance(self.key, tuple) else (self.key,))

    @property
    def values(self) -> tuple:
        return self.value if isinstance(self.key, tuple) else (self.value,)

    @property
    def cli(self) -> str:
        if not self.key:
            return self.name
        extra = [f"{key} {format_value(value)}" for key, value in zip(self.keys[1:], self.values[1:])]
        return " ".join([self.name, format_value(self.values[0]), *extra])

    @property
    def gnmi(self) -> str:
        return self.name + "".join(f"[{key}={value}]" for key, value in zip(self.keys, self.values)) if self.key else self.name


@dataclass(frozen=True)
class Operation:
    """One ``set``: the node path, and either a leaf assignment or (``leaf == ""``) bare creation of that node."""

    steps: tuple[Step, ...]
    leaf: str = ""
    value: object = None
    multi: bool = False   # a leaf-list member

    @property
    def schema(self) -> str:
        return "/".join(step.name for step in self.steps)


def _typed(leaf: str, token: str):
    if leaf in INTEGER_LEAVES and token.lstrip("-").isdigit():
        return int(token)
    return {"true": True, "false": False}.get(token, token)


def format_value(value) -> str:
    """A tree value as one CLI token (quoted when it would not survive tokenisation)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    return json.dumps(text) if not text or any(ch.isspace() or ch in '"#' for ch in text) else text


def statements(lines) -> list[str]:
    """The ``set`` statements of rendered text; comment (``!`` / ``#``) and blank lines are dropped."""
    out = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        if not line.startswith("set "):
            raise ModelError("Not an SR Linux set statement.")
        out.append(line)
    return out


def operation(line: str, *, strict: bool = False) -> Operation:
    try:
        tokens = shlex.split(line.strip())
    except ValueError as exc:
        raise ModelError("Unbalanced quoting in an SR Linux set statement.") from exc
    if not tokens or tokens[0] != "set":
        raise ModelError("Not an SR Linux set statement.")
    tokens = tokens[2:] if tokens[1:2] == ["/"] else tokens[1:]
    if not tokens:
        raise ModelError("Empty SR Linux set statement.")
    steps: list[Step] = []
    schema: list[str] = []
    i = 0
    while i < len(tokens):
        candidate = "/".join([*schema, tokens[i]])
        if candidate in LIST_KEYS:
            step, i = _list_step(tokens, i, LIST_KEYS[candidate])
            steps.append(step)
            schema.append(step.name)
            continue
        if candidate in LEAF_LISTS:
            op = Operation(tuple(steps), tokens[i], _members(tokens[i + 1:], tokens[i]), multi=True)
            break
        remaining = len(tokens) - i
        if remaining == 2 and f"{candidate}/{tokens[i + 1]}" in PRESENCE:
            steps.append(Step(tokens[i]))
            schema.append(tokens[i])
            i += 1
            continue
        if remaining == 2:        # <leaf> <value>
            op = Operation(tuple(steps), tokens[i], _typed(tokens[i], tokens[i + 1]))
            break
        if remaining == 1:        # presence container / valueless leaf
            op = Operation((*steps, Step(tokens[i])))
            break
        steps.append(Step(tokens[i]))
        schema.append(tokens[i])
        i += 1
    else:
        op = Operation(tuple(steps))
    if not op.steps:
        raise ModelError("A root-level leaf is not part of the modelled tree.")
    if strict:
        where = "/".join([op.schema, op.leaf]) if op.leaf else op.schema
        if not any(where == root or where.startswith(root + "/") for root in MODELLED):
            raise ModelError("Statement is outside the SR Linux subtrees NMAS can invert.")
    return op


def _list_step(tokens: list[str], i: int, keys) -> tuple[Step, int]:
    """The list entry starting at ``tokens[i]`` -> (its Step, the index after its keys).  A multi-key list names every key
    after the first (``acl-filter NAME type ipv4``)."""
    names = keys if isinstance(keys, tuple) else (keys,)
    if i + 1 >= len(tokens):
        raise ModelError("List entry without its key.")
    values, j = [_typed(names[0], tokens[i + 1])], i + 2
    for name in names[1:]:
        if tokens[j:j + 1] != [name] or j + 1 >= len(tokens):
            raise ModelError("List entry without all of its keys.")
        values.append(_typed(name, tokens[j + 1]))
        j += 2
    return Step(tokens[i], keys, tuple(values) if isinstance(keys, tuple) else values[0]), j


def _members(rest: list[str], leaf: str) -> tuple:
    """The members of a bracketed leaf-list value ``[ a b ]``; the statement must end with the closing bracket."""
    if len(rest) < 2 or rest[0] != "[" or rest[-1] != "]" or "[" in rest[1:-1] or "]" in rest[1:-1]:
        raise ModelError("An SR Linux leaf-list takes a bracketed value list.")
    return tuple(_typed(leaf, token) for token in rest[1:-1])


def operations(lines, *, strict: bool = False) -> list[Operation]:
    return [operation(line, strict=strict) for line in statements(lines)]


# --- tree ------------------------------------------------------------------------------------------------------------
def _child(node: dict, step: Step, *, create: bool):
    if not step.key:
        if step.name not in node:
            if not create:
                return MISSING
            node[step.name] = {}
        found = node[step.name]
        return found if isinstance(found, dict) else MISSING
    rows = node.get(step.name)
    if rows is None:
        if not create:
            return MISSING
        rows = node[step.name] = []
    if not isinstance(rows, list):
        return MISSING
    pairs = list(zip(step.keys, step.values))
    for row in rows:
        if isinstance(row, dict) and all(str(row.get(key)) == str(value) for key, value in pairs):
            return row
    if not create:
        return MISSING
    row = dict(pairs)
    rows.append(row)
    return row


def _choice_siblings(schema: str, case: str) -> frozenset:
    cases = CHOICES.get(schema, frozenset())
    return cases - {case} if case in cases else frozenset()


def apply_operation(tree: dict, op: Operation) -> None:
    """Merge one ``set`` into ``tree`` the way the device's candidate datastore would (a leaf-list is replaced, and creating
    one case of a choice removes its sibling cases)."""
    node = tree
    for depth, step in enumerate(op.steps):
        for sibling in _choice_siblings("/".join(s.name for s in op.steps[:depth]), step.name):
            node.pop(sibling, None)
        node = _child(node, step, create=True)
        if node is MISSING:
            raise ModelError("Statement conflicts with the tree's existing structure.")
    if op.leaf and op.multi:
        node[op.leaf] = list(op.value)
    elif op.leaf:
        node[op.leaf] = op.value


def tree_from_set_lines(lines) -> dict:
    """Rendered ``set`` statements -> the JSON tree SR Linux would hold for them (``info | as json`` shape)."""
    tree: dict = {}
    for op in operations(lines):
        apply_operation(tree, op)
    return tree


def looks_like_set_lines(text: str) -> bool:
    return any(line.strip().startswith("set ") for line in text.splitlines()) and not text.lstrip().startswith(("{", "["))


def _bare(name: str) -> str:
    return name.split(":", 1)[1] if ":" in name and name.split(":", 1)[0].startswith("srl_nokia") else name


def normalize(value):
    """A gNMI JSON_IETF value with module qualifiers removed from member names and identity values."""
    if isinstance(value, dict):
        return {_bare(key): normalize(item) for key, item in value.items() if key != "_annotate"}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return _bare(value) if isinstance(value, str) else value


def tree_from_gnmi(response: dict) -> dict:
    """The updates of one gNMI GetResponse merged into a single plain tree rooted at ``/``."""
    tree: dict = {}
    for notification in (response or {}).get("notification") or []:
        for update in notification.get("update") or []:
            value = normalize(update.get("val"))
            if not update.get("path"):
                if isinstance(value, dict):
                    tree.update(value)
                continue
            node, steps = tree, _steps_from_gnmi(update["path"])
            for step in steps[:-1]:
                node = _child(node, step, create=True)
            last = steps[-1]
            if last.key or isinstance(value, dict):
                target = _child(node, last, create=True)
                target.update(value if isinstance(value, dict) else {})
            else:
                node[last.name] = value
    return tree


_GNMI_KEY = re.compile(r"\[([^=\]]+)=([^\]]*)\]")


def _steps_from_gnmi(path: str) -> list[Step]:
    steps, token, depth = [], "", 0
    for ch in path.strip("/") + "/":
        if ch == "/" and depth == 0:
            name = _bare(token.partition("[")[0])
            pairs = _GNMI_KEY.findall(token)
            if len(pairs) == 1:
                steps.append(Step(name, pairs[0][0], _typed(pairs[0][0], pairs[0][1])))
            elif pairs:
                steps.append(Step(name, tuple(k for k, _ in pairs), tuple(_typed(k, v) for k, v in pairs)))
            else:
                steps.append(Step(name))
            token = ""
            continue
        depth += ch == "["
        depth -= ch == "]"
        token += ch
    return steps


def lookup(tree: dict, steps):
    node = tree
    for step in steps:
        node = _child(node, step, create=False)
        if node is MISSING:
            return MISSING
    return node


def cli_path(steps, leaf: str = "") -> str:
    return " ".join([*(step.cli for step in steps), *([leaf] if leaf else [])])


def gnmi_path(steps, leaf: str = "") -> str:
    return "/" + "/".join([*(step.gnmi for step in steps), *([leaf] if leaf else [])])


def _members_text(values) -> str:
    return "[ " + " ".join(format_value(value) for value in values) + " ]"


def statement(op: Operation) -> str:
    """The CLI ``set`` statement of one operation (a leaf-list in its bracket form)."""
    if op.leaf and op.multi:
        return f"set / {cli_path(op.steps, op.leaf)} {_members_text(op.value)}"
    if op.leaf:
        return f"set / {cli_path(op.steps, op.leaf)} {format_value(op.value)}"
    return f"set / {cli_path(op.steps)}"


def additive(ops, tree: dict) -> list[Operation]:
    """``ops`` with every leaf-list operation widened to the members ``tree`` already holds plus its own.

    A ``set`` replaces an SR Linux leaf-list, but a Configlet adds ONE object (one DHCP relay server, one export policy):
    sending its rendered members alone would silently drop the members another Configlet or the operator configured.
    Captured members keep their order; the Configlet's new members follow."""
    widened = []
    for op in ops:
        node = lookup(tree, op.steps) if op.multi else MISSING
        current = node.get(op.leaf) if node is not MISSING else None
        if op.multi and isinstance(current, list) and current:
            held = {str(value) for value in current}
            widened.append(Operation(op.steps, op.leaf, (*current, *(v for v in op.value if str(v) not in held)), multi=True))
        else:
            widened.append(op)
    return widened


def inverse(ops, tree: dict) -> list[str] | None:
    """Exact undo of ``ops`` against the captured ``tree`` as CLI statements: [] when satisfied, None when unprovable.

    * a node on the path that did not exist is deleted at its TOPMOST absent ancestor (a new address removes only that
      address; a new interface removes the interface; nothing that existed is ever deleted);
    * a leaf that existed with another value is set back to the captured value, a leaf-list to its captured members;
    * a leaf (or leaf-list) that did not exist under an existing node is deleted on its own.
    Deletions run last-created-first, before the value restores.  A non-scalar captured value where a leaf is set, or a new
    choice case whose sibling case is captured, is not inverted here (None): the caller must fail closed.
    """
    deletes: list[tuple[Step, ...]] = []
    leaf_deletes: list[str] = []
    restores: list[str] = []
    for op in ops:
        node, absent = tree, None
        for depth, step in enumerate(op.steps, 1):
            parent, node = node, _child(node, step, create=False)
            if node is MISSING:
                if any(sibling in parent for sibling in _choice_siblings("/".join(s.name for s in op.steps[:depth - 1]), step.name)):
                    return None
                absent = op.steps[:depth]
                break
        if absent is not None:
            if not any(absent[:len(seen)] == seen for seen in deletes):
                deletes = [seen for seen in deletes if seen[:len(absent)] != absent] + [absent]
            continue
        if not op.leaf:
            continue
        current = node.get(op.leaf, MISSING)
        if current is MISSING or (op.multi and current == []):
            path = cli_path(op.steps, op.leaf)
            if path not in leaf_deletes:
                leaf_deletes.append(path)
        elif op.multi:
            if not isinstance(current, list):
                return None
            if sorted(map(str, current)) != sorted(map(str, op.value)):
                restores.append(f"set / {cli_path(op.steps, op.leaf)} {_members_text(current)}")
        elif isinstance(current, (dict, list)):
            return None
        elif str(current) != str(op.value) or isinstance(current, bool) != isinstance(op.value, bool):
            restores.append(f"set / {cli_path(op.steps, op.leaf)} {format_value(current)}")
    return ([f"delete / {cli_path(steps)}" for steps in reversed(deletes)]
            + [f"delete / {path}" for path in reversed(leaf_deletes)] + list(dict.fromkeys(restores)))


def digest_text(tree: dict) -> str:
    """Canonical serialisation of a configuration tree (list order is not significant in keyed YANG lists)."""
    def canon(value):
        if isinstance(value, dict):
            return {key: canon(item) for key, item in sorted(value.items())}
        if isinstance(value, list):
            return sorted((canon(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
        return value
    return json.dumps(canon(tree), sort_keys=True, separators=(",", ":"))
